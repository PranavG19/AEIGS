use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

const MT19937_N: usize = 624;
const MT19937_M: usize = 397;
const MT19937_MATRIX_A: u32 = 0x9908B0DF;
const MT19937_UPPER_MASK: u32 = 0x80000000;
const MT19937_LOWER_MASK: u32 = 0x7FFFFFFF;
const SUFFICIENT_ENTROPY_BITS: f64 = 64.0;
const MINIMUM_TOKEN_LENGTH: usize = 16;
const SEQUENTIAL_DIFF_TOLERANCE: f64 = 0.01;
const TIMESTAMP_WINDOW_MS: u64 = 86_400_000;
const LCG_MODULUS_CANDIDATES: [u64; 3] = [2_147_483_647, 4_294_967_296, 2_147_483_648];

/// Weakness classification for CSRF token generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenWeakness {
    LowEntropy,
    Sequential,
    TimestampBased,
    PrngPredictable,
    StaticToken,
    ShortLength,
    PredictableCharset,
    MersenneTwisterRecoverable,
}

impl fmt::Display for TokenWeakness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenWeakness::LowEntropy => write!(f, "Low Entropy"),
            TokenWeakness::Sequential => write!(f, "Sequential"),
            TokenWeakness::TimestampBased => write!(f, "Timestamp Based"),
            TokenWeakness::PrngPredictable => write!(f, "PRNG Predictable"),
            TokenWeakness::StaticToken => write!(f, "Static Token"),
            TokenWeakness::ShortLength => write!(f, "Short Length"),
            TokenWeakness::PredictableCharset => write!(f, "Predictable Charset"),
            TokenWeakness::MersenneTwisterRecoverable => {
                write!(f, "Mersenne Twister Recoverable")
            }
        }
    }
}

/// Detected PRNG family backing the token generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrngType {
    MersenneTwister,
    LCG,
    XorShift,
    SystemRandom,
    Unknown,
}

impl fmt::Display for PrngType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrngType::MersenneTwister => write!(f, "Mersenne Twister"),
            PrngType::LCG => write!(f, "LCG"),
            PrngType::XorShift => write!(f, "XorShift"),
            PrngType::SystemRandom => write!(f, "System Random"),
            PrngType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Recovered internal state of a Mersenne Twister MT19937 PRNG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MersenneTwisterState {
    pub state: Vec<u32>,
    pub index: usize,
    pub recovered_from_outputs: usize,
}

impl MersenneTwisterState {
    pub fn new(state: Vec<u32>, index: usize, recovered_from_outputs: usize) -> Self {
        Self {
            state,
            index,
            recovered_from_outputs,
        }
    }
}

/// Result of Shannon and min-entropy analysis on a token corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub shannon_entropy: f64,
    pub min_entropy: f64,
    pub byte_distribution: HashMap<u8, usize>,
    pub is_sufficient: bool,
    pub weakness_type: Option<TokenWeakness>,
}

/// A single collected CSRF token sample with timing metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfTokenSample {
    pub value: String,
    pub collected_at_ms: u64,
    pub request_index: u64,
}

/// Prediction of the next CSRF token value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPrediction {
    pub predicted_next: String,
    pub confidence: f64,
    pub method_used: String,
}

/// Full entropy and predictability report for a CSRF token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub samples_collected: usize,
    pub shannon_entropy: f64,
    pub min_entropy: f64,
    pub detected_weakness: Option<TokenWeakness>,
    pub prng_type: PrngType,
    pub prediction: Option<TokenPrediction>,
    pub recommendations: Vec<String>,
}

/// Charset frequency profile for token character analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharsetProfile {
    pub charset_size: usize,
    pub hex_only: bool,
    pub numeric_only: bool,
    pub alphanumeric_only: bool,
    pub lowercase_only: bool,
    pub uppercase_only: bool,
    pub unique_chars: usize,
}

/// Analyzer that collects CSRF token samples and performs entropy,
/// PRNG detection, and predictability analysis including MT19937
/// state recovery from 624 observed outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfEntropyAnalyzer {
    samples: Vec<CsrfTokenSample>,
    numeric_values: Vec<u64>,
    mt_candidates: Vec<u32>,
}

impl CsrfEntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
            numeric_values: Vec::new(),
            mt_candidates: Vec::new(),
        }
    }

    pub fn collect_token_sample(&mut self, value: String, collected_at_ms: u64) {
        let request_index = self.samples.len() as u64;
        if let Ok(n) = value.parse::<u64>() {
            self.numeric_values.push(n);
            if n <= u32::MAX as u64 {
                self.mt_candidates.push(n as u32);
            }
        } else if value.starts_with("0x") || value.starts_with("0X") {
            if let Ok(n) = u64::from_str_radix(&value[2..], 16) {
                self.numeric_values.push(n);
                if n <= u32::MAX as u64 {
                    self.mt_candidates.push(n as u32);
                }
            }
        } else if !value.is_empty()
            && value.chars().all(|c| c.is_ascii_hexdigit())
            && u64::from_str_radix(&value, 16).is_ok()
        {
            let n = u64::from_str_radix(&value, 16).unwrap();
            self.numeric_values.push(n);
            if n <= u32::MAX as u64 {
                self.mt_candidates.push(n as u32);
            }
        }
        self.samples.push(CsrfTokenSample {
            value,
            collected_at_ms,
            request_index,
        });
    }

    pub fn samples(&self) -> &[CsrfTokenSample] {
        &self.samples
    }

    pub fn calculate_shannon_entropy(&self) -> f64 {
        let concatenated: String = self.samples.iter().map(|s| s.value.as_str()).collect();
        compute_shannon_entropy(&concatenated)
    }

    pub fn calculate_min_entropy(&self) -> f64 {
        let concatenated: String = self.samples.iter().map(|s| s.value.as_str()).collect();
        compute_min_entropy(&concatenated)
    }

    pub fn analyze_entropy(&self) -> EntropyAnalysis {
        let concatenated: String = self.samples.iter().map(|s| s.value.as_str()).collect();
        let shannon = compute_shannon_entropy(&concatenated);
        let min_ent = compute_min_entropy(&concatenated);
        let distribution = byte_frequency_map(&concatenated);
        let avg_len = if self.samples.is_empty() {
            0
        } else {
            self.samples.iter().map(|s| s.value.len()).sum::<usize>() / self.samples.len()
        };
        let effective_bits = shannon * avg_len as f64;
        let is_sufficient = effective_bits >= SUFFICIENT_ENTROPY_BITS;
        let weakness_type = self.primary_weakness(shannon, avg_len);

        EntropyAnalysis {
            shannon_entropy: shannon,
            min_entropy: min_ent,
            byte_distribution: distribution,
            is_sufficient,
            weakness_type,
        }
    }

    pub fn detect_sequential_pattern(&self) -> bool {
        if self.numeric_values.len() < 3 {
            return false;
        }
        let diffs: Vec<i64> = self
            .numeric_values
            .windows(2)
            .map(|w| w[1] as i64 - w[0] as i64)
            .collect();
        if diffs.is_empty() {
            return false;
        }
        let first = diffs[0] as f64;
        diffs
            .iter()
            .all(|&d| (d as f64 - first).abs() <= SEQUENTIAL_DIFF_TOLERANCE)
    }

    pub fn detect_timestamp_pattern(&self) -> bool {
        if self.samples.len() < 3 {
            return false;
        }
        let mut timestamp_correlated = 0usize;
        for sample in &self.samples {
            if let Ok(token_val) = sample.value.parse::<u64>() {
                let diff = token_val.abs_diff(sample.collected_at_ms);
                if diff < TIMESTAMP_WINDOW_MS {
                    timestamp_correlated += 1;
                }
            }
        }
        let ratio = timestamp_correlated as f64 / self.samples.len() as f64;
        ratio > 0.8
    }

    pub fn detect_prng_type(&self) -> PrngType {
        if self.numeric_values.len() < 4 {
            return PrngType::Unknown;
        }
        if self.detect_lcg_pattern() {
            return PrngType::LCG;
        }
        if self.detect_xorshift_pattern() {
            return PrngType::XorShift;
        }
        if self.mt_candidates.len() >= MT19937_N && self.attempt_mt19937_recovery().is_some() {
            return PrngType::MersenneTwister;
        }
        let entropy = self.calculate_shannon_entropy();
        if entropy > 7.5 {
            return PrngType::SystemRandom;
        }
        PrngType::Unknown
    }

    pub fn attempt_mt19937_recovery(&self) -> Option<MersenneTwisterState> {
        if self.mt_candidates.len() < MT19937_N {
            return None;
        }
        let outputs = &self.mt_candidates[..MT19937_N];
        let mut state = vec![0u32; MT19937_N];
        for (i, &output) in outputs.iter().enumerate() {
            state[i] = mt19937_untemper(output);
        }
        let predicted = mt19937_generate_from_state(&state, MT19937_N);
        if self.mt_candidates.len() > MT19937_N && predicted == self.mt_candidates[MT19937_N] {
            return Some(MersenneTwisterState::new(state, MT19937_N, MT19937_N));
        }
        if self.mt_candidates.len() == MT19937_N {
            return Some(MersenneTwisterState::new(state, MT19937_N, MT19937_N));
        }
        None
    }

    pub fn predict_next_token(&self) -> Option<TokenPrediction> {
        if self.samples.is_empty() {
            return None;
        }
        if self.detect_static_tokens() {
            return Some(TokenPrediction {
                predicted_next: self.samples.last().unwrap().value.clone(),
                confidence: 1.0,
                method_used: "static_token".to_string(),
            });
        }
        if self.detect_sequential_pattern() {
            return self.predict_sequential();
        }
        if let Some(mt_state) = self.attempt_mt19937_recovery() {
            return self.predict_from_mt_state(&mt_state);
        }
        if self.detect_timestamp_pattern() {
            return self.predict_timestamp_based();
        }
        None
    }

    pub fn analyze_charset(&self) -> CharsetProfile {
        let all_chars: Vec<char> = self.samples.iter().flat_map(|s| s.value.chars()).collect();
        let unique: std::collections::HashSet<char> = all_chars.iter().copied().collect();
        CharsetProfile {
            charset_size: unique.len(),
            hex_only: all_chars.iter().all(|c| c.is_ascii_hexdigit()),
            numeric_only: all_chars.iter().all(|c| c.is_ascii_digit()),
            alphanumeric_only: all_chars.iter().all(|c| c.is_ascii_alphanumeric()),
            lowercase_only: all_chars
                .iter()
                .filter(|c| c.is_ascii_alphabetic())
                .all(|c| c.is_ascii_lowercase()),
            uppercase_only: all_chars
                .iter()
                .filter(|c| c.is_ascii_alphabetic())
                .all(|c| c.is_ascii_uppercase()),
            unique_chars: unique.len(),
        }
    }

    pub fn generate_report(&self) -> EntropyReport {
        let entropy_analysis = self.analyze_entropy();
        let prng_type = self.detect_prng_type();
        let prediction = self.predict_next_token();
        let recommendations = self.build_recommendations(&entropy_analysis, prng_type);

        EntropyReport {
            samples_collected: self.samples.len(),
            shannon_entropy: entropy_analysis.shannon_entropy,
            min_entropy: entropy_analysis.min_entropy,
            detected_weakness: entropy_analysis.weakness_type,
            prng_type,
            prediction,
            recommendations,
        }
    }

    fn primary_weakness(&self, shannon: f64, avg_len: usize) -> Option<TokenWeakness> {
        if self.detect_static_tokens() {
            return Some(TokenWeakness::StaticToken);
        }
        if avg_len < MINIMUM_TOKEN_LENGTH {
            return Some(TokenWeakness::ShortLength);
        }
        if self.detect_sequential_pattern() {
            return Some(TokenWeakness::Sequential);
        }
        if self.detect_timestamp_pattern() {
            return Some(TokenWeakness::TimestampBased);
        }
        if self.mt_candidates.len() >= MT19937_N && self.attempt_mt19937_recovery().is_some() {
            return Some(TokenWeakness::MersenneTwisterRecoverable);
        }
        let charset = self.analyze_charset();
        if charset.numeric_only && charset.charset_size <= 10 {
            return Some(TokenWeakness::PredictableCharset);
        }
        let effective = shannon * avg_len as f64;
        if effective < SUFFICIENT_ENTROPY_BITS {
            return Some(TokenWeakness::LowEntropy);
        }
        None
    }

    fn detect_static_tokens(&self) -> bool {
        if self.samples.len() < 2 {
            return false;
        }
        let first = &self.samples[0].value;
        self.samples.iter().all(|s| s.value == *first)
    }

    fn detect_lcg_pattern(&self) -> bool {
        if self.numeric_values.len() < 4 {
            return false;
        }
        for &modulus in &LCG_MODULUS_CANDIDATES {
            if self.check_lcg_with_modulus(modulus) {
                return true;
            }
        }
        false
    }

    fn check_lcg_with_modulus(&self, modulus: u64) -> bool {
        let vals = &self.numeric_values;
        if vals.len() < 4 {
            return false;
        }
        let s0 = vals[0] % modulus;
        let s1 = vals[1] % modulus;
        let s2 = vals[2] % modulus;
        let diff1 = (s1 as i128 - s0 as i128).rem_euclid(modulus as i128) as u64;
        let diff2 = (s2 as i128 - s1 as i128).rem_euclid(modulus as i128) as u64;
        if diff1 == 0 {
            return false;
        }
        let a = compute_lcg_multiplier(diff1, diff2, modulus);
        if a.is_none() {
            return false;
        }
        let a = a.unwrap();
        let c = (s1 as i128 - a as i128 * s0 as i128).rem_euclid(modulus as i128) as u64;
        for window in vals.windows(2).skip(2).take(5) {
            let expected =
                (a as u128 * window[0] as u128 + c as u128).rem_euclid(modulus as u128) as u64;
            if expected != window[1] % modulus {
                return false;
            }
        }
        true
    }

    fn detect_xorshift_pattern(&self) -> bool {
        if self.numeric_values.len() < 8 {
            return false;
        }
        let vals = &self.numeric_values;
        let shift_triples: [(u32, u32, u32); 3] = [(13, 17, 5), (1, 7, 9), (12, 25, 27)];
        for (a, b, c) in shift_triples {
            if self.check_xorshift_triple(vals, a, b, c) {
                return true;
            }
        }
        false
    }

    fn check_xorshift_triple(&self, vals: &[u64], a: u32, b: u32, c: u32) -> bool {
        let mut matches = 0;
        for window in vals.windows(2).take(6) {
            let x = window[0] as u32;
            let mut t = x;
            t ^= t << a;
            t ^= t >> b;
            t ^= t << c;
            if t as u64 == window[1] {
                matches += 1;
            }
        }
        matches >= 4
    }

    fn predict_sequential(&self) -> Option<TokenPrediction> {
        if self.numeric_values.len() < 2 {
            return None;
        }
        let last_two = &self.numeric_values[self.numeric_values.len() - 2..];
        let diff = last_two[1] as i64 - last_two[0] as i64;
        let predicted = (last_two[1] as i64 + diff) as u64;
        let last_sample = self.samples.last().unwrap();
        let predicted_str = if last_sample.value.starts_with("0x") {
            format!("0x{:x}", predicted)
        } else if last_sample
            .value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_digit())
            || last_sample.value.len() > 10
                && last_sample.value.chars().all(|c| c.is_ascii_hexdigit())
        {
            format!("{:x}", predicted)
        } else {
            predicted.to_string()
        };

        Some(TokenPrediction {
            predicted_next: predicted_str,
            confidence: 0.95,
            method_used: "sequential_extrapolation".to_string(),
        })
    }

    fn predict_from_mt_state(&self, mt_state: &MersenneTwisterState) -> Option<TokenPrediction> {
        let predicted_raw = mt19937_generate_from_state(&mt_state.state, mt_state.index);
        let predicted_str = format!("{}", predicted_raw);

        Some(TokenPrediction {
            predicted_next: predicted_str,
            confidence: 0.99,
            method_used: "mt19937_state_recovery".to_string(),
        })
    }

    fn predict_timestamp_based(&self) -> Option<TokenPrediction> {
        if self.samples.len() < 2 {
            return None;
        }
        let last = self.samples.last().unwrap();
        let prev = &self.samples[self.samples.len() - 2];
        let time_diff = last.collected_at_ms.saturating_sub(prev.collected_at_ms);
        let estimated_next_ms = last.collected_at_ms + time_diff;

        Some(TokenPrediction {
            predicted_next: estimated_next_ms.to_string(),
            confidence: 0.6,
            method_used: "timestamp_extrapolation".to_string(),
        })
    }

    fn build_recommendations(
        &self,
        analysis: &EntropyAnalysis,
        prng_type: PrngType,
    ) -> Vec<String> {
        let mut recs = Vec::new();
        if let Some(ref weakness) = analysis.weakness_type {
            match weakness {
                TokenWeakness::StaticToken => {
                    recs.push(
                        "Token is static across requests; generate a unique token per session"
                            .to_string(),
                    );
                }
                TokenWeakness::ShortLength => {
                    recs.push(
                        "Token length below 16 characters; use at least 32 hex characters"
                            .to_string(),
                    );
                }
                TokenWeakness::Sequential => {
                    recs.push(
                        "Tokens follow a sequential pattern; use a CSPRNG instead of a counter"
                            .to_string(),
                    );
                }
                TokenWeakness::TimestampBased => {
                    recs.push(
                        "Tokens correlate with timestamps; do not derive tokens from time values"
                            .to_string(),
                    );
                }
                TokenWeakness::LowEntropy => {
                    recs.push(format!(
                        "Effective entropy {:.1} bits is below 64-bit threshold; use /dev/urandom or equivalent",
                        analysis.shannon_entropy
                    ));
                }
                TokenWeakness::PredictableCharset => {
                    recs.push(
                        "Token charset is limited; use hex or base64 encoding of random bytes"
                            .to_string(),
                    );
                }
                TokenWeakness::PrngPredictable => {
                    recs.push("Weak PRNG detected; replace with OS-level CSPRNG".to_string());
                }
                TokenWeakness::MersenneTwisterRecoverable => {
                    recs.push(
                        "Mersenne Twister state recoverable from outputs; MT19937 is not cryptographically secure"
                            .to_string(),
                    );
                }
            }
        }
        match prng_type {
            PrngType::MersenneTwister => {
                recs.push(
                    "Replace MT19937 with a CSPRNG such as ChaCha20 or AES-CTR-DRBG".to_string(),
                );
            }
            PrngType::LCG => {
                recs.push(
                    "Linear Congruential Generator is trivially predictable; use getrandom or /dev/urandom"
                        .to_string(),
                );
            }
            PrngType::XorShift => {
                recs.push(
                    "XorShift PRNG is not cryptographically secure; replace with CSPRNG"
                        .to_string(),
                );
            }
            PrngType::SystemRandom | PrngType::Unknown => {}
        }
        if !analysis.is_sufficient && recs.is_empty() {
            recs.push("Increase token entropy to at least 128 bits".to_string());
        }
        recs
    }
}

impl Default for CsrfEntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Reverse the MT19937 tempering transform to recover internal state from output.
pub fn mt19937_untemper(mut y: u32) -> u32 {
    y = untemper_right(y, 18);
    y = untemper_left(y, 15, 0xEFC60000);
    y = untemper_left(y, 7, 0x9D2C5680);
    y = untemper_right(y, 11);
    y
}

fn untemper_right(value: u32, shift: u32) -> u32 {
    let mut result = value;
    let mut i = shift;
    while i < 32 {
        result = value ^ (result >> shift);
        i += shift;
    }
    let _ = result;
    let mut tmp = value;
    let mut s = shift;
    while s < 32 {
        tmp = value ^ (tmp >> shift);
        s += shift;
    }
    tmp
}

fn untemper_left(value: u32, shift: u32, mask: u32) -> u32 {
    let mut result = value;
    let mut i = shift;
    while i < 32 {
        result = value ^ ((result << shift) & mask);
        i += shift;
    }
    let _ = result;
    let mut tmp = value;
    let mut s = shift;
    while s < 32 {
        tmp = value ^ ((tmp << shift) & mask);
        s += shift;
    }
    tmp
}

/// Generate the next MT19937 output given a full state array and current index.
pub fn mt19937_generate_from_state(state: &[u32], index: usize) -> u32 {
    let mut mt = state.to_vec();
    let mut idx = index;
    if idx >= MT19937_N {
        mt19937_twist(&mut mt);
        idx = 0;
    }
    mt19937_temper(mt[idx])
}

fn mt19937_twist(mt: &mut [u32]) {
    for i in 0..MT19937_N {
        let x = (mt[i] & MT19937_UPPER_MASK) | (mt[(i + 1) % MT19937_N] & MT19937_LOWER_MASK);
        let mut x_a = x >> 1;
        if x & 1 != 0 {
            x_a ^= MT19937_MATRIX_A;
        }
        mt[i] = mt[(i + MT19937_M) % MT19937_N] ^ x_a;
    }
}

fn mt19937_temper(mut y: u32) -> u32 {
    y ^= y >> 11;
    y ^= (y << 7) & 0x9D2C5680;
    y ^= (y << 15) & 0xEFC60000;
    y ^= y >> 18;
    y
}

fn compute_shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let freq = byte_frequency_map(data);
    let len = data.len() as f64;
    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

fn compute_min_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let freq = byte_frequency_map(data);
    let len = data.len() as f64;
    let max_freq = freq.values().copied().max().unwrap_or(0) as f64 / len;
    if max_freq <= 0.0 {
        return 0.0;
    }
    -(max_freq.log2())
}

fn byte_frequency_map(data: &str) -> HashMap<u8, usize> {
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in data.as_bytes() {
        *freq.entry(b).or_insert(0) += 1;
    }
    freq
}

fn compute_lcg_multiplier(diff1: u64, diff2: u64, modulus: u64) -> Option<u64> {
    if diff1 == 0 {
        return None;
    }
    let inv = mod_inverse(diff1, modulus)?;
    Some((diff2 as u128 * inv as u128 % modulus as u128) as u64)
}

fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    let (mut old_r, mut r) = (a as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let quotient = old_r / r;
        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;
        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;
    }
    if old_r != 1 {
        return None;
    }
    Some(old_s.rem_euclid(m as i128) as u64)
}

/// Seed an MT19937 state array from a single u32 seed (standard initialization).
pub fn mt19937_seed(seed: u32) -> Vec<u32> {
    let mut mt = vec![0u32; MT19937_N];
    mt[0] = seed;
    for i in 1..MT19937_N {
        mt[i] = 1812433253u32
            .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
            .wrapping_add(i as u32);
    }
    mt
}

/// Generate a sequence of MT19937 outputs from a seed.
pub fn mt19937_sequence(seed: u32, count: usize) -> Vec<u32> {
    let mut mt = mt19937_seed(seed);
    let mut results = Vec::with_capacity(count);
    let mut index = MT19937_N;
    for _ in 0..count {
        if index >= MT19937_N {
            mt19937_twist(&mut mt);
            index = 0;
        }
        results.push(mt19937_temper(mt[index]));
        index += 1;
    }
    results
}
