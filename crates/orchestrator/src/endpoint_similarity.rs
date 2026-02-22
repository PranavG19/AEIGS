use std::collections::{HashMap, HashSet};

use aegis_protocol::finding::VulnerabilityClass;

/// An endpoint's structural signature used for TF-IDF similarity comparison.
///
/// Captures the path structure, HTTP method, parameter names, and any
/// vulnerability classes previously confirmed at this endpoint. Two endpoints
/// with similar signatures are likely to share vulnerability classes.
#[derive(Debug, Clone)]
pub struct EndpointSignature {
    pub endpoint: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub vulnerability_classes_found: Vec<VulnerabilityClass>,
}

/// A finding transferred from a confirmed-vulnerable endpoint to a
/// structurally similar one, serving as a high-priority hypothesis.
#[derive(Debug, Clone)]
pub struct TransferredFinding {
    pub source_endpoint: String,
    pub target_endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
    pub similarity_score: f64,
    pub confidence: f64,
}

/// Tokenizes an endpoint signature into a bag-of-words representation.
///
/// Produces tokens from: path segments (with pattern normalization),
/// parameter names, and the HTTP method. All tokens are lowercased.
/// Path segments matching `:name` patterns become "param_segment";
/// segments matching UUID patterns become "uuid_segment".
pub fn tokenize_endpoint(sig: &EndpointSignature) -> Vec<String> {
    let mut tokens = Vec::new();

    for segment in sig.endpoint.split('/') {
        if segment.is_empty() {
            continue;
        }
        if segment.starts_with(':') {
            tokens.push("param_segment".to_string());
        } else if looks_like_uuid(segment) {
            tokens.push("uuid_segment".to_string());
        } else {
            tokens.push(segment.to_lowercase());
        }
    }

    for param in &sig.parameters {
        tokens.push(param.to_lowercase());
    }

    tokens.push(sig.method.to_lowercase());

    tokens
}

fn looks_like_uuid(s: &str) -> bool {
    // 8-4-4-4-12 hex pattern with dashes
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Positionally-weighted TF-IDF index with trigram secondary signal.
///
/// Each endpoint is represented as a sparse TF-IDF vector where tokens
/// at earlier positions receive higher weight (`1.0 / (1.0 + i)`).
/// Final similarity blends weighted cosine (0.7) with character trigram
/// Jaccard similarity (0.3).
pub struct TfIdfIndex {
    vectors: Vec<HashMap<String, f64>>,
    norms: Vec<f64>,
    trigram_sets: Vec<HashSet<[u8; 3]>>,
}

impl TfIdfIndex {
    /// Builds a positionally-weighted TF-IDF index from the given endpoint signatures.
    pub fn build(signatures: &[EndpointSignature]) -> Self {
        let n = signatures.len();
        let token_sets: Vec<Vec<String>> = signatures.iter().map(tokenize_endpoint).collect();

        let df = compute_document_frequencies(&token_sets);
        let vectors: Vec<HashMap<String, f64>> = token_sets
            .iter()
            .map(|tokens| compute_positional_tfidf_vector(tokens, &df, n))
            .collect();
        let norms: Vec<f64> = vectors.iter().map(vector_norm).collect();
        let trigram_sets: Vec<HashSet<[u8; 3]>> = signatures
            .iter()
            .map(|s| extract_trigrams(&s.endpoint))
            .collect();

        Self {
            vectors,
            norms,
            trigram_sets,
        }
    }

    /// Returns the blended similarity between two indexed endpoints.
    ///
    /// Combines positionally-weighted cosine similarity (70%) with
    /// character trigram Jaccard similarity (30%).
    pub fn cosine_similarity(&self, a: usize, b: usize) -> f64 {
        let positional = positional_cosine(
            &self.vectors[a],
            &self.vectors[b],
            self.norms[a],
            self.norms[b],
        );
        let trigram = trigram_jaccard(&self.trigram_sets[a], &self.trigram_sets[b]);
        0.7 * positional + 0.3 * trigram
    }

    /// Finds all endpoints with similarity to `index` above the given threshold.
    ///
    /// Returns (endpoint_index, similarity) pairs sorted by similarity descending.
    pub fn find_similar(&self, index: usize, threshold: f64) -> Vec<(usize, f64)> {
        let mut results: Vec<(usize, f64)> = (0..self.vectors.len())
            .filter(|&i| i != index)
            .map(|i| (i, self.cosine_similarity(index, i)))
            .filter(|&(_, sim)| sim >= threshold)
            .collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Returns the number of endpoints in the index.
    pub fn endpoint_count(&self) -> usize {
        self.vectors.len()
    }
}

/// Transfers vulnerability classes from a confirmed-vulnerable source endpoint
/// to structurally similar target endpoints as high-priority hypotheses.
///
/// Confidence is computed as `similarity_score * source_base_confidence`
/// (capped at 1.0), where `source_base_confidence` is 0.9 for confirmed
/// findings.
pub fn transfer_findings(
    source_idx: usize,
    targets: &[(usize, f64)],
    signatures: &[EndpointSignature],
) -> Vec<TransferredFinding> {
    let source = &signatures[source_idx];
    let mut transferred = Vec::new();
    // 0.9 = confirmed evidence base confidence
    let source_base_confidence = 0.9_f64;

    for &(target_idx, similarity_score) in targets {
        let target = &signatures[target_idx];
        for &vuln_class in &source.vulnerability_classes_found {
            let confidence = (similarity_score * source_base_confidence).min(1.0);
            transferred.push(TransferredFinding {
                source_endpoint: source.endpoint.clone(),
                target_endpoint: target.endpoint.clone(),
                vulnerability_class: vuln_class,
                similarity_score,
                confidence,
            });
        }
    }

    transferred
}

fn compute_document_frequencies(token_sets: &[Vec<String>]) -> HashMap<String, usize> {
    let mut df: HashMap<String, usize> = HashMap::new();
    for tokens in token_sets {
        let unique: std::collections::HashSet<&str> = tokens.iter().map(|t| t.as_str()).collect();
        for term in unique {
            *df.entry(term.to_string()).or_insert(0) += 1;
        }
    }
    df
}

fn compute_positional_tfidf_vector(
    tokens: &[String],
    df: &HashMap<String, usize>,
    total_docs: usize,
) -> HashMap<String, f64> {
    if tokens.is_empty() {
        return HashMap::new();
    }

    let mut weighted_counts: HashMap<&str, f64> = HashMap::new();
    let mut total_weight = 0.0_f64;
    for (i, token) in tokens.iter().enumerate() {
        let position_weight = 1.0 / (1.0 + i as f64);
        *weighted_counts.entry(token.as_str()).or_insert(0.0) += position_weight;
        total_weight += position_weight;
    }

    let mut vector = HashMap::new();
    for (term, weighted_count) in weighted_counts {
        let tf = weighted_count / total_weight;
        let doc_freq = df.get(term).copied().unwrap_or(0);
        let idf = (1.0 + total_docs as f64 / (1.0 + doc_freq as f64)).ln();
        vector.insert(term.to_string(), tf * idf);
    }
    vector
}

pub(crate) fn extract_trigrams(path: &str) -> HashSet<[u8; 3]> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 {
        return HashSet::new();
    }
    bytes.windows(3).map(|w| [w[0], w[1], w[2]]).collect()
}

pub(crate) fn trigram_jaccard(a: &HashSet<[u8; 3]>, b: &HashSet<[u8; 3]>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        return 0.0;
    }
    intersection / union
}

fn positional_cosine(
    a: &HashMap<String, f64>,
    b: &HashMap<String, f64>,
    norm_a: f64,
    norm_b: f64,
) -> f64 {
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    let dot = dot_product(a, b);
    dot / (norm_a * norm_b)
}

fn vector_norm(v: &HashMap<String, f64>) -> f64 {
    v.values().map(|x| x * x).sum::<f64>().sqrt()
}

fn dot_product(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
    let (smaller, larger) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    smaller
        .iter()
        .filter_map(|(k, v)| larger.get(k).map(|w| v * w))
        .sum()
}
