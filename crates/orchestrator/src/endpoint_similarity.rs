use std::collections::HashMap;

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

/// TF-IDF index over a collection of endpoint signatures.
///
/// Each endpoint is represented as a sparse TF-IDF vector. Cosine similarity
/// between any pair of endpoints can be computed in O(min(|a|, |b|)) time
/// where |a| and |b| are the number of distinct terms in each document.
pub struct TfIdfIndex {
    vectors: Vec<HashMap<String, f64>>,
    norms: Vec<f64>,
}

impl TfIdfIndex {
    /// Builds a TF-IDF index from the given endpoint signatures.
    pub fn build(signatures: &[EndpointSignature]) -> Self {
        let n = signatures.len();
        let token_sets: Vec<Vec<String>> = signatures.iter().map(tokenize_endpoint).collect();

        let df = compute_document_frequencies(&token_sets);
        let vectors: Vec<HashMap<String, f64>> = token_sets
            .iter()
            .map(|tokens| compute_tfidf_vector(tokens, &df, n))
            .collect();
        let norms: Vec<f64> = vectors.iter().map(vector_norm).collect();

        Self { vectors, norms }
    }

    /// Returns the cosine similarity between two indexed endpoints.
    ///
    /// Returns 0.0 if either endpoint has a zero-norm vector (no terms).
    pub fn cosine_similarity(&self, a: usize, b: usize) -> f64 {
        let norm_a = self.norms[a];
        let norm_b = self.norms[b];
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        let dot = dot_product(&self.vectors[a], &self.vectors[b]);
        dot / (norm_a * norm_b)
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

fn compute_tfidf_vector(
    tokens: &[String],
    df: &HashMap<String, usize>,
    total_docs: usize,
) -> HashMap<String, f64> {
    let total_terms = tokens.len() as f64;
    if total_terms == 0.0 {
        return HashMap::new();
    }

    let mut term_counts: HashMap<&str, usize> = HashMap::new();
    for token in tokens {
        *term_counts.entry(token.as_str()).or_insert(0) += 1;
    }

    let mut vector = HashMap::new();
    for (term, count) in term_counts {
        let tf = count as f64 / total_terms;
        let doc_freq = df.get(term).copied().unwrap_or(0);
        // smoothed IDF: ln(1 + N / (1 + df)) — always positive
        let idf = (1.0 + total_docs as f64 / (1.0 + doc_freq as f64)).ln();
        vector.insert(term.to_string(), tf * idf);
    }
    vector
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
