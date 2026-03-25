use std::collections::HashMap;

use regex::Regex;

/// Type of payment processor detected in public-facing assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymentProcessor {
    Stripe,
    Square,
    PayPal,
    Braintree,
    Adyen,
    Klarna,
    Affirm,
    Shopify,
    WooCommerce,
    Authorize,
    Unknown,
}

impl std::fmt::Display for PaymentProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stripe => write!(f, "Stripe"),
            Self::Square => write!(f, "Square"),
            Self::PayPal => write!(f, "PayPal"),
            Self::Braintree => write!(f, "Braintree"),
            Self::Adyen => write!(f, "Adyen"),
            Self::Klarna => write!(f, "Klarna"),
            Self::Affirm => write!(f, "Affirm"),
            Self::Shopify => write!(f, "Shopify Payments"),
            Self::WooCommerce => write!(f, "WooCommerce"),
            Self::Authorize => write!(f, "Authorize.net"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Type of cryptocurrency detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoNetwork {
    Bitcoin,
    Ethereum,
    Monero,
    Litecoin,
    BitcoinCash,
    Solana,
    Unknown,
}

impl std::fmt::Display for CryptoNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bitcoin => write!(f, "Bitcoin"),
            Self::Ethereum => write!(f, "Ethereum"),
            Self::Monero => write!(f, "Monero"),
            Self::Litecoin => write!(f, "Litecoin"),
            Self::BitcoinCash => write!(f, "Bitcoin Cash"),
            Self::Solana => write!(f, "Solana"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Sensitivity level of financial data exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FinancialSensitivity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FinancialSensitivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// A detected public key from a payment processor in JS bundles.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyFinding {
    pub processor: PaymentProcessor,
    pub key_value: String,
    pub is_live_key: bool,
    pub source_url: String,
    pub context_snippet: String,
}

/// A cryptocurrency wallet address found in page source.
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoWalletFinding {
    pub network: CryptoNetwork,
    pub address: String,
    pub source_url: String,
    pub context_snippet: String,
}

/// SEC EDGAR filing reference.
#[derive(Debug, Clone, PartialEq)]
pub struct SecFilingReference {
    pub filing_type: String,
    pub company_name: String,
    pub cik: String,
    pub filed_date: String,
    pub financial_indicators: Vec<String>,
}

/// A merchant ID extracted from checkout flows.
#[derive(Debug, Clone, PartialEq)]
pub struct MerchantIdFinding {
    pub processor: PaymentProcessor,
    pub merchant_id: String,
    pub source_url: String,
    pub is_sandbox: bool,
}

/// PCI DSS scope inference from checkout flow analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct PciScopeInference {
    pub in_scope: bool,
    pub card_data_handling: CardDataHandling,
    pub third_party_processors: Vec<String>,
    pub iframe_isolation: bool,
    pub tokenization_detected: bool,
    pub evidence: Vec<String>,
}

/// How the target handles card data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardDataHandling {
    FullyOutsourced,
    IframeTokenized,
    DirectPost,
    ServerSide,
    Unknown,
}

impl std::fmt::Display for CardDataHandling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullyOutsourced => write!(f, "Fully Outsourced (SAQ A)"),
            Self::IframeTokenized => write!(f, "Iframe/Tokenized (SAQ A-EP)"),
            Self::DirectPost => write!(f, "Direct Post (SAQ D)"),
            Self::ServerSide => write!(f, "Server-Side Processing (SAQ D)"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// PII transit path through financial infrastructure.
#[derive(Debug, Clone, PartialEq)]
pub struct PiiTransitPath {
    pub data_type: String,
    pub source_endpoint: String,
    pub destination: String,
    pub encrypted: bool,
    pub sensitivity: FinancialSensitivity,
}

/// Complete financial attack surface analysis result.
#[derive(Debug, Clone)]
pub struct FinancialFootprintResult {
    pub public_keys: Vec<PublicKeyFinding>,
    pub crypto_wallets: Vec<CryptoWalletFinding>,
    pub sec_filings: Vec<SecFilingReference>,
    pub merchant_ids: Vec<MerchantIdFinding>,
    pub pci_scope: Option<PciScopeInference>,
    pub pii_paths: Vec<PiiTransitPath>,
    pub risk_score: f64,
    pub summary: String,
}

/// Configuration for the financial footprint mapper.
#[derive(Debug, Clone)]
pub struct FinancialFootprintConfig {
    pub scan_js_bundles: bool,
    pub scan_page_source: bool,
    pub check_sec_edgar: bool,
    pub detect_crypto: bool,
    pub infer_pci_scope: bool,
    pub max_js_bundle_size_bytes: usize,
}

impl Default for FinancialFootprintConfig {
    fn default() -> Self {
        Self {
            scan_js_bundles: true,
            scan_page_source: true,
            check_sec_edgar: true,
            detect_crypto: true,
            infer_pci_scope: true,
            max_js_bundle_size_bytes: 10 * 1024 * 1024,
        }
    }
}

impl FinancialFootprintConfig {
    pub fn with_scan_js_bundles(mut self, enabled: bool) -> Self {
        self.scan_js_bundles = enabled;
        self
    }

    pub fn with_detect_crypto(mut self, enabled: bool) -> Self {
        self.detect_crypto = enabled;
        self
    }

    pub fn with_max_js_bundle_size(mut self, bytes: usize) -> Self {
        self.max_js_bundle_size_bytes = bytes;
        self
    }
}

/// Maps financial infrastructure from publicly observable data.
pub struct FinancialFootprintMapper {
    config: FinancialFootprintConfig,
}

impl FinancialFootprintMapper {
    pub fn new(config: FinancialFootprintConfig) -> Self {
        Self { config }
    }

    /// Extract payment processor public keys from JS bundle content.
    pub fn extract_public_keys(&self, js_content: &str, source_url: &str) -> Vec<PublicKeyFinding> {
        if !self.config.scan_js_bundles {
            return Vec::new();
        }
        let mut findings = Vec::new();
        findings.extend(self.detect_stripe_keys(js_content, source_url));
        findings.extend(self.detect_square_keys(js_content, source_url));
        findings.extend(self.detect_braintree_keys(js_content, source_url));
        findings.extend(self.detect_paypal_keys(js_content, source_url));
        findings.extend(self.detect_adyen_keys(js_content, source_url));
        findings
    }

    /// Detect cryptocurrency wallet addresses in page source.
    pub fn detect_crypto_wallets(
        &self,
        page_source: &str,
        source_url: &str,
    ) -> Vec<CryptoWalletFinding> {
        if !self.config.detect_crypto {
            return Vec::new();
        }
        let mut findings = Vec::new();
        findings.extend(self.detect_bitcoin_addresses(page_source, source_url));
        findings.extend(self.detect_ethereum_addresses(page_source, source_url));
        findings.extend(self.detect_monero_addresses(page_source, source_url));
        findings
    }

    /// Extract merchant IDs from checkout flow HTML/JS.
    pub fn extract_merchant_ids(&self, content: &str, source_url: &str) -> Vec<MerchantIdFinding> {
        let mut findings = Vec::new();
        let patterns: Vec<(PaymentProcessor, &str, bool)> = vec![
            (
                PaymentProcessor::Stripe,
                r#"data-merchant[_-]id\s*=\s*["']([^"']+)["']"#,
                false,
            ),
            (
                PaymentProcessor::Square,
                r#"application[_-]id\s*[=:]\s*["']?(sq0[a-z]{3}-[A-Za-z0-9_-]+)"#,
                false,
            ),
            (
                PaymentProcessor::Square,
                r#"sandbox[_-]application[_-]id\s*[=:]\s*["']?(sandbox-sq0[a-z]{3}-[A-Za-z0-9_-]+)"#,
                true,
            ),
            (
                PaymentProcessor::PayPal,
                r#"data-client-id\s*=\s*["']([A-Za-z0-9_-]{20,})["']"#,
                false,
            ),
            (
                PaymentProcessor::Braintree,
                r#"data-braintree-merchant\s*=\s*["']([^"']+)["']"#,
                false,
            ),
            (
                PaymentProcessor::Authorize,
                r#"x_login\s*[=:]\s*["']?(\d{6,12})"#,
                false,
            ),
        ];

        for (processor, pattern, is_sandbox) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(m) = cap.get(1) {
                        findings.push(MerchantIdFinding {
                            processor: *processor,
                            merchant_id: m.as_str().to_string(),
                            source_url: source_url.to_string(),
                            is_sandbox: *is_sandbox,
                        });
                    }
                }
            }
        }
        findings
    }

    /// Infer PCI DSS scope from checkout flow analysis.
    pub fn infer_pci_scope(&self, page_contents: &[(&str, &str)]) -> PciScopeInference {
        let mut evidence = Vec::new();
        let mut iframe_detected = false;
        let mut tokenization = false;
        let mut third_parties = Vec::new();
        let mut direct_post = false;

        for (url, content) in page_contents {
            if content.contains("iframe") && self.contains_payment_iframe(content) {
                iframe_detected = true;
                evidence.push(format!("Payment iframe detected at {}", url));
            }
            if content.contains("createToken") || content.contains("tokenize") {
                tokenization = true;
                evidence.push(format!("Tokenization API call at {}", url));
            }
            if let Some(re) =
                Regex::new(r#"action\s*=\s*["'][^"']*(/pay|/charge|/checkout)[^"']*["']"#).ok()
            {
                if re.is_match(content) {
                    direct_post = true;
                    evidence.push(format!("Direct form post to payment endpoint at {}", url));
                }
            }
            for processor_domain in &[
                "js.stripe.com",
                "checkout.stripe.com",
                "www.paypal.com",
                "web.squarecdn.com",
                "js.braintreegateway.com",
                "checkoutshopper-live.adyen.com",
            ] {
                if content.contains(processor_domain) {
                    third_parties.push(processor_domain.to_string());
                }
            }
        }

        let card_handling = if iframe_detected && tokenization {
            CardDataHandling::IframeTokenized
        } else if !third_parties.is_empty() && !direct_post {
            CardDataHandling::FullyOutsourced
        } else if direct_post {
            CardDataHandling::DirectPost
        } else {
            CardDataHandling::Unknown
        };

        PciScopeInference {
            in_scope: direct_post || (!iframe_detected && third_parties.is_empty()),
            card_data_handling: card_handling,
            third_party_processors: third_parties,
            iframe_isolation: iframe_detected,
            tokenization_detected: tokenization,
            evidence,
        }
    }

    /// Parse SEC EDGAR filing data (from pre-fetched JSON).
    pub fn parse_sec_filings(&self, edgar_json: &str) -> Vec<SecFilingReference> {
        let mut filings = Vec::new();
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(edgar_json) {
            if let Some(recent) = parsed.get("filings").and_then(|f| f.get("recent")) {
                let forms = recent.get("form").and_then(|v| v.as_array());
                let names = recent.get("companyName").and_then(|v| v.as_str());
                let dates = recent.get("filingDate").and_then(|v| v.as_array());
                let cik = parsed
                    .get("cik")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                if let Some(forms) = forms {
                    for (i, form) in forms.iter().enumerate() {
                        let form_type = form.as_str().unwrap_or("").to_string();
                        let filed = dates
                            .and_then(|d| d.get(i))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let indicators = self.extract_financial_indicators(&form_type);
                        if !indicators.is_empty() {
                            filings.push(SecFilingReference {
                                filing_type: form_type,
                                company_name: names.unwrap_or("Unknown").to_string(),
                                cik: cik.to_string(),
                                filed_date: filed,
                                financial_indicators: indicators,
                            });
                        }
                    }
                }
            }
        }
        filings
    }

    /// Analyze all collected data and produce a financial footprint result.
    pub fn analyze(
        &self,
        js_bundles: &[(&str, &str)],
        page_sources: &[(&str, &str)],
        edgar_json: Option<&str>,
    ) -> FinancialFootprintResult {
        let mut public_keys = Vec::new();
        let mut crypto_wallets = Vec::new();
        let mut merchant_ids = Vec::new();

        for (url, content) in js_bundles {
            public_keys.extend(self.extract_public_keys(content, url));
            merchant_ids.extend(self.extract_merchant_ids(content, url));
        }

        for (url, content) in page_sources {
            crypto_wallets.extend(self.detect_crypto_wallets(content, url));
            merchant_ids.extend(self.extract_merchant_ids(content, url));
        }

        let sec_filings = edgar_json
            .map(|json| self.parse_sec_filings(json))
            .unwrap_or_default();

        let pci_scope = if self.config.infer_pci_scope {
            Some(self.infer_pci_scope(page_sources))
        } else {
            None
        };

        let pii_paths = self.map_pii_transit_paths(&public_keys, &merchant_ids, &pci_scope);
        let risk_score =
            self.compute_risk_score(&public_keys, &crypto_wallets, &merchant_ids, &pci_scope);

        let mut processor_counts: HashMap<PaymentProcessor, usize> = HashMap::new();
        for key in &public_keys {
            *processor_counts.entry(key.processor).or_default() += 1;
        }
        let summary = format!(
            "Financial footprint: {} payment keys, {} crypto wallets, {} merchant IDs, {} SEC filings. Risk: {:.1}/10",
            public_keys.len(),
            crypto_wallets.len(),
            merchant_ids.len(),
            sec_filings.len(),
            risk_score
        );

        FinancialFootprintResult {
            public_keys,
            crypto_wallets,
            sec_filings,
            merchant_ids,
            pci_scope,
            pii_paths,
            risk_score,
            summary,
        }
    }

    fn detect_stripe_keys(&self, content: &str, source_url: &str) -> Vec<PublicKeyFinding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"pk_live_[A-Za-z0-9]{24,}", true),
            (r"pk_test_[A-Za-z0-9]{24,}", false),
        ];
        for (pattern, is_live) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(content) {
                    let start = m.start().saturating_sub(30);
                    let end = (m.end() + 30).min(content.len());
                    findings.push(PublicKeyFinding {
                        processor: PaymentProcessor::Stripe,
                        key_value: m.as_str().to_string(),
                        is_live_key: *is_live,
                        source_url: source_url.to_string(),
                        context_snippet: content[start..end].to_string(),
                    });
                }
            }
        }
        findings
    }

    fn detect_square_keys(&self, content: &str, source_url: &str) -> Vec<PublicKeyFinding> {
        let mut findings = Vec::new();
        if let Ok(re) = Regex::new(r"sq0[a-z]{3}-[A-Za-z0-9_-]{22,}") {
            for m in re.find_iter(content) {
                let is_live = !content[..m.start()].ends_with("sandbox");
                let start = m.start().saturating_sub(30);
                let end = (m.end() + 30).min(content.len());
                findings.push(PublicKeyFinding {
                    processor: PaymentProcessor::Square,
                    key_value: m.as_str().to_string(),
                    is_live_key: is_live,
                    source_url: source_url.to_string(),
                    context_snippet: content[start..end].to_string(),
                });
            }
        }
        findings
    }

    fn detect_braintree_keys(&self, content: &str, source_url: &str) -> Vec<PublicKeyFinding> {
        let mut findings = Vec::new();
        if let Ok(re) =
            Regex::new(r#"(?:braintree|bt)[\w.]*(?:key|token|auth)\s*[=:]\s*['"]([\w-]{20,})['"]"#)
        {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    let start = cap
                        .get(0)
                        .map(|c| c.start())
                        .unwrap_or(0)
                        .saturating_sub(20);
                    let end = (cap.get(0).map(|c| c.end()).unwrap_or(0) + 20).min(content.len());
                    findings.push(PublicKeyFinding {
                        processor: PaymentProcessor::Braintree,
                        key_value: m.as_str().to_string(),
                        is_live_key: true,
                        source_url: source_url.to_string(),
                        context_snippet: content[start..end].to_string(),
                    });
                }
            }
        }
        findings
    }

    fn detect_paypal_keys(&self, content: &str, source_url: &str) -> Vec<PublicKeyFinding> {
        let mut findings = Vec::new();
        if let Ok(re) = Regex::new(r#"client[_-]id\s*[=:]\s*["']([A-Za-z0-9_-]{20,80})["']"#) {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    if content.contains("paypal") || content.contains("PayPal") {
                        let start = cap
                            .get(0)
                            .map(|c| c.start())
                            .unwrap_or(0)
                            .saturating_sub(20);
                        let end =
                            (cap.get(0).map(|c| c.end()).unwrap_or(0) + 20).min(content.len());
                        findings.push(PublicKeyFinding {
                            processor: PaymentProcessor::PayPal,
                            key_value: m.as_str().to_string(),
                            is_live_key: !m.as_str().contains("sandbox"),
                            source_url: source_url.to_string(),
                            context_snippet: content[start..end].to_string(),
                        });
                    }
                }
            }
        }
        findings
    }

    fn detect_adyen_keys(&self, content: &str, source_url: &str) -> Vec<PublicKeyFinding> {
        let mut findings = Vec::new();
        if let Ok(re) =
            Regex::new(r#"(?:adyen|clientKey)\s*[=:]\s*['"]([a-z]{2,4}_[A-Za-z0-9]{20,})['"]"#)
        {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    let is_live = m.as_str().starts_with("live_");
                    let start = cap
                        .get(0)
                        .map(|c| c.start())
                        .unwrap_or(0)
                        .saturating_sub(20);
                    let end = (cap.get(0).map(|c| c.end()).unwrap_or(0) + 20).min(content.len());
                    findings.push(PublicKeyFinding {
                        processor: PaymentProcessor::Adyen,
                        key_value: m.as_str().to_string(),
                        is_live_key: is_live,
                        source_url: source_url.to_string(),
                        context_snippet: content[start..end].to_string(),
                    });
                }
            }
        }
        findings
    }

    fn detect_bitcoin_addresses(
        &self,
        content: &str,
        source_url: &str,
    ) -> Vec<CryptoWalletFinding> {
        let mut findings = Vec::new();
        let patterns = [
            r"\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,62})\b",
            r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
        ];
        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(m) = cap.get(1) {
                        let addr = m.as_str();
                        if self.looks_like_btc_address(addr) {
                            let start = m.start().saturating_sub(40);
                            let end = (m.end() + 40).min(content.len());
                            findings.push(CryptoWalletFinding {
                                network: CryptoNetwork::Bitcoin,
                                address: addr.to_string(),
                                source_url: source_url.to_string(),
                                context_snippet: content[start..end].to_string(),
                            });
                        }
                    }
                }
            }
        }
        findings
    }

    fn detect_ethereum_addresses(
        &self,
        content: &str,
        source_url: &str,
    ) -> Vec<CryptoWalletFinding> {
        let mut findings = Vec::new();
        if let Ok(re) = Regex::new(r"\b(0x[0-9a-fA-F]{40})\b") {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    let start = m.start().saturating_sub(40);
                    let end = (m.end() + 40).min(content.len());
                    findings.push(CryptoWalletFinding {
                        network: CryptoNetwork::Ethereum,
                        address: m.as_str().to_string(),
                        source_url: source_url.to_string(),
                        context_snippet: content[start..end].to_string(),
                    });
                }
            }
        }
        findings
    }

    fn detect_monero_addresses(&self, content: &str, source_url: &str) -> Vec<CryptoWalletFinding> {
        let mut findings = Vec::new();
        if let Ok(re) = Regex::new(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b") {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    let start = m.start().saturating_sub(40);
                    let end = (m.end() + 40).min(content.len());
                    findings.push(CryptoWalletFinding {
                        network: CryptoNetwork::Monero,
                        address: m.as_str().to_string(),
                        source_url: source_url.to_string(),
                        context_snippet: content[start..end].to_string(),
                    });
                }
            }
        }
        findings
    }

    fn looks_like_btc_address(&self, addr: &str) -> bool {
        if addr.starts_with("bc1") {
            return addr.len() >= 42;
        }
        addr.len() >= 26 && addr.len() <= 35
    }

    fn contains_payment_iframe(&self, content: &str) -> bool {
        let payment_iframe_patterns = [
            "js.stripe.com",
            "checkout.stripe.com",
            "www.paypal.com",
            "checkoutshopper",
            "braintreegateway.com",
            "web.squarecdn.com",
        ];
        for pattern in &payment_iframe_patterns {
            if content.contains(pattern) {
                return true;
            }
        }
        false
    }

    fn extract_financial_indicators(&self, filing_type: &str) -> Vec<String> {
        match filing_type {
            "10-K" => vec![
                "Annual report".to_string(),
                "Revenue disclosure".to_string(),
                "Risk factors".to_string(),
            ],
            "10-Q" => vec![
                "Quarterly report".to_string(),
                "Financial statements".to_string(),
            ],
            "8-K" => vec!["Material event disclosure".to_string()],
            "DEF 14A" => vec![
                "Proxy statement".to_string(),
                "Executive compensation".to_string(),
            ],
            "S-1" => vec![
                "IPO registration".to_string(),
                "Business model disclosure".to_string(),
            ],
            _ => Vec::new(),
        }
    }

    fn map_pii_transit_paths(
        &self,
        keys: &[PublicKeyFinding],
        merchant_ids: &[MerchantIdFinding],
        pci_scope: &Option<PciScopeInference>,
    ) -> Vec<PiiTransitPath> {
        let mut paths = Vec::new();

        for key in keys {
            paths.push(PiiTransitPath {
                data_type: "Payment card token".to_string(),
                source_endpoint: key.source_url.clone(),
                destination: format!("{} API", key.processor),
                encrypted: true,
                sensitivity: if key.is_live_key {
                    FinancialSensitivity::High
                } else {
                    FinancialSensitivity::Low
                },
            });
        }

        for mid in merchant_ids {
            paths.push(PiiTransitPath {
                data_type: "Merchant transaction data".to_string(),
                source_endpoint: mid.source_url.clone(),
                destination: format!("{} ({})", mid.processor, mid.merchant_id),
                encrypted: true,
                sensitivity: if mid.is_sandbox {
                    FinancialSensitivity::Low
                } else {
                    FinancialSensitivity::Medium
                },
            });
        }

        if let Some(scope) = pci_scope {
            if scope.card_data_handling == CardDataHandling::DirectPost
                || scope.card_data_handling == CardDataHandling::ServerSide
            {
                paths.push(PiiTransitPath {
                    data_type: "Raw card data".to_string(),
                    source_endpoint: "checkout form".to_string(),
                    destination: "application server".to_string(),
                    encrypted: scope.iframe_isolation,
                    sensitivity: FinancialSensitivity::Critical,
                });
            }
        }

        paths
    }

    fn compute_risk_score(
        &self,
        keys: &[PublicKeyFinding],
        wallets: &[CryptoWalletFinding],
        merchant_ids: &[MerchantIdFinding],
        pci_scope: &Option<PciScopeInference>,
    ) -> f64 {
        let mut score = 0.0_f64;

        let live_keys = keys.iter().filter(|k| k.is_live_key).count();
        score += live_keys as f64 * 1.5;
        score += (keys.len() - live_keys) as f64 * 0.5;
        score += wallets.len() as f64 * 1.0;

        let live_merchants = merchant_ids.iter().filter(|m| !m.is_sandbox).count();
        score += live_merchants as f64 * 2.0;

        if let Some(scope) = pci_scope {
            match scope.card_data_handling {
                CardDataHandling::DirectPost | CardDataHandling::ServerSide => score += 3.0,
                CardDataHandling::IframeTokenized => score += 1.0,
                CardDataHandling::FullyOutsourced => score += 0.5,
                CardDataHandling::Unknown => score += 1.5,
            }
        }

        score.min(10.0)
    }
}
