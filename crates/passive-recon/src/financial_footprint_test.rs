use super::financial_footprint::*;

#[test]
fn test_payment_processor_display() {
    assert_eq!(PaymentProcessor::Stripe.to_string(), "Stripe");
    assert_eq!(PaymentProcessor::Square.to_string(), "Square");
    assert_eq!(PaymentProcessor::PayPal.to_string(), "PayPal");
    assert_eq!(PaymentProcessor::Adyen.to_string(), "Adyen");
    assert_eq!(PaymentProcessor::Authorize.to_string(), "Authorize.net");
}

#[test]
fn test_crypto_network_display() {
    assert_eq!(CryptoNetwork::Bitcoin.to_string(), "Bitcoin");
    assert_eq!(CryptoNetwork::Ethereum.to_string(), "Ethereum");
    assert_eq!(CryptoNetwork::Monero.to_string(), "Monero");
}

#[test]
fn test_sensitivity_ordering() {
    assert!(FinancialSensitivity::Low < FinancialSensitivity::Medium);
    assert!(FinancialSensitivity::Medium < FinancialSensitivity::High);
    assert!(FinancialSensitivity::High < FinancialSensitivity::Critical);
}

#[test]
fn test_card_data_handling_display() {
    assert_eq!(
        CardDataHandling::FullyOutsourced.to_string(),
        "Fully Outsourced (SAQ A)"
    );
    assert_eq!(
        CardDataHandling::DirectPost.to_string(),
        "Direct Post (SAQ D)"
    );
}

#[test]
fn test_default_config() {
    let config = FinancialFootprintConfig::default();
    assert!(config.scan_js_bundles);
    assert!(config.detect_crypto);
    assert_eq!(config.max_js_bundle_size_bytes, 10 * 1024 * 1024);
}

#[test]
fn test_config_builder() {
    let config = FinancialFootprintConfig::default()
        .with_scan_js_bundles(false)
        .with_detect_crypto(false)
        .with_max_js_bundle_size(1024);
    assert!(!config.scan_js_bundles);
    assert!(!config.detect_crypto);
    assert_eq!(config.max_js_bundle_size_bytes, 1024);
}

#[test]
fn test_detect_stripe_live_key() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let js = r#"var key = "pk_live_abcdefghijklmnopqrstuvwx";"#;
    let findings = mapper.extract_public_keys(js, "https://example.com/app.js");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].processor, PaymentProcessor::Stripe);
    assert!(findings[0].is_live_key);
    assert!(findings[0].key_value.starts_with("pk_live_"));
}

#[test]
fn test_detect_stripe_test_key() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let js = r#"stripe = Stripe("pk_test_abcdefghijklmnopqrstuvwx");"#;
    let findings = mapper.extract_public_keys(js, "https://example.com/checkout.js");
    assert_eq!(findings.len(), 1);
    assert!(!findings[0].is_live_key);
}

#[test]
fn test_detect_square_key() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let js = r#"applicationId: "sq0idp-ABCDEFGHIJKLMNOPQRSTUV""#;
    let findings = mapper.extract_public_keys(js, "https://store.com/pay.js");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].processor, PaymentProcessor::Square);
}

#[test]
fn test_detect_ethereum_address() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let html = r#"<p>Donate: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00</p>"#;
    let findings = mapper.detect_crypto_wallets(html, "https://donate.org");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].network, CryptoNetwork::Ethereum);
    assert!(findings[0].address.starts_with("0x"));
}

#[test]
fn test_detect_bitcoin_bech32_address() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let html = "Send BTC: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 thank you";
    let findings = mapper.detect_crypto_wallets(html, "https://donate.org");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].network, CryptoNetwork::Bitcoin);
}

#[test]
fn test_no_crypto_when_disabled() {
    let config = FinancialFootprintConfig::default().with_detect_crypto(false);
    let mapper = FinancialFootprintMapper::new(config);
    let html = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00";
    let findings = mapper.detect_crypto_wallets(html, "https://donate.org");
    assert!(findings.is_empty());
}

#[test]
fn test_no_keys_when_scanning_disabled() {
    let config = FinancialFootprintConfig::default().with_scan_js_bundles(false);
    let mapper = FinancialFootprintMapper::new(config);
    let js = r#"pk_live_abcdefghijklmnopqrstuvwx"#;
    let findings = mapper.extract_public_keys(js, "https://example.com/app.js");
    assert!(findings.is_empty());
}

#[test]
fn test_extract_merchant_ids() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let html = r#"<div data-merchant-id="merch_abc123"></div>"#;
    let findings = mapper.extract_merchant_ids(html, "https://shop.com/checkout");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].merchant_id, "merch_abc123");
}

#[test]
fn test_pci_scope_iframe_tokenized() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let pages = vec![(
        "https://shop.com/checkout",
        r#"<iframe src="https://js.stripe.com/v3"></iframe>
        <script>stripe.createToken(card)</script>"#,
    )];
    let scope = mapper.infer_pci_scope(&pages);
    assert!(scope.iframe_isolation);
    assert!(scope.tokenization_detected);
    assert_eq!(scope.card_data_handling, CardDataHandling::IframeTokenized);
}

#[test]
fn test_pci_scope_direct_post() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let pages = vec![(
        "https://shop.com/pay",
        r#"<form action="/charge" method="POST"><input name="card_number"></form>"#,
    )];
    let scope = mapper.infer_pci_scope(&pages);
    assert!(scope.in_scope);
    assert_eq!(scope.card_data_handling, CardDataHandling::DirectPost);
}

#[test]
fn test_pci_scope_fully_outsourced() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let pages = vec![(
        "https://shop.com/checkout",
        r#"<script src="https://js.stripe.com/v3/"></script>
        <div id="payment-element"></div>"#,
    )];
    let scope = mapper.infer_pci_scope(&pages);
    assert_eq!(scope.card_data_handling, CardDataHandling::FullyOutsourced);
    assert!(!scope.third_party_processors.is_empty());
}

#[test]
fn test_parse_sec_filings() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let json = r#"{
        "cik": "0001234567",
        "filings": {
            "recent": {
                "form": ["10-K", "10-Q", "8-K", "4"],
                "companyName": "Target Corp",
                "filingDate": ["2024-01-15", "2024-04-15", "2024-06-01", "2024-07-01"]
            }
        }
    }"#;
    let filings = mapper.parse_sec_filings(json);
    assert_eq!(filings.len(), 3);
    assert_eq!(filings[0].filing_type, "10-K");
    assert_eq!(filings[0].company_name, "Target Corp");
    assert!(!filings[0].financial_indicators.is_empty());
}

#[test]
fn test_parse_sec_filings_invalid_json() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let filings = mapper.parse_sec_filings("not valid json");
    assert!(filings.is_empty());
}

#[test]
fn test_full_analysis() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());

    let js_bundles = vec![(
        "https://shop.com/app.js",
        r#"const key = "pk_live_abcdefghijklmnopqrstuvwx"; stripe.init(key);"#,
    )];
    let page_sources = vec![(
        "https://shop.com/donate",
        "Donate ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD00",
    )];

    let result = mapper.analyze(&js_bundles, &page_sources, None);
    assert_eq!(result.public_keys.len(), 1);
    assert_eq!(result.crypto_wallets.len(), 1);
    assert!(result.risk_score > 0.0);
    assert!(!result.summary.is_empty());
}

#[test]
fn test_risk_score_bounds() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let many_keys: String = (0..20)
        .map(|i| format!(r#"pk_live_{:024}"#, i))
        .collect::<Vec<_>>()
        .join(" ");
    let js_bundles = vec![("https://example.com/huge.js", many_keys.as_str())];
    let result = mapper.analyze(&js_bundles, &[], None);
    assert!(result.risk_score <= 10.0, "Risk score should cap at 10.0");
}

#[test]
fn test_empty_analysis() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let result = mapper.analyze(&[], &[], None);
    assert!(result.public_keys.is_empty());
    assert!(result.crypto_wallets.is_empty());
    assert!(result.merchant_ids.is_empty());
    assert!(result.pci_scope.is_some());
}

#[test]
fn test_pii_transit_paths_generated() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let js_bundles = vec![(
        "https://shop.com/app.js",
        r#"const key = "pk_live_abcdefghijklmnopqrstuvwx";"#,
    )];
    let result = mapper.analyze(&js_bundles, &[], None);
    assert!(!result.pii_paths.is_empty());
    assert_eq!(result.pii_paths[0].data_type, "Payment card token");
}

#[test]
fn test_multiple_processors_in_same_page() {
    let mapper = FinancialFootprintMapper::new(FinancialFootprintConfig::default());
    let js = r#"
        stripe_key = "pk_live_abcdefghijklmnopqrstuvwx";
        square_app = "sq0idp-ABCDEFGHIJKLMNOPQRSTUV01";
    "#;
    let findings = mapper.extract_public_keys(js, "https://shop.com/bundle.js");
    assert_eq!(findings.len(), 2);
    let processors: Vec<PaymentProcessor> = findings.iter().map(|f| f.processor).collect();
    assert!(processors.contains(&PaymentProcessor::Stripe));
    assert!(processors.contains(&PaymentProcessor::Square));
}
