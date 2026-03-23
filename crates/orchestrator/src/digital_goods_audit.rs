use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DigitalGoodsIssue {
    ApiDetected,
    PriceManipulation,
    PurchaseWithoutConfirmation,
    ItemEnumeration,
    ReceiptExfiltration,
    NoServerValidation,
}

impl std::fmt::Display for DigitalGoodsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::PriceManipulation => write!(f, "price_manipulation"),
            Self::PurchaseWithoutConfirmation => write!(f, "purchase_without_confirmation"),
            Self::ItemEnumeration => write!(f, "item_enumeration"),
            Self::ReceiptExfiltration => write!(f, "receipt_exfiltration"),
            Self::NoServerValidation => write!(f, "no_server_validation"),
        }
    }
}

pub fn audit_digital_goods(target: &str) -> Vec<DigitalGoodsIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_digital_goods(&body)
}

pub fn analyze_digital_goods(body: &str) -> Vec<DigitalGoodsIssue> {
    if !body.contains("getDigitalGoodsService") && !body.contains("DigitalGoodsService") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(DigitalGoodsIssue::ApiDetected);

    if body.contains("getDetails(") {
        issues.push(DigitalGoodsIssue::ItemEnumeration);

        if body.contains("price") && !body.contains("confirm") && !body.contains("dialog") {
            issues.push(DigitalGoodsIssue::PriceManipulation);
        }
    }

    if (body.contains("consume(") || body.contains("acknowledge("))
        && !body.contains("confirm")
        && !body.contains("prompt")
        && !body.contains("dialog")
    {
        issues.push(DigitalGoodsIssue::PurchaseWithoutConfirmation);
    }

    let has_purchase_data = body.contains("purchaseToken")
        || body.contains("itemId")
        || body.contains("getDetails(");
    if has_purchase_data
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(DigitalGoodsIssue::ReceiptExfiltration);
    }

    if has_purchase_data && !body.contains("/api/") && !body.contains("/verify") && !body.contains("server") {
        issues.push(DigitalGoodsIssue::NoServerValidation);
    }

    issues
}

pub fn digital_goods_severity(issue: &DigitalGoodsIssue) -> f64 {
    match issue {
        DigitalGoodsIssue::PriceManipulation => 8.0,
        DigitalGoodsIssue::PurchaseWithoutConfirmation => 7.5,
        DigitalGoodsIssue::ReceiptExfiltration => 7.0,
        DigitalGoodsIssue::NoServerValidation => 6.0,
        DigitalGoodsIssue::ItemEnumeration => 4.5,
        DigitalGoodsIssue::ApiDetected => 2.5,
    }
}

pub fn digital_goods_to_operations(
    issues: &[DigitalGoodsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                digital_goods_severity(issue),
                0.6,
            )
        })
        .collect()
}
