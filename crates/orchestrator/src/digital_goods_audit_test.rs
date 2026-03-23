use crate::digital_goods_audit::*;

#[test]
fn no_digital_goods_no_issues() {
    assert!(analyze_digital_goods("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_get_service() {
    let body = r#"<script>const svc = await window.getDigitalGoodsService("https://play.google.com/billing");</script>"#;
    let issues = analyze_digital_goods(body);
    assert!(issues.contains(&DigitalGoodsIssue::ApiDetected));
}

#[test]
fn detects_api_class_name() {
    let body = r#"<script>if (window.DigitalGoodsService) {}</script>"#;
    let issues = analyze_digital_goods(body);
    assert!(issues.contains(&DigitalGoodsIssue::ApiDetected));
}

#[test]
fn detects_item_enumeration() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        const items = await svc.getDetails(["item1", "item2"]);
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(issues.contains(&DigitalGoodsIssue::ItemEnumeration));
}

#[test]
fn detects_price_manipulation() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        const items = await svc.getDetails(["item1"]);
        const price = items[0].price;
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(issues.contains(&DigitalGoodsIssue::PriceManipulation));
}

#[test]
fn no_price_manipulation_with_confirm() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        const items = await svc.getDetails(["item1"]);
        if (confirm("Purchase for " + items[0].price + "?")) {}
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(!issues.contains(&DigitalGoodsIssue::PriceManipulation));
}

#[test]
fn detects_purchase_without_confirmation() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        await svc.consume("token123");
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(issues.contains(&DigitalGoodsIssue::PurchaseWithoutConfirmation));
}

#[test]
fn no_purchase_issue_with_prompt() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        if (confirm("Are you sure?")) { await svc.consume("token"); }
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(!issues.contains(&DigitalGoodsIssue::PurchaseWithoutConfirmation));
}

#[test]
fn detects_receipt_exfiltration() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        const items = await svc.getDetails(["item1"]);
        fetch("/collect", {body: JSON.stringify({purchaseToken: "tok"})});
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(issues.contains(&DigitalGoodsIssue::ReceiptExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        const items = await svc.getDetails(["item1"]);
        console.log(items);
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(!issues.contains(&DigitalGoodsIssue::ReceiptExfiltration));
}

#[test]
fn detects_no_server_validation() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        const items = await svc.getDetails(["item1"]);
        localStorage.setItem("purchased", "true");
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(issues.contains(&DigitalGoodsIssue::NoServerValidation));
}

#[test]
fn no_validation_issue_with_api() {
    let body = r#"<script>
        const svc = await window.getDigitalGoodsService("https://play.google.com/billing");
        const items = await svc.getDetails(["item1"]);
        fetch("/api/validate", {body: JSON.stringify({purchaseToken: "tok"})});
    </script>"#;
    let issues = analyze_digital_goods(body);
    assert!(!issues.contains(&DigitalGoodsIssue::NoServerValidation));
}

#[test]
fn severity_price_highest() {
    assert_eq!(digital_goods_severity(&DigitalGoodsIssue::PriceManipulation), 8.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(digital_goods_severity(&DigitalGoodsIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![DigitalGoodsIssue::ApiDetected, DigitalGoodsIssue::ItemEnumeration];
    let mut seq = 0;
    let ops = digital_goods_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(DigitalGoodsIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(DigitalGoodsIssue::PriceManipulation.to_string(), "price_manipulation");
    assert_eq!(DigitalGoodsIssue::PurchaseWithoutConfirmation.to_string(), "purchase_without_confirmation");
    assert_eq!(DigitalGoodsIssue::ItemEnumeration.to_string(), "item_enumeration");
    assert_eq!(DigitalGoodsIssue::ReceiptExfiltration.to_string(), "receipt_exfiltration");
    assert_eq!(DigitalGoodsIssue::NoServerValidation.to_string(), "no_server_validation");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_digital_goods("").is_empty());
}
