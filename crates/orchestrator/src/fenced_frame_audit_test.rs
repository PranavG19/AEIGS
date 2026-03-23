use crate::fenced_frame_audit::*;

#[test]
fn no_fenced_frame_no_issues() {
    assert!(analyze_fenced_frame("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_fenced_frame_element() {
    let body = r#"<fencedframe src="about:blank"></fencedframe>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::ApiDetected));
}

#[test]
fn detects_fenced_frame_config() {
    let body = r#"<script>const config = new FencedFrameConfig(url);</script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::ApiDetected));
}

#[test]
fn detects_ad_auction() {
    let body = r#"<script>navigator.runAdAuction({seller: "https://ssp.example"});</script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::ApiDetected));
}

#[test]
fn detects_join_interest_group() {
    let body = r#"<script>navigator.joinAdInterestGroup({name: "shoes"});</script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::ApiDetected));
}

#[test]
fn detects_ad_auction_abuse() {
    let body = r#"<script>
        navigator.runAdAuction({
            seller: "https://ssp.example",
            decisionLogicUrl: "https://evil.com/score.js",
            biddingLogicUrl: "https://evil.com/bid.js"
        });
    </script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::AdAuctionAbuse));
}

#[test]
fn no_auction_abuse_with_trusted_signals() {
    let body = r#"<script>
        navigator.runAdAuction({
            seller: "https://ssp.example",
            decisionLogicUrl: "https://ssp.example/score.js",
            trustedScoringSignalsUrl: "https://ssp.example/signals"
        });
    </script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(!issues.contains(&FencedFrameIssue::AdAuctionAbuse));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<fencedframe></fencedframe>
    <script>
        fence.reportEvent({eventType: "click"});
        fetch("/collect", {body: data});
    </script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_network() {
    let body = r#"<fencedframe></fencedframe>
    <script>fence.reportEvent({eventType: "click"});</script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(!issues.contains(&FencedFrameIssue::DataExfiltration));
}

#[test]
fn detects_opaque_url_bypass() {
    let body = r#"<script>
        const config = new FencedFrameConfig(url);
        const loc = window.location.href;
    </script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::OpaqueUrlBypass));
}

#[test]
fn no_bypass_without_location() {
    let body = r#"<script>const config = new FencedFrameConfig(url);</script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(!issues.contains(&FencedFrameIssue::OpaqueUrlBypass));
}

#[test]
fn detects_shared_storage_leak() {
    let body = r#"<fencedframe></fencedframe>
    <script>
        const val = await sharedStorage.get("user_id");
    </script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(issues.contains(&FencedFrameIssue::SharedStorageLeak));
}

#[test]
fn no_shared_storage_without_read() {
    let body = r#"<fencedframe></fencedframe>
    <script>sharedStorage.set("key", "value");</script>"#;
    let issues = analyze_fenced_frame(body);
    assert!(!issues.contains(&FencedFrameIssue::SharedStorageLeak));
}

#[test]
fn severity_exfil_highest() {
    assert_eq!(fenced_frame_severity(&FencedFrameIssue::DataExfiltration), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(fenced_frame_severity(&FencedFrameIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![FencedFrameIssue::ApiDetected, FencedFrameIssue::AdAuctionAbuse];
    let mut seq = 0;
    let ops = fenced_frame_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(FencedFrameIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(FencedFrameIssue::AdAuctionAbuse.to_string(), "ad_auction_abuse");
    assert_eq!(FencedFrameIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(FencedFrameIssue::OpaqueUrlBypass.to_string(), "opaque_url_bypass");
    assert_eq!(FencedFrameIssue::SharedStorageLeak.to_string(), "shared_storage_leak");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_fenced_frame("").is_empty());
}
