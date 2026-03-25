use super::*;

#[test]
fn build_creates_at_least_30_responses() {
    let lib = FixtureResponseLibrary::build();
    assert!(
        lib.count() >= 30,
        "Expected >=30 responses, got {}",
        lib.count()
    );
}

#[test]
fn has_waf_block_pages_for_6_vendors() {
    let lib = FixtureResponseLibrary::build();
    let waf = lib.by_category(ResponseCategory::WafBlock);
    assert_eq!(
        waf.len(),
        6,
        "Expected 6 WAF block pages, got {}",
        waf.len()
    );
}

#[test]
fn has_error_pages_for_6_frameworks() {
    let lib = FixtureResponseLibrary::build();
    let errors = lib.by_category(ResponseCategory::ErrorPage);
    assert_eq!(
        errors.len(),
        6,
        "Expected 6 error pages, got {}",
        errors.len()
    );
}

#[test]
fn has_login_pages_for_3_cms() {
    let lib = FixtureResponseLibrary::build();
    let logins = lib.by_category(ResponseCategory::LoginPage);
    assert_eq!(
        logins.len(),
        3,
        "Expected 3 login pages, got {}",
        logins.len()
    );
}

#[test]
fn has_json_api_responses() {
    let lib = FixtureResponseLibrary::build();
    let json = lib.by_category(ResponseCategory::ApiJson);
    assert!(
        json.len() >= 4,
        "Expected >=4 JSON API responses, got {}",
        json.len()
    );
}

#[test]
fn has_xml_api_responses() {
    let lib = FixtureResponseLibrary::build();
    let xml = lib.by_category(ResponseCategory::ApiXml);
    assert!(
        xml.len() >= 2,
        "Expected >=2 XML API responses, got {}",
        xml.len()
    );
}

#[test]
fn has_graphql_api_responses() {
    let lib = FixtureResponseLibrary::build();
    let gql = lib.by_category(ResponseCategory::ApiGraphQl);
    assert!(
        gql.len() >= 3,
        "Expected >=3 GraphQL responses, got {}",
        gql.len()
    );
}

#[test]
fn has_vulnerable_responses_for_scanner_verification() {
    let lib = FixtureResponseLibrary::build();
    let vulns = lib.vulnerable_responses();
    assert!(
        vulns.len() >= 7,
        "Expected >=7 vulnerable responses, got {}",
        vulns.len()
    );
}

#[test]
fn by_id_returns_correct_fixture() {
    let lib = FixtureResponseLibrary::build();
    let cf = lib
        .by_id("waf-cloudflare")
        .expect("cloudflare fixture not found");
    assert_eq!(cf.vendor, "Cloudflare");
    assert_eq!(cf.status_code, 403);
    assert!(cf.body.contains("Cloudflare"));
}

#[test]
fn by_id_returns_none_for_missing() {
    let lib = FixtureResponseLibrary::build();
    assert!(lib.by_id("nonexistent").is_none());
}

#[test]
fn by_vendor_filters_correctly() {
    let lib = FixtureResponseLibrary::build();
    let aws = lib.by_vendor("AWS");
    assert_eq!(aws.len(), 1);
    assert_eq!(aws[0].id, "waf-aws");
}

#[test]
fn vendors_list_is_sorted_and_nonempty() {
    let lib = FixtureResponseLibrary::build();
    let vendors = lib.vendors();
    assert!(!vendors.is_empty());
    for window in vendors.windows(2) {
        assert!(window[0] <= window[1], "Vendors not sorted: {:?}", vendors);
    }
}

#[test]
fn all_fixtures_have_nonempty_body() {
    let lib = FixtureResponseLibrary::build();
    for resp in lib.all() {
        assert!(!resp.body.is_empty(), "Fixture {} has empty body", resp.id);
    }
}

#[test]
fn all_fixtures_have_content_type_header() {
    let lib = FixtureResponseLibrary::build();
    for resp in lib.all() {
        assert!(
            resp.headers.contains_key("content-type"),
            "Fixture {} missing content-type header",
            resp.id
        );
    }
}

#[test]
fn waf_pages_all_return_403() {
    let lib = FixtureResponseLibrary::build();
    for waf in lib.by_category(ResponseCategory::WafBlock) {
        assert_eq!(
            waf.status_code, 403,
            "WAF {} should return 403, got {}",
            waf.id, waf.status_code
        );
    }
}

#[test]
fn error_pages_all_return_500() {
    let lib = FixtureResponseLibrary::build();
    for err in lib.by_category(ResponseCategory::ErrorPage) {
        assert_eq!(
            err.status_code, 500,
            "Error page {} should return 500, got {}",
            err.id, err.status_code
        );
    }
}

#[test]
fn to_json_produces_valid_json() {
    let lib = FixtureResponseLibrary::build();
    let json = lib.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON output");
    assert!(parsed.is_array());
}

#[test]
fn ids_are_unique() {
    let lib = FixtureResponseLibrary::build();
    let mut ids: Vec<&str> = lib.all().iter().map(|r| r.id.as_str()).collect();
    let original_len = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), original_len, "Duplicate fixture IDs found");
}

#[test]
fn cloudflare_waf_contains_ray_id() {
    let lib = FixtureResponseLibrary::build();
    let cf = lib.by_id("waf-cloudflare").unwrap();
    assert!(cf.body.contains("Ray ID"));
    assert!(cf.headers.contains_key("cf-ray"));
}

#[test]
fn modsecurity_waf_contains_matched_rule() {
    let lib = FixtureResponseLibrary::build();
    let ms = lib.by_id("waf-modsecurity").unwrap();
    assert!(ms.body.contains("ModSecurity"));
    assert!(ms.body.contains("Operator"));
}

#[test]
fn sqli_vuln_contains_sql_query() {
    let lib = FixtureResponseLibrary::build();
    let sqli = lib.by_id("vuln-sqli-error").unwrap();
    assert!(sqli.body.contains("SELECT"));
    assert!(sqli.body.contains("OR 1=1"));
}

#[test]
fn ssrf_vuln_contains_aws_credentials() {
    let lib = FixtureResponseLibrary::build();
    let ssrf = lib.by_id("vuln-ssrf-metadata").unwrap();
    assert!(ssrf.body.contains("AccessKeyId"));
    assert!(ssrf.body.contains("SecretAccessKey"));
}
