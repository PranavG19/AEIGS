use super::sqli_payloads::*;

#[test]
fn test_total_payload_count_meets_minimum() {
    assert!(
        sqli_payload_count() >= 200,
        "Expected 200+ SQLi payloads, got {}",
        sqli_payload_count()
    );
}

#[test]
fn test_union_payloads_exist() {
    let union_p = sqli_payloads_by_category(SqliCategory::UnionBased);
    assert!(
        union_p.len() >= 30,
        "Expected 30+ UNION payloads, got {}",
        union_p.len()
    );
}

#[test]
fn test_error_payloads_exist() {
    let error_p = sqli_payloads_by_category(SqliCategory::ErrorBased);
    assert!(
        error_p.len() >= 15,
        "Expected 15+ error-based payloads, got {}",
        error_p.len()
    );
}

#[test]
fn test_boolean_blind_payloads_exist() {
    let bool_p = sqli_payloads_by_category(SqliCategory::BooleanBlind);
    assert!(
        bool_p.len() >= 20,
        "Expected 20+ boolean-blind payloads, got {}",
        bool_p.len()
    );
}

#[test]
fn test_time_blind_payloads_exist() {
    let time_p = sqli_payloads_by_category(SqliCategory::TimeBlind);
    assert!(
        time_p.len() >= 15,
        "Expected 15+ time-blind payloads, got {}",
        time_p.len()
    );
}

#[test]
fn test_stacked_query_payloads_exist() {
    let stacked = sqli_payloads_by_category(SqliCategory::StackedQuery);
    assert!(
        stacked.len() >= 10,
        "Expected 10+ stacked query payloads, got {}",
        stacked.len()
    );
}

#[test]
fn test_oob_payloads_exist() {
    let oob = sqli_payloads_by_category(SqliCategory::OutOfBand);
    assert!(
        oob.len() >= 10,
        "Expected 10+ OOB payloads, got {}",
        oob.len()
    );
}

#[test]
fn test_second_order_payloads_exist() {
    let second = sqli_payloads_by_category(SqliCategory::SecondOrder);
    assert!(
        second.len() >= 10,
        "Expected 10+ second-order payloads, got {}",
        second.len()
    );
}

#[test]
fn test_all_dbms_covered() {
    for dbms in SqliDbms::all() {
        let payloads = sqli_payloads_by_dbms(*dbms);
        assert!(!payloads.is_empty(), "No payloads for DBMS {:?}", dbms);
    }
}

#[test]
fn test_all_categories_covered() {
    for cat in SqliCategory::all() {
        let payloads = sqli_payloads_by_category(*cat);
        assert!(!payloads.is_empty(), "No payloads for category {:?}", cat);
    }
}

#[test]
fn test_waf_bypass_payloads_exist() {
    let bypass = sqli_waf_bypass_payloads();
    assert!(
        bypass.len() >= 10,
        "Expected 10+ WAF bypass payloads, got {}",
        bypass.len()
    );
}

#[test]
fn test_no_empty_payloads() {
    for payload in all_sqli_payloads() {
        assert!(!payload.payload.is_empty(), "Empty payload found");
        assert!(
            !payload.description.is_empty(),
            "Empty description for payload: {}",
            payload.payload
        );
    }
}

#[test]
fn test_mysql_specific_payloads() {
    let mysql = sqli_payloads_by_dbms(SqliDbms::MySQL);
    assert!(
        mysql.len() >= 20,
        "Expected 20+ MySQL payloads, got {}",
        mysql.len()
    );
    let has_sleep = mysql.iter().any(|p| p.payload.contains("SLEEP"));
    assert!(has_sleep, "MySQL payloads should include SLEEP");
}

#[test]
fn test_mssql_specific_payloads() {
    let mssql = sqli_payloads_by_dbms(SqliDbms::Mssql);
    assert!(
        mssql.len() >= 10,
        "Expected 10+ MSSQL payloads, got {}",
        mssql.len()
    );
    let has_waitfor = mssql.iter().any(|p| p.payload.contains("WAITFOR"));
    assert!(has_waitfor, "MSSQL payloads should include WAITFOR");
}

#[test]
fn test_oracle_specific_payloads() {
    let oracle = sqli_payloads_by_dbms(SqliDbms::Oracle);
    assert!(
        oracle.len() >= 5,
        "Expected 5+ Oracle payloads, got {}",
        oracle.len()
    );
}

#[test]
fn test_sqlite_specific_payloads() {
    let sqlite = sqli_payloads_by_dbms(SqliDbms::SQLite);
    assert!(
        sqlite.len() >= 4,
        "Expected 4+ SQLite payloads, got {}",
        sqlite.len()
    );
}

#[test]
fn test_contains_classic_auth_bypass() {
    let all = all_sqli_payloads();
    let has_or_bypass = all.iter().any(|p| p.payload.contains("OR 1=1"));
    assert!(has_or_bypass, "Should include classic OR 1=1 auth bypass");
}
