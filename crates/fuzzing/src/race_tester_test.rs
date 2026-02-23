use crate::race_tester::{RaceTester, interpret_results, is_race_candidate};

#[test]
fn race_candidate_post_transfer_is_candidate() {
    assert!(is_race_candidate(
        "http://127.0.0.1:3000/api/transfer",
        "POST"
    ));
}

#[test]
fn race_candidate_post_purchase_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/purchase", "POST"));
}

#[test]
fn race_candidate_put_payment_is_candidate() {
    assert!(is_race_candidate(
        "http://127.0.0.1:3000/api/payment",
        "PUT"
    ));
}

#[test]
fn race_candidate_delete_order_is_candidate() {
    assert!(is_race_candidate(
        "http://127.0.0.1:3000/order/123",
        "DELETE"
    ));
}

#[test]
fn race_candidate_patch_redeem_is_candidate() {
    assert!(is_race_candidate(
        "http://127.0.0.1:3000/coupon/redeem",
        "PATCH"
    ));
}

#[test]
fn race_candidate_post_vote_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/vote", "POST"));
}

#[test]
fn race_candidate_post_apply_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/apply", "POST"));
}

#[test]
fn race_candidate_post_withdraw_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/withdraw", "POST"));
}

#[test]
fn race_candidate_post_deposit_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/deposit", "POST"));
}

#[test]
fn race_candidate_post_submit_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/submit", "POST"));
}

#[test]
fn race_candidate_post_checkout_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/checkout", "POST"));
}

#[test]
fn race_candidate_post_book_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/book", "POST"));
}

#[test]
fn race_candidate_post_reserve_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/reserve", "POST"));
}

#[test]
fn race_candidate_post_claim_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/claim", "POST"));
}

#[test]
fn race_candidate_post_activate_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/activate", "POST"));
}

#[test]
fn race_candidate_post_send_is_candidate() {
    assert!(is_race_candidate("http://127.0.0.1:3000/send", "POST"));
}

#[test]
fn race_candidate_get_is_not_candidate() {
    assert!(!is_race_candidate(
        "http://127.0.0.1:3000/api/transfer",
        "GET"
    ));
}

#[test]
fn race_candidate_head_is_not_candidate() {
    assert!(!is_race_candidate(
        "http://127.0.0.1:3000/api/transfer",
        "HEAD"
    ));
}

#[test]
fn race_candidate_post_generic_api_is_not_candidate() {
    assert!(!is_race_candidate(
        "http://127.0.0.1:3000/api/users",
        "POST"
    ));
}

#[test]
fn race_candidate_post_health_is_not_candidate() {
    assert!(!is_race_candidate("http://127.0.0.1:3000/health", "POST"));
}

#[test]
fn race_candidate_case_insensitive_method() {
    assert!(is_race_candidate("http://127.0.0.1:3000/transfer", "post"));
}

#[test]
fn race_candidate_case_insensitive_path() {
    assert!(is_race_candidate(
        "http://127.0.0.1:3000/api/Transfer",
        "POST"
    ));
}

#[test]
fn race_candidate_nested_path_matches() {
    assert!(is_race_candidate(
        "http://127.0.0.1:3000/api/v2/payment/process",
        "POST"
    ));
}

#[test]
fn interpret_single_success_is_no_race() {
    let responses = vec![(200, 100), (409, 50), (409, 50), (409, 50), (409, 50)];
    let result = interpret_results("http://127.0.0.1:3000/transfer", "POST", &responses, 5);
    assert!(result.is_none());
}

#[test]
fn interpret_zero_successes_is_no_race() {
    let responses = vec![(500, 0), (500, 0), (500, 0)];
    let result = interpret_results("http://127.0.0.1:3000/transfer", "POST", &responses, 3);
    assert!(result.is_none());
}

#[test]
fn interpret_five_successes_is_race() {
    let responses = vec![(200, 100), (200, 100), (200, 100), (200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/transfer", "POST", &responses, 5);
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.concurrent_successes, 5);
    assert_eq!(r.total_sent, 5);
}

#[test]
fn interpret_two_successes_is_race() {
    let responses = vec![(200, 100), (201, 50), (409, 50), (500, 0)];
    let result = interpret_results("http://127.0.0.1:3000/order", "POST", &responses, 4);
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.concurrent_successes, 2);
}

#[test]
fn interpret_204_counted_as_success() {
    let responses = vec![(204, 0), (204, 0), (409, 50)];
    let result = interpret_results("http://127.0.0.1:3000/transfer", "POST", &responses, 3);
    assert!(result.is_some());
    assert_eq!(result.unwrap().concurrent_successes, 2);
}

#[test]
fn severity_high_for_transfer_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/api/transfer", "POST", &responses, 2);
    assert!((result.unwrap().severity - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_high_for_payment_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/payment", "POST", &responses, 2);
    assert!((result.unwrap().severity - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_high_for_purchase_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/purchase", "POST", &responses, 2);
    assert!((result.unwrap().severity - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_high_for_withdraw_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/withdraw", "POST", &responses, 2);
    assert!((result.unwrap().severity - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_high_for_deposit_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/deposit", "POST", &responses, 2);
    assert!((result.unwrap().severity - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_high_for_send_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/send", "POST", &responses, 2);
    assert!((result.unwrap().severity - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_high_for_checkout_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/checkout", "POST", &responses, 2);
    assert!((result.unwrap().severity - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_medium_for_vote_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/vote", "POST", &responses, 2);
    assert!((result.unwrap().severity - 5.5).abs() < f64::EPSILON);
}

#[test]
fn severity_medium_for_order_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/order", "POST", &responses, 2);
    assert!((result.unwrap().severity - 5.5).abs() < f64::EPSILON);
}

#[test]
fn severity_medium_for_claim_endpoint() {
    let responses = vec![(200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/claim", "POST", &responses, 2);
    assert!((result.unwrap().severity - 5.5).abs() < f64::EPSILON);
}

#[test]
fn evidence_contains_success_count_and_endpoint() {
    let responses = vec![(200, 100), (200, 100), (200, 100)];
    let result = interpret_results("http://127.0.0.1:3000/transfer", "POST", &responses, 3);
    let r = result.unwrap();
    assert!(r.evidence.contains("3/3"));
    assert!(r.evidence.contains("transfer"));
    assert!(r.evidence.contains("POST"));
}

#[test]
fn race_tester_default_concurrency_is_ten() {
    let tester = RaceTester::new();
    assert_eq!(tester.concurrency(), 10);
}

#[test]
fn race_tester_with_concurrency_sets_value() {
    let tester = RaceTester::new().with_concurrency(5);
    assert_eq!(tester.concurrency(), 5);
}

#[test]
fn race_tester_with_concurrency_clamps_to_one() {
    let tester = RaceTester::new().with_concurrency(0);
    assert_eq!(tester.concurrency(), 1);
}

#[test]
fn race_tester_rejects_non_localhost() {
    let tester = RaceTester::new();
    let result = tester.test_race_condition("http://example.com/transfer", "POST", None, &[]);
    assert!(result.is_none());
}

#[test]
fn race_tester_rejects_get_method() {
    let tester = RaceTester::new();
    let result = tester.test_race_condition("http://127.0.0.1:3000/transfer", "GET", None, &[]);
    assert!(result.is_none());
}

#[test]
fn race_tester_rejects_non_candidate_path() {
    let tester = RaceTester::new();
    let result = tester.test_race_condition("http://127.0.0.1:3000/api/users", "POST", None, &[]);
    assert!(result.is_none());
}

#[test]
fn result_fields_populated_correctly() {
    let responses = vec![(200, 50), (200, 50), (409, 20)];
    let result =
        interpret_results("http://127.0.0.1:3000/transfer", "post", &responses, 3).unwrap();
    assert_eq!(result.endpoint, "http://127.0.0.1:3000/transfer");
    assert_eq!(result.method, "POST");
    assert_eq!(result.concurrent_successes, 2);
    assert_eq!(result.total_sent, 3);
}

#[test]
fn interpret_empty_responses_is_no_race() {
    let responses: Vec<(u16, usize)> = vec![];
    let result = interpret_results("http://127.0.0.1:3000/transfer", "POST", &responses, 0);
    assert!(result.is_none());
}

#[test]
fn interpret_all_failures_is_no_race() {
    let responses = vec![(0, 0), (0, 0), (0, 0)];
    let result = interpret_results("http://127.0.0.1:3000/transfer", "POST", &responses, 3);
    assert!(result.is_none());
}

#[test]
fn interpret_mixed_success_codes_counted() {
    let responses = vec![(200, 50), (201, 30), (204, 0), (409, 20)];
    let result = interpret_results("http://127.0.0.1:3000/order", "POST", &responses, 4);
    assert!(result.is_some());
    assert_eq!(result.unwrap().concurrent_successes, 3);
}
