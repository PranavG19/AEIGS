use std::net::SocketAddr;

use axum::Router;
use axum::routing::get;

use super::*;
use crate::grep::{GrepExtract, GrepMatch, SearchTarget};
use crate::payload::{PayloadEncoding, PayloadPipeline, PayloadSource};
use crate::repeater::ModifiedRequest;

fn make_template(url: &str, body: &str) -> ModifiedRequest {
    ModifiedRequest {
        method: "GET".to_string(),
        url: url.to_string(),
        headers: vec![("X-Custom".to_string(), "val-\u{00a7}0\u{00a7}".to_string())],
        body: body.as_bytes().to_vec(),
    }
}

fn make_config(mode: AttackMode, positions: Vec<&str>, lists: Vec<Vec<&str>>) -> IntruderConfig {
    IntruderConfig {
        template: make_template(
            "http://localhost/path?p=\u{00a7}0\u{00a7}&q=\u{00a7}1\u{00a7}",
            "",
        ),
        positions: positions.into_iter().map(String::from).collect(),
        payload_lists: lists
            .into_iter()
            .map(|l| l.into_iter().map(String::from).collect())
            .collect(),
        mode,
        concurrency: 4,
    }
}

#[test]
fn sniper_generates_n_times_m_requests() {
    let config = make_config(
        AttackMode::Sniper,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["a", "b", "c"]],
    );
    let requests = generate_attack_requests(&config);
    assert_eq!(requests.len(), 6);
}

#[test]
fn sniper_substitutes_one_position_at_a_time() {
    let config = make_config(
        AttackMode::Sniper,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["X"]],
    );
    let requests = generate_attack_requests(&config);
    assert_eq!(requests.len(), 2);
    assert!(requests[0].1.url.contains("p=X"));
    assert!(requests[0].1.url.contains("q=\u{00a7}1\u{00a7}"));
    assert!(requests[1].1.url.contains("p=\u{00a7}0\u{00a7}"));
    assert!(requests[1].1.url.contains("q=X"));
}

#[test]
fn battering_ram_generates_n_requests() {
    let config = make_config(
        AttackMode::BatteringRam,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["a", "b", "c"]],
    );
    let requests = generate_attack_requests(&config);
    assert_eq!(requests.len(), 3);
}

#[test]
fn battering_ram_same_payload_all_positions() {
    let config = make_config(
        AttackMode::BatteringRam,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["BOOM"]],
    );
    let requests = generate_attack_requests(&config);
    assert_eq!(requests.len(), 1);
    assert!(requests[0].1.url.contains("p=BOOM"));
    assert!(requests[0].1.url.contains("q=BOOM"));
}

#[test]
fn pitchfork_generates_min_length_requests() {
    let config = make_config(
        AttackMode::Pitchfork,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["a", "b", "c"], vec!["1", "2"]],
    );
    let requests = generate_attack_requests(&config);
    assert_eq!(requests.len(), 2);
}

#[test]
fn pitchfork_zips_lists_in_parallel() {
    let config = make_config(
        AttackMode::Pitchfork,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["X", "Y"], vec!["1", "2"]],
    );
    let requests = generate_attack_requests(&config);
    assert_eq!(requests.len(), 2);
    assert!(requests[0].1.url.contains("p=X"));
    assert!(requests[0].1.url.contains("q=1"));
    assert!(requests[1].1.url.contains("p=Y"));
    assert!(requests[1].1.url.contains("q=2"));
}

#[test]
fn cluster_bomb_generates_cartesian_product() {
    let config = make_config(
        AttackMode::ClusterBomb,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["a", "b"], vec!["1", "2", "3"]],
    );
    let requests = generate_attack_requests(&config);
    assert_eq!(requests.len(), 6);
}

#[test]
fn cluster_bomb_covers_all_combinations() {
    let config = make_config(
        AttackMode::ClusterBomb,
        vec!["\u{00a7}0\u{00a7}", "\u{00a7}1\u{00a7}"],
        vec![vec!["A", "B"], vec!["1", "2"]],
    );
    let requests = generate_attack_requests(&config);
    let urls: Vec<String> = requests.iter().map(|(_, r)| r.url.clone()).collect();
    assert!(urls.iter().any(|u| u.contains("p=A") && u.contains("q=1")));
    assert!(urls.iter().any(|u| u.contains("p=A") && u.contains("q=2")));
    assert!(urls.iter().any(|u| u.contains("p=B") && u.contains("q=1")));
    assert!(urls.iter().any(|u| u.contains("p=B") && u.contains("q=2")));
}

#[test]
fn position_substitution_applies_to_headers() {
    let config = IntruderConfig {
        template: make_template("http://localhost/test", ""),
        positions: vec!["\u{00a7}0\u{00a7}".to_string()],
        payload_lists: vec![vec!["injected".to_string()]],
        mode: AttackMode::BatteringRam,
        concurrency: 1,
    };
    let requests = generate_attack_requests(&config);
    let header_val = &requests[0].1.headers[0].1;
    assert_eq!(header_val, "val-injected");
}

#[test]
fn position_substitution_applies_to_body() {
    let config = IntruderConfig {
        template: ModifiedRequest {
            method: "POST".to_string(),
            url: "http://localhost/test".to_string(),
            headers: vec![],
            body: b"data=\xc2\xa70\xc2\xa7".to_vec(),
        },
        positions: vec!["\u{00a7}0\u{00a7}".to_string()],
        payload_lists: vec![vec!["payload_value".to_string()]],
        mode: AttackMode::BatteringRam,
        concurrency: 1,
    };
    let requests = generate_attack_requests(&config);
    assert_eq!(
        String::from_utf8_lossy(&requests[0].1.body),
        "data=payload_value"
    );
}

#[test]
fn empty_payload_lists_produces_no_requests() {
    let config = make_config(AttackMode::ClusterBomb, vec!["\u{00a7}0\u{00a7}"], vec![]);
    let requests = generate_attack_requests(&config);
    assert!(requests.is_empty());
}

#[test]
fn single_position_sniper_equals_battering_ram_count() {
    let sniper = make_config(
        AttackMode::Sniper,
        vec!["\u{00a7}0\u{00a7}"],
        vec![vec!["a", "b", "c"]],
    );
    let ram = make_config(
        AttackMode::BatteringRam,
        vec!["\u{00a7}0\u{00a7}"],
        vec![vec!["a", "b", "c"]],
    );
    assert_eq!(
        generate_attack_requests(&sniper).len(),
        generate_attack_requests(&ram).len()
    );
}

async fn spawn_status_server() -> SocketAddr {
    let app = Router::new().route("/ok", get(|| async { "ok" })).route(
        "/not-found",
        get(|| async { (axum::http::StatusCode::NOT_FOUND, "nope") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn run_intruder_sends_requests_and_collects_results() {
    let target = spawn_status_server().await;
    let marker = "\u{00a7}0\u{00a7}";
    let config = IntruderConfig {
        template: ModifiedRequest {
            method: "GET".to_string(),
            url: format!("http://{target}/{marker}"),
            headers: vec![],
            body: vec![],
        },
        positions: vec![marker.to_string()],
        payload_lists: vec![vec!["ok".to_string(), "not-found".to_string()]],
        mode: AttackMode::BatteringRam,
        concurrency: 2,
    };
    let results = run_intruder(config).await;
    assert_eq!(results.len(), 2);
    let statuses: Vec<u16> = results.iter().map(|r| r.status_code).collect();
    assert!(statuses.contains(&200));
    assert!(statuses.contains(&404));
}

#[tokio::test]
async fn run_intruder_sorts_anomalous_first() {
    let target = spawn_status_server().await;
    let marker = "\u{00a7}0\u{00a7}";
    let config = IntruderConfig {
        template: ModifiedRequest {
            method: "GET".to_string(),
            url: format!("http://{target}/{marker}"),
            headers: vec![],
            body: vec![],
        },
        positions: vec![marker.to_string()],
        payload_lists: vec![vec!["ok".to_string(), "not-found".to_string()]],
        mode: AttackMode::BatteringRam,
        concurrency: 1,
    };
    let results = run_intruder(config).await;
    assert_eq!(results[0].status_code, 404);
}

#[test]
fn pipeline_intruder_generates_from_number_range() {
    let marker = "\u{00a7}0\u{00a7}";
    let pipeline = PayloadPipeline {
        source: PayloadSource::NumberRange {
            start: 1,
            end: 5,
            step: 1,
        },
        processors: vec![],
        encoding: PayloadEncoding::None,
    };
    let config = PipelineIntruderConfig {
        template: ModifiedRequest {
            method: "GET".to_string(),
            url: format!("http://localhost/id={marker}"),
            headers: vec![],
            body: vec![],
        },
        positions: vec![marker.to_string()],
        pipelines: vec![pipeline],
        mode: AttackMode::BatteringRam,
        concurrency: 1,
        grep_matches: vec![],
        grep_extracts: vec![],
    };

    let payloads = config.pipelines[0].generate().expect("generate");
    assert_eq!(payloads.len(), 5);

    let inner = IntruderConfig {
        template: config.template,
        positions: config.positions,
        payload_lists: vec![payloads],
        mode: config.mode,
        concurrency: config.concurrency,
    };
    let requests = generate_attack_requests(&inner);
    assert_eq!(requests.len(), 5);
    assert!(requests[0].1.url.contains("id=1"));
    assert!(requests[4].1.url.contains("id=5"));
}

#[tokio::test]
async fn pipeline_intruder_applies_grep_match() {
    let target = spawn_status_server().await;
    let marker = "\u{00a7}0\u{00a7}";
    let pipeline = PayloadPipeline {
        source: PayloadSource::SimpleList(vec!["ok".to_string()]),
        processors: vec![],
        encoding: PayloadEncoding::None,
    };
    let config = PipelineIntruderConfig {
        template: ModifiedRequest {
            method: "GET".to_string(),
            url: format!("http://{target}/{marker}"),
            headers: vec![],
            body: vec![],
        },
        positions: vec![marker.to_string()],
        pipelines: vec![pipeline],
        mode: AttackMode::BatteringRam,
        concurrency: 1,
        grep_matches: vec![GrepMatch {
            pattern: "ok".to_string(),
            search_in: SearchTarget::Body,
            negate: false,
        }],
        grep_extracts: vec![],
    };
    let results = run_pipeline_intruder(config).await.expect("run");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status_code, 200);
    assert!(results[0].grep_match_results.contains(&"ok".to_string()));
}

#[tokio::test]
async fn pipeline_intruder_applies_grep_extract() {
    let target = spawn_status_server().await;
    let marker = "\u{00a7}0\u{00a7}";
    let pipeline = PayloadPipeline {
        source: PayloadSource::SimpleList(vec!["ok".to_string()]),
        processors: vec![],
        encoding: PayloadEncoding::None,
    };
    let config = PipelineIntruderConfig {
        template: ModifiedRequest {
            method: "GET".to_string(),
            url: format!("http://{target}/{marker}"),
            headers: vec![],
            body: vec![],
        },
        positions: vec![marker.to_string()],
        pipelines: vec![pipeline],
        mode: AttackMode::BatteringRam,
        concurrency: 1,
        grep_matches: vec![],
        grep_extracts: vec![GrepExtract {
            pattern: "(ok)".to_string(),
            group: 1,
            search_in: SearchTarget::Body,
        }],
    };
    let results = run_pipeline_intruder(config).await.expect("run");
    assert_eq!(results.len(), 1);
    assert!(results[0].grep_extract_results.contains(&"ok".to_string()));
}

#[tokio::test]
async fn pipeline_intruder_backwards_compat() {
    let target = spawn_status_server().await;
    let marker = "\u{00a7}0\u{00a7}";
    let config = IntruderConfig {
        template: ModifiedRequest {
            method: "GET".to_string(),
            url: format!("http://{target}/{marker}"),
            headers: vec![],
            body: vec![],
        },
        positions: vec![marker.to_string()],
        payload_lists: vec![vec!["ok".to_string(), "not-found".to_string()]],
        mode: AttackMode::BatteringRam,
        concurrency: 2,
    };
    let results = run_intruder(config).await;
    assert_eq!(results.len(), 2);
    let statuses: Vec<u16> = results.iter().map(|r| r.status_code).collect();
    assert!(statuses.contains(&200));
    assert!(statuses.contains(&404));
}
