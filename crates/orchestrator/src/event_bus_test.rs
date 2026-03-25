use std::sync::{Arc, Mutex};

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::ModuleIdentifier;
use aegis_protocol::scan_event::ScanEvent;

use crate::event_bus::{EventBus, EventTopic, SharedEventBus};

fn test_module(name: &str) -> ModuleIdentifier {
    ModuleIdentifier {
        crate_name: name.to_string(),
        module_path: format!("aegis_{}", name),
    }
}

#[test]
fn subscribe_and_publish_endpoint_discovered() {
    let mut bus = EventBus::new();
    let received = Arc::new(Mutex::new(Vec::new()));
    let recv = received.clone();

    bus.subscribe(
        test_module("crawler"),
        EventTopic::EndpointDiscovered,
        Arc::new(move |envelope| {
            recv.lock().unwrap().push(envelope.event_id);
        }),
    );

    bus.publish(
        test_module("crawler"),
        ScanEvent::EndpointDiscovered {
            endpoint: "/api/users".to_string(),
            method: "GET".to_string(),
            source_module: test_module("crawler"),
        },
    );

    let ids = received.lock().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], 0);
}

#[test]
fn all_topic_receives_every_event() {
    let mut bus = EventBus::new();
    let count = Arc::new(Mutex::new(0u64));
    let c = count.clone();

    bus.subscribe(
        test_module("monitor"),
        EventTopic::All,
        Arc::new(move |_envelope| {
            *c.lock().unwrap() += 1;
        }),
    );

    bus.publish(
        test_module("crawler"),
        ScanEvent::EndpointDiscovered {
            endpoint: "/a".to_string(),
            method: "GET".to_string(),
            source_module: test_module("crawler"),
        },
    );

    bus.publish(
        test_module("fuzzer"),
        ScanEvent::FindingConfirmed {
            finding_id: 1,
            vulnerability_class: VulnerabilityClass::SqlInjection,
            severity: 8.5,
            confidence: 0.9,
        },
    );

    assert_eq!(*count.lock().unwrap(), 2);
}

#[test]
fn topic_filtering_works() {
    let mut bus = EventBus::new();
    let findings_count = Arc::new(Mutex::new(0u64));
    let fc = findings_count.clone();

    bus.subscribe(
        test_module("reporter"),
        EventTopic::FindingConfirmed,
        Arc::new(move |_| {
            *fc.lock().unwrap() += 1;
        }),
    );

    bus.publish(
        test_module("crawler"),
        ScanEvent::EndpointDiscovered {
            endpoint: "/x".to_string(),
            method: "POST".to_string(),
            source_module: test_module("crawler"),
        },
    );

    bus.publish(
        test_module("fuzzer"),
        ScanEvent::FindingConfirmed {
            finding_id: 42,
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            severity: 6.0,
            confidence: 0.85,
        },
    );

    assert_eq!(*findings_count.lock().unwrap(), 1);
}

#[test]
fn unsubscribe_stops_delivery() {
    let mut bus = EventBus::new();
    let count = Arc::new(Mutex::new(0u64));
    let c = count.clone();

    let sub_id = bus.subscribe(
        test_module("test"),
        EventTopic::PhaseCompleted,
        Arc::new(move |_| {
            *c.lock().unwrap() += 1;
        }),
    );

    bus.publish(
        test_module("pipeline"),
        ScanEvent::PhaseCompleted {
            phase_name: "recon".to_string(),
            operations_applied: 10,
            findings_count: 0,
            duration_ms: 500,
        },
    );

    assert_eq!(*count.lock().unwrap(), 1);

    let removed = bus.unsubscribe(sub_id);
    assert!(removed);

    bus.publish(
        test_module("pipeline"),
        ScanEvent::PhaseCompleted {
            phase_name: "crawl".to_string(),
            operations_applied: 20,
            findings_count: 2,
            duration_ms: 1000,
        },
    );

    assert_eq!(*count.lock().unwrap(), 1);
}

#[test]
fn event_log_records_published_events() {
    let mut bus = EventBus::new();

    bus.publish(
        test_module("recon"),
        ScanEvent::EndpointDiscovered {
            endpoint: "/login".to_string(),
            method: "POST".to_string(),
            source_module: test_module("recon"),
        },
    );

    bus.publish(
        test_module("fuzzer"),
        ScanEvent::AnomalyDetected {
            endpoint: "/login".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            anomaly_type: "status_code_diff".to_string(),
            score: 0.95,
        },
    );

    assert_eq!(bus.event_log().len(), 2);
    assert_eq!(bus.total_events_published(), 2);
}

#[test]
fn events_by_topic_filters_correctly() {
    let mut bus = EventBus::new();

    bus.publish(
        test_module("crawler"),
        ScanEvent::EndpointDiscovered {
            endpoint: "/a".to_string(),
            method: "GET".to_string(),
            source_module: test_module("crawler"),
        },
    );
    bus.publish(
        test_module("crawler"),
        ScanEvent::EndpointDiscovered {
            endpoint: "/b".to_string(),
            method: "POST".to_string(),
            source_module: test_module("crawler"),
        },
    );
    bus.publish(
        test_module("pipeline"),
        ScanEvent::PhaseCompleted {
            phase_name: "crawl".to_string(),
            operations_applied: 5,
            findings_count: 0,
            duration_ms: 200,
        },
    );

    let endpoints = bus.events_by_topic(EventTopic::EndpointDiscovered);
    assert_eq!(endpoints.len(), 2);

    let phases = bus.events_by_topic(EventTopic::PhaseCompleted);
    assert_eq!(phases.len(), 1);
}

#[test]
fn subscriber_count_reflects_registrations() {
    let mut bus = EventBus::new();
    assert_eq!(bus.subscriber_count(EventTopic::FindingConfirmed), 0);

    bus.subscribe(
        test_module("a"),
        EventTopic::FindingConfirmed,
        Arc::new(|_| {}),
    );
    bus.subscribe(
        test_module("b"),
        EventTopic::FindingConfirmed,
        Arc::new(|_| {}),
    );
    bus.subscribe(test_module("c"), EventTopic::All, Arc::new(|_| {}));

    assert_eq!(bus.subscriber_count(EventTopic::FindingConfirmed), 3);
    assert_eq!(bus.subscriber_count(EventTopic::EndpointDiscovered), 1);
}

#[test]
fn clear_log_keeps_subscriptions() {
    let mut bus = EventBus::new();
    let count = Arc::new(Mutex::new(0u64));
    let c = count.clone();

    bus.subscribe(
        test_module("test"),
        EventTopic::All,
        Arc::new(move |_| {
            *c.lock().unwrap() += 1;
        }),
    );

    bus.publish(
        test_module("x"),
        ScanEvent::PhaseCompleted {
            phase_name: "recon".to_string(),
            operations_applied: 1,
            findings_count: 0,
            duration_ms: 100,
        },
    );

    assert_eq!(bus.event_log().len(), 1);
    bus.clear_log();
    assert_eq!(bus.event_log().len(), 0);

    bus.publish(
        test_module("x"),
        ScanEvent::PhaseCompleted {
            phase_name: "crawl".to_string(),
            operations_applied: 2,
            findings_count: 0,
            duration_ms: 200,
        },
    );

    assert_eq!(*count.lock().unwrap(), 2);
    assert_eq!(bus.event_log().len(), 1);
}

#[test]
fn shared_event_bus_thread_safe() {
    let bus = SharedEventBus::new();
    let count = Arc::new(Mutex::new(0u64));
    let c = count.clone();

    bus.subscribe(
        test_module("test"),
        EventTopic::All,
        Arc::new(move |_| {
            *c.lock().unwrap() += 1;
        }),
    );

    bus.publish(
        test_module("crawler"),
        ScanEvent::EndpointDiscovered {
            endpoint: "/test".to_string(),
            method: "GET".to_string(),
            source_module: test_module("crawler"),
        },
    );

    assert_eq!(*count.lock().unwrap(), 1);
    assert_eq!(bus.total_events_published(), 1);
    assert_eq!(bus.subscriber_count(EventTopic::EndpointDiscovered), 1);
}

#[test]
fn log_capacity_is_respected() {
    let mut bus = EventBus::with_log_capacity(3);

    for i in 0..5 {
        bus.publish(
            test_module("test"),
            ScanEvent::PhaseCompleted {
                phase_name: format!("phase_{}", i),
                operations_applied: 0,
                findings_count: 0,
                duration_ms: 0,
            },
        );
    }

    assert_eq!(bus.event_log().len(), 3);
    assert_eq!(bus.total_events_published(), 5);
}

#[test]
fn reset_clears_everything() {
    let mut bus = EventBus::new();
    bus.subscribe(test_module("a"), EventTopic::All, Arc::new(|_| {}));
    bus.publish(
        test_module("x"),
        ScanEvent::PhaseCompleted {
            phase_name: "test".to_string(),
            operations_applied: 0,
            findings_count: 0,
            duration_ms: 0,
        },
    );

    assert_eq!(bus.subscriber_count(EventTopic::All), 1);
    assert_eq!(bus.event_log().len(), 1);

    bus.reset();

    assert_eq!(bus.subscriber_count(EventTopic::All), 0);
    assert_eq!(bus.event_log().len(), 0);
    assert_eq!(bus.total_events_published(), 0);
}
