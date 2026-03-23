use crate::battery_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_battery("");
    assert!(issues.is_empty());
}

#[test]
fn no_battery_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_battery(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_battery_api() {
    let body = "navigator.getBattery().then(battery => {});";
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryApiUsed));
}

#[test]
fn detects_battery_level() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.level);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryLevelRead));
}

#[test]
fn detects_charging_state() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.charging);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::ChargingStateRead));
}

#[test]
fn detects_discharging_time() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.dischargingTime);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::ChargingStateRead));
}

#[test]
fn detects_event_listener() {
    let body = r#"
        navigator.getBattery().then(battery => {
            battery.addEventListener('levelchange', update);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryEventListener));
}

#[test]
fn detects_charging_change_event() {
    let body = r#"
        navigator.getBattery().then(battery => {
            battery.addEventListener('chargingchange', update);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryEventListener));
}

#[test]
fn detects_battery_data_sent() {
    let body = r#"
        navigator.getBattery().then(battery => {
            fetch('/track', {body: JSON.stringify({level: battery.level})});
        });
    "#;
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryDataSent));
}

#[test]
fn no_data_sent_without_network() {
    let body = r#"
        navigator.getBattery().then(battery => {
            console.log(battery.level);
        });
    "#;
    let issues = analyze_battery(body);
    assert!(!issues.contains(&BatteryIssue::BatteryDataSent));
}

#[test]
fn detects_battery_manager() {
    let body = "if (typeof BatteryManager !== 'undefined') { }";
    let issues = analyze_battery(body);
    assert!(issues.contains(&BatteryIssue::BatteryApiUsed));
}

#[test]
fn severity_data_sent_highest() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryDataSent), 6.0);
}

#[test]
fn severity_api_used_lowest() {
    assert_eq!(battery_severity(&BatteryIssue::BatteryApiUsed), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        BatteryIssue::BatteryApiUsed,
        BatteryIssue::BatteryLevelRead,
    ];
    let mut seq = 0;
    let ops = battery_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(BatteryIssue::BatteryApiUsed.to_string(), "battery_api");
    assert_eq!(BatteryIssue::BatteryLevelRead.to_string(), "battery_level_read");
    assert_eq!(BatteryIssue::ChargingStateRead.to_string(), "charging_state_read");
    assert_eq!(BatteryIssue::BatteryEventListener.to_string(), "battery_event_listener");
    assert_eq!(BatteryIssue::BatteryDataSent.to_string(), "battery_data_sent");
}
