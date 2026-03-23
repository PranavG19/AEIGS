use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebBluetoothIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    CharacteristicAccess,
    DeviceScan,
    PersistentConnection,
}

impl std::fmt::Display for WebBluetoothIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::CharacteristicAccess => write!(f, "characteristic_access"),
            Self::DeviceScan => write!(f, "device_scan"),
            Self::PersistentConnection => write!(f, "persistent_connection"),
        }
    }
}

pub fn audit_web_bluetooth(target: &str) -> Vec<WebBluetoothIssue> {
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
    analyze_web_bluetooth(&body)
}

pub fn analyze_web_bluetooth(body: &str) -> Vec<WebBluetoothIssue> {
    if !body.contains("navigator.bluetooth") && !body.contains("BluetoothDevice") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebBluetoothIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebBluetoothIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebBluetoothIssue::NoUserActivation);
    }

    if body.contains("getCharacteristic")
        || body.contains("readValue")
        || body.contains("writeValue")
        || body.contains("startNotifications")
    {
        issues.push(WebBluetoothIssue::CharacteristicAccess);
    }

    if body.contains("requestDevice") || body.contains("acceptAllDevices") {
        issues.push(WebBluetoothIssue::DeviceScan);
    }

    if body.contains("gattserverdisconnected")
        || body.contains("addEventListener(\"characteristicvaluechanged\"")
        || body.contains("addEventListener('characteristicvaluechanged'")
    {
        issues.push(WebBluetoothIssue::PersistentConnection);
    }

    issues
}

pub fn web_bluetooth_severity(issue: &WebBluetoothIssue) -> f64 {
    match issue {
        WebBluetoothIssue::DataExfiltration => 7.5,
        WebBluetoothIssue::CharacteristicAccess => 7.0,
        WebBluetoothIssue::PersistentConnection => 6.0,
        WebBluetoothIssue::DeviceScan => 5.5,
        WebBluetoothIssue::NoUserActivation => 5.0,
        WebBluetoothIssue::ApiDetected => 3.0,
    }
}

pub fn web_bluetooth_to_operations(
    issues: &[WebBluetoothIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_bluetooth_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebBluetoothSecurityIssue {
    BluetoothDeviceEnumeration,
    BluetoothDataInterception,
    BluetoothWithoutPermission,
    BluetoothPersistentConnection,
    BluetoothCrossOrigin,
    BluetoothGattExploration,
    BluetoothWriteCharacteristic,
    BluetoothLocationTracking,
    BluetoothInBackground,
    BluetoothDeviceFingerprinting,
}

impl std::fmt::Display for WebBluetoothSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BluetoothDeviceEnumeration => write!(f, "bluetooth_device_enumeration"),
            Self::BluetoothDataInterception => write!(f, "bluetooth_data_interception"),
            Self::BluetoothWithoutPermission => write!(f, "bluetooth_without_permission"),
            Self::BluetoothPersistentConnection => write!(f, "bluetooth_persistent_connection"),
            Self::BluetoothCrossOrigin => write!(f, "bluetooth_cross_origin"),
            Self::BluetoothGattExploration => write!(f, "bluetooth_gatt_exploration"),
            Self::BluetoothWriteCharacteristic => write!(f, "bluetooth_write_characteristic"),
            Self::BluetoothLocationTracking => write!(f, "bluetooth_location_tracking"),
            Self::BluetoothInBackground => write!(f, "bluetooth_in_background"),
            Self::BluetoothDeviceFingerprinting => write!(f, "bluetooth_device_fingerprinting"),
        }
    }
}

pub fn analyze_web_bluetooth_security(body: &str) -> Vec<WebBluetoothSecurityIssue> {
    if !body.contains("navigator.bluetooth")
        && !body.contains("BluetoothDevice")
        && !body.contains("characteristic")
        && !body.contains("gatt")
        && !body.contains("bluetooth")
        && !body.contains("device.rssi")
        && !body.contains("device.txPower")
        && !body.contains("server.getPrimaryServices")
        && !body.contains("service.getCharacteristics")
        && !body.contains("calculateProximity(device)")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // BluetoothDeviceEnumeration: scanning all nearby BT devices
    if (body.contains("requestDevice") && body.contains("acceptAllDevices"))
        || (body.contains("requestDevice") && body.contains("optionalServices"))
        || body.contains("getDevices()")
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothDeviceEnumeration);
    }

    // BluetoothDataInterception: reading BT characteristic data
    if (body.contains("readValue") || body.contains("startNotifications"))
        && (body.contains("DataView")
            || body.contains("getUint")
            || body.contains(".buffer")
            || body.contains("value.buffer"))
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothDataInterception);
    }

    // BluetoothWithoutPermission: BT access without user gesture
    if body.contains("requestDevice")
        && !body.contains("click")
        && !body.contains("touchstart")
        && !body.contains("keypress")
        && !body.contains("pointerdown")
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothWithoutPermission);
    }

    // BluetoothPersistentConnection: maintaining long-lived BT connections
    if (body.contains("gattserverdisconnected") && body.contains("reconnect"))
        || (body.contains("setInterval") && body.contains("gatt.connect"))
        || (body.contains("keepalive") && body.contains("bluetooth"))
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothPersistentConnection);
    }

    // BluetoothCrossOrigin: BT data shared cross-origin
    if (body.contains("postMessage")
        || body.contains("window.parent")
        || body.contains("window.opener"))
        && (body.contains("bluetooth") || body.contains("gatt") || body.contains("characteristic"))
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothCrossOrigin);
    }

    // BluetoothGattExploration: enumerating GATT services/characteristics
    if body.contains("getPrimaryServices")
        || body.contains("getCharacteristics")
        || (body.contains("for") && body.contains("getCharacteristic"))
        || body.contains("descriptors")
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothGattExploration);
    }

    // BluetoothWriteCharacteristic: writing to BT devices
    if body.contains("writeValue")
        || body.contains("writeValueWithResponse")
        || body.contains("writeValueWithoutResponse")
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothWriteCharacteristic);
    }

    // BluetoothLocationTracking: using BT for indoor positioning
    let body_lower = body.to_lowercase();
    if (body.contains("rssi") || body.contains("txPower") || body.contains("proximity"))
        && (body_lower.contains("position")
            || body_lower.contains("location")
            || body_lower.contains("coordinates"))
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothLocationTracking);
    }

    // BluetoothInBackground: BT operations when page hidden
    if (body.contains("visibilitychange") || body.contains("document.hidden"))
        && (body.contains("bluetooth") || body.contains("gatt") || body.contains("characteristic"))
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothInBackground);
    }

    // BluetoothDeviceFingerprinting: using BT device list for fingerprinting
    if (body.contains("requestDevice") || body.contains("getDevices"))
        && (body.contains("fingerprint") || body.contains("tracking") || body.contains("analytics"))
    {
        issues.push(WebBluetoothSecurityIssue::BluetoothDeviceFingerprinting);
    }

    issues
}

pub fn web_bluetooth_security_severity(issue: &WebBluetoothSecurityIssue) -> f64 {
    match issue {
        WebBluetoothSecurityIssue::BluetoothDataInterception => 8.5,
        WebBluetoothSecurityIssue::BluetoothWriteCharacteristic => 8.0,
        WebBluetoothSecurityIssue::BluetoothCrossOrigin => 7.5,
        WebBluetoothSecurityIssue::BluetoothLocationTracking => 7.0,
        WebBluetoothSecurityIssue::BluetoothDeviceFingerprinting => 6.5,
        WebBluetoothSecurityIssue::BluetoothPersistentConnection => 6.0,
        WebBluetoothSecurityIssue::BluetoothGattExploration => 5.5,
        WebBluetoothSecurityIssue::BluetoothDeviceEnumeration => 5.0,
        WebBluetoothSecurityIssue::BluetoothInBackground => 4.5,
        WebBluetoothSecurityIssue::BluetoothWithoutPermission => 4.0,
    }
}

pub fn web_bluetooth_security_to_operations(
    issues: &[WebBluetoothSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                web_bluetooth_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
