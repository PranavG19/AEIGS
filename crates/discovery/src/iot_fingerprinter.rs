use regex::Regex;
use std::collections::HashMap;
use std::fmt;

/// Category of IoT device detected on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceType {
    Router,
    Camera,
    Printer,
    IndustrialController,
    SmartHome,
    NAS,
    AccessPoint,
    Switch,
    Firewall,
    Modem,
    Other,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Router => "Router",
            Self::Camera => "IP Camera",
            Self::Printer => "Printer",
            Self::IndustrialController => "Industrial Controller",
            Self::SmartHome => "Smart Home Device",
            Self::NAS => "Network Attached Storage",
            Self::AccessPoint => "Wireless Access Point",
            Self::Switch => "Network Switch",
            Self::Firewall => "Firewall",
            Self::Modem => "Modem",
            Self::Other => "Other IoT Device",
        };
        write!(f, "{label}")
    }
}

/// Network protocol through which default credentials apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Telnet,
    SSH,
    HTTP,
    HTTPS,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Telnet => "Telnet",
            Self::SSH => "SSH",
            Self::HTTP => "HTTP",
            Self::HTTPS => "HTTPS",
        };
        write!(f, "{label}")
    }
}

/// Risk level assigned to a discovered IoT device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IoTRisk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for IoTRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// A default credential entry for a specific device model.
#[derive(Debug, Clone, PartialEq)]
pub struct DefaultCredential {
    pub device_type: DeviceType,
    pub manufacturer: String,
    pub model_pattern: String,
    pub default_username: String,
    pub default_password: String,
    pub protocol: Protocol,
    pub cve_references: Vec<String>,
}

/// Result of matching a network banner to a known device signature.
#[derive(Debug, Clone, PartialEq)]
pub struct BannerMatch {
    pub device_type: DeviceType,
    pub manufacturer: String,
    pub model_hint: String,
    pub firmware_version: Option<String>,
    pub banner_text: String,
    pub confidence: f64,
}

/// A single IoT security finding attached to a target host.
#[derive(Debug, Clone, PartialEq)]
pub struct IoTFinding {
    pub host: String,
    pub device_type: DeviceType,
    pub manufacturer: String,
    pub model: String,
    pub risk: IoTRisk,
    pub default_creds_found: Vec<DefaultCredential>,
    pub banner_matches: Vec<BannerMatch>,
    pub description: String,
    pub cve_references: Vec<String>,
}

impl fmt::Display for IoTFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{risk}] {dtype} {mfr} {model} @ {host} — {desc}",
            risk = self.risk,
            dtype = self.device_type,
            mfr = self.manufacturer,
            model = self.model,
            host = self.host,
            desc = self.description,
        )
    }
}

/// Aggregated IoT reconnaissance report across all scanned hosts.
#[derive(Debug, Clone, PartialEq)]
pub struct IoTReport {
    pub findings: Vec<IoTFinding>,
    pub total_devices: usize,
    pub risk_summary: HashMap<IoTRisk, usize>,
    pub device_type_summary: HashMap<DeviceType, usize>,
    pub manufacturer_summary: HashMap<String, usize>,
    pub critical_count: usize,
    pub high_count: usize,
}

impl fmt::Display for IoTReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IoT Report: {total} devices, {crit} critical, {high} high",
            total = self.total_devices,
            crit = self.critical_count,
            high = self.high_count,
        )
    }
}

/// Returns a database of 100+ default credential entries spanning routers, cameras,
/// printers, industrial controllers, smart-home devices, NAS appliances, access points,
/// switches, firewalls, and modems from major manufacturers.
pub fn get_default_credentials_db() -> Vec<DefaultCredential> {
    vec![
        // ── Routers ──────────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Cisco".into(),
            model_pattern: "RV340".into(),
            default_username: "cisco".into(),
            default_password: "cisco".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-20707".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Cisco".into(),
            model_pattern: "RV160".into(),
            default_username: "cisco".into(),
            default_password: "cisco".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-20700".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Cisco".into(),
            model_pattern: "ISR4321".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::SSH,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "TP-Link".into(),
            model_pattern: "Archer C7".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-35575".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "TP-Link".into(),
            model_pattern: "TL-WR841N".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Netgear".into(),
            model_pattern: "R7000".into(),
            default_username: "admin".into(),
            default_password: "password".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-45521".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Netgear".into(),
            model_pattern: "R6700".into(),
            default_username: "admin".into(),
            default_password: "password".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-34991".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Linksys".into(),
            model_pattern: "WRT54G".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Linksys".into(),
            model_pattern: "EA7500".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-35713".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "D-Link".into(),
            model_pattern: "DIR-615".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2019-17621".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "D-Link".into(),
            model_pattern: "DIR-825".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-29557".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "MikroTik".into(),
            model_pattern: "RouterOS".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::SSH,
            cve_references: vec!["CVE-2023-30799".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "MikroTik".into(),
            model_pattern: "hAP ac2".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Ubiquiti".into(),
            model_pattern: "EdgeRouter X".into(),
            default_username: "ubnt".into(),
            default_password: "ubnt".into(),
            protocol: Protocol::SSH,
            cve_references: vec!["CVE-2021-22886".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Ubiquiti".into(),
            model_pattern: "USG".into(),
            default_username: "ubnt".into(),
            default_password: "ubnt".into(),
            protocol: Protocol::SSH,
            cve_references: vec![],
        },
        // ── Cameras ──────────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Hikvision".into(),
            model_pattern: "DS-2CD2143G2".into(),
            default_username: "admin".into(),
            default_password: "12345".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-36260".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Hikvision".into(),
            model_pattern: "DS-7608NI".into(),
            default_username: "admin".into(),
            default_password: "12345".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2017-7921".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Hikvision".into(),
            model_pattern: "DS-2DE2A404IW".into(),
            default_username: "admin".into(),
            default_password: "admin12345".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Dahua".into(),
            model_pattern: "IPC-HDW2431T".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-33044".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Dahua".into(),
            model_pattern: "DH-NVR4104HS".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-33045".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Axis".into(),
            model_pattern: "M3057-PLVE".into(),
            default_username: "root".into(),
            default_password: "pass".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-51882".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Axis".into(),
            model_pattern: "P1448-LE".into(),
            default_username: "root".into(),
            default_password: "root".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Foscam".into(),
            model_pattern: "FI9821W".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2018-6830".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Foscam".into(),
            model_pattern: "R2".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Reolink".into(),
            model_pattern: "RLC-510A".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-21236".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Reolink".into(),
            model_pattern: "Argus 3 Pro".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        // ── Printers ─────────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "HP".into(),
            model_pattern: "LaserJet Pro M404".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-39238".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "HP".into(),
            model_pattern: "OfficeJet Pro 9015".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-3942".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "HP".into(),
            model_pattern: "Color LaserJet M553".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Brother".into(),
            model_pattern: "HL-L2350DW".into(),
            default_username: "admin".into(),
            default_password: "access".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-25078".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Brother".into(),
            model_pattern: "MFC-L8900CDW".into(),
            default_username: "admin".into(),
            default_password: "access".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Canon".into(),
            model_pattern: "imageCLASS MF743Cdw".into(),
            default_username: "7654321".into(),
            default_password: "7654321".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2023-0851".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Canon".into(),
            model_pattern: "PIXMA G6020".into(),
            default_username: "ADMIN".into(),
            default_password: "canon".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Epson".into(),
            model_pattern: "WorkForce WF-2860".into(),
            default_username: "epson".into(),
            default_password: "epson".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-12692".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Epson".into(),
            model_pattern: "EcoTank ET-4760".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Xerox".into(),
            model_pattern: "VersaLink C405".into(),
            default_username: "admin".into(),
            default_password: "1111".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-23968".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Xerox".into(),
            model_pattern: "WorkCentre 6515".into(),
            default_username: "admin".into(),
            default_password: "1111".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Ricoh".into(),
            model_pattern: "SP C261SFNw".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2019-14308".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Printer,
            manufacturer: "Ricoh".into(),
            model_pattern: "IM C3000".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        // ── Industrial Controllers ───────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Siemens".into(),
            model_pattern: "S7-1200".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2019-13945".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Siemens".into(),
            model_pattern: "SCALANCE X200".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-46350".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Siemens".into(),
            model_pattern: "LOGO! 8".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-25243".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Schneider".into(),
            model_pattern: "Modicon M340".into(),
            default_username: "USER".into(),
            default_password: "USER".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-45788".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Schneider".into(),
            model_pattern: "PowerLogic PM5500".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-22767".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "ABB".into(),
            model_pattern: "AC500".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2023-0580".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "ABB".into(),
            model_pattern: "IRC5".into(),
            default_username: "Default User".into(),
            default_password: "robotics".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Rockwell".into(),
            model_pattern: "CompactLogix 5380".into(),
            default_username: "admin".into(),
            default_password: "1234".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-1161".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Rockwell".into(),
            model_pattern: "MicroLogix 1100".into(),
            default_username: "admin".into(),
            default_password: "1234".into(),
            protocol: Protocol::Telnet,
            cve_references: vec!["CVE-2012-6435".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Honeywell".into(),
            model_pattern: "Experion PKS".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2023-24474".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Honeywell".into(),
            model_pattern: "ControlEdge PLC".into(),
            default_username: "admin".into(),
            default_password: "honeywell".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "GE".into(),
            model_pattern: "PACSystems RX3i".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2018-10936".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "GE".into(),
            model_pattern: "Mark VIe".into(),
            default_username: "admin".into(),
            default_password: "GEfanuc".into(),
            protocol: Protocol::Telnet,
            cve_references: vec![],
        },
        // ── Smart Home ───────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Philips Hue".into(),
            model_pattern: "Bridge 2.0".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-6007".into()],
        },
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Philips Hue".into(),
            model_pattern: "Bridge v1".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Samsung SmartThings".into(),
            model_pattern: "Hub v3".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2018-3911".into()],
        },
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Samsung SmartThings".into(),
            model_pattern: "Hub v2".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Nest".into(),
            model_pattern: "Thermostat E".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2019-5035".into()],
        },
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Nest".into(),
            model_pattern: "Cam Indoor".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Nest".into(),
            model_pattern: "Hello Doorbell".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2019-5034".into()],
        },
        // ── NAS ──────────────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "Synology".into(),
            model_pattern: "DS220+".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-27610".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "Synology".into(),
            model_pattern: "DS920+".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2021-29086".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "Synology".into(),
            model_pattern: "RS1221+".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "QNAP".into(),
            model_pattern: "TS-453D".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-27596".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "QNAP".into(),
            model_pattern: "TS-231K".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-28816".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "QNAP".into(),
            model_pattern: "TS-873A".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "WD".into(),
            model_pattern: "My Cloud EX2 Ultra".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-22995".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "WD".into(),
            model_pattern: "My Cloud PR4100".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-35941".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "Netgear ReadyNAS".into(),
            model_pattern: "RN422".into(),
            default_username: "admin".into(),
            default_password: "netgear1".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2021-34991".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "Netgear ReadyNAS".into(),
            model_pattern: "RN214".into(),
            default_username: "admin".into(),
            default_password: "netgear1".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        // ── Access Points ────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "Ubiquiti".into(),
            model_pattern: "UniFi AP AC Pro".into(),
            default_username: "ubnt".into(),
            default_password: "ubnt".into(),
            protocol: Protocol::SSH,
            cve_references: vec!["CVE-2020-8149".into()],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "Ubiquiti".into(),
            model_pattern: "UniFi AP U6 Pro".into(),
            default_username: "ubnt".into(),
            default_password: "ubnt".into(),
            protocol: Protocol::SSH,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "TP-Link".into(),
            model_pattern: "EAP245".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-27246".into()],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "TP-Link".into(),
            model_pattern: "EAP225".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "Cisco".into(),
            model_pattern: "Aironet 2800".into(),
            default_username: "Cisco".into(),
            default_password: "Cisco".into(),
            protocol: Protocol::SSH,
            cve_references: vec!["CVE-2019-15264".into()],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "Cisco".into(),
            model_pattern: "Catalyst 9115AX".into(),
            default_username: "Cisco".into(),
            default_password: "Cisco".into(),
            protocol: Protocol::SSH,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "Aruba".into(),
            model_pattern: "AP-505".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-37897".into()],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "Aruba".into(),
            model_pattern: "IAP-315".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "Ruckus".into(),
            model_pattern: "R750".into(),
            default_username: "super".into(),
            default_password: "sp-admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2023-25717".into()],
        },
        // ── Switches ─────────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "Cisco".into(),
            model_pattern: "Catalyst 2960".into(),
            default_username: "cisco".into(),
            default_password: "cisco".into(),
            protocol: Protocol::Telnet,
            cve_references: vec!["CVE-2018-0171".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "Cisco".into(),
            model_pattern: "SG350".into(),
            default_username: "cisco".into(),
            default_password: "cisco".into(),
            protocol: Protocol::SSH,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "Netgear".into(),
            model_pattern: "GS308E".into(),
            default_username: "admin".into(),
            default_password: "password".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-40847".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "Netgear".into(),
            model_pattern: "GS724T".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "HP".into(),
            model_pattern: "ProCurve 2920".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::Telnet,
            cve_references: vec!["CVE-2019-5390".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "D-Link".into(),
            model_pattern: "DGS-1210-28".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2019-7642".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "Juniper".into(),
            model_pattern: "EX2300".into(),
            default_username: "root".into(),
            default_password: "".into(),
            protocol: Protocol::SSH,
            cve_references: vec!["CVE-2023-36845".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "Arista".into(),
            model_pattern: "7050X3".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::SSH,
            cve_references: vec!["CVE-2021-28496".into()],
        },
        // ── Firewalls ────────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "Fortinet".into(),
            model_pattern: "FortiGate 60F".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-40684".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "Fortinet".into(),
            model_pattern: "FortiGate 100F".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2023-27997".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "Palo Alto".into(),
            model_pattern: "PA-220".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2020-2021".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "Palo Alto".into(),
            model_pattern: "PA-440".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "SonicWall".into(),
            model_pattern: "TZ370".into(),
            default_username: "admin".into(),
            default_password: "password".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2021-20016".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "SonicWall".into(),
            model_pattern: "NSA 2700".into(),
            default_username: "admin".into(),
            default_password: "password".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "pfSense".into(),
            model_pattern: "CE 2.7".into(),
            default_username: "admin".into(),
            default_password: "pfsense".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-31814".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "WatchGuard".into(),
            model_pattern: "Firebox T40".into(),
            default_username: "admin".into(),
            default_password: "readwrite".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-23176".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "Sophos".into(),
            model_pattern: "XGS 2100".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-1040".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "Check Point".into(),
            model_pattern: "1570".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2024-24919".into()],
        },
        // ── Modems ───────────────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Arris".into(),
            model_pattern: "SB8200".into(),
            default_username: "admin".into(),
            default_password: "password".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-10173".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Arris".into(),
            model_pattern: "SBG10".into(),
            default_username: "admin".into(),
            default_password: "motorola".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Motorola".into(),
            model_pattern: "MB8600".into(),
            default_username: "admin".into(),
            default_password: "motorola".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2019-19494".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Motorola".into(),
            model_pattern: "MG7700".into(),
            default_username: "admin".into(),
            default_password: "motorola".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "ZTE".into(),
            model_pattern: "ZXHN H198A".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-6866".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Huawei".into(),
            model_pattern: "HG8245H5".into(),
            default_username: "telecomadmin".into(),
            default_password: "admintelecom".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2017-17215".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Technicolor".into(),
            model_pattern: "TC8717T".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-10376".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Sagemcom".into(),
            model_pattern: "F@st 5260".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-15023".into()],
        },
        // ── Additional routers to hit count ──────────────────────────
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "ASUS".into(),
            model_pattern: "RT-AX88U".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-26376".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "ASUS".into(),
            model_pattern: "RT-AC68U".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2021-32030".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Zyxel".into(),
            model_pattern: "USG FLEX 100".into(),
            default_username: "admin".into(),
            default_password: "1234".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-0342".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Router,
            manufacturer: "Tenda".into(),
            model_pattern: "AC15".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-10987".into()],
        },
        // ── Additional cameras ───────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Amcrest".into(),
            model_pattern: "IP2M-841".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2020-5735".into()],
        },
        DefaultCredential {
            device_type: DeviceType::Camera,
            manufacturer: "Vivotek".into(),
            model_pattern: "FD9167-HT".into(),
            default_username: "root".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2018-14494".into()],
        },
        // ── Additional NAS ───────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "Asustor".into(),
            model_pattern: "AS5304T".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2022-0847".into()],
        },
        DefaultCredential {
            device_type: DeviceType::NAS,
            manufacturer: "TerraMaster".into(),
            model_pattern: "F2-221".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-24990".into()],
        },
        // ── Additional smart home ────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Wemo".into(),
            model_pattern: "Insight Switch".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2018-6692".into()],
        },
        DefaultCredential {
            device_type: DeviceType::SmartHome,
            manufacturer: "Ring".into(),
            model_pattern: "Video Doorbell Pro".into(),
            default_username: "".into(),
            default_password: "".into(),
            protocol: Protocol::HTTPS,
            cve_references: vec!["CVE-2019-9483".into()],
        },
        // ── Additional switches ──────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Switch,
            manufacturer: "MikroTik".into(),
            model_pattern: "CRS305-1G-4S+".into(),
            default_username: "admin".into(),
            default_password: "".into(),
            protocol: Protocol::SSH,
            cve_references: vec![],
        },
        // ── Additional access points ─────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::AccessPoint,
            manufacturer: "EnGenius".into(),
            model_pattern: "ECW220".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-46381".into()],
        },
        // ── Additional industrial ────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Omron".into(),
            model_pattern: "NJ501".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::HTTP,
            cve_references: vec!["CVE-2022-34151".into()],
        },
        DefaultCredential {
            device_type: DeviceType::IndustrialController,
            manufacturer: "Mitsubishi".into(),
            model_pattern: "MELSEC iQ-R".into(),
            default_username: "admin".into(),
            default_password: "mitsubishi".into(),
            protocol: Protocol::Telnet,
            cve_references: vec!["CVE-2021-20594".into()],
        },
        // ── Additional firewalls ─────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Firewall,
            manufacturer: "Cisco".into(),
            model_pattern: "ASA 5506".into(),
            default_username: "admin".into(),
            default_password: "admin".into(),
            protocol: Protocol::SSH,
            cve_references: vec!["CVE-2018-0101".into()],
        },
        // ── Additional modems ────────────────────────────────────────
        DefaultCredential {
            device_type: DeviceType::Modem,
            manufacturer: "Netgear".into(),
            model_pattern: "CM1000".into(),
            default_username: "admin".into(),
            default_password: "password".into(),
            protocol: Protocol::HTTP,
            cve_references: vec![],
        },
    ]
}

/// Telnet banner signature used for device fingerprinting.
struct TelnetSignature {
    pattern: Regex,
    device_type: DeviceType,
    manufacturer: &'static str,
    model_hint: &'static str,
}

/// SSH banner signature used for device fingerprinting.
struct SshSignature {
    pattern: Regex,
    device_type: DeviceType,
    manufacturer: &'static str,
    model_hint: &'static str,
}

/// Parses a Telnet banner and returns matching device fingerprints.
///
/// Scans the banner text against known login prompts, welcome messages,
/// and manufacturer-specific patterns. Returns all matches with confidence
/// scores based on pattern specificity.
pub fn match_telnet_banner(banner: &str) -> Vec<BannerMatch> {
    let signatures = telnet_signatures();
    let lower = banner.to_lowercase();
    let mut matches = Vec::new();

    for sig in &signatures {
        if sig.pattern.is_match(&lower) {
            let firmware = extract_firmware_from_telnet(&lower);
            let confidence = if lower.contains(sig.manufacturer.to_lowercase().as_str()) {
                0.9
            } else {
                0.7
            };
            matches.push(BannerMatch {
                device_type: sig.device_type,
                manufacturer: sig.manufacturer.to_string(),
                model_hint: sig.model_hint.to_string(),
                firmware_version: firmware,
                banner_text: banner.to_string(),
                confidence,
            });
        }
    }

    matches
}

/// Parses an SSH version string and returns matching device fingerprints.
///
/// Extracts firmware version information from SSH-2.0 and SSH-1.99 banners.
/// Matches vendor-specific SSH implementations (dropbear on embedded devices,
/// Cisco SSH, MikroTik, etc.) and correlates with known device types.
pub fn match_ssh_banner(banner: &str) -> Vec<BannerMatch> {
    let signatures = ssh_signatures();
    let lower = banner.to_lowercase();
    let mut matches = Vec::new();

    for sig in &signatures {
        if sig.pattern.is_match(&lower) {
            let firmware = extract_firmware_from_ssh(banner);
            let confidence = if lower.contains(sig.manufacturer.to_lowercase().as_str()) {
                0.9
            } else {
                0.75
            };
            matches.push(BannerMatch {
                device_type: sig.device_type,
                manufacturer: sig.manufacturer.to_string(),
                model_hint: sig.model_hint.to_string(),
                firmware_version: firmware,
                banner_text: banner.to_string(),
                confidence,
            });
        }
    }

    matches
}

/// Identifies a device based on combined Telnet and SSH banner analysis,
/// plus optional HTTP response headers.
///
/// Merges results from all available banner sources, deduplicates by
/// manufacturer, and returns the highest-confidence identification.
pub fn identify_device(
    telnet_banner: Option<&str>,
    ssh_banner: Option<&str>,
    http_headers: Option<&HashMap<String, String>>,
) -> Vec<BannerMatch> {
    let mut all_matches: Vec<BannerMatch> = Vec::new();

    if let Some(tb) = telnet_banner {
        all_matches.extend(match_telnet_banner(tb));
    }
    if let Some(sb) = ssh_banner {
        all_matches.extend(match_ssh_banner(sb));
    }
    if let Some(headers) = http_headers {
        all_matches.extend(match_http_headers(headers));
    }

    deduplicate_matches(&mut all_matches);
    all_matches
}

/// Assigns a risk level to a discovered IoT device based on its type,
/// whether default credentials were found, and the presence of known CVEs.
pub fn assess_device_risk(
    device_type: DeviceType,
    has_default_creds: bool,
    cve_count: usize,
    is_internet_facing: bool,
) -> IoTRisk {
    let base_risk = match device_type {
        DeviceType::IndustrialController => IoTRisk::Critical,
        DeviceType::Firewall => IoTRisk::High,
        DeviceType::Router => IoTRisk::High,
        DeviceType::Switch => IoTRisk::High,
        DeviceType::Camera => IoTRisk::Medium,
        DeviceType::NAS => IoTRisk::Medium,
        DeviceType::AccessPoint => IoTRisk::Medium,
        DeviceType::Modem => IoTRisk::Medium,
        DeviceType::Printer => IoTRisk::Low,
        DeviceType::SmartHome => IoTRisk::Low,
        DeviceType::Other => IoTRisk::Info,
    };

    let escalated = if has_default_creds {
        escalate_risk(base_risk)
    } else {
        base_risk
    };

    let cve_adjusted = if cve_count >= 3 {
        escalate_risk(escalated)
    } else {
        escalated
    };

    if is_internet_facing {
        escalate_risk(cve_adjusted)
    } else {
        cve_adjusted
    }
}

/// Constructs an aggregated IoT report from a list of individual findings.
///
/// Computes per-risk, per-device-type, and per-manufacturer summaries,
/// plus critical/high totals for triage.
pub fn build_iot_report(findings: Vec<IoTFinding>) -> IoTReport {
    let total_devices = findings.len();
    let mut risk_summary: HashMap<IoTRisk, usize> = HashMap::new();
    let mut device_type_summary: HashMap<DeviceType, usize> = HashMap::new();
    let mut manufacturer_summary: HashMap<String, usize> = HashMap::new();
    let mut critical_count = 0usize;
    let mut high_count = 0usize;

    for finding in &findings {
        *risk_summary.entry(finding.risk).or_insert(0) += 1;
        *device_type_summary.entry(finding.device_type).or_insert(0) += 1;
        *manufacturer_summary
            .entry(finding.manufacturer.clone())
            .or_insert(0) += 1;

        match finding.risk {
            IoTRisk::Critical => critical_count += 1,
            IoTRisk::High => high_count += 1,
            _ => {}
        }
    }

    IoTReport {
        findings,
        total_devices,
        risk_summary,
        device_type_summary,
        manufacturer_summary,
        critical_count,
        high_count,
    }
}

/// Looks up default credentials for a given manufacturer and optional model substring.
pub fn lookup_credentials(manufacturer: &str, model_hint: Option<&str>) -> Vec<DefaultCredential> {
    let db = get_default_credentials_db();
    let mfr_lower = manufacturer.to_lowercase();
    db.into_iter()
        .filter(|cred| {
            let matches_mfr = cred.manufacturer.to_lowercase().contains(&mfr_lower);
            let matches_model = match model_hint {
                Some(hint) => cred
                    .model_pattern
                    .to_lowercase()
                    .contains(&hint.to_lowercase()),
                None => true,
            };
            matches_mfr && matches_model
        })
        .collect()
}

/// Returns credentials for a specific device type.
pub fn credentials_by_device_type(device_type: DeviceType) -> Vec<DefaultCredential> {
    let db = get_default_credentials_db();
    db.into_iter()
        .filter(|cred| cred.device_type == device_type)
        .collect()
}

fn telnet_signatures() -> Vec<TelnetSignature> {
    vec![
        TelnetSignature {
            pattern: Regex::new(r"cisco\s+(ios|adaptive|asa)").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "Cisco",
            model_hint: "IOS Router",
        },
        TelnetSignature {
            pattern: Regex::new(r"user\s+access\s+verification").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "Cisco",
            model_hint: "Cisco Device",
        },
        TelnetSignature {
            pattern: Regex::new(r"mikrotik").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "MikroTik",
            model_hint: "RouterOS",
        },
        TelnetSignature {
            pattern: Regex::new(r"(hikvision|hikdigital)").unwrap(),
            device_type: DeviceType::Camera,
            manufacturer: "Hikvision",
            model_hint: "IP Camera",
        },
        TelnetSignature {
            pattern: Regex::new(r"dahua").unwrap(),
            device_type: DeviceType::Camera,
            manufacturer: "Dahua",
            model_hint: "IP Camera",
        },
        TelnetSignature {
            pattern: Regex::new(r"axis\s+(communications|network\s+camera)").unwrap(),
            device_type: DeviceType::Camera,
            manufacturer: "Axis",
            model_hint: "Network Camera",
        },
        TelnetSignature {
            pattern: Regex::new(r"hp\s+(laserjet|officejet|jet\s*direct)").unwrap(),
            device_type: DeviceType::Printer,
            manufacturer: "HP",
            model_hint: "Printer",
        },
        TelnetSignature {
            pattern: Regex::new(r"brother\s+(hl-|mfc-|dcp-)").unwrap(),
            device_type: DeviceType::Printer,
            manufacturer: "Brother",
            model_hint: "Printer",
        },
        TelnetSignature {
            pattern: Regex::new(r"siemens\s+(simatic|scalance|logo)").unwrap(),
            device_type: DeviceType::IndustrialController,
            manufacturer: "Siemens",
            model_hint: "SIMATIC",
        },
        TelnetSignature {
            pattern: Regex::new(r"schneider\s+(electric|modicon)").unwrap(),
            device_type: DeviceType::IndustrialController,
            manufacturer: "Schneider",
            model_hint: "PLC",
        },
        TelnetSignature {
            pattern: Regex::new(r"busybox").unwrap(),
            device_type: DeviceType::Other,
            manufacturer: "Generic",
            model_hint: "Embedded Linux",
        },
        TelnetSignature {
            pattern: Regex::new(r"synology").unwrap(),
            device_type: DeviceType::NAS,
            manufacturer: "Synology",
            model_hint: "DiskStation",
        },
        TelnetSignature {
            pattern: Regex::new(r"qnap").unwrap(),
            device_type: DeviceType::NAS,
            manufacturer: "QNAP",
            model_hint: "TurboNAS",
        },
        TelnetSignature {
            pattern: Regex::new(r"ubnt|ubiquiti|unifi").unwrap(),
            device_type: DeviceType::AccessPoint,
            manufacturer: "Ubiquiti",
            model_hint: "UniFi AP",
        },
        TelnetSignature {
            pattern: Regex::new(r"fortios|fortigate").unwrap(),
            device_type: DeviceType::Firewall,
            manufacturer: "Fortinet",
            model_hint: "FortiGate",
        },
        TelnetSignature {
            pattern: Regex::new(r"arris").unwrap(),
            device_type: DeviceType::Modem,
            manufacturer: "Arris",
            model_hint: "Cable Modem",
        },
        TelnetSignature {
            pattern: Regex::new(r"(tp-link|tl-wr|tl-wa|archer)").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "TP-Link",
            model_hint: "Wireless Router",
        },
        TelnetSignature {
            pattern: Regex::new(r"d-link|dir-\d+").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "D-Link",
            model_hint: "Router",
        },
        TelnetSignature {
            pattern: Regex::new(r"netgear").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "Netgear",
            model_hint: "Router",
        },
        TelnetSignature {
            pattern: Regex::new(r"zte\s").unwrap(),
            device_type: DeviceType::Modem,
            manufacturer: "ZTE",
            model_hint: "Modem",
        },
    ]
}

fn ssh_signatures() -> Vec<SshSignature> {
    vec![
        SshSignature {
            pattern: Regex::new(r"ssh-\d+\.\d+.*cisco").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "Cisco",
            model_hint: "IOS Device",
        },
        SshSignature {
            pattern: Regex::new(r"dropbear").unwrap(),
            device_type: DeviceType::Other,
            manufacturer: "Generic",
            model_hint: "Embedded Device",
        },
        SshSignature {
            pattern: Regex::new(r"mikrotik").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "MikroTik",
            model_hint: "RouterOS",
        },
        SshSignature {
            pattern: Regex::new(r"ubnt|ubiquiti").unwrap(),
            device_type: DeviceType::AccessPoint,
            manufacturer: "Ubiquiti",
            model_hint: "EdgeOS/UniFi",
        },
        SshSignature {
            pattern: Regex::new(r"fortissl|fortios").unwrap(),
            device_type: DeviceType::Firewall,
            manufacturer: "Fortinet",
            model_hint: "FortiGate",
        },
        SshSignature {
            pattern: Regex::new(r"junos|juniper").unwrap(),
            device_type: DeviceType::Switch,
            manufacturer: "Juniper",
            model_hint: "JunOS Device",
        },
        SshSignature {
            pattern: Regex::new(r"hp-ux|procurve").unwrap(),
            device_type: DeviceType::Switch,
            manufacturer: "HP",
            model_hint: "ProCurve Switch",
        },
        SshSignature {
            pattern: Regex::new(r"lancom").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "LANCOM",
            model_hint: "Router",
        },
        SshSignature {
            pattern: Regex::new(r"zyxel").unwrap(),
            device_type: DeviceType::Router,
            manufacturer: "Zyxel",
            model_hint: "Router/Firewall",
        },
        SshSignature {
            pattern: Regex::new(r"(synology|diskstation)").unwrap(),
            device_type: DeviceType::NAS,
            manufacturer: "Synology",
            model_hint: "DiskStation",
        },
        SshSignature {
            pattern: Regex::new(r"(qnap|qts)").unwrap(),
            device_type: DeviceType::NAS,
            manufacturer: "QNAP",
            model_hint: "QTS NAS",
        },
        SshSignature {
            pattern: Regex::new(r"hikvision").unwrap(),
            device_type: DeviceType::Camera,
            manufacturer: "Hikvision",
            model_hint: "IP Camera",
        },
    ]
}

fn match_http_headers(headers: &HashMap<String, String>) -> Vec<BannerMatch> {
    let mut matches = Vec::new();

    let combined: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();

    let http_patterns: Vec<(&str, DeviceType, &str, &str)> = vec![
        ("hikvision", DeviceType::Camera, "Hikvision", "IP Camera"),
        ("dahua", DeviceType::Camera, "Dahua", "IP Camera"),
        (
            "synology",
            DeviceType::NAS,
            "Synology",
            "DiskStation Manager",
        ),
        ("qnap", DeviceType::NAS, "QNAP", "QTS"),
        ("mikrotik", DeviceType::Router, "MikroTik", "RouterOS"),
        ("fortios", DeviceType::Firewall, "Fortinet", "FortiGate"),
        ("cisco", DeviceType::Router, "Cisco", "Web UI"),
        ("hp-ews", DeviceType::Printer, "HP", "EWS Printer"),
        ("xerox", DeviceType::Printer, "Xerox", "Embedded Web Server"),
        ("brother", DeviceType::Printer, "Brother", "Printer"),
        ("epson", DeviceType::Printer, "Epson", "Printer"),
    ];

    for (keyword, device_type, manufacturer, model_hint) in http_patterns {
        if combined.contains(keyword) {
            matches.push(BannerMatch {
                device_type,
                manufacturer: manufacturer.to_string(),
                model_hint: model_hint.to_string(),
                firmware_version: None,
                banner_text: combined.clone(),
                confidence: 0.8,
            });
        }
    }

    matches
}

fn extract_firmware_from_telnet(banner: &str) -> Option<String> {
    let version_re = Regex::new(r"(?i)(?:version|firmware|ver|v)[\s.:]+(\d+\.\d+[\.\d]*)").unwrap();
    version_re.captures(banner).map(|caps| caps[1].to_string())
}

fn extract_firmware_from_ssh(banner: &str) -> Option<String> {
    let ssh_version_re = Regex::new(r"SSH-\d+\.\d+-[\w_]+[_-](\d+\.\d+[\.\w]*)").unwrap();
    if let Some(caps) = ssh_version_re.captures(banner) {
        return Some(caps[1].to_string());
    }

    let generic_re = Regex::new(r"(\d+\.\d+\.\d+[\w.]*)").unwrap();
    generic_re.captures(banner).map(|caps| caps[1].to_string())
}

fn escalate_risk(risk: IoTRisk) -> IoTRisk {
    match risk {
        IoTRisk::Info => IoTRisk::Low,
        IoTRisk::Low => IoTRisk::Medium,
        IoTRisk::Medium => IoTRisk::High,
        IoTRisk::High => IoTRisk::Critical,
        IoTRisk::Critical => IoTRisk::Critical,
    }
}

fn deduplicate_matches(matches: &mut Vec<BannerMatch>) {
    matches.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut seen: HashMap<String, f64> = HashMap::new();
    matches.retain(|m| {
        let key = format!("{}:{}", m.manufacturer, m.device_type);
        match seen.get(&key) {
            Some(existing_conf) if *existing_conf >= m.confidence => false,
            _ => {
                seen.insert(key, m.confidence);
                true
            }
        }
    });
}
