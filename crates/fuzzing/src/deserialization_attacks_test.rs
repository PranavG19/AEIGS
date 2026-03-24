use super::deserialization_attacks::*;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Framework enumeration
// ---------------------------------------------------------------------------

#[test]
fn all_frameworks_returns_six() {
    assert_eq!(DeserializationFramework::all().len(), 6);
}

#[test]
fn framework_labels_are_unique() {
    let labels: Vec<&str> = DeserializationFramework::all()
        .iter()
        .map(|f| f.label())
        .collect();
    let mut deduped = labels.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(labels.len(), deduped.len());
}

#[test]
fn framework_display_names_non_empty() {
    for fw in DeserializationFramework::all() {
        assert!(!fw.display_name().is_empty());
        assert!(!fw.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Gadget chain enumeration
// ---------------------------------------------------------------------------

#[test]
fn all_gadget_chains_cover_all_frameworks() {
    for fw in DeserializationFramework::all() {
        let chains = GadgetChain::for_framework(*fw);
        assert!(
            !chains.is_empty(),
            "framework {} has no gadget chains",
            fw.label()
        );
    }
}

#[test]
fn gadget_chain_labels_are_unique() {
    let labels: Vec<&str> = ALL_GADGET_CHAINS.iter().map(|g| g.label()).collect();
    let mut deduped = labels.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(labels.len(), deduped.len());
}

#[test]
fn gadget_chain_descriptions_non_empty() {
    for chain in ALL_GADGET_CHAINS {
        assert!(
            !chain.description().is_empty(),
            "chain {} has empty description",
            chain.label()
        );
    }
}

#[test]
fn gadget_chain_framework_mapping_consistent() {
    for chain in ALL_GADGET_CHAINS {
        let fw = chain.framework();
        let fw_chains = GadgetChain::for_framework(fw);
        assert!(
            fw_chains.contains(chain),
            "chain {} not in framework {} chains",
            chain.label(),
            fw.label()
        );
    }
}

// ---------------------------------------------------------------------------
// Payload generation — per framework
// ---------------------------------------------------------------------------

#[test]
fn java_payloads_start_with_stream_magic() {
    let payloads = generate_payloads(DeserializationFramework::JavaYsoserial, "id");
    assert!(payloads.len() >= 3);
    for p in &payloads {
        assert_eq!(
            &p.raw_bytes[..4],
            &[0xAC, 0xED, 0x00, 0x05],
            "Java payload {} missing stream magic",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn java_payloads_contain_command() {
    let cmd = "touch /tmp/pwned";
    let payloads = generate_payloads(DeserializationFramework::JavaYsoserial, cmd);
    for p in &payloads {
        let raw_str = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            raw_str.contains(cmd),
            "Java payload {} does not embed command",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn python_pickle_payloads_start_with_proto2() {
    let payloads = generate_payloads(DeserializationFramework::PythonPickle, "whoami");
    assert!(payloads.len() >= 3);
    for p in &payloads {
        assert_eq!(
            &p.raw_bytes[..2],
            &[0x80, 0x02],
            "Pickle payload {} missing proto2 header",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn python_pickle_payloads_end_with_stop() {
    let payloads = generate_payloads(DeserializationFramework::PythonPickle, "ls");
    for p in &payloads {
        assert_eq!(
            *p.raw_bytes.last().unwrap(),
            0x2E,
            "Pickle payload {} missing STOP opcode",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn php_payloads_contain_serialized_objects() {
    let payloads = generate_payloads(DeserializationFramework::PhpUnserialize, "cat /etc/passwd");
    assert!(payloads.len() >= 3);
    for p in &payloads {
        let text = String::from_utf8_lossy(&p.raw_bytes);
        // PHP serialized objects contain O: or s: patterns
        assert!(
            text.contains("O:") || text.contains("s:"),
            "PHP payload {} missing serialized object markers",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn dotnet_payloads_start_with_serialization_header() {
    let payloads = generate_payloads(DeserializationFramework::DotNetBinaryFormatter, "calc.exe");
    assert!(payloads.len() >= 3);
    for p in &payloads {
        assert_eq!(
            p.raw_bytes[0],
            0x00,
            ".NET payload {} missing serialization header record type",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn ruby_payloads_start_with_marshal_version() {
    let payloads = generate_payloads(DeserializationFramework::RubyMarshal, "uname -a");
    assert!(payloads.len() >= 3);
    for p in &payloads {
        assert_eq!(
            &p.raw_bytes[..2],
            &[0x04, 0x08],
            "Ruby payload {} missing Marshal version header",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn node_payloads_contain_nd_func_marker() {
    let payloads = generate_payloads(DeserializationFramework::NodeSerialize, "ls");
    assert!(payloads.len() >= 3);
    for p in &payloads {
        let text = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            text.contains("_$$ND_FUNC$$_"),
            "Node payload {} missing _$$ND_FUNC$$_ marker",
            p.gadget_chain.label()
        );
    }
}

#[test]
fn node_payloads_are_valid_json() {
    let payloads = generate_payloads(DeserializationFramework::NodeSerialize, "echo test");
    for p in &payloads {
        let text = String::from_utf8(p.raw_bytes.clone()).expect("not valid UTF-8");
        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(&text);
        assert!(
            parsed.is_ok(),
            "Node payload {} is not valid JSON: {}",
            p.gadget_chain.label(),
            text
        );
    }
}

// ---------------------------------------------------------------------------
// generate_all_payloads
// ---------------------------------------------------------------------------

#[test]
fn generate_all_payloads_covers_all_frameworks() {
    let payloads = generate_all_payloads("id");
    let frameworks: std::collections::HashSet<_> = payloads.iter().map(|p| p.framework).collect();
    for fw in DeserializationFramework::all() {
        assert!(
            frameworks.contains(fw),
            "generate_all_payloads missing framework {}",
            fw.label()
        );
    }
}

#[test]
fn generate_all_payloads_minimum_count() {
    let payloads = generate_all_payloads("id");
    // 5 Java + 3 Python + 3 PHP + 3 .NET + 3 Ruby + 3 Node = 20
    assert!(
        payloads.len() >= 20,
        "expected >=20 total payloads, got {}",
        payloads.len()
    );
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

#[test]
fn base64_encoding_is_valid() {
    let payloads = generate_payloads(DeserializationFramework::PythonPickle, "id");
    let encoded = payloads[0].encode(PayloadEncoding::Base64);
    let encoded_str = String::from_utf8(encoded).unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded_str)
        .expect("invalid base64");
    assert_eq!(decoded, payloads[0].raw_bytes);
}

#[test]
fn hex_encoding_roundtrips() {
    let payloads = generate_payloads(DeserializationFramework::JavaYsoserial, "id");
    let encoded = payloads[0].encode(PayloadEncoding::Hex);
    let hex_str = String::from_utf8(encoded).unwrap();
    // Verify it's valid hex and roundtrips
    assert!(hex_str.len() == payloads[0].raw_bytes.len() * 2);
    for (i, byte) in payloads[0].raw_bytes.iter().enumerate() {
        let parsed = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap();
        assert_eq!(parsed, *byte);
    }
}

#[test]
fn url_encoding_encodes_special_bytes() {
    let payloads = generate_payloads(DeserializationFramework::JavaYsoserial, "id");
    let encoded = payloads[0].encode(PayloadEncoding::UrlEncoded);
    let encoded_str = String::from_utf8(encoded).unwrap();
    // Java stream magic 0xAC should be percent-encoded
    assert!(encoded_str.contains("%AC"));
}

#[test]
fn raw_encoding_returns_exact_bytes() {
    let payloads = generate_payloads(DeserializationFramework::RubyMarshal, "id");
    let encoded = payloads[0].encode(PayloadEncoding::Raw);
    assert_eq!(encoded, payloads[0].raw_bytes);
}

#[test]
fn all_encodings_returns_four_variants() {
    let payloads = generate_payloads(DeserializationFramework::PhpUnserialize, "id");
    let encodings = payloads[0].all_encodings();
    assert_eq!(encodings.len(), 4);
    assert!(encodings.contains_key(&PayloadEncoding::Raw));
    assert!(encodings.contains_key(&PayloadEncoding::Base64));
    assert!(encodings.contains_key(&PayloadEncoding::Hex));
    assert!(encodings.contains_key(&PayloadEncoding::UrlEncoded));
}

// ---------------------------------------------------------------------------
// Framework detection
// ---------------------------------------------------------------------------

#[test]
fn detect_java_from_headers() {
    let mut headers = HashMap::new();
    headers.insert("X-Powered-By".into(), "Servlet/3.0".into());
    let detected = detect_frameworks(&headers, "", None);
    assert!(detected.contains(&DeserializationFramework::JavaYsoserial));
}

#[test]
fn detect_python_from_server_header() {
    let mut headers = HashMap::new();
    headers.insert("Server".into(), "gunicorn/21.0.1".into());
    let detected = detect_frameworks(&headers, "", None);
    assert!(detected.contains(&DeserializationFramework::PythonPickle));
}

#[test]
fn detect_php_from_header() {
    let mut headers = HashMap::new();
    headers.insert("X-Powered-By".into(), "PHP/8.2.3".into());
    let detected = detect_frameworks(&headers, "", None);
    assert!(detected.contains(&DeserializationFramework::PhpUnserialize));
}

#[test]
fn detect_dotnet_from_aspnet_header() {
    let mut headers = HashMap::new();
    headers.insert("X-AspNet-Version".into(), "4.0.30319".into());
    let detected = detect_frameworks(&headers, "", None);
    assert!(detected.contains(&DeserializationFramework::DotNetBinaryFormatter));
}

#[test]
fn detect_ruby_from_server_header() {
    let mut headers = HashMap::new();
    headers.insert("Server".into(), "puma 6.0.0".into());
    let detected = detect_frameworks(&headers, "", None);
    assert!(detected.contains(&DeserializationFramework::RubyMarshal));
}

#[test]
fn detect_node_from_express_header() {
    let mut headers = HashMap::new();
    headers.insert("X-Powered-By".into(), "Express".into());
    let detected = detect_frameworks(&headers, "", None);
    assert!(detected.contains(&DeserializationFramework::NodeSerialize));
}

#[test]
fn detect_java_from_body_error() {
    let headers = HashMap::new();
    let body = "java.io.StreamCorruptedException: invalid stream header";
    let detected = detect_frameworks(&headers, body, None);
    assert!(detected.contains(&DeserializationFramework::JavaYsoserial));
}

#[test]
fn detect_python_from_content_type() {
    let headers = HashMap::new();
    let detected = detect_frameworks(&headers, "", Some("application/x-python-serialize"));
    assert!(detected.contains(&DeserializationFramework::PythonPickle));
}

#[test]
fn detect_nothing_from_empty_response() {
    let headers = HashMap::new();
    let detected = detect_frameworks(&headers, "", None);
    assert!(detected.is_empty());
}

// ---------------------------------------------------------------------------
// Framework signatures structure
// ---------------------------------------------------------------------------

#[test]
fn all_framework_signatures_cover_all_frameworks() {
    let sigs = all_framework_signatures();
    let covered: std::collections::HashSet<_> = sigs.iter().map(|s| s.framework).collect();
    for fw in DeserializationFramework::all() {
        assert!(
            covered.contains(fw),
            "no signature for framework {}",
            fw.label()
        );
    }
}

#[test]
fn payload_encoding_all_returns_four() {
    assert_eq!(PayloadEncoding::all().len(), 4);
}

#[test]
fn payload_encoding_labels_unique() {
    let labels: Vec<&str> = PayloadEncoding::all().iter().map(|e| e.label()).collect();
    let mut deduped = labels.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(labels.len(), deduped.len());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_command_produces_valid_payloads() {
    let payloads = generate_all_payloads("");
    assert!(!payloads.is_empty());
    for p in &payloads {
        assert!(!p.raw_bytes.is_empty());
    }
}

#[test]
fn command_with_special_chars_embedded() {
    let cmd = "echo 'hello && rm -rf / ; cat /etc/passwd'";
    let payloads = generate_all_payloads(cmd);
    for p in &payloads {
        assert!(!p.raw_bytes.is_empty());
        assert_eq!(p.command, cmd);
    }
}

use base64::Engine as _;
