use crate::forward_secrecy::*;

#[test]
fn test_key_exchange_produces_shared_key() {
    let mut alice = ForwardSecrecySession::new(10);
    let bob = ForwardSecrecySession::new(10);

    assert!(!alice.is_established());
    assert!(alice.current_session_key().is_none());

    let result = alice.establish(bob.public_key());
    assert!(result.is_ok());
    assert!(alice.is_established());

    let key = alice.current_session_key().unwrap();
    assert!(!key.is_zero());
    assert_eq!(key.as_bytes().len(), 32);
}

#[test]
fn test_session_keys_unique_per_exchange() {
    let bob = ForwardSecrecySession::new(10);

    let mut session_a = ForwardSecrecySession::new(10);
    session_a.establish(bob.public_key()).unwrap();
    let key_a = session_a.current_session_key().unwrap().bytes;

    let mut session_b = ForwardSecrecySession::new(10);
    session_b.establish(bob.public_key()).unwrap();
    let key_b = session_b.current_session_key().unwrap().bytes;

    assert_ne!(key_a, key_b);
}

#[test]
fn test_ratchet_produces_new_key() {
    let mut session = ForwardSecrecySession::new(1);
    let peer = ForwardSecrecySession::new(1);
    session.establish(peer.public_key()).unwrap();

    let key_before = session.current_session_key().unwrap().bytes;

    session.force_ratchet();
    let key_after = session.current_session_key().unwrap().bytes;

    assert_ne!(key_before, key_after);
    assert!(!session.current_session_key().unwrap().is_zero());
}

#[test]
fn test_previous_keys_irrecoverable() {
    let mut session = ForwardSecrecySession::new(1);
    let peer = ForwardSecrecySession::new(1);
    session.establish(peer.public_key()).unwrap();

    let original_key = session.current_session_key().unwrap().bytes;

    session.force_ratchet();
    session.destroy_previous();

    let current_key = session.current_session_key().unwrap().bytes;
    assert_ne!(original_key, current_key);

    session.force_ratchet();
    session.destroy_previous();

    let newest_key = session.current_session_key().unwrap().bytes;
    assert_ne!(current_key, newest_key);
    assert_ne!(original_key, newest_key);
}

#[test]
fn test_key_commitment_scheme() {
    let mut session = ForwardSecrecySession::new(10);
    let peer = ForwardSecrecySession::new(10);

    assert!(session.key_commitment().is_none());

    session.establish(peer.public_key()).unwrap();
    let commitment = session.key_commitment().unwrap();
    assert_ne!(commitment, [0u8; 32]);

    let commitment_again = session.key_commitment().unwrap();
    assert_eq!(commitment, commitment_again);

    let key_bytes = session.current_session_key().unwrap().bytes;
    assert_ne!(commitment, key_bytes);

    session.force_ratchet();
    let new_commitment = session.key_commitment().unwrap();
    assert_ne!(commitment, new_commitment);
}

#[test]
fn test_secure_zeroing_on_drop() {
    let mut key = SessionKey::from_bytes([0xAB; 32]);
    assert!(!key.is_zero());

    secure_zero(&mut key.bytes);
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

    assert!(key.is_zero());
    assert_eq!(key.bytes, [0u8; 32]);
}

#[test]
fn test_ephemeral_keypair_generation_unique() {
    let pair_a = EphemeralKeyPair::generate();
    let pair_b = EphemeralKeyPair::generate();
    assert_ne!(pair_a.public_key, pair_b.public_key);
    assert_ne!(pair_a.private_key, pair_b.private_key);
}

#[test]
fn test_hkdf_derive_deterministic() {
    let secret = [0x42u8; 32];
    let key_a = HkdfDerive::derive(&secret, b"same-info");
    let key_b = HkdfDerive::derive(&secret, b"same-info");
    assert_eq!(key_a.bytes, key_b.bytes);
}

#[test]
fn test_hkdf_derive_different_info_different_key() {
    let secret = [0x42u8; 32];
    let key_a = HkdfDerive::derive(&secret, b"info-alpha");
    let key_b = HkdfDerive::derive(&secret, b"info-bravo");
    assert_ne!(key_a.bytes, key_b.bytes);
}

#[test]
fn test_establish_rejects_zero_peer_key() {
    let mut session = ForwardSecrecySession::new(10);
    let zero_key = [0u8; 32];
    let result = session.establish(&zero_key);
    assert_eq!(result, Err(ForwardSecrecyError::KeyExchangeFailed));
    assert!(!session.is_established());
}

#[test]
fn test_ratchet_should_rotate() {
    let initial = HkdfDerive::derive(&[0xAA; 32], b"init");
    let mut ratchet = KeyRatchet::new(initial, 3);

    assert!(!ratchet.should_rotate());

    ratchet.ratchet();
    assert!(!ratchet.should_rotate());
    ratchet.ratchet();
    assert!(!ratchet.should_rotate());
    ratchet.ratchet();
    assert!(ratchet.should_rotate());
}

#[test]
fn test_ratchet_if_needed_auto_rotates() {
    let mut session = ForwardSecrecySession::new(2);
    let peer = ForwardSecrecySession::new(2);
    session.establish(peer.public_key()).unwrap();

    let key_initial = session.current_session_key().unwrap().bytes;

    session.force_ratchet();
    session.force_ratchet();

    let key_before_auto = session.current_session_key().unwrap().bytes;
    assert_ne!(key_initial, key_before_auto);

    let rotated = session.ratchet_if_needed();
    assert!(rotated);

    let key_after_auto = session.current_session_key().unwrap().bytes;
    assert_ne!(key_before_auto, key_after_auto);
}

#[test]
fn test_ratchet_if_needed_no_session() {
    let mut session = ForwardSecrecySession::new(5);
    let rotated = session.ratchet_if_needed();
    assert!(!rotated);
}

#[test]
fn test_message_count_tracks_ratchets() {
    let mut session = ForwardSecrecySession::new(100);
    let peer = ForwardSecrecySession::new(100);
    session.establish(peer.public_key()).unwrap();

    assert_eq!(session.message_count(), 0);

    session.force_ratchet();
    assert_eq!(session.message_count(), 1);

    session.force_ratchet();
    session.force_ratchet();
    assert_eq!(session.message_count(), 3);
}

#[test]
fn test_forward_secrecy_error_display() {
    assert_eq!(
        format!("{}", ForwardSecrecyError::NoKeyEstablished),
        "no-key-established"
    );
    assert_eq!(
        format!("{}", ForwardSecrecyError::KeyExchangeFailed),
        "key-exchange-failed"
    );
}

#[test]
fn test_shared_secret_debug_redacted() {
    let secret = SharedSecret([0xFF; 32]);
    let debug_str = format!("{:?}", secret);
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("255"));
}

#[test]
fn test_session_key_debug_redacted() {
    let key = SessionKey::from_bytes([0xAB; 32]);
    let debug_str = format!("{:?}", key);
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("171"));
}

#[test]
fn test_ephemeral_keypair_debug_redacts_private() {
    let pair = EphemeralKeyPair::generate();
    let debug_str = format!("{:?}", pair);
    assert!(debug_str.contains("REDACTED"));
    assert!(debug_str.contains("public_key"));
}

#[test]
fn test_destroy_previous_without_ratchet_is_safe() {
    let mut session = ForwardSecrecySession::new(10);
    let peer = ForwardSecrecySession::new(10);
    session.establish(peer.public_key()).unwrap();
    session.destroy_previous();
    assert!(session.current_session_key().is_some());
}

#[test]
fn test_multiple_ratchet_cycles_never_repeat() {
    let mut session = ForwardSecrecySession::new(1);
    let peer = ForwardSecrecySession::new(1);
    session.establish(peer.public_key()).unwrap();

    let mut seen_keys: Vec<[u8; 32]> = Vec::new();
    seen_keys.push(session.current_session_key().unwrap().bytes);

    for _ in 0..50 {
        session.force_ratchet();
        let key = session.current_session_key().unwrap().bytes;
        assert!(!seen_keys.contains(&key));
        seen_keys.push(key);
    }
}
