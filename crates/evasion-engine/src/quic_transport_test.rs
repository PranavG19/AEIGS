use super::quic_transport::*;

#[test]
fn connect_transitions_to_connected() {
    let mut transport = QuicTransport::with_defaults();
    let state = transport.connect().unwrap();
    assert_eq!(state, QuicConnectionState::Connected);
}

#[test]
fn zero_rtt_with_session_ticket() {
    let mut transport = QuicTransport::with_defaults();
    transport.store_session_ticket(SessionTicket {
        server_name: "localhost".to_string(),
        ticket_data: vec![1, 2, 3],
        obtained_at_ms: 1000,
        max_early_data_size: 16384,
        alpn_protocol: "h3".to_string(),
    });
    let state = transport.connect().unwrap();
    assert_eq!(state, QuicConnectionState::ZeroRttEstablished);
    assert!(transport.stats().zero_rtt_accepted);
}

#[test]
fn zero_rtt_disabled_ignores_ticket() {
    let config = QuicTransportConfig {
        enable_0rtt: false,
        ..Default::default()
    };
    let mut transport = QuicTransport::new(config);
    transport.store_session_ticket(SessionTicket {
        server_name: "localhost".to_string(),
        ticket_data: vec![1, 2, 3],
        obtained_at_ms: 1000,
        max_early_data_size: 16384,
        alpn_protocol: "h3".to_string(),
    });
    let state = transport.connect().unwrap();
    assert_eq!(state, QuicConnectionState::Connected);
    assert!(!transport.stats().zero_rtt_accepted);
}

#[test]
fn open_stream_returns_stream_id() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    let id = transport.open_stream().unwrap();
    assert_eq!(id, 0);
    let id2 = transport.open_stream().unwrap();
    assert_eq!(id2, 4);
}

#[test]
fn open_stream_fails_when_not_connected() {
    let mut transport = QuicTransport::with_defaults();
    assert!(transport.open_stream().is_err());
}

#[test]
fn stream_limit_enforced() {
    let config = QuicTransportConfig {
        max_concurrent_streams: 2,
        ..Default::default()
    };
    let mut transport = QuicTransport::new(config);
    transport.connect().unwrap();
    transport.open_stream().unwrap();
    transport.open_stream().unwrap();
    assert!(transport.open_stream().is_err());
}

#[test]
fn send_data_on_stream() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    let id = transport.open_stream().unwrap();
    transport.send(id, b"hello world").unwrap();
    assert_eq!(transport.stats().bytes_sent, 11);
}

#[test]
fn send_on_unknown_stream_fails() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    assert!(transport.send(999, b"data").is_err());
}

#[test]
fn send_on_closed_stream_fails() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    let id = transport.open_stream().unwrap();
    transport.close_stream(id).unwrap();
    assert!(transport.send(id, b"data").is_err());
}

#[test]
fn receive_tracks_bytes() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    let id = transport.open_stream().unwrap();
    transport.receive(id, 1024).unwrap();
    assert_eq!(transport.stats().bytes_received, 1024);
}

#[test]
fn close_stream_updates_stats() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    let id = transport.open_stream().unwrap();
    assert_eq!(transport.active_stream_count(), 1);
    transport.close_stream(id).unwrap();
    assert_eq!(transport.active_stream_count(), 0);
    assert_eq!(transport.stats().streams_closed, 1);
}

#[test]
fn close_connection_closes_all_streams() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    transport.open_stream().unwrap();
    transport.open_stream().unwrap();
    assert_eq!(transport.active_stream_count(), 2);
    transport.close().unwrap();
    assert_eq!(transport.connection_state(), QuicConnectionState::Closed);
    assert_eq!(transport.active_stream_count(), 0);
}

#[test]
fn double_close_is_ok() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    transport.close().unwrap();
    assert!(transport.close().is_ok());
}

#[test]
fn remote_addr_parses_correctly() {
    let transport = QuicTransport::with_defaults();
    let addr = transport.remote_addr().unwrap();
    assert_eq!(addr.port(), 443);
}

#[test]
fn uni_stream_opens_successfully() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    let id = transport.open_uni_stream().unwrap();
    transport.send(id, b"data").unwrap();
    assert_eq!(transport.stats().bytes_sent, 4);
}

#[test]
fn connect_from_closed_state_works() {
    let mut transport = QuicTransport::with_defaults();
    transport.connect().unwrap();
    transport.close().unwrap();
    let state = transport.connect().unwrap();
    assert_eq!(state, QuicConnectionState::Connected);
}

#[test]
fn handshake_duration_is_zero_for_0rtt() {
    let mut transport = QuicTransport::with_defaults();
    transport.store_session_ticket(SessionTicket {
        server_name: "localhost".to_string(),
        ticket_data: vec![1],
        obtained_at_ms: 0,
        max_early_data_size: 4096,
        alpn_protocol: "h3".to_string(),
    });
    transport.connect().unwrap();
    assert_eq!(transport.stats().handshake_duration_ms, 0);
}
