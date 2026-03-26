use std::collections::HashMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// QUIC transport layer for evasion traffic.
///
/// Wraps a QUIC connection providing stream multiplexing and 0-RTT resumption
/// capabilities. Many WAFs and IDS systems have limited QUIC inspection,
/// making it an effective evasion transport.

/// QUIC connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuicConnectionState {
    Idle,
    Connecting,
    Connected,
    ZeroRttAttempt,
    ZeroRttEstablished,
    Draining,
    Closed,
    Failed,
}

impl std::fmt::Display for QuicConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::ZeroRttAttempt => write!(f, "0-rtt-attempt"),
            Self::ZeroRttEstablished => write!(f, "0-rtt-established"),
            Self::Draining => write!(f, "draining"),
            Self::Closed => write!(f, "closed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Configuration for a QUIC transport connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicTransportConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub server_name: String,
    pub enable_0rtt: bool,
    pub max_concurrent_streams: u32,
    pub idle_timeout_ms: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub keep_alive_interval_ms: Option<u64>,
    pub alpn_protocols: Vec<String>,
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1".to_string(),
            server_port: 443,
            server_name: "localhost".to_string(),
            enable_0rtt: true,
            max_concurrent_streams: 100,
            idle_timeout_ms: 30_000,
            initial_max_data: 10_485_760,
            initial_max_stream_data: 1_048_576,
            keep_alive_interval_ms: Some(15_000),
            alpn_protocols: vec!["h3".to_string()],
        }
    }
}

/// Represents a single QUIC stream within a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicStream {
    pub stream_id: u64,
    pub direction: StreamDirection,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub state: StreamState,
}

/// Direction of a QUIC stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamDirection {
    Bidirectional,
    UnidirectionalSend,
    UnidirectionalRecv,
}

/// State of an individual stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamState {
    Open,
    HalfClosed,
    Closed,
    Reset,
}

/// Cached session ticket for 0-RTT resumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicket {
    pub server_name: String,
    pub ticket_data: Vec<u8>,
    pub obtained_at_ms: u64,
    pub max_early_data_size: u64,
    pub alpn_protocol: String,
}

/// QUIC connection statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuicStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub zero_rtt_accepted: bool,
    pub handshake_duration_ms: u64,
    pub rtt_ms: u64,
    pub congestion_events: u64,
    pub packets_lost: u64,
}

/// Simulated QUIC transport manager for evasion operations.
///
/// In production, this would wrap the `quinn` crate. For testing and planning,
/// it maintains connection state and stream tracking without actual network I/O.
pub struct QuicTransport {
    config: QuicTransportConfig,
    state: QuicConnectionState,
    streams: HashMap<u64, QuicStream>,
    next_stream_id: u64,
    session_tickets: HashMap<String, SessionTicket>,
    stats: QuicStats,
}

impl QuicTransport {
    pub fn new(config: QuicTransportConfig) -> Self {
        Self {
            config,
            state: QuicConnectionState::Idle,
            streams: HashMap::new(),
            next_stream_id: 0,
            session_tickets: HashMap::new(),
            stats: QuicStats::default(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(QuicTransportConfig::default())
    }

    /// Initiate a QUIC connection. If a session ticket exists and 0-RTT is enabled,
    /// attempts 0-RTT resumption.
    pub fn connect(&mut self) -> Result<QuicConnectionState, QuicTransportError> {
        if self.state != QuicConnectionState::Idle && self.state != QuicConnectionState::Closed {
            return Err(QuicTransportError::InvalidState(self.state));
        }

        if self.config.enable_0rtt {
            if let Some(_ticket) = self.session_tickets.get(&self.config.server_name) {
                self.state = QuicConnectionState::ZeroRttAttempt;
                self.state = QuicConnectionState::ZeroRttEstablished;
                self.stats.zero_rtt_accepted = true;
                self.stats.handshake_duration_ms = 0;
                return Ok(self.state);
            }
        }

        self.state = QuicConnectionState::Connecting;
        self.state = QuicConnectionState::Connected;
        self.stats.handshake_duration_ms = 50;
        Ok(self.state)
    }

    /// Open a new bidirectional stream on the connection.
    pub fn open_stream(&mut self) -> Result<u64, QuicTransportError> {
        self.require_connected()?;

        if self.streams.len() as u32 >= self.config.max_concurrent_streams {
            return Err(QuicTransportError::StreamLimitReached);
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 4;

        self.streams.insert(
            stream_id,
            QuicStream {
                stream_id,
                direction: StreamDirection::Bidirectional,
                bytes_sent: 0,
                bytes_received: 0,
                state: StreamState::Open,
            },
        );

        self.stats.streams_opened += 1;
        Ok(stream_id)
    }

    /// Open a unidirectional send stream.
    pub fn open_uni_stream(&mut self) -> Result<u64, QuicTransportError> {
        self.require_connected()?;

        if self.streams.len() as u32 >= self.config.max_concurrent_streams {
            return Err(QuicTransportError::StreamLimitReached);
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 4;

        self.streams.insert(
            stream_id,
            QuicStream {
                stream_id,
                direction: StreamDirection::UnidirectionalSend,
                bytes_sent: 0,
                bytes_received: 0,
                state: StreamState::Open,
            },
        );

        self.stats.streams_opened += 1;
        Ok(stream_id)
    }

    /// Send data on a stream.
    pub fn send(&mut self, stream_id: u64, data: &[u8]) -> Result<(), QuicTransportError> {
        self.require_connected()?;

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(QuicTransportError::UnknownStream(stream_id))?;

        if stream.state != StreamState::Open {
            return Err(QuicTransportError::StreamClosed(stream_id));
        }

        stream.bytes_sent += data.len() as u64;
        self.stats.bytes_sent += data.len() as u64;
        Ok(())
    }

    /// Simulate receiving data on a stream.
    pub fn receive(&mut self, stream_id: u64, bytes: u64) -> Result<(), QuicTransportError> {
        self.require_connected()?;

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(QuicTransportError::UnknownStream(stream_id))?;

        stream.bytes_received += bytes;
        self.stats.bytes_received += bytes;
        Ok(())
    }

    /// Close a specific stream.
    pub fn close_stream(&mut self, stream_id: u64) -> Result<(), QuicTransportError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(QuicTransportError::UnknownStream(stream_id))?;

        stream.state = StreamState::Closed;
        self.stats.streams_closed += 1;
        Ok(())
    }

    /// Store a session ticket for future 0-RTT connections.
    pub fn store_session_ticket(&mut self, ticket: SessionTicket) {
        self.session_tickets
            .insert(ticket.server_name.clone(), ticket);
    }

    /// Close the QUIC connection gracefully.
    pub fn close(&mut self) -> Result<(), QuicTransportError> {
        if self.state == QuicConnectionState::Closed || self.state == QuicConnectionState::Idle {
            return Ok(());
        }
        self.state = QuicConnectionState::Draining;
        for stream in self.streams.values_mut() {
            stream.state = StreamState::Closed;
        }
        self.state = QuicConnectionState::Closed;
        Ok(())
    }

    /// Current connection state.
    pub fn connection_state(&self) -> QuicConnectionState {
        self.state
    }

    /// Number of active (open) streams.
    pub fn active_stream_count(&self) -> usize {
        self.streams
            .values()
            .filter(|s| s.state == StreamState::Open)
            .count()
    }

    /// Connection statistics.
    pub fn stats(&self) -> &QuicStats {
        &self.stats
    }

    /// Target socket address.
    pub fn remote_addr(&self) -> Result<SocketAddr, QuicTransportError> {
        let addr: SocketAddr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse()
            .map_err(|_| QuicTransportError::InvalidAddress(self.config.server_addr.clone()))?;
        Ok(addr)
    }

    fn require_connected(&self) -> Result<(), QuicTransportError> {
        match self.state {
            QuicConnectionState::Connected | QuicConnectionState::ZeroRttEstablished => Ok(()),
            _ => Err(QuicTransportError::NotConnected),
        }
    }
}

/// Errors from QUIC transport operations.
#[derive(Debug)]
pub enum QuicTransportError {
    NotConnected,
    InvalidState(QuicConnectionState),
    StreamLimitReached,
    UnknownStream(u64),
    StreamClosed(u64),
    InvalidAddress(String),
    ConnectionLost,
}

impl std::fmt::Display for QuicTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "not connected"),
            Self::InvalidState(s) => write!(f, "invalid connection state: {s}"),
            Self::StreamLimitReached => write!(f, "maximum concurrent streams reached"),
            Self::UnknownStream(id) => write!(f, "unknown stream id: {id}"),
            Self::StreamClosed(id) => write!(f, "stream {id} is closed"),
            Self::InvalidAddress(a) => write!(f, "invalid address: {a}"),
            Self::ConnectionLost => write!(f, "connection lost"),
        }
    }
}

impl std::error::Error for QuicTransportError {}
