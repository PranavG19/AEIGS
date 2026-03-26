use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::state::AppState;

/// Events sent over the SSE stream to update the browser graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GraphEvent {
    NodeAdded {
        id: String,
        node_type: String,
        label: String,
        severity: Option<String>,
        data: serde_json::Value,
    },
    EdgeAdded {
        source: String,
        target: String,
        label: String,
    },
    NodeUpdated {
        id: String,
        status: String,
        confidence: Option<f64>,
    },
    FindingConfirmed {
        node_id: String,
        vuln_class: String,
        severity: String,
        evidence_preview: String,
    },
    PhaseChanged {
        phase: String,
        progress_pct: f64,
    },
    ScanComplete {
        total_findings: u64,
        risk_score: f64,
        duration_ms: u64,
    },
    LogMessage {
        level: String,
        message: String,
    },
}

/// SSE endpoint handler — sends the full current state as a burst, then streams
/// live updates from the broadcast channel.
pub async fn sse_graph_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let existing_events = {
        let graph = state.graph.read();
        graph.events.clone()
    };

    let stream = GraphEventStream {
        replay: existing_events,
        replay_idx: 0,
        rx,
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

struct GraphEventStream {
    replay: Vec<GraphEvent>,
    replay_idx: usize,
    rx: tokio::sync::broadcast::Receiver<GraphEvent>,
}

impl Stream for GraphEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First replay existing events so a late-joining browser gets full state
        if self.replay_idx < self.replay.len() {
            let event = self.replay[self.replay_idx].clone();
            self.replay_idx += 1;
            let json = serde_json::to_string(&event).unwrap_or_default();
            return Poll::Ready(Some(Ok(Event::default().data(json))));
        }

        // Then stream live events from broadcast
        match self.rx.try_recv() {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                Poll::Ready(Some(Ok(Event::default().data(json))))
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                tracing::warn!("SSE client lagged behind by {} events", n);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
#[path = "graph_api_test.rs"]
mod graph_api_test;
