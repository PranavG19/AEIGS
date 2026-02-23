use aegis_proxy::{ModifiedRequest, RecordedExchange, compare_responses};

use crate::keybinds::Action;
use crate::widgets::diff_view::DiffView;

#[derive(Debug, Clone)]
struct HistoryEntry {
    request: ModifiedRequest,
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    duration_ms: u64,
}

/// Events emitted by `RepeaterView` in response to user actions.
#[derive(Debug, Clone)]
pub enum RepeaterEvent {
    SendRequest(ModifiedRequest),
    None,
}

/// View state for the request repeater tab.
///
/// Maintains an ordered history of sent requests and their responses,
/// supports navigation through that history, and provides diff computation
/// between the original loaded exchange and subsequent responses.
pub struct RepeaterView {
    pub current_request: ModifiedRequest,
    history: Vec<HistoryEntry>,
    /// Current position in history: 0 = most recent, higher = older.
    pub history_index: usize,
    pub diff_view: DiffView,
    pub show_diff: bool,
    original: Option<HistoryEntry>,
}

impl RepeaterView {
    pub fn new() -> Self {
        Self {
            current_request: ModifiedRequest {
                method: String::new(),
                url: String::new(),
                headers: vec![],
                body: vec![],
            },
            history: vec![],
            history_index: 0,
            diff_view: DiffView::new(),
            show_diff: false,
            original: None,
        }
    }

    /// Populates `current_request` from the exchange and stores a baseline for diffing.
    pub fn load_exchange(&mut self, exchange: &RecordedExchange) {
        self.current_request = ModifiedRequest::from_exchange(exchange);
        self.original = Some(HistoryEntry {
            request: self.current_request.clone(),
            status_code: exchange.response_status,
            headers: exchange.response_headers.clone(),
            body: exchange.response_body.clone(),
            duration_ms: exchange.duration_ms,
        });
    }

    /// Records the response for the current request, prepending to history.
    ///
    /// Resets `history_index` to 0 (most recent) after each append.
    pub fn record_response(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        duration_ms: u64,
    ) {
        let entry = HistoryEntry {
            request: self.current_request.clone(),
            status_code: status,
            headers,
            body,
            duration_ms,
        };
        self.history.insert(0, entry);
        self.history_index = 0;
    }

    /// Moves through history. `delta=-1` goes further back (older); `delta=+1` goes forward (newer).
    ///
    /// Clamps `history_index` to `[0, history.len() - 1]` and updates `current_request`.
    pub fn navigate_history(&mut self, delta: i32) {
        if self.history.is_empty() {
            return;
        }
        let max = self.history.len().saturating_sub(1);
        let new_index = (self.history_index as i64 - delta as i64).clamp(0, max as i64) as usize;
        self.history_index = new_index;
        self.current_request = self.history[new_index].request.clone();
    }

    /// Diffs the original loaded exchange against the most recent history entry.
    ///
    /// Sets `show_diff = true` when both an original and at least one history entry exist.
    pub fn diff_with_original(&mut self) {
        let Some(orig) = &self.original else { return };
        let Some(latest) = self.history.first() else {
            return;
        };
        let diff = compare_responses(
            orig.status_code,
            &orig.headers,
            &orig.body,
            orig.duration_ms,
            latest.status_code,
            &latest.headers,
            &latest.body,
            latest.duration_ms,
        );
        self.diff_view.set_diff(diff);
        self.show_diff = true;
    }

    /// Diffs the most recent history entry against the one before it.
    ///
    /// Sets `show_diff = true` when at least two history entries exist.
    pub fn diff_current_vs_previous(&mut self) {
        if self.history.len() < 2 {
            return;
        }
        let current = &self.history[0];
        let previous = &self.history[1];
        let diff = compare_responses(
            previous.status_code,
            &previous.headers,
            &previous.body,
            previous.duration_ms,
            current.status_code,
            &current.headers,
            &current.body,
            current.duration_ms,
        );
        self.diff_view.set_diff(diff);
        self.show_diff = true;
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Dispatches a user action and returns the resulting `RepeaterEvent`.
    pub fn handle_action(&mut self, action: Action) -> RepeaterEvent {
        match action {
            Action::Enter => RepeaterEvent::SendRequest(self.current_request.clone()),
            Action::NavLeft => {
                self.navigate_history(-1);
                RepeaterEvent::None
            }
            Action::NavRight => {
                self.navigate_history(1);
                RepeaterEvent::None
            }
            _ => RepeaterEvent::None,
        }
    }

    /// Returns the status code of the most recent history entry, if any.
    pub fn current_status(&self) -> Option<u16> {
        self.history.first().map(|e| e.status_code)
    }
}

impl Default for RepeaterView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "repeater_test.rs"]
mod repeater_test;
