use aegis_proxy::{RecordedExchange, compare_responses};

use crate::widgets::diff_view::DiffView;

/// View state for the response comparer tab.
///
/// Holds optional left/right `RecordedExchange` values and a `DiffView`
/// populated by `compute_and_store_diff`. Call `compute_and_store_diff`
/// after setting both sides to update the diff widget.
pub struct ComparerView {
    pub diff_view: DiffView,
    left: Option<RecordedExchange>,
    right: Option<RecordedExchange>,
}

impl ComparerView {
    /// Creates a new comparer view with no exchanges loaded.
    pub fn new() -> Self {
        Self {
            diff_view: DiffView::new(),
            left: None,
            right: None,
        }
    }

    /// Stores a clone of the given exchange as the left (old) side.
    pub fn set_left(&mut self, exchange: &RecordedExchange) {
        self.left = Some(exchange.clone());
    }

    /// Stores a clone of the given exchange as the right (new) side.
    pub fn set_right(&mut self, exchange: &RecordedExchange) {
        self.right = Some(exchange.clone());
    }

    /// Returns `true` if the left side has been set.
    pub fn has_left(&self) -> bool {
        self.left.is_some()
    }

    /// Returns `true` if the right side has been set.
    pub fn has_right(&self) -> bool {
        self.right.is_some()
    }

    /// Returns `true` when both sides are populated and a diff can be computed.
    pub fn has_both_sides(&self) -> bool {
        self.left.is_some() && self.right.is_some()
    }

    /// Computes a diff between the two exchanges and stores it in `diff_view`.
    ///
    /// Does nothing when either side is absent.
    pub fn compute_and_store_diff(&mut self) {
        let (Some(left), Some(right)) = (&self.left, &self.right) else {
            return;
        };
        let diff = compare_responses(
            left.response_status,
            &left.response_headers,
            &left.response_body,
            left.duration_ms,
            right.response_status,
            &right.response_headers,
            &right.response_body,
            right.duration_ms,
        );
        self.diff_view.set_diff(diff);
    }

    /// Returns human-readable summary lines from the diff widget.
    ///
    /// Delegates to `DiffView::summary_lines`. Returns an empty `Vec` when
    /// no diff has been computed.
    pub fn summary(&self) -> Vec<String> {
        self.diff_view.summary_lines()
    }

    /// Clears the left exchange.
    pub fn clear_left(&mut self) {
        self.left = None;
    }

    /// Clears the right exchange.
    pub fn clear_right(&mut self) {
        self.right = None;
    }

    /// Returns a one-line description of the left exchange, or `None` if unset.
    ///
    /// Format: `"{method} {url} ({status})"`.
    pub fn left_info(&self) -> Option<String> {
        self.left.as_ref().map(exchange_info)
    }

    /// Returns a one-line description of the right exchange, or `None` if unset.
    ///
    /// Format: `"{method} {url} ({status})"`.
    pub fn right_info(&self) -> Option<String> {
        self.right.as_ref().map(exchange_info)
    }
}

impl Default for ComparerView {
    fn default() -> Self {
        Self::new()
    }
}

fn exchange_info(ex: &RecordedExchange) -> String {
    format!(
        "{} {} ({})",
        ex.request_method, ex.request_url, ex.response_status
    )
}

#[cfg(test)]
#[path = "comparer_test.rs"]
mod comparer_test;
