use aegis_proxy::{DiffChunk, DiffResult, HeaderDiff};

/// Which diff presentation mode to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    Line,
    Word,
    Hex,
}

/// Side-by-side diff widget state.
///
/// Holds a `DiffResult` from the proxy crate and provides rendered lines
/// for the left (old) and right (new) panes, plus a human-readable summary.
pub struct DiffView {
    pub mode: DiffMode,
    pub diff: Option<DiffResult>,
    pub scroll_offset: usize,
    /// When true, both panes scroll in lockstep.
    pub sync_scroll: bool,
}

impl DiffView {
    /// Creates a new `DiffView` with no diff loaded.
    pub fn new() -> Self {
        Self {
            mode: DiffMode::Line,
            diff: None,
            scroll_offset: 0,
            sync_scroll: true,
        }
    }

    /// Stores the given diff result, replacing any previous one.
    pub fn set_diff(&mut self, diff: DiffResult) {
        self.diff = Some(diff);
        self.scroll_offset = 0;
    }

    /// Clears the current diff and resets scroll position.
    pub fn clear(&mut self) {
        self.diff = None;
        self.scroll_offset = 0;
    }

    /// Cycles through `Line -> Word -> Hex -> Line`.
    pub fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            DiffMode::Line => DiffMode::Word,
            DiffMode::Word => DiffMode::Hex,
            DiffMode::Hex => DiffMode::Line,
        };
    }

    /// Returns true if the current diff contains any Added or Removed body chunks.
    pub fn has_changes(&self) -> bool {
        self.change_count() > 0
    }

    /// Counts Added and Removed chunks in the current body diff.
    pub fn change_count(&self) -> usize {
        let Some(diff) = &self.diff else {
            return 0;
        };
        diff.body_diff
            .iter()
            .filter(|c| matches!(c, DiffChunk::Added(_) | DiffChunk::Removed(_)))
            .count()
    }

    /// Returns a human-readable list of change summary lines.
    ///
    /// Includes status change, per-header diffs, body size delta, and timing delta.
    pub fn summary_lines(&self) -> Vec<String> {
        let Some(diff) = &self.diff else {
            return vec![];
        };
        let mut lines = Vec::new();
        if diff.status_changed {
            lines.push(format!(
                "Status: {} → {} (changed)",
                diff.old_status, diff.new_status
            ));
        } else {
            lines.push(format!("Status: {} (unchanged)", diff.old_status));
        }
        for hd in &diff.header_diffs {
            lines.push(render_header_diff(hd));
        }
        if diff.body_length_delta != 0 {
            let added = diff.body_length_delta.max(0);
            let removed = (-diff.body_length_delta).max(0);
            lines.push(format!("Body: +{}B / -{}B", added, removed));
        }
        if diff.duration_delta_ms != 0 {
            lines.push(format!("Timing: {}ms", diff.duration_delta_ms));
        }
        lines
    }

    /// Returns rendered lines for the left (old) pane.
    ///
    /// - `Equal` chunks appear as-is.
    /// - `Removed` chunks are prefixed with `"- "`.
    /// - `Added` chunks produce an empty placeholder to maintain alignment.
    pub fn left_lines(&self) -> Vec<String> {
        let Some(diff) = &self.diff else {
            return vec![];
        };
        diff.body_diff
            .iter()
            .map(|chunk| match chunk {
                DiffChunk::Equal(s) => s.clone(),
                DiffChunk::Removed(s) => format!("- {s}"),
                DiffChunk::Added(_) => String::new(),
            })
            .collect()
    }

    /// Returns rendered lines for the right (new) pane.
    ///
    /// - `Equal` chunks appear as-is.
    /// - `Added` chunks are prefixed with `"+ "`.
    /// - `Removed` chunks produce an empty placeholder to maintain alignment.
    pub fn right_lines(&self) -> Vec<String> {
        let Some(diff) = &self.diff else {
            return vec![];
        };
        diff.body_diff
            .iter()
            .map(|chunk| match chunk {
                DiffChunk::Equal(s) => s.clone(),
                DiffChunk::Added(s) => format!("+ {s}"),
                DiffChunk::Removed(_) => String::new(),
            })
            .collect()
    }

    /// Scrolls both panes down by `count` lines.
    pub fn scroll_down(&mut self, count: usize) {
        self.scroll_offset = self.scroll_offset.saturating_add(count);
    }

    /// Scrolls both panes up by `count` lines, clamping at zero.
    pub fn scroll_up(&mut self, count: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(count);
    }
}

impl Default for DiffView {
    fn default() -> Self {
        Self::new()
    }
}

fn render_header_diff(hd: &HeaderDiff) -> String {
    match hd {
        HeaderDiff::Added(name, value) => format!("+ {name}: {value}"),
        HeaderDiff::Removed(name, value) => format!("- {name}: {value}"),
        HeaderDiff::Changed(name, old, new) => format!("~ {name}: {old} → {new}"),
    }
}

#[cfg(test)]
#[path = "diff_view_test.rs"]
mod diff_view_test;
