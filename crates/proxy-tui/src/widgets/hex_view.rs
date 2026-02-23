/// The three rendering modes for body content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyViewMode {
    /// Lossy UTF-8 text rendering.
    Raw,
    /// Classic 16-bytes-per-line hexdump.
    Hex,
    /// Pretty-printed JSON; falls back to Raw if the body is not valid JSON.
    Pretty,
}

/// Widget that renders raw HTTP body bytes in one of three modes.
pub struct HexView {
    /// The raw bytes to display.
    pub body: Vec<u8>,
    /// Active rendering mode.
    pub mode: BodyViewMode,
    /// Line offset for vertical scrolling.
    pub scroll_offset: usize,
}

impl HexView {
    /// Create a new `HexView` in `Raw` mode with zero scroll offset.
    pub fn new(body: Vec<u8>) -> Self {
        Self {
            body,
            mode: BodyViewMode::Raw,
            scroll_offset: 0,
        }
    }

    /// Replace the body bytes and reset scroll position to zero.
    pub fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
        self.scroll_offset = 0;
    }

    /// Cycle through modes: Raw → Hex → Pretty → Raw.
    pub fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            BodyViewMode::Raw => BodyViewMode::Hex,
            BodyViewMode::Hex => BodyViewMode::Pretty,
            BodyViewMode::Pretty => BodyViewMode::Raw,
        };
    }

    /// Return all rendered lines for the current mode.
    pub fn lines(&self) -> Vec<String> {
        match self.mode {
            BodyViewMode::Raw => raw_lines(&self.body),
            BodyViewMode::Hex => hex_lines(&self.body),
            BodyViewMode::Pretty => pretty_lines(&self.body),
        }
    }

    /// Advance the scroll offset by `count` lines (clamped to the total line count).
    pub fn scroll_down(&mut self, count: usize) {
        let total = self.lines().len();
        self.scroll_offset = (self.scroll_offset + count).min(total.saturating_sub(1));
    }

    /// Decrease the scroll offset by `count` lines (clamped at zero).
    pub fn scroll_up(&mut self, count: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(count);
    }

    /// Return up to `height` rendered lines starting at `scroll_offset`.
    pub fn visible_lines(&self, height: usize) -> Vec<String> {
        let all = self.lines();
        let start = self.scroll_offset.min(all.len());
        all[start..].iter().take(height).cloned().collect()
    }
}

fn raw_lines(body: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(body)
        .split('\n')
        .map(str::to_owned)
        .collect()
}

fn hex_lines(body: &[u8]) -> Vec<String> {
    body.chunks(16)
        .enumerate()
        .map(|(chunk_idx, chunk)| format_hex_line(chunk_idx * 16, chunk))
        .collect()
}

fn format_hex_line(address: usize, chunk: &[u8]) -> String {
    let mut hex_left = String::new();
    let mut hex_right = String::new();

    for (i, byte) in chunk.iter().enumerate() {
        let target = if i < 8 { &mut hex_left } else { &mut hex_right };
        if !target.is_empty() {
            target.push(' ');
        }
        target.push_str(&format!("{byte:02x}"));
    }

    let hex_section_width = 49;
    let combined = format!("{hex_left}  {hex_right}");
    let padded = format!("{combined:<hex_section_width$}");

    let ascii: String = chunk
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    format!("{address:08x}  {padded} |{ascii}|")
}

fn pretty_lines(body: &[u8]) -> Vec<String> {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body)
        && let Ok(pretty) = serde_json::to_string_pretty(&value)
    {
        return pretty.split('\n').map(str::to_owned).collect();
    }
    raw_lines(body)
}

#[cfg(test)]
#[path = "hex_view_test.rs"]
mod hex_view_test;
