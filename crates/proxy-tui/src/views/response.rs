use crate::widgets::hex_view::{BodyViewMode, HexView};

/// View state for a single HTTP response, including headers and body rendering.
pub struct ResponseView {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub duration_ms: u64,
    pub hex_view: HexView,
}

impl ResponseView {
    pub fn new() -> Self {
        Self {
            status_code: 0,
            headers: Vec::new(),
            duration_ms: 0,
            hex_view: HexView::new(Vec::new()),
        }
    }

    pub fn load_response(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        duration_ms: u64,
    ) {
        self.status_code = status;
        self.headers = headers;
        self.duration_ms = duration_ms;
        self.hex_view.set_body(body);
    }

    pub fn clear(&mut self) {
        self.status_code = 0;
        self.headers.clear();
        self.duration_ms = 0;
        self.hex_view.set_body(Vec::new());
    }

    pub fn toggle_mode(&mut self) {
        self.hex_view.toggle_mode();
    }

    pub fn mode(&self) -> BodyViewMode {
        self.hex_view.mode
    }

    /// Returns the status line followed by one line per header.
    pub fn header_lines(&self) -> Vec<String> {
        let reason = status_reason(self.status_code);
        let mut lines = Vec::with_capacity(1 + self.headers.len());
        lines.push(format!("HTTP/1.1 {} {}", self.status_code, reason));
        for (name, value) in &self.headers {
            lines.push(format!("{name}: {value}"));
        }
        lines
    }

    pub fn body_lines(&self) -> Vec<String> {
        self.hex_view.lines()
    }

    pub fn status_summary(&self) -> String {
        format!("{} ({}ms)", self.status_code, self.duration_ms)
    }

    pub fn body_length(&self) -> usize {
        self.hex_view.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.status_code == 0
    }
}

impl Default for ResponseView {
    fn default() -> Self {
        Self::new()
    }
}

fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
#[path = "response_test.rs"]
mod response_test;
