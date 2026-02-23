use aegis_proxy::{ModifiedRequest, RecordedExchange};

use crate::keybinds::Action;

/// Which field in the request editor currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorField {
    Method,
    Url,
    Headers,
    Body,
}

/// Events produced by the request editor in response to user actions.
#[derive(Debug, Clone)]
pub enum RequestEditorEvent {
    SendRequest(ModifiedRequest),
    /// The formatted curl command string for clipboard copy.
    CopyAsCurl(String),
    None,
}

/// View state for the HTTP request editor panel.
pub struct RequestEditorView {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub focused_field: EditorField,
}

impl RequestEditorView {
    pub fn new() -> Self {
        Self {
            method: "GET".to_string(),
            url: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            focused_field: EditorField::Method,
        }
    }

    pub fn load_request(&mut self, req: ModifiedRequest) {
        self.method = req.method;
        self.url = req.url;
        self.headers = req.headers;
        self.body = req.body;
    }

    pub fn load_exchange(&mut self, exchange: &RecordedExchange) {
        self.method = exchange.request_method.clone();
        self.url = exchange.request_url.clone();
        self.headers = exchange.request_headers.clone();
        self.body = exchange.request_body.clone();
    }

    pub fn current_request(&self) -> ModifiedRequest {
        ModifiedRequest {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }

    /// Format the current request as a curl command.
    ///
    /// Format: `curl -X {METHOD} '{url}' [-H 'name: value']... [-d '{body}']`
    /// The body part is omitted when empty.
    pub fn as_curl(&self) -> String {
        let mut parts = vec![format!("curl -X {} '{}'", self.method, self.url)];
        for (name, value) in &self.headers {
            parts.push(format!("-H '{}: {}'", name, value));
        }
        if !self.body.is_empty() {
            let body_str = String::from_utf8_lossy(&self.body);
            parts.push(format!("-d '{}'", body_str));
        }
        parts.join(" ")
    }

    pub fn handle_action(&mut self, action: Action) -> RequestEditorEvent {
        match action {
            Action::Enter => RequestEditorEvent::SendRequest(self.current_request()),
            Action::NavLeft | Action::NavRight => {
                self.cycle_field();
                RequestEditorEvent::None
            }
            Action::Save => RequestEditorEvent::CopyAsCurl(self.as_curl()),
            _ => RequestEditorEvent::None,
        }
    }

    /// Advance focus through Method → Url → Headers → Body → Method.
    pub fn cycle_field(&mut self) {
        self.focused_field = match self.focused_field {
            EditorField::Method => EditorField::Url,
            EditorField::Url => EditorField::Headers,
            EditorField::Headers => EditorField::Body,
            EditorField::Body => EditorField::Method,
        };
    }
}

impl Default for RequestEditorView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "request_editor_test.rs"]
mod request_editor_test;
