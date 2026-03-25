use std::collections::HashMap;

/// Manages browser session state including cookies, request history, and Referer headers.
///
/// Automatically rotates sessions after `max_requests_per_session` requests,
/// clearing cookies and history to simulate a fresh browsing session.
/// Processes Set-Cookie response headers and injects Cookie/Referer request headers.
#[derive(Debug, Clone)]
pub struct SessionManager {
    cookies: HashMap<String, String>,
    request_history: Vec<String>,
    session_id: u64,
    requests_in_session: u32,
    max_requests_per_session: u32,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(50)
    }
}

impl SessionManager {
    pub fn new(max_requests_per_session: u32) -> Self {
        Self {
            cookies: HashMap::new(),
            request_history: Vec::new(),
            session_id: 0,
            requests_in_session: 0,
            max_requests_per_session,
        }
    }

    pub fn session_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if !self.cookies.is_empty() {
            let cookie_value: String = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            headers.push(("Cookie".to_string(), cookie_value));
        }
        if let Some(url) = self.request_history.last() {
            headers.push(("Referer".to_string(), url.clone()));
        }
        headers
    }

    pub fn record_request(&mut self, url: &str) {
        self.request_history.push(url.to_string());
        self.requests_in_session += 1;
        if self.requests_in_session >= self.max_requests_per_session {
            self.rotate_session();
        }
    }

    pub fn process_set_cookie(&mut self, set_cookie_value: &str) {
        let kv_part = set_cookie_value.split(';').next().unwrap_or("");
        if let Some((name, value)) = kv_part.split_once('=') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if !name.is_empty() {
                self.cookies.insert(name, value);
            }
        }
    }

    pub fn rotate_session(&mut self) {
        self.cookies.clear();
        self.request_history.clear();
        self.session_id += 1;
        self.requests_in_session = 0;
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn requests_in_session(&self) -> u32 {
        self.requests_in_session
    }

    pub fn last_url(&self) -> Option<&str> {
        self.request_history.last().map(|s| s.as_str())
    }
}

#[cfg(test)]
#[path = "session_manager_test.rs"]
mod session_manager_test;
