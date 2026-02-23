/// Proxy running state for the status bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStatus {
    Running,
    Stopped,
}

/// Data driving the status bar display.
#[derive(Debug, Clone)]
pub struct StatusBarState {
    pub proxy_status: ProxyStatus,
    pub listen_addr: String,
    pub exchange_count: u64,
    pub scope_enabled: bool,
    pub in_scope_count: u64,
    pub filter_active: bool,
    pub filter_text: Option<String>,
}

impl StatusBarState {
    /// Create a new `StatusBarState` with the given listen address and all other
    /// fields at their default (stopped, no exchanges, scope/filter off).
    pub fn new(listen_addr: String) -> Self {
        Self {
            proxy_status: ProxyStatus::Stopped,
            listen_addr,
            exchange_count: 0,
            scope_enabled: false,
            in_scope_count: 0,
            filter_active: false,
            filter_text: None,
        }
    }

    /// Build the status line string for display.
    ///
    /// Format: `[RUNNING|STOPPED] <addr> | N request[s][Scope: ON (N in-scope)][Filter: <text>|active]`
    pub fn status_line(&self) -> String {
        let prefix = match self.proxy_status {
            ProxyStatus::Running => "[RUNNING]",
            ProxyStatus::Stopped => "[STOPPED]",
        };

        let request_word = if self.exchange_count == 1 {
            "request"
        } else {
            "requests"
        };
        let mut line = format!(
            "{} {} | {} {}",
            prefix, self.listen_addr, self.exchange_count, request_word
        );

        if self.scope_enabled {
            line.push_str(&format!(" | Scope: ON ({} in-scope)", self.in_scope_count));
        }

        if self.filter_active {
            let label = self.filter_text.as_deref().unwrap_or("active");
            line.push_str(&format!(" | Filter: {}", label));
        }

        line
    }
}

#[cfg(test)]
#[path = "status_bar_test.rs"]
mod status_bar_test;
