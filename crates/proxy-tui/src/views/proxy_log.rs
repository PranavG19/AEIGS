use aegis_proxy::RecordedExchange;

use crate::keybinds::Action;
use crate::widgets::table::{ColumnDef, TableWidget};

/// Events emitted by the proxy log view to the caller.
#[derive(Debug, Clone)]
pub enum ProxyLogEvent {
    SendToRepeater(RecordedExchange),
    SendToIntruder(RecordedExchange),
    Save(RecordedExchange),
    None,
}

/// Which sub-pane of the proxy log view has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyLogFocus {
    List,
    Request,
    Response,
}

/// View state for the Proxy Log tab.
///
/// Owns the exchange list and a `TableWidget` that presents a filtered,
/// sorted view of the list. `selected_exchange()` resolves the table
/// selection back to the original `RecordedExchange` via the id stored in
/// column 0.
pub struct ProxyLogView {
    pub table: TableWidget,
    exchanges: Vec<RecordedExchange>,
    pub focus: ProxyLogFocus,
}

fn build_columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            title: "#".into(),
            width: 6,
            sortable: false,
        },
        ColumnDef {
            title: "Method".into(),
            width: 8,
            sortable: true,
        },
        ColumnDef {
            title: "URL".into(),
            width: 50,
            sortable: true,
        },
        ColumnDef {
            title: "Status".into(),
            width: 8,
            sortable: true,
        },
        ColumnDef {
            title: "Length".into(),
            width: 10,
            sortable: true,
        },
        ColumnDef {
            title: "Time".into(),
            width: 8,
            sortable: true,
        },
        ColumnDef {
            title: "Tags".into(),
            width: 20,
            sortable: false,
        },
    ]
}

fn exchange_to_row(ex: &RecordedExchange) -> Vec<String> {
    let url = if ex.request_url.len() > 40 {
        ex.request_url[..40].to_string()
    } else {
        ex.request_url.clone()
    };
    vec![
        ex.id.to_string(),
        ex.request_method.clone(),
        url,
        ex.response_status.to_string(),
        ex.response_body.len().to_string(),
        ex.duration_ms.to_string(),
        ex.tags.join(", "),
    ]
}

impl ProxyLogView {
    /// Create a new view with an empty exchange list.
    pub fn new() -> Self {
        Self {
            table: TableWidget::new(build_columns()),
            exchanges: Vec::new(),
            focus: ProxyLogFocus::List,
        }
    }

    /// Replace the exchange list and rebuild table rows.
    pub fn load_exchanges(&mut self, exchanges: Vec<RecordedExchange>) {
        let rows = exchanges.iter().map(exchange_to_row).collect();
        self.exchanges = exchanges;
        self.table.set_rows(rows);
    }

    /// Delegate filter control to the underlying table widget.
    pub fn apply_filter(&mut self, pattern: Option<String>) {
        self.table.set_filter(pattern);
    }

    /// Return the exchange corresponding to the current table selection.
    ///
    /// Resolves via the id stored in column 0 of the selected row. Returns
    /// `None` when the table is empty or the id cannot be matched.
    pub fn selected_exchange(&self) -> Option<&RecordedExchange> {
        let row = self.table.selected_row()?;
        let id: u64 = row.first()?.parse().ok()?;
        self.exchanges.iter().find(|ex| ex.id == id)
    }

    /// Return the total number of loaded exchanges (unfiltered).
    pub fn exchange_count(&self) -> usize {
        self.exchanges.len()
    }

    /// Handle an application action and return any resulting event.
    ///
    /// Navigation actions update the table selection. Exchange-sending actions
    /// clone and return the selected exchange. `Search` toggles the filter.
    /// `Tab`/`NavRight` cycle focus between panes. All other actions return
    /// `ProxyLogEvent::None`.
    pub fn handle_action(&mut self, action: Action) -> ProxyLogEvent {
        match action {
            Action::NavUp => {
                self.table.select_prev();
                ProxyLogEvent::None
            }
            Action::NavDown => {
                self.table.select_next();
                ProxyLogEvent::None
            }
            Action::SendToRepeater => self
                .selected_exchange()
                .cloned()
                .map(ProxyLogEvent::SendToRepeater)
                .unwrap_or(ProxyLogEvent::None),
            Action::SendToIntruder => self
                .selected_exchange()
                .cloned()
                .map(ProxyLogEvent::SendToIntruder)
                .unwrap_or(ProxyLogEvent::None),
            Action::Save => self
                .selected_exchange()
                .cloned()
                .map(ProxyLogEvent::Save)
                .unwrap_or(ProxyLogEvent::None),
            Action::Search => {
                if self.table.filter.is_some() {
                    self.table.set_filter(None);
                }
                ProxyLogEvent::None
            }
            Action::NavRight => {
                self.cycle_focus();
                ProxyLogEvent::None
            }
            _ => ProxyLogEvent::None,
        }
    }

    /// Cycle focus: List -> Request -> Response -> List.
    pub fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            ProxyLogFocus::List => ProxyLogFocus::Request,
            ProxyLogFocus::Request => ProxyLogFocus::Response,
            ProxyLogFocus::Response => ProxyLogFocus::List,
        };
    }
}

impl Default for ProxyLogView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "proxy_log_test.rs"]
mod proxy_log_test;
