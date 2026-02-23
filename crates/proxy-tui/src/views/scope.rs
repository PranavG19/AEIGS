use aegis_proxy::{ScopeEngine, ScopeError, ScopeRule};

use crate::widgets::table::{ColumnDef, TableWidget};

/// View state for the scope rule manager tab.
///
/// Owns the `ScopeEngine` and keeps a `TableWidget` in sync after every
/// mutation so the TUI renderer always has an up-to-date row set.
pub struct ScopeView {
    engine: ScopeEngine,
    pub table: TableWidget,
}

impl ScopeView {
    /// Creates a new scope view with columns: ID, Type, Pattern, Enabled.
    pub fn new() -> Self {
        let columns = vec![
            ColumnDef {
                title: "ID".to_string(),
                width: 6,
                sortable: true,
            },
            ColumnDef {
                title: "Type".to_string(),
                width: 10,
                sortable: true,
            },
            ColumnDef {
                title: "Pattern".to_string(),
                width: 50,
                sortable: false,
            },
            ColumnDef {
                title: "Enabled".to_string(),
                width: 8,
                sortable: false,
            },
        ];
        Self {
            engine: ScopeEngine::new(),
            table: TableWidget::new(columns),
        }
    }

    /// Adds a rule to the engine and rebuilds the table.
    ///
    /// Returns the assigned rule ID on success, or a `ScopeError` if the
    /// pattern is not a valid regex.
    pub fn add_rule(&mut self, pattern: &str, is_include: bool) -> Result<u64, ScopeError> {
        let id = self.engine.add_rule(pattern, is_include)?;
        self.rebuild_table();
        Ok(id)
    }

    /// Removes a rule by ID. Returns `true` if the rule was found and removed.
    pub fn remove_rule(&mut self, id: u64) -> bool {
        let removed = self.engine.remove_rule(id);
        if removed {
            self.rebuild_table();
        }
        removed
    }

    /// Toggles the enabled state of a rule. Returns `true` if the rule was found.
    pub fn toggle_rule(&mut self, id: u64) -> bool {
        let found = self.engine.toggle_rule(id);
        if found {
            self.rebuild_table();
        }
        found
    }

    /// Returns a slice of all current scope rules.
    pub fn rules(&self) -> &[ScopeRule] {
        self.engine.rules()
    }

    /// Returns the number of rules in the engine.
    pub fn rule_count(&self) -> usize {
        self.engine.rules().len()
    }

    /// Delegates URL scope evaluation to the underlying engine.
    pub fn test_url(&self, url: &str) -> bool {
        self.engine.is_in_scope(url)
    }

    fn rebuild_table(&mut self) {
        let rows = self
            .engine
            .rules()
            .iter()
            .map(|r| {
                let include_or_exclude = if r.is_include { "Include" } else { "Exclude" };
                let enabled_str = if r.enabled { "Yes" } else { "No" };
                vec![
                    r.id.to_string(),
                    include_or_exclude.to_string(),
                    r.pattern.clone(),
                    enabled_str.to_string(),
                ]
            })
            .collect();
        self.table.set_rows(rows);
    }
}

impl Default for ScopeView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "scope_test.rs"]
mod scope_test;
