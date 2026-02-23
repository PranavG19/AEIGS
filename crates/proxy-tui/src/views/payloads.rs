use aegis_proxy::PayloadListRecord;

use crate::widgets::table::{ColumnDef, TableWidget};

/// View state for the payload list manager tab.
///
/// Holds a cached `Vec<PayloadListRecord>` and keeps the `TableWidget`
/// in sync. The `selected` index tracks which list is currently active
/// for preview.
pub struct PayloadsView {
    lists: Vec<PayloadListRecord>,
    pub table: TableWidget,
    pub selected: usize,
}

impl PayloadsView {
    /// Creates an empty payloads view with columns: Name, Source, Count.
    pub fn new() -> Self {
        let columns = vec![
            ColumnDef {
                title: "Name".to_string(),
                width: 30,
                sortable: true,
            },
            ColumnDef {
                title: "Source".to_string(),
                width: 15,
                sortable: true,
            },
            ColumnDef {
                title: "Count".to_string(),
                width: 10,
                sortable: false,
            },
        ];
        Self {
            lists: Vec::new(),
            table: TableWidget::new(columns),
            selected: 0,
        }
    }

    /// Replaces all lists and rebuilds the table rows.
    pub fn load_lists(&mut self, lists: Vec<PayloadListRecord>) {
        self.lists = lists;
        self.selected = 0;
        self.rebuild_table();
    }

    /// Returns a reference to the currently selected `PayloadListRecord`,
    /// or `None` when the list is empty.
    pub fn selected_list(&self) -> Option<&PayloadListRecord> {
        self.lists.get(self.selected)
    }

    /// Parses the selected list's entries JSON and returns the first `limit` items.
    ///
    /// Returns an empty `Vec` when no list is selected or when the entries
    /// field is not a valid JSON array of strings.
    pub fn preview_entries(&self, limit: usize) -> Vec<String> {
        let Some(record) = self.selected_list() else {
            return vec![];
        };
        let entries: Vec<String> = serde_json::from_str(&record.entries).unwrap_or_default();
        entries.into_iter().take(limit).collect()
    }

    /// Moves the selection one step toward the end, clamping at the last entry.
    pub fn select_next(&mut self) {
        if !self.lists.is_empty() {
            self.selected = (self.selected + 1).min(self.lists.len() - 1);
        }
    }

    /// Moves the selection one step toward the start, clamping at zero.
    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Returns the number of loaded payload lists.
    pub fn list_count(&self) -> usize {
        self.lists.len()
    }

    fn rebuild_table(&mut self) {
        let rows = self
            .lists
            .iter()
            .map(|pl| {
                let count_str = serde_json::from_str::<Vec<serde_json::Value>>(&pl.entries)
                    .map(|v| v.len().to_string())
                    .unwrap_or_else(|_| "?".to_string());
                vec![pl.name.clone(), pl.source.clone(), count_str]
            })
            .collect();
        self.table.set_rows(rows);
    }
}

impl Default for PayloadsView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "payloads_test.rs"]
mod payloads_test;
