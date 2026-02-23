use regex::Regex;

/// Definition of a single column in the table.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub title: String,
    /// Fixed display width in terminal columns.
    pub width: u16,
    pub sortable: bool,
}

/// Sort direction for a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir {
    Asc,
    Desc,
}

/// A sortable, filterable table widget backed by a `Vec` of rows.
///
/// Each row is a `Vec<String>` with one entry per column. Filtering uses a
/// regex matched against any cell in a row. Sorting is alphabetical on the
/// selected column. `selected` is an index into the filtered+sorted view and
/// is always clamped to valid bounds.
pub struct TableWidget {
    pub columns: Vec<ColumnDef>,
    pub rows: Vec<Vec<String>>,
    pub sort_column: Option<usize>,
    pub sort_dir: SortDir,
    pub filter: Option<String>,
    /// Index into the filtered+sorted row view.
    pub selected: usize,
}

impl TableWidget {
    /// Create a new table with the given column definitions and no rows.
    pub fn new(columns: Vec<ColumnDef>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            sort_column: None,
            sort_dir: SortDir::Asc,
            filter: None,
            selected: 0,
        }
    }

    /// Replace all rows and clamp the selection to the new length.
    pub fn set_rows(&mut self, rows: Vec<Vec<String>>) {
        self.rows = rows;
        self.clamp_selected();
    }

    /// Set the sort column. Calling with the same column index toggles
    /// direction; switching to a different column resets to ascending.
    pub fn sort_by(&mut self, col_idx: usize) {
        match self.sort_column {
            Some(current) if current == col_idx => {
                self.sort_dir = match self.sort_dir {
                    SortDir::Asc => SortDir::Desc,
                    SortDir::Desc => SortDir::Asc,
                };
            }
            _ => {
                self.sort_column = Some(col_idx);
                self.sort_dir = SortDir::Asc;
            }
        }
        self.clamp_selected();
    }

    /// Set a regex filter applied to every cell in a row. Pass `None` to
    /// clear the filter and show all rows.
    pub fn set_filter(&mut self, pattern: Option<String>) {
        self.filter = pattern;
        self.clamp_selected();
    }

    /// Return rows after applying the current filter and sort.
    ///
    /// Filter is applied first (regex match on any cell), then the result is
    /// sorted alphabetically by the active sort column.
    #[must_use]
    pub fn filtered_rows(&self) -> Vec<&Vec<String>> {
        let re = self.filter.as_deref().and_then(|p| Regex::new(p).ok());

        let mut view: Vec<&Vec<String>> = self
            .rows
            .iter()
            .filter(|row| match &re {
                None => true,
                Some(r) => row.iter().any(|cell| r.is_match(cell)),
            })
            .collect();

        if let Some(col) = self.sort_column {
            view.sort_by(|a, b| {
                let av = a.get(col).map(String::as_str).unwrap_or("");
                let bv = b.get(col).map(String::as_str).unwrap_or("");
                match self.sort_dir {
                    SortDir::Asc => av.cmp(bv),
                    SortDir::Desc => bv.cmp(av),
                }
            });
        }

        view
    }

    /// Move the selection one step toward the end, clamping at the last row.
    pub fn select_next(&mut self) {
        let len = self.filtered_rows().len();
        if len > 0 {
            self.selected = (self.selected + 1).min(len - 1);
        }
    }

    /// Move the selection one step toward the start, clamping at zero.
    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Return a reference to the currently selected row in the filtered+sorted
    /// view, or `None` when the view is empty.
    #[must_use]
    pub fn selected_row(&self) -> Option<&Vec<String>> {
        self.filtered_rows().into_iter().nth(self.selected)
    }

    fn clamp_selected(&mut self) {
        let len = self.filtered_rows().len();
        if len == 0 {
            self.selected = 0;
        } else {
            self.selected = self.selected.min(len - 1);
        }
    }
}

#[cfg(test)]
#[path = "table_test.rs"]
mod table_test;
