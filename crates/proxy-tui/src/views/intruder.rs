use aegis_proxy::{
    AttackMode, GrepExtract, GrepMatch, ModifiedRequest, PayloadPipeline, PipelineIntruderResult,
    RecordedExchange,
};

use crate::widgets::table::{ColumnDef, TableWidget};

/// Phase of the intruder view state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderPhase {
    Config,
    Results,
}

/// Running totals for an intruder attack.
#[derive(Debug, Clone)]
pub struct AttackStats {
    pub total: usize,
    pub completed: usize,
    pub matches: usize,
    pub errors: usize,
}

/// View-layer state for the Intruder tab.
pub struct IntruderView {
    pub phase: IntruderPhase,
    pub template: Option<ModifiedRequest>,
    pub positions: Vec<String>,
    pub mode: AttackMode,
    pub pipelines: Vec<PayloadPipeline>,
    pub grep_matches: Vec<GrepMatch>,
    pub grep_extracts: Vec<GrepExtract>,
    pub results: Vec<PipelineIntruderResult>,
    pub results_table: TableWidget,
    pub running: bool,
}

fn results_table_columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            title: "Payload".to_string(),
            width: 30,
            sortable: true,
        },
        ColumnDef {
            title: "Status".to_string(),
            width: 8,
            sortable: true,
        },
        ColumnDef {
            title: "Length".to_string(),
            width: 10,
            sortable: true,
        },
        ColumnDef {
            title: "Time".to_string(),
            width: 8,
            sortable: true,
        },
        ColumnDef {
            title: "Match".to_string(),
            width: 20,
            sortable: true,
        },
    ]
}

impl IntruderView {
    pub fn new() -> Self {
        Self {
            phase: IntruderPhase::Config,
            template: None,
            positions: Vec::new(),
            mode: AttackMode::Sniper,
            pipelines: Vec::new(),
            grep_matches: Vec::new(),
            grep_extracts: Vec::new(),
            results: Vec::new(),
            results_table: TableWidget::new(results_table_columns()),
            running: false,
        }
    }

    /// Populate the template from a recorded exchange and reset attack state.
    pub fn load_exchange(&mut self, exchange: &RecordedExchange) {
        self.template = Some(ModifiedRequest {
            method: exchange.request_method.clone(),
            url: exchange.request_url.clone(),
            headers: exchange.request_headers.clone(),
            body: exchange.request_body.clone(),
        });
        self.positions.clear();
        self.results.clear();
        self.results_table.set_rows(Vec::new());
    }

    pub fn set_mode(&mut self, mode: AttackMode) {
        self.mode = mode;
    }

    pub fn add_position(&mut self, marker: String) {
        self.positions.push(marker);
    }

    pub fn clear_positions(&mut self) {
        self.positions.clear();
    }

    /// Append a result and add the corresponding row to the results table.
    pub fn add_result(&mut self, result: PipelineIntruderResult) {
        let row = vec![
            result.payload.join(","),
            result.status_code.to_string(),
            result.body_length.to_string(),
            result.duration_ms.to_string(),
            result.grep_match_results.join(","),
        ];
        self.results.push(result);
        self.results_table.rows.push(row);
    }

    pub fn stats(&self) -> AttackStats {
        let total = self.results.len();
        let matches = self
            .results
            .iter()
            .filter(|r| !r.grep_match_results.is_empty())
            .count();
        let errors = self.results.iter().filter(|r| r.status_code == 0).count();
        AttackStats {
            total,
            completed: total,
            matches,
            errors,
        }
    }

    /// Transition to the Results phase, mark as running, and clear prior results.
    pub fn start_attack(&mut self) {
        self.results.clear();
        self.results_table.set_rows(Vec::new());
        self.running = true;
        self.phase = IntruderPhase::Results;
    }

    pub fn stop_attack(&mut self) {
        self.running = false;
    }

    pub fn position_count(&self) -> usize {
        self.positions.len()
    }

    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

impl Default for IntruderView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "intruder_test.rs"]
mod intruder_test;
