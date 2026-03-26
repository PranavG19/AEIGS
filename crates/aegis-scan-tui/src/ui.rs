use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Wrap,
};

use crate::app::{App, LogLevel, ScanPhase, Severity};

/// Render the main 4-panel dashboard layout.
pub fn render_dashboard(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(8),
        ])
        .split(frame.area());

    render_top_bar(frame, app, outer[0]);
    render_main_panels(frame, app, outer[1]);
    render_log_panel(frame, app, outer[2]);
}

fn render_top_bar(frame: &mut Frame, app: &App, area: Rect) {
    let paused_indicator = if app.is_paused { " [PAUSED]" } else { "" };
    let phase_label = app.current_phase.label();
    let text = format!(
        " TARGET: {}  |  PROFILE: {}  |  PHASE: {}  |  TIME: {}  |  REQ: {}  |  FINDINGS: {}  |  RISK: {} ({}){}",
        app.target_url,
        app.profile.label(),
        phase_label,
        app.elapsed_display(),
        app.request_count,
        app.findings.len(),
        app.risk_score as u32,
        app.risk_grade(),
        paused_indicator,
    );
    let bar = Paragraph::new(text)
        .style(
            Style::default()
                .fg(Color::White)
                .bg(Color::Rgb(20, 20, 40)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" AEGIS SCAN DASHBOARD "),
        );
    frame.render_widget(bar, area);
}

fn render_main_panels(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(45),
            Constraint::Percentage(25),
        ])
        .split(area);

    render_scan_progress(frame, app, columns[0]);
    render_findings_table(frame, app, columns[1]);
    render_attack_chains(frame, app, columns[2]);
}

fn render_scan_progress(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(" Scan Progress ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(1),
            Constraint::Min(2),
            Constraint::Length(2),
        ])
        .split(inner);

    let mut phase_items: Vec<ListItem> = Vec::new();
    for (i, phase) in ScanPhase::ALL.iter().enumerate() {
        let progress = app.phase_progress[i];
        let marker = if *phase == app.current_phase {
            "▶"
        } else if progress >= 1.0 {
            "✓"
        } else {
            " "
        };
        let bar_width = 12;
        let filled = (progress * bar_width as f64) as usize;
        let bar: String =
            "█".repeat(filled) + &"░".repeat(bar_width - filled);
        let color = if *phase == app.current_phase {
            Color::Yellow
        } else if progress >= 1.0 {
            Color::Green
        } else {
            Color::DarkGray
        };
        let line = format!("{marker} {:<10} [{bar}] {:>3}%", phase.label(), (progress * 100.0) as u32);
        phase_items.push(ListItem::new(line).style(Style::default().fg(color)));
    }
    let phase_list = List::new(phase_items);
    frame.render_widget(phase_list, chunks[0]);

    let module_items: Vec<ListItem> = app
        .active_modules
        .iter()
        .map(|m| {
            let spin = m.spinner_char();
            ListItem::new(format!("  {spin} {}", m.name))
                .style(Style::default().fg(Color::Cyan))
        })
        .collect();
    let modules = List::new(module_items)
        .block(Block::default().title(" Active Modules "));
    frame.render_widget(modules, chunks[2]);

    let stealth_color = if app.stealth_score >= 80 {
        Color::Green
    } else if app.stealth_score >= 50 {
        Color::Yellow
    } else {
        Color::Red
    };
    let stealth = Gauge::default()
        .block(Block::default().title(" Stealth "))
        .gauge_style(Style::default().fg(stealth_color))
        .ratio(app.stealth_score as f64 / 100.0)
        .label(format!("{}%", app.stealth_score));
    frame.render_widget(stealth, chunks[3]);
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Rgb(255, 165, 0),
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Info => Color::DarkGray,
    }
}

fn render_findings_table(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(format!(" Findings ({}) ", app.findings.len()));

    let header = Row::new(vec![
        Cell::from("SEV").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("TYPE").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("ENDPOINT").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("CONF").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("AGE").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .bottom_margin(1);

    let now = std::time::Instant::now();
    let rows: Vec<Row> = app
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let age_secs = now.duration_since(f.discovered_at).as_secs();
            let age = if age_secs < 60 {
                format!("{age_secs}s")
            } else {
                format!("{}m", age_secs / 60)
            };

            let style = if i == app.selected_finding {
                Style::default()
                    .fg(severity_color(f.severity))
                    .add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(severity_color(f.severity))
            };

            Row::new(vec![
                Cell::from(f.severity.label()),
                Cell::from(f.vuln_type.clone()),
                Cell::from(truncate_str(&f.endpoint, 30)),
                Cell::from(format!("{:.0}%", f.confidence * 100.0)),
                Cell::from(age),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(9),
        Constraint::Min(15),
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(5),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(table, area);
}

fn render_attack_chains(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(format!(" Attack Chains ({}) ", app.attack_chains.len()));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.attack_chains.is_empty() {
        let waiting = Paragraph::new("  Waiting for chains...")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(waiting, inner);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    for (i, chain) in app.attack_chains.iter().enumerate() {
        let severity_str = format!("  Chain #{} (severity: {:.1})", i + 1, chain.total_severity);
        lines.push(Line::from(Span::styled(
            severity_str,
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        for (j, node) in chain.nodes.iter().enumerate() {
            let prefix = if j == 0 { "  ● " } else { "  ↓ " };
            lines.push(Line::from(Span::styled(
                format!("{prefix}{}", truncate_str(&node.label, 20)),
                Style::default().fg(Color::White),
            )));
        }
        lines.push(Line::from(""));
    }

    let chain_text = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(chain_text, inner);
}

fn render_log_panel(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue))
        .title(" Live Log ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let visible_count = inner.height as usize;
    let start = app.log_lines.len().saturating_sub(visible_count);
    let lines: Vec<Line> = app.log_lines[start..]
        .iter()
        .map(|entry| {
            let color = match entry.level {
                LogLevel::Error => Color::Red,
                LogLevel::Warn => Color::Yellow,
                LogLevel::Info => Color::Green,
                LogLevel::Debug => Color::Cyan,
                LogLevel::Trace => Color::DarkGray,
            };
            let prefix = match entry.level {
                LogLevel::Error => "ERR",
                LogLevel::Warn => "WRN",
                LogLevel::Info => "INF",
                LogLevel::Debug => "DBG",
                LogLevel::Trace => "TRC",
            };
            let elapsed_s = entry.elapsed_ms / 1000;
            let elapsed_ms_part = entry.elapsed_ms % 1000;
            Line::from(vec![
                Span::styled(
                    format!("[{elapsed_s:>3}.{elapsed_ms_part:03}] "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{prefix}: "),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    entry.message.clone(),
                    Style::default().fg(color),
                ),
            ])
        })
        .collect();

    let log = Paragraph::new(lines);
    frame.render_widget(log, inner);
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}

#[cfg(test)]
#[path = "ui_test.rs"]
mod ui_test;
