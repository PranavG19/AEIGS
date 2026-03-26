use ratatui::prelude::*;
use ratatui::widgets::{BarChart, Block, Borders, Paragraph};

use crate::app::App;

/// Render the full-screen stats overlay.
pub fn render_stats(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Scan Statistics — ESC to close ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Min(4),
        ])
        .split(inner);

    render_severity_chart(frame, app, layout[0]);
    render_vuln_class_chart(frame, app, layout[1]);
    render_coverage(frame, app, layout[2]);
    render_risk_summary(frame, app, layout[3]);
}

fn render_severity_chart(frame: &mut Frame, app: &App, area: Rect) {
    let counts = app.severity_counts();
    let labels = ["CRIT", "HIGH", "MED", "LOW", "INFO"];
    let colors = [
        Color::Red,
        Color::Rgb(255, 165, 0),
        Color::Yellow,
        Color::Cyan,
        Color::DarkGray,
    ];

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        " Findings by Severity",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    let max_count = counts.iter().copied().max().unwrap_or(1).max(1);
    let bar_max = 30;
    for (i, &count) in counts.iter().enumerate() {
        let bar_len = (count * bar_max) / max_count;
        let bar: String = "█".repeat(bar_len);
        let pad: String = " ".repeat(bar_max - bar_len);
        let line = Line::from(vec![
            Span::styled(
                format!("  {:<5}", labels[i]),
                Style::default().fg(colors[i]),
            ),
            Span::styled(bar, Style::default().fg(colors[i])),
            Span::raw(pad),
            Span::styled(format!(" {count}"), Style::default().fg(Color::White)),
        ]);
        lines.push(line);
    }

    let chart = Paragraph::new(lines);
    frame.render_widget(chart, area);
}

fn render_vuln_class_chart(frame: &mut Frame, app: &App, area: Rect) {
    let mut type_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for f in &app.findings {
        *type_counts.entry(f.vuln_type.clone()).or_default() += 1;
    }

    let mut sorted: Vec<(String, u64)> = type_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let data: Vec<(&str, u64)> = sorted
        .iter()
        .take(8)
        .map(|(name, count)| (name.as_str(), *count))
        .collect();

    if data.is_empty() {
        let empty = Paragraph::new("  No findings yet.")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Findings by Type "),
            );
        frame.render_widget(empty, area);
        return;
    }

    let chart = BarChart::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta))
                .title(" Findings by Type "),
        )
        .data(&data)
        .bar_width(8)
        .bar_gap(1)
        .bar_style(Style::default().fg(Color::Magenta))
        .value_style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(chart, area);
}

fn render_coverage(frame: &mut Frame, app: &App, area: Rect) {
    let total = app.endpoints_discovered.max(1);
    let tested = app.endpoints_tested.min(total);
    let pct = (tested as f64 / total as f64 * 100.0) as u64;

    let bar_width = 40;
    let filled = (pct as usize * bar_width) / 100;
    let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);

    let lines = vec![
        Line::from(Span::styled(
            " Endpoint Coverage",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  ["),
            Span::styled(&bar, Style::default().fg(Color::Green)),
            Span::raw("] "),
            Span::styled(
                format!("{pct}% ({tested}/{total} endpoints)"),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    let coverage = Paragraph::new(lines);
    frame.render_widget(coverage, area);
}

fn render_risk_summary(frame: &mut Frame, app: &App, area: Rect) {
    let grade = app.risk_grade();
    let grade_color = match grade {
        "A" => Color::Green,
        "B" => Color::Cyan,
        "C" => Color::Yellow,
        "D" => Color::Rgb(255, 165, 0),
        _ => Color::Red,
    };

    let lines = vec![
        Line::from(Span::styled(
            " Risk Assessment",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Risk Score: "),
            Span::styled(
                format!("{:.0}/100", app.risk_score),
                Style::default()
                    .fg(grade_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Grade: "),
            Span::styled(
                grade,
                Style::default()
                    .fg(grade_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    let summary = Paragraph::new(lines);
    frame.render_widget(summary, area);
}

#[cfg(test)]
#[path = "stats_view_test.rs"]
mod stats_view_test;
