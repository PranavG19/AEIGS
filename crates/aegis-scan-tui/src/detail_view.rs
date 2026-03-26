use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};

use crate::app::{App, Severity};

/// Render the full-screen finding detail overlay.
pub fn render_detail(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Finding Detail — ESC to close, ↑↓ to navigate ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let finding = match app.findings.get(app.selected_finding) {
        Some(f) => f,
        None => {
            let msg = Paragraph::new("No finding selected.")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, inner);
            return;
        }
    };

    let severity_color = match finding.severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Rgb(255, 165, 0),
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Info => Color::DarkGray,
    };

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(8),
            Constraint::Min(6),
            Constraint::Length(6),
        ])
        .split(inner);

    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!(" [{}] ", finding.severity.label()),
                Style::default()
                    .fg(Color::Black)
                    .bg(severity_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                &finding.vuln_type,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  (Finding #{}/{})", app.selected_finding + 1, app.findings.len()),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ]);
    frame.render_widget(title, layout[0]);

    let meta_rows = vec![
        Row::new(vec![
            Cell::from("Endpoint").style(Style::default().fg(Color::Cyan)),
            Cell::from(format!("{} {}", finding.method, finding.endpoint)),
        ]),
        Row::new(vec![
            Cell::from("Confidence").style(Style::default().fg(Color::Cyan)),
            Cell::from(format!("{:.0}%", finding.confidence * 100.0)),
        ]),
        Row::new(vec![
            Cell::from("CVSS").style(Style::default().fg(Color::Cyan)),
            Cell::from(format!("{:.1} — {}", finding.cvss_score, finding.cvss_vector)),
        ]),
        Row::new(vec![
            Cell::from("CWE").style(Style::default().fg(Color::Cyan)),
            Cell::from(finding.cwe_id.clone()),
        ]),
        Row::new(vec![
            Cell::from("ATT&CK").style(Style::default().fg(Color::Cyan)),
            Cell::from(finding.attack_technique.clone()),
        ]),
    ];
    let meta_table = Table::new(
        meta_rows,
        [Constraint::Length(14), Constraint::Min(40)],
    );
    frame.render_widget(meta_table, layout[1]);

    let evidence_sections = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[2]);

    let req_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(" Request ");
    let request_text = Paragraph::new(finding.evidence_request.clone())
        .style(Style::default().fg(Color::Green))
        .block(req_block)
        .wrap(Wrap { trim: false });
    frame.render_widget(request_text, evidence_sections[0]);

    let resp_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" Response ");
    let response_text = Paragraph::new(finding.evidence_response.clone())
        .style(Style::default().fg(Color::Red))
        .block(resp_block)
        .wrap(Wrap { trim: false });
    frame.render_widget(response_text, evidence_sections[1]);

    let bottom = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(2), Constraint::Min(1)])
        .split(layout[3]);

    let curl = Paragraph::new(vec![Line::from(vec![
        Span::styled("Reproduce: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(&finding.curl_command, Style::default().fg(Color::White)),
    ])]);
    frame.render_widget(curl, bottom[0]);

    let remediation = Paragraph::new(vec![Line::from(vec![
        Span::styled("Fix: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(&finding.remediation, Style::default().fg(Color::White)),
    ])])
    .wrap(Wrap { trim: false });
    frame.render_widget(remediation, bottom[1]);
}

#[cfg(test)]
#[path = "detail_view_test.rs"]
mod detail_view_test;
