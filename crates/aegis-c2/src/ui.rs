use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;

use crate::app::App;

/// Run the TUI event loop.
pub fn run_tui(app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, app);

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    result
}

fn event_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => {
                        app.quit();
                    }
                    KeyCode::Tab => {
                        app.select_next();
                    }
                    KeyCode::BackTab => {
                        app.select_prev();
                    }
                    KeyCode::Enter => {
                        app.submit_input();
                    }
                    KeyCode::Backspace => {
                        app.pop_input();
                    }
                    KeyCode::Char(c) => {
                        app.push_input(c);
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit() {
            break;
        }
    }
    Ok(())
}

fn draw_ui(f: &mut Frame, app: &App) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // body
            Constraint::Length(3), // input
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25), // implant list
            Constraint::Percentage(50), // command output
            Constraint::Percentage(25), // implant details
        ])
        .split(main_chunks[0]);

    draw_implant_list(f, app, body_chunks[0]);
    draw_command_output(f, app, body_chunks[1]);
    draw_implant_details(f, app, body_chunks[2]);
    draw_input(f, app, main_chunks[1]);
    draw_status_bar(f, app, main_chunks[2]);
}

fn draw_implant_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .implants()
        .iter()
        .enumerate()
        .map(|(i, imp)| {
            let style = if i == app.selected_index() {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let line = format!(
                "{} | {} | {} | {}s",
                imp.id, imp.hostname, imp.username, imp.sleep_secs
            );
            ListItem::new(Line::from(Span::styled(line, style)))
        })
        .collect();

    let implant_count = app.implants().len();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Implants ({implant_count}) ")),
    );

    f.render_widget(list, area);
}

fn draw_command_output(f: &mut Frame, app: &App, area: Rect) {
    let history = app.current_history();
    let mut lines: Vec<Line> = Vec::new();

    for entry in history {
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", entry.timestamp),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("> {}", entry.input),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        if let Some(ref output) = entry.output {
            for out_line in output.lines() {
                lines.push(Line::from(Span::styled(
                    format!("  {out_line}"),
                    Style::default().fg(Color::White),
                )));
            }
        }
        lines.push(Line::from(""));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No commands yet. Type 'help' for usage.",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let title = app
        .selected_implant()
        .map(|imp| format!(" Session: {} ", imp.id))
        .unwrap_or_else(|| " No Session ".to_string());

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

fn draw_implant_details(f: &mut Frame, app: &App, area: Rect) {
    let content = match app.selected_implant() {
        Some(imp) => {
            vec![
                Line::from(vec![
                    Span::styled("ID:       ", Style::default().fg(Color::Cyan)),
                    Span::raw(&imp.id),
                ]),
                Line::from(vec![
                    Span::styled("Hostname: ", Style::default().fg(Color::Cyan)),
                    Span::raw(&imp.hostname),
                ]),
                Line::from(vec![
                    Span::styled("User:     ", Style::default().fg(Color::Cyan)),
                    Span::raw(&imp.username),
                ]),
                Line::from(vec![
                    Span::styled("OS:       ", Style::default().fg(Color::Cyan)),
                    Span::raw(&imp.os),
                ]),
                Line::from(vec![
                    Span::styled("IP:       ", Style::default().fg(Color::Cyan)),
                    Span::raw(&imp.ip),
                ]),
                Line::from(vec![
                    Span::styled("Sleep:    ", Style::default().fg(Color::Cyan)),
                    Span::raw(format!("{}s", imp.sleep_secs)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Tab: switch implant",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "Esc: quit",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        }
        None => {
            vec![Line::from(Span::styled(
                "No implant selected",
                Style::default().fg(Color::DarkGray),
            ))]
        }
    };

    let paragraph =
        Paragraph::new(content).block(Block::default().borders(Borders::ALL).title(" Details "));

    f.render_widget(paragraph, area);
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let prompt = app
        .selected_implant()
        .map(|imp| format!("{}> ", imp.id))
        .unwrap_or_else(|| "> ".to_string());

    let input_line = Line::from(vec![
        Span::styled(
            &prompt,
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(app.input()),
    ]);

    let input =
        Paragraph::new(input_line).block(Block::default().borders(Borders::ALL).title(" Command "));

    f.render_widget(input, area);

    // Place cursor after input text
    let cursor_x = area.x + 1 + prompt.len() as u16 + app.input().len() as u16;
    let cursor_y = area.y + 1;
    f.set_cursor_position((cursor_x, cursor_y));
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status = Paragraph::new(Line::from(Span::styled(
        format!(" {} ", app.status()),
        Style::default().fg(Color::White).bg(Color::DarkGray),
    )));
    f.render_widget(status, area);
}
