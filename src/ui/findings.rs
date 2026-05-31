use crate::app::App;
use crate::sarif::Severity;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Row, Table, TableState};
use ratatui::Frame;

fn severity_style(sev: Severity) -> Style {
    let color = match sev {
        Severity::Error => Color::Red,
        Severity::Warning => Color::Yellow,
        Severity::Note => Color::Cyan,
        Severity::None => Color::Gray,
    };
    Style::default().fg(color)
}

/// Left pane: tools and their (visible) finding counts.
pub fn render_tools(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .tool_counts()
        .into_iter()
        .map(|(tool, n)| ListItem::new(Line::from(format!("{tool:<14}{n:>5}"))))
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Runs / Tools"));
    frame.render_widget(list, area);
}

/// Right pane: the findings table.
pub fn render_findings(frame: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec!["SEV", "RULE", "TOOL", "LOCATION", "MESSAGE"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .visible
        .iter()
        .map(|&i| {
            let f = &app.findings[i];
            let sev = if f.suppressed {
                Cell::from(format!("{}*", f.level.as_str())).style(severity_style(f.level))
            } else {
                Cell::from(f.level.as_str()).style(severity_style(f.level))
            };
            Row::new(vec![
                sev,
                Cell::from(f.rule_id.clone()),
                Cell::from(f.tool_name.clone()),
                Cell::from(f.location_str()),
                Cell::from(f.message.clone()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(26),
        Constraint::Length(10),
        Constraint::Length(22),
        Constraint::Min(20),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            "Findings ({}/{})",
            app.visible.len(),
            app.findings.len()
        )))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    let mut state = TableState::default();
    if !app.visible.is_empty() {
        state.select(Some(app.selected));
    }
    frame.render_stateful_widget(table, area, &mut state);
}
