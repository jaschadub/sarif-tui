use crate::app::App;
use crate::sarif::Severity;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::help::centered_rect;

/// One-line search prompt rendered in the status row while in Search mode.
pub fn render_search_line(frame: &mut Frame, area: Rect, app: &App) {
    let text = format!("/{}", app.buffer);
    frame.render_widget(
        Paragraph::new(text).style(Style::default().add_modifier(Modifier::BOLD)),
        area,
    );
}

/// Filter panel popup listing the toggles and current state.
pub fn render_filter_panel(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(60, 60, area);
    frame.render_widget(Clear, popup);

    let on = |b: bool| if b { "[x]" } else { "[ ]" };
    let sev = |s: Severity| on(app.filters.severities.contains(&s));
    let editing_rule = app.editing == Some(crate::app::EditTarget::FilterRule);
    let editing_path = app.editing == Some(crate::app::EditTarget::FilterPath);
    let rule_val = if editing_rule {
        &app.buffer
    } else {
        &app.filters.rule_substr
    };
    let path_val = if editing_path {
        &app.buffer
    } else {
        &app.filters.path_substr
    };
    let tool_val = if app.filters.tools.is_empty() {
        "all".to_string()
    } else {
        app.filters
            .tools
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",")
    };

    let body = format!(
        "Severity:\n  1 {} Error   2 {} Warning   3 {} Note   4 {} None\n\n\
         t tool: {}\n\
         s {} hide suppressed\n\n\
         r rule contains: {}{}\n\
         p path contains: {}{}\n\n\
         c clear all    Esc/f close",
        sev(Severity::Error),
        sev(Severity::Warning),
        sev(Severity::Note),
        sev(Severity::None),
        tool_val,
        on(app.filters.hide_suppressed),
        rule_val,
        if editing_rule { "_" } else { "" },
        path_val,
        if editing_path { "_" } else { "" },
    );

    frame.render_widget(
        Paragraph::new(body).block(Block::default().borders(Borders::ALL).title("Filters")),
        popup,
    );
}
