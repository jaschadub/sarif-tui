use crate::app::App;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render_details(frame: &mut Frame, area: Rect, app: &App) {
    let title = if app.show_raw {
        "Details (raw JSON — press r)"
    } else {
        "Details (press r for raw)"
    };
    let block = Block::default().borders(Borders::ALL).title(title);

    let Some(f) = app.selected_finding() else {
        frame.render_widget(Paragraph::new("No finding selected").block(block), area);
        return;
    };

    if app.show_raw {
        let raw = serde_json::to_string_pretty(&f.raw_json).unwrap_or_default();
        frame.render_widget(
            Paragraph::new(raw).block(block).wrap(Wrap { trim: false }),
            area,
        );
        return;
    }

    let bold = Style::default().add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line> = vec![
        Line::from(vec![Span::styled("Rule:    ", bold), Span::raw(f.rule_id.clone())]),
        Line::from(vec![Span::styled("Level:   ", bold), Span::raw(f.level.as_str())]),
        Line::from(vec![Span::styled("Tool:    ", bold), Span::raw(f.tool_name.clone())]),
        Line::from(vec![Span::styled("File:    ", bold), Span::raw(f.location_str())]),
        Line::from(vec![Span::styled("Message: ", bold), Span::raw(f.message.clone())]),
    ];
    if let Some(t) = f.triage {
        lines.push(Line::from(vec![
            Span::styled("Triage:  ", bold),
            Span::raw(t.as_str()),
        ]));
        if let Some(notes) = app.triage_state.notes_of(&f.fingerprint) {
            if !notes.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Notes:   ", bold),
                    Span::raw(notes.to_string()),
                ]));
            }
        }
    }
    if let Some(b) = f.severity_bucket() {
        lines.push(Line::from(vec![
            Span::styled("CVSS:    ", bold),
            Span::raw(format!("{b} ({:.1})", f.security_severity.unwrap_or(0.0))),
        ]));
    }
    if let Some(help) = &f.help_text {
        lines.push(Line::from(vec![
            Span::styled("Help:    ", bold),
            Span::raw(help.clone()),
        ]));
    }
    if let Some(uri) = &f.help_uri {
        lines.push(Line::from(vec![
            Span::styled("HelpURI: ", bold),
            Span::raw(uri.clone()),
        ]));
    }
    if !f.tags.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Tags:    ", bold),
            Span::raw(f.tags.join(", ")),
        ]));
    }
    if !f.code_flow_steps.is_empty() {
        lines.push(Line::from(Span::styled("Code flow:", bold)));
        for (n, step) in f.code_flow_steps.iter().enumerate() {
            let loc = match (&step.path, step.line) {
                (Some(p), Some(l)) => format!("{p}:{l}"),
                (Some(p), None) => p.clone(),
                _ => "-".into(),
            };
            let msg = step.message.clone().unwrap_or_default();
            lines.push(Line::from(format!("  {}. {loc}  {msg}", n + 1)));
        }
    }
    if !f.related_locations.is_empty() {
        lines.push(Line::from(Span::styled("Related:", bold)));
        for rel in &f.related_locations {
            let loc = match (&rel.path, rel.line) {
                (Some(p), Some(l)) => format!("{p}:{l}"),
                (Some(p), None) => p.clone(),
                _ => "-".into(),
            };
            let msg = rel.message.clone().unwrap_or_default();
            lines.push(Line::from(format!("  • {loc}  {msg}")));
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        area,
    );
}
