pub mod details;
pub mod filters;
pub mod findings;
pub mod help;
pub mod triage;

use crate::app::{App, Mode};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn ui(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(55), // top: tools + findings
            Constraint::Percentage(40), // details
            Constraint::Length(1),      // status line
        ])
        .split(area);

    // Collapse the Runs/Tools pane when there's only one tool — the findings
    // table then gets the full width.
    if app.distinct_tool_count() <= 1 {
        findings::render_findings(frame, chunks[0], app);
    } else {
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(22), Constraint::Percentage(78)])
            .split(chunks[0]);
        findings::render_tools(frame, top[0], app);
        findings::render_findings(frame, top[1], app);
    }
    details::render_details(frame, chunks[1], app);

    if app.mode == Mode::Search {
        filters::render_search_line(frame, chunks[2], app);
    } else if app.editing == Some(crate::app::EditTarget::Note) {
        let text = format!("note> {}", app.buffer);
        frame.render_widget(Paragraph::new(text), chunks[2]);
    } else {
        let status = if app.status.is_empty() {
            "j/k move · / search · f filter · s sort · y copy · o edit · e export · t triage · ? help · q quit"
                .to_string()
        } else {
            app.status.clone()
        };
        frame.render_widget(
            Paragraph::new(status).block(Block::default().borders(Borders::NONE)),
            chunks[2],
        );
    }

    match app.mode {
        Mode::Help => help::render_help(frame, area),
        Mode::Filter => filters::render_filter_panel(frame, area, app),
        Mode::Triage => triage::render_triage(frame, area),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load_findings;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn render_to_string(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| ui(f, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn renders_findings_without_panicking() {
        let findings = load_findings(&[PathBuf::from("tests/fixtures/codeql.sarif")]).unwrap();
        let app = App::new(findings);
        let content = render_to_string(&app);
        assert!(content.contains("CodeQL"));
        assert!(content.contains("js/sql-injection"));
    }

    #[test]
    fn single_tool_collapses_runs_pane() {
        let findings = load_findings(&[PathBuf::from("tests/fixtures/codeql.sarif")]).unwrap();
        let content = render_to_string(&App::new(findings));
        assert!(!content.contains("Runs / Tools"));
    }

    #[test]
    fn multiple_tools_show_runs_pane() {
        let findings = load_findings(&[
            PathBuf::from("tests/fixtures/codeql.sarif"),
            PathBuf::from("tests/fixtures/semgrep.sarif"),
        ])
        .unwrap();
        let content = render_to_string(&App::new(findings));
        assert!(content.contains("Runs / Tools"));
    }

    #[test]
    fn renders_filter_panel_in_filter_mode() {
        let findings = load_findings(&[PathBuf::from("tests/fixtures/semgrep.sarif")]).unwrap();
        let mut app = App::new(findings);
        app.mode = crate::app::Mode::Filter;
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("Filters"));
        assert!(content.contains("hide suppressed"));
    }
}
