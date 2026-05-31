pub mod details;
pub mod findings;
pub mod help;

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

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(22), Constraint::Percentage(78)])
        .split(chunks[0]);

    findings::render_tools(frame, top[0], app);
    findings::render_findings(frame, top[1], app);
    details::render_details(frame, chunks[1], app);

    let status = if app.status.is_empty() {
        "j/k move · r raw · ? help · q quit".to_string()
    } else {
        app.status.clone()
    };
    frame.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::NONE)),
        chunks[2],
    );

    if app.mode == Mode::Help {
        help::render_help(frame, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load_findings;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    #[test]
    fn renders_findings_without_panicking() {
        let findings = load_findings(&[PathBuf::from("tests/fixtures/codeql.sarif")]).unwrap();
        let app = App::new(findings);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("CodeQL"));
        assert!(content.contains("js/sql-injection"));
    }
}
