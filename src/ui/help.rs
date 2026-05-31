use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

const HELP_TEXT: &str = "\
 sarif-tui keys

  j / down    move down
  k / up      move up
  PgDn / PgUp page down / up
  g / G       first / last (Home / End)
  /           search
  f           filter
  s           sort (severity / file / rule)
  y           copy finding JSON
  o           open in $EDITOR
  O           open source file
  e           export visible findings
  t / n       triage status / note
  r           toggle raw JSON in details
  ?           toggle this help
  q           quit
";

/// Centered popup. Used by the Help overlay (and reused later).
pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

pub fn render_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(50, 50, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(HELP_TEXT).block(Block::default().borders(Borders::ALL).title("Help")),
        popup,
    );
}
