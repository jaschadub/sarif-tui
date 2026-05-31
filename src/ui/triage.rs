use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::help::centered_rect;

const TRIAGE_TEXT: &str = "\
 Set triage status

  c   confirmed
  f   false positive
  r   needs review
  a   accepted risk
  u   clear status

  Esc cancel
";

pub fn render_triage(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(40, 40, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(TRIAGE_TEXT).block(Block::default().borders(Borders::ALL).title("Triage")),
        popup,
    );
}
