use crate::app::App;
use crate::ui;
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::DefaultTerminal;

/// Run the TUI loop until the user quits. `ratatui::init()`/`restore()` handle
/// raw mode, the alternate screen, and a panic hook that restores the terminal.
pub fn run(mut terminal: DefaultTerminal, mut app: App) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui::ui(f, &app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                handle_key(&mut app, key.code);
            }
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, code: KeyCode) {
    // Help overlay swallows everything except dismiss/quit.
    if app.mode == crate::app::Mode::Help {
        match code {
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => app.toggle_help(),
            _ => {}
        }
        return;
    }
    match code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('r') => app.toggle_raw(),
        KeyCode::Char('?') => app.toggle_help(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load_findings;
    use std::path::PathBuf;

    fn app() -> App {
        App::new(load_findings(&[PathBuf::from("tests/fixtures/semgrep.sarif")]).unwrap())
    }

    #[test]
    fn keys_drive_navigation_and_quit() {
        let mut a = app();
        handle_key(&mut a, KeyCode::Char('j'));
        assert_eq!(a.selected, 1);
        handle_key(&mut a, KeyCode::Char('k'));
        assert_eq!(a.selected, 0);
        handle_key(&mut a, KeyCode::Char('r'));
        assert!(a.show_raw);
        handle_key(&mut a, KeyCode::Char('q'));
        assert!(a.should_quit);
    }

    #[test]
    fn help_overlay_swallows_navigation() {
        let mut a = app();
        handle_key(&mut a, KeyCode::Char('?'));
        assert_eq!(a.mode, crate::app::Mode::Help);
        handle_key(&mut a, KeyCode::Char('j'));
        assert_eq!(a.selected, 0); // navigation ignored while help is open
        handle_key(&mut a, KeyCode::Char('?'));
        assert_eq!(a.mode, crate::app::Mode::Normal);
    }
}
