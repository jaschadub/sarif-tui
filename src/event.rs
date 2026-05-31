use crate::app::{App, Effect};
use crate::{actions, ui};
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
        if let Some(effect) = app.pending.take() {
            app.status = perform_effect(&mut terminal, effect);
        }
    }
    Ok(())
}

fn perform_effect(terminal: &mut DefaultTerminal, effect: Effect) -> String {
    match effect {
        Effect::Copy(text) => match actions::clipboard::copy(&text) {
            Ok(()) => "Copied finding JSON to clipboard".to_string(),
            Err(e) => e,
        },
        Effect::OpenSource { path } => match actions::open_editor::open_path(&path) {
            Ok(()) => format!("Opened {path}"),
            Err(e) => e,
        },
        Effect::Export(items) => {
            for (name, content) in &items {
                if let Err(e) = std::fs::write(name, content) {
                    return format!("export failed for {name}: {e}");
                }
            }
            let names: Vec<&str> = items.iter().map(|(n, _)| n.as_str()).collect();
            format!("Exported to {}", names.join(", "))
        }
        Effect::OpenEditor { path, line } => {
            // Suspend the TUI so an interactive editor can take the terminal.
            ratatui::restore();
            let res = actions::open_editor::open_in_editor(&path, line);
            *terminal = ratatui::init();
            let _ = terminal.clear();
            match res {
                Ok(()) => format!("Opened {path} in editor"),
                Err(e) => e,
            }
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode) {
    use crate::app::{EditTarget, Mode};

    match app.mode {
        Mode::Help => match code {
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => app.toggle_help(),
            _ => {}
        },
        Mode::Search => match code {
            KeyCode::Esc => app.cancel_edit(),
            KeyCode::Enter => app.commit_edit(),
            KeyCode::Backspace => app.input_backspace(),
            KeyCode::Char(c) => app.input_push(c),
            _ => {}
        },
        Mode::Filter => {
            // While typing into a filter text field, route keys to the editor.
            if app.editing.is_some() {
                match code {
                    KeyCode::Esc => app.cancel_edit(),
                    KeyCode::Enter => app.commit_edit(),
                    KeyCode::Backspace => app.input_backspace(),
                    KeyCode::Char(c) => app.input_push(c),
                    _ => {}
                }
                return;
            }
            match code {
                KeyCode::Char('1') => app.toggle_severity(crate::sarif::Severity::Error),
                KeyCode::Char('2') => app.toggle_severity(crate::sarif::Severity::Warning),
                KeyCode::Char('3') => app.toggle_severity(crate::sarif::Severity::Note),
                KeyCode::Char('4') => app.toggle_severity(crate::sarif::Severity::None),
                KeyCode::Char('s') => app.toggle_hide_suppressed(),
                KeyCode::Char('t') => app.cycle_tool_filter(),
                KeyCode::Char('r') => app.start_edit(EditTarget::FilterRule),
                KeyCode::Char('p') => app.start_edit(EditTarget::FilterPath),
                KeyCode::Char('c') => app.clear_filters(),
                KeyCode::Char('f') | KeyCode::Esc | KeyCode::Enter => app.mode = Mode::Normal,
                _ => {}
            }
        }
        Mode::Normal => match code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Char('j') | KeyCode::Down => app.select_next(),
            KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
            KeyCode::Char('r') => app.toggle_raw(),
            KeyCode::Char('?') => app.toggle_help(),
            KeyCode::Char('/') => app.start_edit(EditTarget::Search),
            KeyCode::Char('f') => app.mode = Mode::Filter,
            KeyCode::Char('s') => app.cycle_sort(),
            KeyCode::Char('y') => app.request_copy(),
            KeyCode::Char('o') => app.request_open_editor(),
            KeyCode::Char('O') => app.request_open_source(),
            KeyCode::Char('e') => app.request_export(),
            _ => {}
        },
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

    #[test]
    fn slash_enters_search_and_types_query() {
        let mut a = app();
        handle_key(&mut a, KeyCode::Char('/'));
        assert_eq!(a.mode, crate::app::Mode::Search);
        for c in "xss".chars() {
            handle_key(&mut a, KeyCode::Char(c));
        }
        assert_eq!(a.visible.len(), 1);
        handle_key(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, crate::app::Mode::Normal);
    }

    #[test]
    fn filter_mode_toggles_severity() {
        let mut a = app();
        handle_key(&mut a, KeyCode::Char('f'));
        assert_eq!(a.mode, crate::app::Mode::Filter);
        handle_key(&mut a, KeyCode::Char('1')); // Error only
        assert_eq!(a.visible.len(), 1);
        handle_key(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, crate::app::Mode::Normal);
    }
}
