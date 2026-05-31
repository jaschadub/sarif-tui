use anyhow::Result;
use clap::Parser;
use sarif_tui::cli::{self, Cli, Command};
use sarif_tui::sarif::{load_findings, load_findings_stdin};
use std::io::{self, Write};

fn main() -> Result<()> {
    let args = Cli::parse();
    match &args.command {
        Some(Command::Summary { files }) => {
            let paths = cli::resolve_files(files, &args.files);
            let findings = if paths.is_empty() {
                load_findings_stdin()?
            } else {
                load_findings(&paths)?
            };
            let mut out = io::stdout().lock();
            cli::write_summary(&mut out, &findings)?;
            out.flush()?;
        }
        Some(Command::List { files }) => {
            let paths = cli::resolve_files(files, &args.files);
            let findings = if paths.is_empty() {
                load_findings_stdin()?
            } else {
                load_findings(&paths)?
            };
            let mut out = io::stdout().lock();
            cli::write_list(&mut out, &findings)?;
            out.flush()?;
        }
        Some(Command::Diff { old, new }) => {
            let old_f = load_findings(&cli::resolve_files(std::slice::from_ref(old), &[]))?;
            let new_f = load_findings(&cli::resolve_files(std::slice::from_ref(new), &[]))?;
            let mut out = io::stdout().lock();
            cli::write_diff(&mut out, &old_f, &new_f)?;
            out.flush()?;
        }
        None => {
            let paths = cli::resolve_files(&[], &args.files);
            let mut findings = if paths.is_empty() {
                load_findings_stdin()?
            } else {
                load_findings(&paths)?
            };
            let state_path = std::path::PathBuf::from(sarif_tui::triage::DEFAULT_STATE_FILE);
            let triage = sarif_tui::triage::TriageState::load(&state_path)?;
            triage.apply(&mut findings);
            let reviewer = std::env::var("USER").unwrap_or_else(|_| "reviewer".into());
            let mut app = sarif_tui::app::App::new(findings);
            app.set_triage(triage, state_path, reviewer);

            let terminal = ratatui::init();
            let result = sarif_tui::event::run(terminal, app);
            ratatui::restore();
            result?;
        }
    }
    Ok(())
}
