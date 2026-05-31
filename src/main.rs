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
        Some(Command::Diff { .. }) => {
            eprintln!("diff: implemented in Milestone 5");
        }
        None => {
            // TUI launches here starting in Milestone 2.
            eprintln!("TUI: implemented in Milestone 2 (run `summary` or `list` for now)");
        }
    }
    Ok(())
}
