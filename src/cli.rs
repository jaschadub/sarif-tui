use crate::sarif::{Finding, Severity};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sarif-tui", version, about = "Explore SARIF static-analysis reports")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// SARIF files (globs allowed). With no subcommand, opens the TUI.
    #[arg(global = true)]
    pub files: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print counts by tool, severity, rule, and file.
    Summary { files: Vec<String> },
    /// Print one row per finding.
    List { files: Vec<String> },
    /// Compare two SARIF reports (new / fixed / unchanged).
    Diff { old: String, new: String },
}

fn count_by<K: Ord + Clone>(items: &[Finding], key: impl Fn(&Finding) -> K) -> BTreeMap<K, usize> {
    let mut m = BTreeMap::new();
    for it in items {
        *m.entry(key(it)).or_insert(0) += 1;
    }
    m
}

pub fn write_summary<W: Write>(w: &mut W, findings: &[Finding]) -> Result<()> {
    writeln!(w, "Total findings: {}", findings.len())?;

    writeln!(w, "\nBy tool:")?;
    for (tool, n) in count_by(findings, |f| f.tool_name.clone()) {
        writeln!(w, "  {tool:<20} {n}")?;
    }

    writeln!(w, "\nBy severity:")?;
    // Print high-to-low for readability.
    for sev in [
        Severity::Error,
        Severity::Warning,
        Severity::Note,
        Severity::None,
    ] {
        let n = findings.iter().filter(|f| f.level == sev).count();
        if n > 0 {
            writeln!(w, "  {:<20} {n}", sev.as_str())?;
        }
    }

    writeln!(w, "\nBy rule:")?;
    for (rule, n) in count_by(findings, |f| f.rule_id.clone()) {
        writeln!(w, "  {rule:<30} {n}")?;
    }

    writeln!(w, "\nBy file:")?;
    for (file, n) in count_by(findings, |f| f.path.clone().unwrap_or_else(|| "-".into())) {
        writeln!(w, "  {file:<30} {n}")?;
    }
    Ok(())
}

pub fn write_list<W: Write>(w: &mut W, findings: &[Finding]) -> Result<()> {
    for f in findings {
        writeln!(
            w,
            "{:<6} {:<28} {:<10} {:<24} {}",
            f.level.as_str(),
            f.rule_id,
            f.tool_name,
            f.location_str(),
            f.message,
        )?;
    }
    Ok(())
}

/// Resolve the file list for a subcommand, falling back to the global list.
pub fn resolve_files(sub: &[String], global: &[String]) -> Vec<PathBuf> {
    let args = if sub.is_empty() { global } else { sub };
    crate::sarif::load::expand_paths(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load_findings;
    use std::path::PathBuf;

    fn fx(name: &str) -> Vec<PathBuf> {
        vec![PathBuf::from(format!("tests/fixtures/{name}"))]
    }

    #[test]
    fn summary_counts_by_tool_and_severity() {
        let findings = load_findings(&fx("semgrep.sarif")).unwrap();
        let mut buf = Vec::new();
        write_summary(&mut buf, &findings).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Semgrep"));
        assert!(out.contains("Total findings: 2"));
        assert!(out.contains("ERROR"));
        assert!(out.contains("WARN"));
    }

    #[test]
    fn list_prints_one_row_per_finding() {
        let findings = load_findings(&fx("codeql.sarif")).unwrap();
        let mut buf = Vec::new();
        write_list(&mut buf, &findings).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("js/sql-injection"));
        assert!(out.contains("src/db.js:42"));
        assert!(out.contains("CodeQL"));
        assert_eq!(out.lines().count(), 1); // one finding -> one row
    }
}
