use crate::sarif::Finding;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Help,
}

pub struct App {
    pub findings: Vec<Finding>,
    /// Indices into `findings` currently shown (after filter/search; M2 = all).
    pub visible: Vec<usize>,
    /// Index into `visible`.
    pub selected: usize,
    pub mode: Mode,
    /// Detail panel shows raw JSON instead of formatted fields.
    pub show_raw: bool,
    pub status: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(findings: Vec<Finding>) -> Self {
        let visible = (0..findings.len()).collect();
        App {
            findings,
            visible,
            selected: 0,
            mode: Mode::Normal,
            show_raw: false,
            status: String::new(),
            should_quit: false,
        }
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.visible.get(self.selected).map(|&i| &self.findings[i])
    }

    pub fn select_next(&mut self) {
        if !self.visible.is_empty() && self.selected + 1 < self.visible.len() {
            self.selected += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn toggle_raw(&mut self) {
        self.show_raw = !self.show_raw;
    }

    pub fn toggle_help(&mut self) {
        self.mode = if self.mode == Mode::Help {
            Mode::Normal
        } else {
            Mode::Help
        };
    }

    /// Counts per tool over the currently-visible findings.
    pub fn tool_counts(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for &i in &self.visible {
            *m.entry(self.findings[i].tool_name.clone()).or_insert(0) += 1;
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load_findings;
    use std::path::PathBuf;

    fn app_for(name: &str) -> App {
        let findings =
            load_findings(&[PathBuf::from(format!("tests/fixtures/{name}"))]).unwrap();
        App::new(findings)
    }

    #[test]
    fn new_selects_first_and_shows_all() {
        let app = app_for("semgrep.sarif");
        assert_eq!(app.visible.len(), 2);
        assert_eq!(app.selected, 0);
        assert_eq!(app.selected_finding().unwrap().rule_id, "xss-risk");
    }

    #[test]
    fn navigation_clamps_at_both_ends() {
        let mut app = app_for("semgrep.sarif");
        app.select_prev(); // already at top -> stays 0
        assert_eq!(app.selected, 0);
        app.select_next();
        assert_eq!(app.selected, 1);
        app.select_next(); // at bottom -> stays 1
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn tool_counts_aggregate_visible() {
        let app = app_for("semgrep.sarif");
        let counts = app.tool_counts();
        assert_eq!(counts.get("Semgrep"), Some(&2));
    }

    #[test]
    fn empty_app_has_no_selection() {
        let app = App::new(vec![]);
        assert!(app.selected_finding().is_none());
    }
}
