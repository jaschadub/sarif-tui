use crate::filter::Filters;
use crate::sarif::{Finding, Severity};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Help,
    Search,
    Filter,
}

/// Which text field the inline editor is currently editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditTarget {
    Search,
    FilterRule,
    FilterPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    None,
    Severity,
    File,
    Rule,
}

impl SortKey {
    pub fn label(self) -> &'static str {
        match self {
            SortKey::None => "",
            SortKey::Severity => " sort:sev",
            SortKey::File => " sort:file",
            SortKey::Rule => " sort:rule",
        }
    }
}

pub struct App {
    pub findings: Vec<Finding>,
    /// Indices into `findings` currently shown (after filter/search).
    pub visible: Vec<usize>,
    /// Index into `visible`.
    pub selected: usize,
    pub mode: Mode,
    /// Detail panel shows raw JSON instead of formatted fields.
    pub show_raw: bool,
    pub status: String,
    pub should_quit: bool,
    pub filters: Filters,
    pub search_query: String,
    /// Inline text editor: Some(target) while a field is being typed into.
    pub editing: Option<EditTarget>,
    pub buffer: String,
    pub sort: SortKey,
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
            filters: Filters::default(),
            search_query: String::new(),
            editing: None,
            buffer: String::new(),
            sort: SortKey::None,
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

    /// Rebuild `visible` from `findings` applying filters then fuzzy search.
    pub fn recompute_visible(&mut self) {
        let matcher = SkimMatcherV2::default();
        let mut scored: Vec<(usize, i64)> = Vec::new();
        for (i, f) in self.findings.iter().enumerate() {
            if !self.filters.matches(f) {
                continue;
            }
            if self.search_query.is_empty() {
                scored.push((i, 0));
            } else {
                let hay = format!(
                    "{} {} {}",
                    f.rule_id,
                    f.message,
                    f.path.as_deref().unwrap_or("")
                );
                if let Some(score) = matcher.fuzzy_match(&hay, &self.search_query) {
                    scored.push((i, score));
                }
            }
        }
        if !self.search_query.is_empty() {
            scored.sort_by_key(|x| std::cmp::Reverse(x.1));
        }
        self.visible = scored.into_iter().map(|(i, _)| i).collect();
        if self.selected >= self.visible.len() {
            self.selected = self.visible.len().saturating_sub(1);
        }
        if self.search_query.is_empty() {
            self.apply_sort();
        }
    }

    fn apply_sort(&mut self) {
        let App {
            findings,
            visible,
            sort,
            ..
        } = self;
        let findings = &*findings;
        match *sort {
            SortKey::None => visible.sort_by_key(|&i| findings[i].id),
            SortKey::Severity => visible.sort_by(|&a, &b| {
                findings[b]
                    .level
                    .cmp(&findings[a].level)
                    .then(findings[a].id.cmp(&findings[b].id))
            }),
            SortKey::File => visible.sort_by(|&a, &b| {
                findings[a]
                    .path
                    .cmp(&findings[b].path)
                    .then(findings[a].line.cmp(&findings[b].line))
            }),
            SortKey::Rule => visible.sort_by(|&a, &b| findings[a].rule_id.cmp(&findings[b].rule_id)),
        }
    }

    pub fn cycle_sort(&mut self) {
        self.sort = match self.sort {
            SortKey::None => SortKey::Severity,
            SortKey::Severity => SortKey::File,
            SortKey::File => SortKey::Rule,
            SortKey::Rule => SortKey::None,
        };
        self.recompute_visible();
    }

    /// Cycle the single-tool filter: all → tool A → tool B → … → all.
    pub fn cycle_tool_filter(&mut self) {
        let mut tools: Vec<String> = self.findings.iter().map(|f| f.tool_name.clone()).collect();
        tools.sort();
        tools.dedup();
        if tools.is_empty() {
            return;
        }
        let current = self.filters.tools.iter().next().cloned();
        let next = match current {
            None => Some(tools[0].clone()),
            Some(c) => {
                let idx = tools.iter().position(|t| *t == c).unwrap_or(0);
                tools.get(idx + 1).cloned() // None past the last entry -> back to "all"
            }
        };
        self.filters.tools.clear();
        if let Some(t) = next {
            self.filters.tools.insert(t);
        }
        self.recompute_visible();
    }

    pub fn set_search(&mut self, q: String) {
        self.search_query = q;
        self.recompute_visible();
    }

    pub fn toggle_severity(&mut self, sev: Severity) {
        if !self.filters.severities.insert(sev) {
            self.filters.severities.remove(&sev);
        }
        self.recompute_visible();
    }

    pub fn toggle_hide_suppressed(&mut self) {
        self.filters.hide_suppressed = !self.filters.hide_suppressed;
        self.recompute_visible();
    }

    pub fn clear_filters(&mut self) {
        self.filters = Filters::default();
        self.search_query.clear();
        self.recompute_visible();
    }

    /// Begin editing a text field; seeds the buffer with the current value.
    pub fn start_edit(&mut self, target: EditTarget) {
        self.buffer = match target {
            EditTarget::Search => self.search_query.clone(),
            EditTarget::FilterRule => self.filters.rule_substr.clone(),
            EditTarget::FilterPath => self.filters.path_substr.clone(),
        };
        self.editing = Some(target);
        if target == EditTarget::Search {
            self.mode = Mode::Search;
        }
    }

    pub fn input_push(&mut self, c: char) {
        if self.editing.is_none() {
            return;
        }
        self.buffer.push(c);
        if self.editing == Some(EditTarget::Search) {
            self.set_search(self.buffer.clone()); // live search
        }
    }

    pub fn input_backspace(&mut self) {
        if self.editing.is_none() {
            return;
        }
        self.buffer.pop();
        if self.editing == Some(EditTarget::Search) {
            self.set_search(self.buffer.clone());
        }
    }

    pub fn commit_edit(&mut self) {
        match self.editing.take() {
            Some(EditTarget::Search) => {
                self.set_search(self.buffer.clone());
                self.mode = Mode::Normal;
            }
            Some(EditTarget::FilterRule) => {
                self.filters.rule_substr = self.buffer.clone();
                self.recompute_visible();
            }
            Some(EditTarget::FilterPath) => {
                self.filters.path_substr = self.buffer.clone();
                self.recompute_visible();
            }
            None => {}
        }
        self.buffer.clear();
    }

    pub fn cancel_edit(&mut self) {
        let was_search = self.editing == Some(EditTarget::Search);
        self.editing = None;
        self.buffer.clear();
        if was_search {
            // Clearing the live search restores the full list.
            self.set_search(String::new());
            self.mode = Mode::Normal;
        }
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

    #[test]
    fn live_search_narrows_then_restores() {
        let mut app = app_for("semgrep.sarif");
        app.start_edit(EditTarget::Search);
        for c in "xss".chars() {
            app.input_push(c);
        }
        assert_eq!(app.visible.len(), 1);
        assert_eq!(app.selected_finding().unwrap().rule_id, "xss-risk");
        app.cancel_edit();
        assert_eq!(app.visible.len(), 2);
    }

    #[test]
    fn severity_toggle_filters_and_untoggles() {
        let mut app = app_for("semgrep.sarif");
        app.toggle_severity(Severity::Error);
        assert_eq!(app.visible.len(), 1);
        app.toggle_severity(Severity::Error);
        assert_eq!(app.visible.len(), 2);
    }

    #[test]
    fn selection_clamps_when_filter_shrinks_list() {
        let mut app = app_for("semgrep.sarif");
        app.select_next(); // selected = 1
        app.toggle_severity(Severity::Error); // only 1 visible now
        assert!(app.selected < app.visible.len());
    }

    #[test]
    fn sort_by_severity_puts_error_first() {
        let mut app = app_for("semgrep.sarif"); // one warning, one error
        app.sort = SortKey::Severity;
        app.recompute_visible();
        assert_eq!(app.selected_finding().unwrap().level, Severity::Error);
    }

    #[test]
    fn cycle_tool_filter_narrows_then_restores() {
        // codeql + semgrep -> two tools
        let findings = load_findings(&[
            PathBuf::from("tests/fixtures/codeql.sarif"),
            PathBuf::from("tests/fixtures/semgrep.sarif"),
        ])
        .unwrap();
        let mut app = App::new(findings);
        let total = app.visible.len();
        app.cycle_tool_filter(); // -> first tool only
        assert!(app.visible.len() < total);
        app.cycle_tool_filter(); // -> second tool only
        assert!(app.visible.len() < total);
        app.cycle_tool_filter(); // -> all again
        assert_eq!(app.visible.len(), total);
    }
}
