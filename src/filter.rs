use crate::sarif::{Finding, Severity};
use std::collections::BTreeSet;

#[derive(Debug, Default, Clone)]
pub struct Filters {
    /// Empty set means "all severities".
    pub severities: BTreeSet<Severity>,
    /// Empty set means "all tools".
    pub tools: BTreeSet<String>,
    pub rule_substr: String,
    pub path_substr: String,
    pub hide_suppressed: bool,
}

impl Filters {
    pub fn is_empty(&self) -> bool {
        self.severities.is_empty()
            && self.tools.is_empty()
            && self.rule_substr.is_empty()
            && self.path_substr.is_empty()
            && !self.hide_suppressed
    }

    pub fn matches(&self, f: &Finding) -> bool {
        if self.hide_suppressed && f.suppressed {
            return false;
        }
        if !self.severities.is_empty() && !self.severities.contains(&f.level) {
            return false;
        }
        if !self.tools.is_empty() && !self.tools.contains(&f.tool_name) {
            return false;
        }
        if !self.rule_substr.is_empty()
            && !f
                .rule_id
                .to_lowercase()
                .contains(&self.rule_substr.to_lowercase())
        {
            return false;
        }
        if !self.path_substr.is_empty() {
            let p = f.path.as_deref().unwrap_or("").to_lowercase();
            if !p.contains(&self.path_substr.to_lowercase()) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load_findings;
    use std::path::PathBuf;

    fn findings() -> Vec<Finding> {
        load_findings(&[PathBuf::from("tests/fixtures/semgrep.sarif")]).unwrap()
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = Filters::default();
        assert!(findings().iter().all(|x| f.matches(x)));
    }

    #[test]
    fn hide_suppressed_drops_suppressed() {
        let f = Filters {
            hide_suppressed: true,
            ..Default::default()
        };
        let kept: Vec<_> = findings().into_iter().filter(|x| f.matches(x)).collect();
        assert_eq!(kept.len(), 1);
        assert!(kept.iter().all(|x| !x.suppressed));
    }

    #[test]
    fn severity_filter_keeps_only_selected() {
        let f = Filters {
            severities: BTreeSet::from([Severity::Error]),
            ..Default::default()
        };
        let kept: Vec<_> = findings().into_iter().filter(|x| f.matches(x)).collect();
        assert!(kept.iter().all(|x| x.level == Severity::Error));
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn rule_substr_is_case_insensitive() {
        let f = Filters {
            rule_substr: "XSS".into(),
            ..Default::default()
        };
        let kept: Vec<_> = findings().into_iter().filter(|x| f.matches(x)).collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].rule_id, "xss-risk");
    }
}
