use crate::sarif::Finding;
use std::collections::BTreeSet;

/// Baseline comparison of two finding sets, keyed by fingerprint.
pub struct Diff<'a> {
    pub new: Vec<&'a Finding>,
    pub fixed: Vec<&'a Finding>,
    pub unchanged: Vec<&'a Finding>,
}

pub fn diff<'a>(old: &'a [Finding], new: &'a [Finding]) -> Diff<'a> {
    let old_fp: BTreeSet<&str> = old.iter().map(|f| f.fingerprint.as_str()).collect();
    let new_fp: BTreeSet<&str> = new.iter().map(|f| f.fingerprint.as_str()).collect();

    let new_findings = new
        .iter()
        .filter(|f| !old_fp.contains(f.fingerprint.as_str()))
        .collect();
    let fixed = old
        .iter()
        .filter(|f| !new_fp.contains(f.fingerprint.as_str()))
        .collect();
    let unchanged = new
        .iter()
        .filter(|f| old_fp.contains(f.fingerprint.as_str()))
        .collect();

    Diff {
        new: new_findings,
        fixed,
        unchanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load_findings;
    use std::path::PathBuf;

    fn fx(name: &str) -> Vec<crate::sarif::Finding> {
        load_findings(&[PathBuf::from(format!("tests/fixtures/{name}"))]).unwrap()
    }

    #[test]
    fn identical_reports_are_all_unchanged() {
        let a = fx("codeql.sarif");
        let b = fx("codeql.sarif");
        let d = diff(&a, &b);
        assert_eq!(d.unchanged.len(), 1);
        assert!(d.new.is_empty());
        assert!(d.fixed.is_empty());
    }

    #[test]
    fn disjoint_reports_are_all_new_and_fixed() {
        let old = fx("codeql.sarif"); // 1 finding
        let new = fx("semgrep.sarif"); // 2 findings, different fingerprints
        let d = diff(&old, &new);
        assert_eq!(d.new.len(), 2);
        assert_eq!(d.fixed.len(), 1);
        assert!(d.unchanged.is_empty());
    }
}
