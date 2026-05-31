use crate::sarif::Finding;
use anyhow::Result;

/// Pretty-printed JSON array of the raw SARIF result objects.
pub fn findings_to_json(findings: &[&Finding]) -> Result<String> {
    let arr: Vec<&serde_json::Value> = findings.iter().map(|f| &f.raw_json).collect();
    Ok(serde_json::to_string_pretty(&arr)?)
}

/// Pretty-printed JSON of a single finding's raw SARIF result.
pub fn finding_to_json(f: &Finding) -> Result<String> {
    Ok(serde_json::to_string_pretty(&f.raw_json)?)
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// A Markdown report with a summary line and one table row per finding.
pub fn findings_to_markdown(findings: &[&Finding]) -> String {
    let mut s = String::new();
    s.push_str("# SARIF Findings Report\n\n");
    s.push_str(&format!("Total findings: {}\n\n", findings.len()));
    s.push_str("| Severity | Rule | Tool | Location | Message |\n");
    s.push_str("|---|---|---|---|---|\n");
    for f in findings {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            f.level.as_str(),
            md_cell(&f.rule_id),
            md_cell(&f.tool_name),
            md_cell(&f.location_str()),
            md_cell(&f.message),
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::{load_findings, Finding};
    use std::path::PathBuf;

    fn findings() -> Vec<Finding> {
        load_findings(&[PathBuf::from("tests/fixtures/semgrep.sarif")]).unwrap()
    }

    #[test]
    fn json_export_is_an_array_of_results() {
        let fs = findings();
        let refs: Vec<&Finding> = fs.iter().collect();
        let json = findings_to_json(&refs).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
    }

    #[test]
    fn markdown_has_a_row_per_finding() {
        let fs = findings();
        let refs: Vec<&Finding> = fs.iter().collect();
        let md = findings_to_markdown(&refs);
        assert!(md.contains("# SARIF Findings Report"));
        assert!(md.contains("xss-risk"));
        assert!(md.contains("hardcoded-secret"));
        // header (2 lines) + 2 finding rows = 4 table lines starting with `|`
        assert_eq!(md.matches("\n|").count() + usize::from(md.starts_with('|')), 4);
    }

    #[test]
    fn markdown_escapes_pipes() {
        let mut fs = findings();
        fs[0].message = "a | b".into();
        let refs: Vec<&Finding> = fs.iter().collect();
        let md = findings_to_markdown(&refs);
        assert!(md.contains("a \\| b"));
    }
}
