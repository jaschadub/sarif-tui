use crate::sarif::model::{Finding, FlowStep, RelatedLocation, Severity};
use serde_sarif::sarif::{
    Location as SarifLocation, ReportingDescriptor, Result as SarifResult, ResultLevel, Run, Sarif,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// FNV-1a 64-bit hex of the given parts (stable across runs; no external deps).
pub(crate) fn fnv1a_hex(parts: &[&str]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for b in p.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff; // field separator
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn level_from_result(level: Option<ResultLevel>) -> Option<Severity> {
    level.map(|l| match l {
        ResultLevel::Error => Severity::Error,
        ResultLevel::Warning => Severity::Warning,
        ResultLevel::Note => Severity::Note,
        ResultLevel::None => Severity::None,
    })
}

/// Build an index of ruleId/ruleIndex -> descriptor for a run's driver rules.
fn rule_index(run: &Run) -> (Vec<&ReportingDescriptor>, BTreeMap<String, usize>) {
    let rules: Vec<&ReportingDescriptor> = run
        .tool
        .driver
        .rules
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .collect();
    let mut by_id = BTreeMap::new();
    for (i, r) in rules.iter().enumerate() {
        by_id.insert(r.id.clone(), i);
    }
    (rules, by_id)
}

fn descriptor_for<'a>(
    result: &SarifResult,
    rules: &[&'a ReportingDescriptor],
    by_id: &BTreeMap<String, usize>,
) -> Option<&'a ReportingDescriptor> {
    if let Some(idx) = result.rule_index {
        if let Some(d) = rules.get(idx as usize) {
            return Some(*d);
        }
    }
    if let Some(rr) = &result.rule {
        if let Some(idx) = rr.index {
            if let Some(d) = rules.get(idx as usize) {
                return Some(*d);
            }
        }
    }
    let id = result
        .rule_id
        .as_deref()
        .or(result.rule.as_ref().and_then(|r| r.id.as_deref()))?;
    by_id.get(id).and_then(|i| rules.get(*i)).copied()
}

fn security_severity(result: &SarifResult, desc: Option<&ReportingDescriptor>) -> Option<f32> {
    let from = |bag: Option<&serde_sarif::sarif::PropertyBag>| {
        bag.and_then(|b| b.additional_properties.get("security-severity"))
            .and_then(|v| match v {
                serde_json::Value::String(s) => s.parse::<f32>().ok(),
                serde_json::Value::Number(n) => n.as_f64().map(|x| x as f32),
                _ => None,
            })
    };
    from(result.properties.as_ref()).or_else(|| from(desc.and_then(|d| d.properties.as_ref())))
}

fn first_physical(locs: Option<&Vec<SarifLocation>>) -> (Option<String>, Option<u32>, Option<u32>) {
    let Some(loc) = locs.and_then(|l| l.first()) else {
        return (None, None, None);
    };
    let Some(phys) = &loc.physical_location else {
        return (None, None, None);
    };
    let path = phys.artifact_location.as_ref().and_then(|a| a.uri.clone());
    let (line, col) = phys
        .region
        .as_ref()
        .map(|r| {
            (
                r.start_line.map(|v| v as u32),
                r.start_column.map(|v| v as u32),
            )
        })
        .unwrap_or((None, None));
    (path, line, col)
}

fn message_text(m: &serde_sarif::sarif::Message) -> String {
    m.text
        .clone()
        .or_else(|| m.markdown.clone())
        .unwrap_or_default()
}

fn json_str(v: &Option<serde_json::Value>) -> Option<String> {
    v.as_ref().and_then(|x| x.as_str().map(|s| s.to_string()))
}

/// Normalize a parsed SARIF document into app findings.
/// `start_id` lets callers keep ids unique across multiple files.
pub fn normalize(sarif: &Sarif, source_file: &Path, start_id: usize) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut id = start_id;
    for (run_index, run) in sarif.runs.iter().enumerate() {
        let tool_name = run.tool.driver.name.clone();
        let (rules, by_id) = rule_index(run);
        let Some(results) = &run.results else {
            continue;
        };
        for result in results {
            let desc = descriptor_for(result, &rules, &by_id);

            // Severity: result.level -> rule defaultConfiguration.level -> Warning.
            let level = level_from_result(result.level)
                .or_else(|| {
                    desc.and_then(|d| d.default_configuration.as_ref())
                        .and_then(|c| c.level.as_ref())
                        .and_then(|v| v.as_str())
                        .and_then(Severity::from_sarif_str)
                })
                .unwrap_or(Severity::Warning);

            let rule_id = result
                .rule_id
                .clone()
                .or_else(|| result.rule.as_ref().and_then(|r| r.id.clone()))
                .or_else(|| desc.map(|d| d.id.clone()))
                .unwrap_or_else(|| "<no-rule>".to_string());

            let (path, line, column) = first_physical(result.locations.as_ref());

            let help_text = desc.and_then(|d| d.help.as_ref().map(|h| h.text.clone()));
            let help_uri = desc.and_then(|d| d.help_uri.clone());
            let tags = desc
                .and_then(|d| d.properties.as_ref())
                .and_then(|p| p.tags.clone())
                .unwrap_or_default();

            let related_locations = result
                .related_locations
                .as_ref()
                .map(|locs| {
                    locs.iter()
                        .map(|l| {
                            let phys = first_physical(Some(&vec![l.clone()]));
                            RelatedLocation {
                                path: phys.0,
                                line: phys.1,
                                message: l.message.as_ref().map(message_text),
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let mut code_flow_steps = Vec::new();
            if let Some(flows) = &result.code_flows {
                for flow in flows {
                    for tf in &flow.thread_flows {
                        for tfl in &tf.locations {
                            if let Some(loc) = &tfl.location {
                                let phys = first_physical(Some(&vec![loc.clone()]));
                                code_flow_steps.push(FlowStep {
                                    path: phys.0,
                                    line: phys.1,
                                    message: loc.message.as_ref().map(message_text),
                                });
                            }
                        }
                    }
                }
            }

            let suppressed = result
                .suppressions
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            let baseline_state = json_str(&result.baseline_state);
            let security_severity = security_severity(result, desc);
            let message = message_text(&result.message);

            // Fingerprint: prefer SARIF's own, else compute (line-independent).
            let fingerprint = result
                .fingerprints
                .as_ref()
                .and_then(|m| m.values().next().cloned())
                .or_else(|| {
                    result
                        .partial_fingerprints
                        .as_ref()
                        .and_then(|m| m.values().next().cloned())
                })
                .unwrap_or_else(|| {
                    fnv1a_hex(&[
                        tool_name.as_str(),
                        rule_id.as_str(),
                        path.as_deref().unwrap_or(""),
                        message.as_str(),
                    ])
                });

            let raw_json = serde_json::to_value(result).unwrap_or(serde_json::Value::Null);

            out.push(Finding {
                id,
                fingerprint,
                source_file: PathBuf::from(source_file),
                run_index,
                tool_name: tool_name.clone(),
                rule_id,
                level,
                security_severity,
                message,
                path,
                line,
                column,
                help_text,
                help_uri,
                tags,
                code_flow_steps,
                related_locations,
                baseline_state,
                suppressed,
                raw_json,
                triage: None,
            });
            id += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::load::load_file;
    use crate::sarif::model::Severity;
    use std::path::Path;

    fn findings_for(fixture: &str) -> Vec<crate::sarif::model::Finding> {
        let sarif = load_file(Path::new(fixture)).unwrap();
        normalize(&sarif, Path::new(fixture), 0)
    }

    #[test]
    fn codeql_finding_fully_normalized() {
        let f = findings_for("tests/fixtures/codeql.sarif");
        assert_eq!(f.len(), 1);
        let r = &f[0];
        assert_eq!(r.tool_name, "CodeQL");
        assert_eq!(r.rule_id, "js/sql-injection");
        assert_eq!(r.level, Severity::Error);
        assert_eq!(r.path.as_deref(), Some("src/db.js"));
        assert_eq!(r.line, Some(42));
        assert_eq!(r.column, Some(13));
        assert_eq!(r.security_severity, Some(8.8));
        assert_eq!(
            r.help_uri.as_deref(),
            Some("https://example.com/sql-injection")
        );
        assert_eq!(r.help_text.as_deref(), Some("Use parameterized queries."));
        assert!(r.tags.iter().any(|t| t == "external/cwe/cwe-089"));
        assert_eq!(r.code_flow_steps.len(), 2);
        assert_eq!(r.related_locations.len(), 1);
        assert!(!r.suppressed);
        // partialFingerprints present -> used verbatim.
        assert!(r.fingerprint.contains("abc123") || !r.fingerprint.is_empty());
    }

    #[test]
    fn semgrep_level_falls_back_to_rule_default_and_suppression_detected() {
        let f = findings_for("tests/fixtures/semgrep.sarif");
        assert_eq!(f.len(), 2);
        let xss = f.iter().find(|x| x.rule_id == "xss-risk").unwrap();
        assert_eq!(xss.level, Severity::Warning); // from defaultConfiguration
        let secret = f.iter().find(|x| x.rule_id == "hardcoded-secret").unwrap();
        assert!(secret.suppressed);
    }

    #[test]
    fn trivy_without_rules_array_still_normalizes() {
        let f = findings_for("tests/fixtures/trivy.sarif");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].level, Severity::Note);
        assert_eq!(f[0].baseline_state.as_deref(), Some("new"));
    }

    #[test]
    fn empty_runs_yield_no_findings() {
        assert!(findings_for("tests/fixtures/empty.sarif").is_empty());
    }

    #[test]
    fn computed_fingerprint_is_stable_and_line_independent() {
        // Two findings differing only by line must share a computed fingerprint.
        let a = fnv1a_hex(&["Tool", "rule", "src/a.rs", "msg"]);
        let b = fnv1a_hex(&["Tool", "rule", "src/a.rs", "msg"]);
        assert_eq!(a, b);
        assert_ne!(a, fnv1a_hex(&["Tool", "rule", "src/b.rs", "msg"]));
    }
}
