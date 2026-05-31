use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity ordered ascending so `derive(Ord)` makes `Error` the greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    None,
    Note,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warning => "WARN",
            Severity::Note => "NOTE",
            Severity::None => "NONE",
        }
    }

    /// Parse a SARIF level string ("error"/"warning"/"note"/"none").
    pub fn from_sarif_str(s: &str) -> Option<Severity> {
        match s {
            "error" => Some(Severity::Error),
            "warning" => Some(Severity::Warning),
            "note" => Some(Severity::Note),
            "none" => Some(Severity::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageStatus {
    Confirmed,
    FalsePositive,
    NeedsReview,
    AcceptedRisk,
}

impl TriageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TriageStatus::Confirmed => "confirmed",
            TriageStatus::FalsePositive => "false_positive",
            TriageStatus::NeedsReview => "needs_review",
            TriageStatus::AcceptedRisk => "accepted_risk",
        }
    }

    pub fn from_status_str(s: &str) -> Option<TriageStatus> {
        match s {
            "confirmed" => Some(TriageStatus::Confirmed),
            "false_positive" => Some(TriageStatus::FalsePositive),
            "needs_review" => Some(TriageStatus::NeedsReview),
            "accepted_risk" => Some(TriageStatus::AcceptedRisk),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowStep {
    pub path: Option<String>,
    pub line: Option<u32>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelatedLocation {
    pub path: Option<String>,
    pub line: Option<u32>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: usize,
    pub fingerprint: String,
    pub source_file: PathBuf,
    pub run_index: usize,
    pub tool_name: String,
    pub rule_id: String,
    pub level: Severity,
    pub security_severity: Option<f32>,
    pub message: String,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub help_text: Option<String>,
    pub help_uri: Option<String>,
    pub tags: Vec<String>,
    pub code_flow_steps: Vec<FlowStep>,
    pub related_locations: Vec<RelatedLocation>,
    pub baseline_state: Option<String>,
    pub suppressed: bool,
    pub raw_json: serde_json::Value,
    /// Joined from triage state at load time; None until triaged.
    pub triage: Option<TriageStatus>,
}

impl Finding {
    /// "src/db.js:42" style location for table/list display.
    pub fn location_str(&self) -> String {
        match (&self.path, self.line) {
            (Some(p), Some(l)) => format!("{p}:{l}"),
            (Some(p), None) => p.clone(),
            _ => "-".to_string(),
        }
    }

    /// High/Med/Low bucket from security-severity score, if present.
    pub fn severity_bucket(&self) -> Option<&'static str> {
        self.security_severity.map(|s| {
            if s >= 7.0 {
                "High"
            } else if s >= 4.0 {
                "Med"
            } else {
                "Low"
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_error_highest() {
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Note);
        assert!(Severity::Note > Severity::None);
        let mut v = vec![Severity::Note, Severity::Error, Severity::None];
        v.sort();
        assert_eq!(v, vec![Severity::None, Severity::Note, Severity::Error]);
    }

    #[test]
    fn severity_roundtrips_sarif_str() {
        assert_eq!(Severity::from_sarif_str("error"), Some(Severity::Error));
        assert_eq!(Severity::from_sarif_str("bogus"), None);
    }

    #[test]
    fn triage_status_roundtrips() {
        for s in ["confirmed", "false_positive", "needs_review", "accepted_risk"] {
            assert_eq!(TriageStatus::from_status_str(s).unwrap().as_str(), s);
        }
    }

    #[test]
    fn severity_bucket_thresholds() {
        let mk = |score: Option<f32>| Finding {
            id: 0,
            fingerprint: String::new(),
            source_file: PathBuf::new(),
            run_index: 0,
            tool_name: String::new(),
            rule_id: String::new(),
            level: Severity::Note,
            security_severity: score,
            message: String::new(),
            path: None,
            line: None,
            column: None,
            help_text: None,
            help_uri: None,
            tags: vec![],
            code_flow_steps: vec![],
            related_locations: vec![],
            baseline_state: None,
            suppressed: false,
            raw_json: serde_json::Value::Null,
            triage: None,
        };
        assert_eq!(mk(Some(9.0)).severity_bucket(), Some("High"));
        assert_eq!(mk(Some(5.0)).severity_bucket(), Some("Med"));
        assert_eq!(mk(Some(1.0)).severity_bucket(), Some("Low"));
        assert_eq!(mk(None).severity_bucket(), None);
    }
}
