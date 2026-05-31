use crate::sarif::{Finding, TriageStatus};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const DEFAULT_STATE_FILE: &str = ".sarif-tui-state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageEntry {
    pub status: String,
    pub reviewer: String,
    pub notes: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageState {
    pub version: u32,
    pub entries: BTreeMap<String, TriageEntry>,
}

impl Default for TriageState {
    fn default() -> Self {
        TriageState {
            version: 1,
            entries: BTreeMap::new(),
        }
    }
}

impl TriageState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self)?;
        std::fs::write(path, s).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn upsert(
        &mut self,
        fingerprint: &str,
        status: TriageStatus,
        reviewer: &str,
        notes: &str,
        timestamp: &str,
    ) {
        self.entries.insert(
            fingerprint.to_string(),
            TriageEntry {
                status: status.as_str().to_string(),
                reviewer: reviewer.to_string(),
                notes: notes.to_string(),
                timestamp: timestamp.to_string(),
            },
        );
    }

    pub fn remove(&mut self, fingerprint: &str) {
        self.entries.remove(fingerprint);
    }

    pub fn status_of(&self, fingerprint: &str) -> Option<TriageStatus> {
        self.entries
            .get(fingerprint)
            .and_then(|e| TriageStatus::from_status_str(&e.status))
    }

    pub fn notes_of(&self, fingerprint: &str) -> Option<&str> {
        self.entries.get(fingerprint).map(|e| e.notes.as_str())
    }

    /// Join triage status onto findings (called once at load).
    pub fn apply(&self, findings: &mut [Finding]) {
        for f in findings.iter_mut() {
            f.triage = self.status_of(&f.fingerprint);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::{load_findings, TriageStatus};
    use std::path::PathBuf;

    #[test]
    fn upsert_and_status_roundtrip() {
        let mut s = TriageState::new();
        s.upsert(
            "fp1",
            TriageStatus::FalsePositive,
            "jascha",
            "looks safe",
            "2026-05-31T00:00:00Z",
        );
        assert_eq!(s.status_of("fp1"), Some(TriageStatus::FalsePositive));
        assert_eq!(s.entries.get("fp1").unwrap().notes, "looks safe");
    }

    #[test]
    fn save_then_load_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".sarif-tui-state.json");
        let mut s = TriageState::new();
        s.upsert(
            "fp1",
            TriageStatus::Confirmed,
            "jascha",
            "",
            "2026-05-31T00:00:00Z",
        );
        s.save(&path).unwrap();
        let loaded = TriageState::load(&path).unwrap();
        assert_eq!(loaded.status_of("fp1"), Some(TriageStatus::Confirmed));
    }

    #[test]
    fn load_missing_file_yields_empty_state() {
        let s = TriageState::load(&PathBuf::from("/nonexistent/.sarif-tui-state.json")).unwrap();
        assert!(s.entries.is_empty());
        assert_eq!(s.version, 1);
    }

    #[test]
    fn apply_joins_status_onto_findings_by_fingerprint() {
        let mut findings =
            load_findings(&[PathBuf::from("tests/fixtures/codeql.sarif")]).unwrap();
        let fp = findings[0].fingerprint.clone();
        let mut s = TriageState::new();
        s.upsert(&fp, TriageStatus::NeedsReview, "jascha", "", "2026-05-31T00:00:00Z");
        s.apply(&mut findings);
        assert_eq!(findings[0].triage, Some(TriageStatus::NeedsReview));
    }
}
