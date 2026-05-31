pub mod load;
pub mod model;
pub mod normalize;

pub use model::{Finding, FlowStep, RelatedLocation, Severity, TriageStatus};

use anyhow::Result;
use std::path::Path;

/// Load + normalize many SARIF paths into one id-contiguous finding list.
pub fn load_findings(paths: &[std::path::PathBuf]) -> Result<Vec<Finding>> {
    let mut all = Vec::new();
    for path in paths {
        let sarif = load::load_file(path)?;
        let next = all.len();
        all.extend(normalize::normalize(&sarif, path, next));
    }
    Ok(all)
}

/// Load + normalize SARIF read from stdin.
pub fn load_findings_stdin() -> Result<Vec<Finding>> {
    let sarif = load::load_stdin()?;
    Ok(normalize::normalize(&sarif, Path::new("<stdin>"), 0))
}
