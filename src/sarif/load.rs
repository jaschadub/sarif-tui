use anyhow::{Context, Result};
use serde_sarif::sarif::Sarif;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Detect gzip by magic bytes (0x1f 0x8b) rather than file extension.
fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

fn parse_bytes(bytes: &[u8]) -> Result<Sarif> {
    let json = if is_gzip(bytes) {
        let mut s = String::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_string(&mut s)
            .context("failed to gunzip SARIF")?;
        s
    } else {
        String::from_utf8(bytes.to_vec()).context("SARIF was not valid UTF-8")?
    };
    serde_json::from_str(&json).context("failed to parse SARIF JSON")
}

/// Load a single SARIF file (transparently gunzipping if needed).
pub fn load_file(path: &Path) -> Result<Sarif> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_bytes(&bytes).with_context(|| format!("in {}", path.display()))
}

/// Load SARIF from stdin (transparently gunzipping if needed).
pub fn load_stdin() -> Result<Sarif> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .context("failed to read stdin")?;
    parse_bytes(&bytes).context("from stdin")
}

/// Expand CLI path arguments: literal files plus any glob patterns
/// (e.g. `reports/*.sarif`). A pattern that matches nothing falls back to
/// being treated as a literal path so the caller gets a clear "not found".
pub fn expand_paths(args: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for arg in args {
        let mut matched = false;
        if let Ok(paths) = glob::glob(arg) {
            for entry in paths.flatten() {
                out.push(entry);
                matched = true;
            }
        }
        if !matched {
            out.push(PathBuf::from(arg));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_plain_sarif_file() {
        let sarif = load_file(std::path::Path::new("tests/fixtures/codeql.sarif")).unwrap();
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "CodeQL");
    }

    #[test]
    fn loads_gzipped_sarif_file() {
        // Gzip the codeql fixture into a temp .sarif.gz, then load it.
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let raw = std::fs::read("tests/fixtures/codeql.sarif").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let gz_path = dir.path().join("codeql.sarif.gz");
        let mut enc =
            GzEncoder::new(std::fs::File::create(&gz_path).unwrap(), Compression::default());
        enc.write_all(&raw).unwrap();
        enc.finish().unwrap();
        let sarif = load_file(&gz_path).unwrap();
        assert_eq!(sarif.runs[0].tool.driver.name, "CodeQL");
    }
}
