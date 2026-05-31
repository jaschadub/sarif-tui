# sarif-tui

A fast terminal UI for exploring [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
static-analysis reports from tools like CodeQL, Semgrep, Trivy, Clippy,
ShellCheck, Snyk, and custom AI code auditors.

## Install

```bash
cargo install --path .
# or run from source
cargo run -- report.sarif
```

## Usage

```bash
# Interactive TUI
sarif-tui report.sarif
sarif-tui reports/*.sarif
cat report.sarif.gz | sarif-tui        # stdin, gzip auto-detected

# Non-interactive CLI
sarif-tui summary report.sarif         # counts by tool / severity / rule / file
sarif-tui list report.sarif            # one row per finding
sarif-tui diff old.sarif new.sarif     # new / fixed / unchanged baseline
```

## Keys

| Key | Action |
|-----|--------|
| `j` / `k` | move down / up |
| `/` | fuzzy search |
| `f` | filter panel (severity, tool, suppressed, rule, path) |
| `s` | cycle sort (severity / file / rule) |
| `r` | toggle raw JSON in details |
| `y` | copy finding JSON to clipboard |
| `o` | open finding in `$EDITOR` |
| `O` | open source file with system handler |
| `e` | export visible findings to `sarif-export.{json,md}` |
| `t` | set triage status (confirmed / false positive / needs review / accepted risk) |
| `n` | add a triage note |
| `?` | help |
| `q` | quit |

In the filter panel: `1`–`4` toggle severities, `t` cycles the tool filter,
`s` hides suppressed findings, `r`/`p` edit the rule/path substring filters,
and `c` clears everything.

## Triage state

Triage decisions are saved to `.sarif-tui-state.json` in the working directory,
keyed by a stable per-finding fingerprint (SARIF's own fingerprint when present,
otherwise a line-independent hash of tool + rule + path + message). State is
re-joined onto findings on the next run, so your review survives code movement
and re-scans.

```json
{
  "version": 1,
  "entries": {
    "<fingerprint>": {
      "status": "false_positive",
      "reviewer": "jascha",
      "notes": "sanitized upstream",
      "timestamp": "2026-05-31T12:00:00Z"
    }
  }
}
```

## Supported input

- SARIF 2.1.0 JSON (single file, multiple files, globs, stdin)
- Gzipped SARIF (auto-detected by magic bytes)

## Architecture

Raw SARIF is parsed by [`serde-sarif`](https://crates.io/crates/serde-sarif) and
immediately normalized into an app-owned `Finding` model — the UI never touches
raw SARIF. `App` holds pure, testable state; `ui/` is render-only; `actions/`
performs side effects (clipboard, editor, export) that degrade gracefully when
unavailable. Triage and diff are keyed by a stable per-finding fingerprint.

```
src/
  cli.rs            summary / list / diff commands
  sarif/            model, load (file/stdin/gzip/glob), normalize
  triage/           state persistence + diff/baseline
  app.rs            pure App state + transitions
  event.rs          key handling + side-effect execution
  ui/               ratatui rendering (findings, details, filters, triage, help)
  actions/          clipboard, open-in-editor, export
```

## Security

SARIF reports are treated as untrusted input. File paths drawn from a report are
neutralized before being handed to `$EDITOR` or the system opener, so a crafted
`artifactLocation.uri` cannot smuggle command-line flags (argv flag smuggling).

## Development

```bash
cargo test -j2
cargo clippy -j2 --all-targets
```

## License

MIT
