/// Build the (program, args) to open `path` at `line` for a given `$EDITOR`
/// string. Handles VS Code's `-g file:line` and the `+line file` convention
/// used by vim/nvim/nano/emacs/kak; otherwise just passes the path.
pub fn editor_command(editor: &str, path: &str, line: Option<u32>) -> (String, Vec<String>) {
    let mut parts = editor.split_whitespace();
    let prog = parts.next().unwrap_or(editor).to_string();
    let mut args: Vec<String> = parts.map(|s| s.to_string()).collect();
    let lower = prog.to_lowercase();

    if lower.contains("code") || lower.contains("codium") {
        args.push("-g".to_string());
        match line {
            Some(l) => args.push(format!("{path}:{l}")),
            None => args.push(path.to_string()),
        }
    } else if lower == "vi"
        || lower.contains("vim")
        || lower.contains("nano")
        || lower.contains("emacs")
        || lower.contains("kak")
    {
        if let Some(l) = line {
            args.push(format!("+{l}"));
        }
        args.push(path.to_string());
    } else {
        args.push(path.to_string());
    }
    (prog, args)
}

/// Open `path` at `line` in `$VISUAL`/`$EDITOR`; falls back to the system opener.
/// Returns a human-readable error string when it cannot (degrade gracefully).
pub fn open_in_editor(path: &str, line: Option<u32>) -> Result<(), String> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .ok()
        .filter(|e| !e.trim().is_empty());

    match editor {
        Some(ed) => {
            let (prog, args) = editor_command(&ed, path, line);
            std::process::Command::new(&prog)
                .args(&args)
                .status()
                .map_err(|e| format!("failed to launch {prog}: {e}"))
                .and_then(|st| {
                    if st.success() {
                        Ok(())
                    } else {
                        Err(format!("{prog} exited with status {st}"))
                    }
                })
        }
        None => open_path(path),
    }
}

/// Open `path` with the OS default handler (degrade gracefully).
pub fn open_path(path: &str) -> Result<(), String> {
    open::that(path).map_err(|e| format!("could not open {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vscode_uses_goto_flag() {
        let (prog, args) = editor_command("code", "src/db.js", Some(42));
        assert_eq!(prog, "code");
        assert_eq!(args, vec!["-g".to_string(), "src/db.js:42".to_string()]);
    }

    #[test]
    fn vim_uses_plus_line() {
        let (prog, args) = editor_command("vim", "src/db.js", Some(42));
        assert_eq!(prog, "vim");
        assert_eq!(args, vec!["+42".to_string(), "src/db.js".to_string()]);
    }

    #[test]
    fn editor_with_flags_is_split() {
        let (prog, args) = editor_command("code --wait", "f.rs", None);
        assert_eq!(prog, "code");
        assert_eq!(
            args,
            vec!["--wait".to_string(), "-g".to_string(), "f.rs".to_string()]
        );
    }

    #[test]
    fn unknown_editor_just_gets_path() {
        let (prog, args) = editor_command("myeditor", "f.rs", Some(9));
        assert_eq!(prog, "myeditor");
        assert_eq!(args, vec!["f.rs".to_string()]);
    }
}
