/// Copy `text` to the system clipboard. Returns a friendly error string when
/// no clipboard is available (e.g. a headless box with no display server).
pub fn copy(text: &str) -> Result<(), String> {
    match arboard::Clipboard::new() {
        Ok(mut cb) => cb
            .set_text(text.to_string())
            .map_err(|e| format!("clipboard write failed: {e}")),
        Err(e) => Err(format!("clipboard unavailable: {e}")),
    }
}
