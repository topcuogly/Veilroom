//! Explicit clipboard copy support (terminal security, section 25).
//!
//! Veilroom never writes to the clipboard automatically; copying is always
//! an explicit user action (a keyboard shortcut). Copying uses external
//! clipboard tools so that no native clipboard dependency is required:
//! `wl-copy` on Wayland, then `xclip` and `xsel` on X11. The full value is
//! written verbatim; nothing is shortened or truncated.
//!
//! The value being copied is the complete invitation URI retained in
//! memory, never the shortened preview.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::process::{Command, Stdio};

use thiserror::Error;

/// Errors produced while copying to the clipboard.
#[derive(Debug, Error)]
pub enum ClipboardError {
    /// No clipboard tool could be found or started.
    #[error("no clipboard tool available (install wl-clipboard, xclip, or xsel)")]
    NoBackend,
    /// The clipboard tool could not be spawned or waited on.
    #[error("the clipboard tool could not be started: {0}")]
    Spawn(std::io::Error),
    /// Writing the value into the clipboard tool failed.
    #[error("writing to the clipboard tool failed: {0}")]
    Write(std::io::Error),
    /// The clipboard tool exited unsuccessfully.
    #[error("the clipboard tool exited with an error")]
    Exit,
    /// The clipboard backend did not finish promptly.
    #[error("the clipboard tool timed out")]
    Timeout,
}

/// Copies `text` to the clipboard through the platform clipboard tool.
pub fn copy_to_clipboard(text: &str) -> Result<(), ClipboardError> {
    copy_to_clipboard_with_backends(text, &detect_backends())
}

/// The candidate clipboard backends for the current display environment.
fn detect_backends() -> Vec<OsString> {
    let mut backends = Vec::new();
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        backends.push(OsString::from("wl-copy"));
    }
    if std::env::var_os("DISPLAY").is_some() {
        backends.push(OsString::from("xclip"));
        backends.push(OsString::from("xsel"));
    }
    if backends.is_empty() {
        backends.extend(["wl-copy", "xclip", "xsel"].map(OsString::from));
    }
    backends
}

/// Copies `text` through the first backend that exists and succeeds.
///
/// Each backend name may be a `PATH` lookup or an absolute path (used by
/// tests with a fake tool). A backend that exists but fails does not stop
/// the remaining candidates from being tried.
fn copy_to_clipboard_with_backends(
    text: &str,
    backends: &[OsString],
) -> Result<(), ClipboardError> {
    let mut last_error = None;
    for backend in backends {
        match spawn_backend(backend, text) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(ClipboardError::NoBackend))
}

/// Spawns one clipboard backend and feeds `text` to its stdin.
fn spawn_backend(backend: &OsStr, text: &str) -> Result<(), ClipboardError> {
    let mut command = Command::new(backend);
    let name = std::path::Path::new(backend).file_name().unwrap_or(backend);
    if name == OsStr::new("wl-copy") {
        command.arg("--type").arg("text/plain;charset=utf-8");
    } else if name == OsStr::new("xclip") {
        // xclip defaults to PRIMARY. Terminal paste shortcuts read the
        // CLIPBOARD selection, so selecting it explicitly is essential.
        command.args(["-selection", "clipboard", "-in"]);
    } else if name == OsStr::new("xsel") {
        command.args(["--clipboard", "--input"]);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ClipboardError::NoBackend
            } else {
                ClipboardError::Spawn(error)
            }
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ClipboardError::Write(std::io::Error::other("the child has no stdin")))?;
    stdin
        .write_all(text.as_bytes())
        .map_err(ClipboardError::Write)?;
    drop(stdin);
    let status = child.wait().map_err(ClipboardError::Spawn)?;
    if status.success() {
        Ok(())
    } else {
        Err(ClipboardError::Exit)
    }
}

/// Copies without blocking the async TUI indefinitely.
pub async fn copy_to_clipboard_async(text: String) -> Result<(), ClipboardError> {
    let task = tokio::task::spawn_blocking(move || copy_to_clipboard(&text));
    match tokio::time::timeout(std::time::Duration::from_secs(2), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(ClipboardError::Spawn(std::io::Error::other(
            error.to_string(),
        ))),
        Err(_) => Err(ClipboardError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A temp directory for one test, cleaned up on drop.
    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("veilroom-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fake clipboard backend whose stdout is discarded and whose stdin is
    /// appended to `out`.
    fn fake_backend(dir: &std::path::Path, out: &std::path::Path) -> std::path::PathBuf {
        let script = dir.join("fake-clipboard");
        let content = format!("#!/usr/bin/env bash\ncat > '{}'\n", out.display());
        std::fs::write(&script, content).unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        script
    }

    #[test]
    fn copy_writes_the_full_uri_verbatim() {
        let dir = TestDir::new("clipboard-full");
        let out = dir.path().join("clipboard.txt");
        let backend = fake_backend(dir.path(), &out);

        // A full-length invitation URI (56-char onion body, 32-byte token).
        let body = "a".repeat(56);
        let token = "0123456789abcdef0123456789abcdef";
        let uri = format!("veilroom://{body}.onion:80?v=1&token={token}");

        copy_to_clipboard_with_backends(&uri, &[backend.into_os_string()]).unwrap();
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(written, uri, "the copied value is the complete URI");
        assert!(written.contains(token), "the token must be copied in full");
        assert_eq!(written.len(), uri.len());
    }

    #[test]
    fn copy_reports_a_missing_backend() {
        let dir = TestDir::new("clipboard-missing");
        let backends = [dir.path().join("does-not-exist").into_os_string()];
        let error = copy_to_clipboard_with_backends("x", &backends).unwrap_err();
        assert!(matches!(error, ClipboardError::NoBackend));
    }

    #[test]
    fn xclip_targets_the_clipboard_selection() {
        let dir = TestDir::new("clipboard-xclip-args");
        let out = dir.path().join("clipboard.txt");
        let args = dir.path().join("args.txt");
        let backend = dir.path().join("xclip");
        let content = format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\n",
            args.display(),
            out.display()
        );
        std::fs::write(&backend, content).unwrap();
        let mut permissions = std::fs::metadata(&backend).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&backend, permissions).unwrap();

        copy_to_clipboard_with_backends("full uri", &[backend.into_os_string()]).unwrap();
        assert_eq!(
            std::fs::read_to_string(args).unwrap(),
            "-selection\nclipboard\n-in\n"
        );
        assert_eq!(std::fs::read_to_string(out).unwrap(), "full uri");
    }
}
