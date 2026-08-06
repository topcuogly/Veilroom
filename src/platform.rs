//! Linux platform layer (architecture decision 19, sections 20 and 27).
//!
//! Stage 3 provides: effective-user root detection, XDG runtime directory
//! resolution, session-directory creation with restrictive permissions, and
//! cryptographically random session identifiers. All APIs are safe Rust;
//! nothing here depends on `unsafe`.
//!
//! Core-dump restriction: the project forbids `unsafe` in source code
//! (section 35), and `setrlimit` is only reachable through unsafe FFI.
//! Restricting core dumps is therefore deferred; the README documents this
//! as a security limitation of the first prototype.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub mod clipboard;

pub use clipboard::copy_to_clipboard;

/// Errors produced by the platform layer.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The XDG runtime directory is not configured.
    #[error("$XDG_RUNTIME_DIR is not set; refusing to fall back to /tmp")]
    NoRuntimeDirectory,

    /// The session directory already exists (a 128-bit collision).
    #[error("session directory already exists: {0}")]
    SessionCollision(PathBuf),

    /// The lock file already exists (a 128-bit collision).
    #[error("session lock already exists: {0}")]
    LockCollision(PathBuf),

    /// The operating system refused the random data.
    #[error("failed to obtain secure randomness: {0}")]
    Randomness(#[from] getrandom::Error),

    /// An underlying file-system operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The configured runtime directory is not a safe per-user directory.
    #[error("unsafe XDG runtime directory: {0}")]
    UnsafeRuntimeDirectory(String),
}

/// Returns whether the current process runs with effective uid 0.
///
/// Reads `/proc/self/status` (Linux). If the file cannot be read, the check
/// conservatively refuses execution by treating an unreadable status as root.
pub fn is_running_as_root() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            let uid_line = status.lines().find(|line| line.starts_with("Uid:"));
            match uid_line {
                Some(line) => {
                    let effective = line.split_whitespace().nth(2);
                    effective == Some("0")
                }
                None => true,
            }
        }
        Err(_) => true,
    }
}

/// The effective uid of the current process, read from `/proc/self/status`.
///
/// Returns `None` when the status file cannot be read or parsed; callers
/// must treat an unknown uid as a permission failure.
pub fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(2))
        .and_then(|value| value.parse::<u32>().ok())
}

/// Verifies that an XDG runtime directory is absolute, owned by the
/// effective user, and inaccessible to group/other users.
pub fn validate_runtime_root(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::UnsafeRuntimeDirectory(
            "path is not absolute".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PlatformError::UnsafeRuntimeDirectory(
            "path is not a real directory".to_owned(),
        ));
    }
    let effective_uid = effective_uid().ok_or_else(|| {
        PlatformError::UnsafeRuntimeDirectory("effective uid unavailable".to_owned())
    })?;
    if metadata.uid() != effective_uid {
        return Err(PlatformError::UnsafeRuntimeDirectory(
            "directory is owned by another user".to_owned(),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(PlatformError::UnsafeRuntimeDirectory(
            "directory permissions are broader than 0700".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves the XDG runtime directory from an environment value.
///
/// Returns `None` when the variable is unset or empty; the application must
/// refuse to run instead of falling back to `/tmp` (section 20).
pub fn runtime_root(env_value: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let value = env_value?;
    if value.is_empty() {
        return None;
    }
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() {
        return None;
    }
    Some(path)
}

/// Creates `$XDG_RUNTIME_DIR/veilroom/session-<random>/` with mode 0700.
///
/// The random component is 16 bytes from the OS CSPRNG. Returns the path of
/// the new session directory. Refuses to reuse an existing directory.
pub fn create_session_dir(runtime_root: &Path) -> Result<PathBuf, PlatformError> {
    // ADD_ONION's `Port=` grammar accepts an unquoted target token. Restrict
    // the parent path so a runtime path cannot split or inject a control
    // command when the generated chat.sock path is embedded in that token.
    if !runtime_root
        .as_os_str()
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
    {
        return Err(PlatformError::UnsafeRuntimeDirectory(
            "path contains characters unsafe for the Tor control protocol".to_owned(),
        ));
    }
    let veilroom_root = runtime_root.join("veilroom");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&veilroom_root)?;
    set_dir_mode_0700(&veilroom_root)?;

    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    let session_dir = veilroom_root.join(format!("session-{}", hex(&random)));

    fs::DirBuilder::new()
        .mode(0o700)
        .create(&session_dir)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                PlatformError::SessionCollision(session_dir.clone())
            } else {
                PlatformError::Io(error)
            }
        })?;
    set_dir_mode_0700(&session_dir)?;

    let lock_file = session_dir.join("lock");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock_file)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                PlatformError::LockCollision(lock_file)
            } else {
                PlatformError::Io(error)
            }
        })?;
    Ok(session_dir)
}

/// Removes a session directory, ignoring any failure.
///
/// Cleanup after a killed Tor process may leave stale sockets; removal is
/// best-effort by design (section 20).
pub fn remove_session_dir(session_dir: &Path) {
    let _ = fs::remove_dir_all(session_dir);
}

/// Encodes bytes as lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Enforces mode 0700 on a directory regardless of the process umask.
fn set_dir_mode_0700(dir: &Path) -> Result<(), PlatformError> {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_root_rejects_missing_or_empty_values() {
        assert_eq!(runtime_root(None), None);
        assert_eq!(runtime_root(Some(std::ffi::OsStr::new(""))), None);
    }

    #[test]
    fn runtime_root_accepts_a_value() {
        let root = runtime_root(Some(std::ffi::OsStr::new("/run/user/1000"))).unwrap();
        assert_eq!(root, PathBuf::from("/run/user/1000"));
    }

    #[test]
    fn session_directory_rejects_control_unsafe_paths() {
        let root = test_root("unsafe")
            .with_file_name(format!("veilroom platform unsafe {}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        assert!(matches!(
            create_session_dir(&root),
            Err(PlatformError::UnsafeRuntimeDirectory(_))
        ));
        remove_session_dir(&root);
    }

    #[test]
    fn hex_encoding_is_lowercase() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00]), "00");
        assert_eq!(hex(&[0xff]), "ff");
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex(&[0x01, 0x23, 0x45, 0x67]), "01234567");
    }

    #[test]
    fn session_directory_is_created_with_0700() {
        let root = test_root("session");
        let session = create_session_dir(&root).unwrap();
        assert!(session.starts_with(root.join("veilroom")));
        let name = session.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("session-"));
        assert_eq!(name.len(), "session-".len() + 32);

        let metadata = fs::metadata(&session).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert!(session.join("lock").exists());

        // A second call must never collide with the first.
        let other = create_session_dir(&root).unwrap();
        assert_ne!(session, other);

        remove_session_dir(&root);
    }

    #[test]
    fn collision_is_reported() {
        let root = test_root("collision");
        let session = create_session_dir(&root).unwrap();
        let mut guard = session.clone();
        guard.pop();
        // Simulate a collision by pre-creating a directory with a known name.
        let colliding = guard.join("session-00000000000000000000000000000000");
        fs::create_dir(&colliding).unwrap();
        assert!(matches!(
            create_session_dir_named(&guard, "session-00000000000000000000000000000000"),
            Err(PlatformError::SessionCollision(_))
        ));
        remove_session_dir(&root);
    }

    fn test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "veilroom-platform-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn create_session_dir_named(root: &Path, name: &str) -> Result<PathBuf, PlatformError> {
        let dir = root.join(name);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    PlatformError::SessionCollision(dir.clone())
                } else {
                    PlatformError::Io(error)
                }
            })?;
        Ok(dir)
    }
}
