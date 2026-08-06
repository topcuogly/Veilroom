//! Tor subprocess management (architecture decisions 9 and 2, sections 19-21).
//!
//! Every Veilroom process launches and manages its own Tor subprocess; it
//! never depends on a system-wide daemon. The manager:
//!
//! - resolves the runtime directory under `$XDG_RUNTIME_DIR`,
//! - discovers the Tor binary (`--tor-binary` override, then `PATH`),
//! - spawns Tor with Unix-socket control and SOCKS endpoints,
//! - authenticates with the control cookie,
//! - waits for the bootstrap to complete,
//! - creates an ephemeral v3 onion service with `ADD_ONION` (no `Detach`,
//!   Unix-socket local target),
//! - shuts the service and subprocess down in a controlled way.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

use crate::constants::ONION_V3_ALPHABET;
use crate::platform::{self, PlatformError};
use crate::tor::control::{ControlClient, ControlError};
use crate::tor::parser::Reply;

/// Configuration for a Tor session.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Explicit Tor binary path (`--tor-binary` override), searched before
    /// `PATH`.
    pub tor_binary: Option<PathBuf>,
    /// Time allowed for bootstrap completion.
    pub bootstrap_timeout: Duration,
    /// Time allowed for the control socket to appear and accept connections.
    pub control_connect_timeout: Duration,
    /// Time allowed for the subprocess to exit after a shutdown signal.
    pub child_exit_timeout: Duration,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            tor_binary: None,
            bootstrap_timeout: Duration::from_secs(120),
            control_connect_timeout: Duration::from_secs(30),
            child_exit_timeout: Duration::from_secs(10),
        }
    }
}

/// Errors produced by the Tor manager.
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    /// `$XDG_RUNTIME_DIR` is not configured.
    #[error(transparent)]
    Platform(#[from] PlatformError),

    /// The application must not run as root.
    #[error("refusing to run as root")]
    RunningAsRoot,

    /// The Tor binary could not be found on `PATH`.
    #[error("tor binary not found; install tor or pass --tor-binary")]
    TorBinaryNotFound,

    /// The Tor subprocess could not be spawned.
    #[error("failed to spawn tor: {0}")]
    SpawnFailed(#[source] io::Error),

    /// The control connection could not be established.
    #[error(transparent)]
    Control(#[from] ControlError),

    /// The control cookie file is missing or malformed.
    #[error("control cookie unavailable: {0}")]
    Cookie(String),

    /// The bootstrap did not complete in time.
    #[error("tor bootstrap timed out after {timeout:?}")]
    BootstrapTimeout {
        /// The configured bootstrap timeout.
        timeout: Duration,
    },

    /// Tor rejected a control command.
    ///
    /// The message includes Tor's full reply: the status code and every
    /// line Tor sent in response.
    #[error("tor command `{command}` failed ({reply})")]
    CommandFailed {
        /// The rejected command.
        command: String,
        /// The reply Tor sent.
        reply: Reply,
    },

    /// An `ADD_ONION` reply did not contain a usable service id.
    #[error("ADD_ONION reply did not contain a valid service id")]
    InvalidServiceId,

    /// The onion address returned by Tor is not a valid v3 address.
    #[error("tor returned an invalid onion address: {0}")]
    InvalidOnionAddress(String),

    /// The virtual port of an onion service must be non-zero.
    #[error("onion service virtual port must be non-zero")]
    InvalidVirtualPort,

    /// The control connection has not been established.
    #[error("tor control connection is not established")]
    NoControlConnection,

    /// The Tor subprocess ended unexpectedly.
    #[error("tor subprocess exited unexpectedly")]
    TorExited,

    /// The subprocess did not exit in time after a shutdown signal.
    #[error("tor subprocess did not exit within {timeout:?}")]
    ChildExitTimeout {
        /// The configured child-exit timeout.
        timeout: Duration,
    },

    /// An underlying file-system operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The on-disk layout of one Tor session (section 20).
#[derive(Debug, Clone)]
pub struct SessionPaths {
    /// `session-<random>/`
    pub session_dir: PathBuf,
    /// Tor's data directory (cookie, cache, state).
    pub tor_data: PathBuf,
    /// Control socket for this application.
    pub control_socket: PathBuf,
    /// SOCKS socket used by room connections.
    pub socks_socket: PathBuf,
    /// Unix socket the onion service forwards to (the app listener).
    pub chat_socket: PathBuf,
    /// Lock sentinel of the session.
    pub lock_file: PathBuf,
    /// Reserved compatibility path; production does not create this file.
    pub tor_log: PathBuf,
}

/// A created ephemeral onion service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionService {
    /// Full v3 onion address, including the `.onion` suffix.
    pub onion_address: String,
    /// The virtual port of the service.
    pub virtual_port: u16,
}

/// Configuration handed to the subprocess spawner.
#[derive(Debug, Clone)]
pub struct SpawnConfig {
    /// The resolved Tor binary path.
    pub binary: PathBuf,
    /// The session paths.
    pub paths: SessionPaths,
}

/// Owns one Tor subprocess and its control connection.
#[derive(Debug)]
pub struct TorManager {
    config: TorConfig,
    paths: SessionPaths,
    child: Option<Child>,
    control: Option<ControlClient>,
    onion: Option<OnionService>,
}

impl TorManager {
    /// Prepares a session using `$XDG_RUNTIME_DIR`.
    ///
    /// Refuses to run when the variable is unset or when running as root.
    pub fn prepare() -> Result<Self, TorError> {
        let root = platform::runtime_root(std::env::var_os("XDG_RUNTIME_DIR").as_deref())
            .ok_or(TorError::Platform(PlatformError::NoRuntimeDirectory))?;
        platform::validate_runtime_root(&root)?;
        Self::prepare_in(&root)
    }

    /// Prepares a normal session with an explicit Tor executable.
    pub fn prepare_with_binary(binary: Option<PathBuf>) -> Result<Self, TorError> {
        let root = platform::runtime_root(std::env::var_os("XDG_RUNTIME_DIR").as_deref())
            .ok_or(TorError::Platform(PlatformError::NoRuntimeDirectory))?;
        platform::validate_runtime_root(&root)?;
        Self::prepare_with(
            &root,
            TorConfig {
                tor_binary: binary,
                ..TorConfig::default()
            },
        )
    }

    /// Prepares a session rooted at `runtime_root` (test and embedding seam).
    pub fn prepare_in(runtime_root: &Path) -> Result<Self, TorError> {
        Self::prepare_with(runtime_root, TorConfig::default())
    }

    /// Prepares a session rooted at `runtime_root` with an explicit config.
    pub fn prepare_with(runtime_root: &Path, config: TorConfig) -> Result<Self, TorError> {
        if platform::is_running_as_root() {
            return Err(TorError::RunningAsRoot);
        }
        let session_dir = platform::create_session_dir(runtime_root)?;
        let paths = SessionPaths {
            session_dir: session_dir.clone(),
            tor_data: session_dir.join("tor-data"),
            control_socket: session_dir.join("control.sock"),
            socks_socket: session_dir.join("socks.sock"),
            chat_socket: session_dir.join("chat.sock"),
            lock_file: session_dir.join("lock"),
            tor_log: session_dir.join("tor.log"),
        };
        Ok(Self {
            config,
            paths,
            child: None,
            control: None,
            onion: None,
        })
    }

    /// The session paths of this manager.
    pub fn paths(&self) -> &SessionPaths {
        &self.paths
    }

    /// The created onion service, if any.
    pub fn onion(&self) -> Option<&OnionService> {
        self.onion.as_ref()
    }

    /// Starts the Tor subprocess and brings the control session up.
    pub async fn start(&mut self) -> Result<(), TorError> {
        self.start_with(Self::spawn_tor).await
    }

    /// Starts Tor and reports each observed bootstrap percentage.
    ///
    /// The callback runs after a validated control reply is received. Values
    /// outside the inclusive `0..=100` range are rejected.
    pub async fn start_with_progress<P>(&mut self, progress: P) -> Result<(), TorError>
    where
        P: FnMut(u8),
    {
        self.start_with_callback(Self::spawn_tor, progress).await
    }

    /// Starts the session against an existing control connection.
    ///
    /// Test seam: authenticates and waits for bootstrap without spawning a
    /// subprocess. Used by the fake-controller tests.
    pub async fn start_with_control(&mut self, control: ControlClient) -> Result<(), TorError> {
        self.control = Some(control);
        self.authenticate_and_bootstrap().await
    }

    /// Internal start: spawns the subprocess with `spawn`, then connects.
    pub(crate) async fn start_with<F, Fut>(&mut self, spawn: F) -> Result<(), TorError>
    where
        F: FnOnce(SpawnConfig) -> Fut,
        Fut: Future<Output = io::Result<Child>>,
    {
        self.start_with_callback(spawn, |_| {}).await
    }

    /// Internal start implementation shared by production and test seams.
    async fn start_with_callback<F, Fut, P>(
        &mut self,
        spawn: F,
        progress: P,
    ) -> Result<(), TorError>
    where
        F: FnOnce(SpawnConfig) -> Fut,
        Fut: Future<Output = io::Result<Child>>,
        P: FnMut(u8),
    {
        let binary = resolve_tor_binary(self.config.tor_binary.as_deref())?;
        let child = spawn(SpawnConfig {
            binary,
            paths: self.paths.clone(),
        })
        .await?;
        self.child = Some(child);

        let control = ControlClient::connect(
            &self.paths.control_socket,
            self.config.control_connect_timeout,
        )
        .await?;
        self.control = Some(control);
        self.authenticate_and_bootstrap_with_progress(progress)
            .await
    }

    /// Spawns the Tor subprocess with the session configuration.
    ///
    /// Tor output is discarded: normal production sessions never create a
    /// file log and never corrupt the TUI's alternate screen.
    pub(crate) async fn spawn_tor(config: SpawnConfig) -> io::Result<Child> {
        let mut command = Command::new(&config.binary);
        command
            .arg("--DataDirectory")
            .arg(&config.paths.tor_data)
            .arg("--ControlSocket")
            .arg(&config.paths.control_socket)
            .arg("--SocksPort")
            .arg(format!("unix:{}", config.paths.socks_socket.display()))
            .arg("--CookieAuthentication")
            .arg("1")
            .arg("--SafeLogging")
            .arg("1")
            .arg("--AvoidDiskWrites")
            .arg("1")
            .arg("--Log")
            .arg("notice stderr")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command.spawn()
    }

    async fn authenticate_and_bootstrap(&mut self) -> Result<(), TorError> {
        self.authenticate_and_bootstrap_with_progress(|_| {}).await
    }

    async fn authenticate_and_bootstrap_with_progress<P>(
        &mut self,
        progress: P,
    ) -> Result<(), TorError>
    where
        P: FnMut(u8),
    {
        let cookie_hex =
            read_cookie_hex(&self.paths.tor_data, self.config.control_connect_timeout).await?;
        let control = self.control.as_mut().ok_or(TorError::NoControlConnection)?;
        control.authenticate(&cookie_hex).await?;
        self.wait_for_bootstrap(progress).await
    }

    /// Polls `GETINFO status/bootstrap-phase` until PROGRESS=100.
    async fn wait_for_bootstrap<P>(&mut self, mut progress: P) -> Result<(), TorError>
    where
        P: FnMut(u8),
    {
        let deadline = tokio::time::Instant::now() + self.config.bootstrap_timeout;
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if self.ensure_child_alive()? {
                return Err(TorError::TorExited);
            }
            let command = self
                .control
                .as_mut()
                .ok_or(TorError::NoControlConnection)?
                .command("GETINFO status/bootstrap-phase");
            let reply = tokio::time::timeout_at(deadline, command)
                .await
                .map_err(|_| TorError::BootstrapTimeout {
                    timeout: self.config.bootstrap_timeout,
                })??;
            let observed_progress = bootstrap_progress(&reply);
            if let Some(percent) = observed_progress {
                progress(percent);
            }
            if observed_progress == Some(100) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(TorError::BootstrapTimeout {
                    timeout: self.config.bootstrap_timeout,
                });
            }
            interval.tick().await;
        }
    }

    /// Creates an ephemeral v3 onion service for `virtual_port`.
    pub async fn add_onion(&mut self, virtual_port: u16) -> Result<OnionService, TorError> {
        if virtual_port == 0 {
            return Err(TorError::InvalidVirtualPort);
        }
        let command = format!(
            "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={virtual_port},unix:{}",
            self.paths.chat_socket.display()
        );
        let reply = self
            .control
            .as_mut()
            .ok_or(TorError::NoControlConnection)?
            .command(&command)
            .await?;
        if !reply.is_ok() {
            return Err(TorError::CommandFailed { command, reply });
        }
        let service_id = reply
            .lines
            .iter()
            .find_map(|line| line.strip_prefix("ServiceID="))
            .ok_or(TorError::InvalidServiceId)?;
        if service_id.len() != 56 {
            return Err(TorError::InvalidServiceId);
        }
        let onion_address = format!("{service_id}.onion");
        if !is_valid_onion_address(&onion_address) {
            return Err(TorError::InvalidOnionAddress(onion_address));
        }
        let service = OnionService {
            onion_address,
            virtual_port,
        };
        self.onion = Some(service.clone());
        Ok(service)
    }

    /// Shuts the onion service, the subprocess, and the session down.
    pub async fn shutdown(mut self) -> Result<(), TorError> {
        if let Some(control) = self.control.as_mut() {
            if let Some(onion) = self.onion.as_ref() {
                let service_id = onion
                    .onion_address
                    .strip_suffix(".onion")
                    .unwrap_or(&onion.onion_address);
                let _ = control.command(&format!("DEL_ONION {service_id}")).await;
            }
            let _ = control.command("SIGNAL SHUTDOWN").await;
        }
        self.control = None;
        self.onion = None;

        let mut result = Ok(());
        if let Some(mut child) = self.child.take() {
            let exited = tokio::time::timeout(self.config.child_exit_timeout, child.wait()).await;
            match exited {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => result = Err(TorError::Io(error)),
                Err(_) => {
                    if let Err(error) = child.kill().await {
                        result = Err(TorError::Io(error));
                    }
                    let _ = child.wait().await;
                    if result.is_ok() {
                        result = Err(TorError::ChildExitTimeout {
                            timeout: self.config.child_exit_timeout,
                        });
                    }
                }
            }
        }
        // Tor is gone: wipe the control cookie before the directory (which
        // also holds the socket files) is removed.
        wipe_cookie_file(&self.paths.tor_data).await;
        platform::remove_session_dir(&self.paths.session_dir);
        result
    }

    /// Returns true when a subprocess exists but has exited.
    fn ensure_child_alive(&mut self) -> Result<bool, TorError> {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Checks whether the owned Tor process ended during an active session.
    pub fn has_exited(&mut self) -> Result<bool, TorError> {
        self.ensure_child_alive()
    }
}

impl Drop for TorManager {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
    }
}

/// Extracts Tor's bootstrap percentage from a `GETINFO` reply.
///
/// Tor emits whitespace-delimited key/value fields. Parsing the field as a
/// bounded integer avoids treating unrelated text containing `PROGRESS=` as
/// a completed bootstrap.
fn bootstrap_progress(reply: &Reply) -> Option<u8> {
    reply
        .lines
        .iter()
        .flat_map(|line| line.split_ascii_whitespace())
        .find_map(|field| field.strip_prefix("PROGRESS="))
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|value| *value <= 100)
}

/// Resolves the Tor binary: explicit path first, then `PATH`.
fn resolve_tor_binary(explicit: Option<&Path>) -> Result<PathBuf, TorError> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(TorError::TorBinaryNotFound);
    }
    let path_value = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_value) {
        let candidate = dir.join("tor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(TorError::TorBinaryNotFound)
}

/// Reads and hex-encodes the control cookie, waiting for it to appear.
///
/// The cookie bytes and their hex form are held in zeroizing buffers and
/// never copied into plain allocations. The cookie file must be owned by
/// the current user with mode `0600`; a broader mode is rejected so a
/// pre-placed or misconfigured cookie cannot be silently accepted.
async fn read_cookie_hex(
    data_dir: &Path,
    timeout_duration: Duration,
) -> Result<zeroize::Zeroizing<String>, TorError> {
    let cookie_path = data_dir.join("control_auth_cookie");
    let deadline = tokio::time::Instant::now() + timeout_duration;
    loop {
        match tokio::fs::read(&cookie_path).await {
            Ok(cookie) if cookie.len() == 32 => {
                let metadata = tokio::fs::metadata(&cookie_path).await?;
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let Some(uid) = platform::effective_uid() else {
                    return Err(TorError::Cookie("effective uid unavailable".to_owned()));
                };
                if metadata.uid() != uid {
                    return Err(TorError::Cookie(
                        "cookie is owned by another user".to_owned(),
                    ));
                }
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(TorError::Cookie(
                        "cookie permissions are broader than 0600".to_owned(),
                    ));
                }
                let mut cookie = zeroize::Zeroizing::new(cookie);
                let hex_value = zeroize::Zeroizing::new(platform::hex(&cookie));
                cookie.clear();
                return Ok(hex_value);
            }
            Ok(_) => {
                return Err(TorError::Cookie(
                    "cookie has an unexpected length".to_owned(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(TorError::Cookie("cookie did not appear in time".to_owned()));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(TorError::Io(error)),
        }
    }
}

/// Best-effort wipe of the control cookie before the session directory is
/// removed, so a crashed or killed process does not leave the credential
/// readable in the runtime directory.
async fn wipe_cookie_file(data_dir: &Path) {
    let cookie_path = data_dir.join("control_auth_cookie");
    let _ = tokio::fs::write(&cookie_path, [0u8; 32]).await;
}

/// Validates a v3 onion address (56 base32 characters plus `.onion`).
fn is_valid_onion_address(address: &str) -> bool {
    let Some(body) = address.strip_suffix(".onion") else {
        return false;
    };
    if body.len() != 56 {
        return false;
    }
    body.bytes()
        .all(|byte| ONION_V3_ALPHABET.as_bytes().contains(&byte))
        && crate::uri::is_valid_onion_v3_body(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[test]
    fn onion_address_validation() {
        let good = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion".to_owned();
        assert!(is_valid_onion_address(&good));
        assert!(!is_valid_onion_address("short.onion"));
        assert!(!is_valid_onion_address(&format!("{}.com", "a".repeat(56))));
        assert!(!is_valid_onion_address(&format!(
            "{}.onion",
            "A".repeat(56)
        )));
        assert!(!is_valid_onion_address(&format!(
            "{}.onion",
            "0".repeat(56)
        )));
        assert_eq!(ONION_V3_ALPHABET.len(), 32);
    }

    #[test]
    fn tor_binary_discovery_prefers_explicit_paths() {
        // An explicit path to an existing file wins over PATH.
        let existing = std::env::current_exe().unwrap();
        let resolved = resolve_tor_binary(Some(&existing)).unwrap();
        assert_eq!(resolved, existing);

        // A missing explicit path is an error.
        assert!(matches!(
            resolve_tor_binary(Some(Path::new("/nonexistent/tor"))),
            Err(TorError::TorBinaryNotFound)
        ));
    }

    #[test]
    fn prepare_refuses_runtime_collisions_via_lock() {
        let root = test_root("lock");
        let manager = TorManager::prepare_in(&root).unwrap();
        let session_dir = manager.paths().session_dir.clone();
        // Re-using the same session directory must fail on the lock file.
        let result = recreate_session_with_lock(&session_dir);
        assert!(result.is_err());
        platform::remove_session_dir(&root);
    }

    fn recreate_session_with_lock(session_dir: &Path) -> Result<(), TorError> {
        let lock_file = session_dir.join("lock");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_file)
            .map(|_| ())
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    TorError::Platform(PlatformError::LockCollision(lock_file))
                } else {
                    TorError::Io(error)
                }
            })
    }

    // ---- Fake control server ------------------------------------------------

    /// A handler processes one command line and returns the reply lines
    /// (each including its `\r\n` terminator).
    type FakeHandler = Box<dyn FnMut(String) -> Vec<String> + Send>;

    /// Serves a fake Tor control endpoint on a Unix socket.
    async fn run_fake_control(socket_path: PathBuf, mut handler: FakeHandler) {
        let listener = UnixListener::bind(&socket_path).unwrap();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            let mut open = true;
            while open {
                match stream.read(&mut byte).await {
                    Ok(0) => open = false,
                    Ok(_) if byte[0] == b'\n' => {
                        let command = String::from_utf8_lossy(&line).trim().to_owned();
                        line.clear();
                        if !command.is_empty() {
                            let replies = handler(command);
                            let mut outgoing = String::new();
                            for reply in replies {
                                outgoing.push_str(&reply);
                            }
                            stream.write_all(outgoing.as_bytes()).await.ok();
                            if outgoing.contains("SHUTDOWN") {
                                stream.shutdown().await.ok();
                                open = false;
                            }
                        }
                    }
                    Ok(_) => line.push(byte[0]),
                    Err(_) => open = false,
                }
            }
        }
    }

    /// A scripted handler that emulates a healthy Tor control endpoint.
    fn healthy_handler() -> (FakeHandler, Arc<Mutex<Vec<String>>>) {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&commands);
        let mut getinfo_calls = 0;
        let handler: FakeHandler = Box::new(move |command: String| {
            log.lock().unwrap().push(command.clone());
            if command.starts_with("AUTHENTICATE") {
                vec!["250 OK\r\n".to_owned()]
            } else if command == "GETINFO status/bootstrap-phase" {
                getinfo_calls += 1;
                if getinfo_calls == 1 {
                    vec![
                        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=25 TAG=handshake\r\n"
                            .to_owned(),
                        "250 OK\r\n".to_owned(),
                    ]
                } else {
                    vec![
                        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n"
                            .to_owned(),
                        "250 OK\r\n".to_owned(),
                    ]
                }
            } else if command.starts_with("ADD_ONION") {
                vec![
                    "250-ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd\r\n"
                        .to_owned(),
                    "250 OK\r\n".to_owned(),
                ]
            } else if command.starts_with("DEL_ONION") || command.starts_with("SIGNAL") {
                vec!["250 OK\r\n".to_owned()]
            } else {
                vec!["510 Unrecognized command\r\n".to_owned()]
            }
        });
        (handler, commands)
    }

    fn test_root(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Short path: Unix socket paths are limited to 108 bytes (SUN_LEN).
        let _ = name;
        let root = std::env::temp_dir().join(format!("tc{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// Writes a fake control cookie so the manager's cookie read succeeds.
    ///
    /// The file is created with mode 0600, like the real Tor cookie, so the
    /// manager's permission check passes.
    fn write_fake_cookie(manager: &TorManager) {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(manager.paths().tor_data.clone()).unwrap();
        let path = manager.paths().tor_data.join("control_auth_cookie");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(&path).unwrap();
        use std::io::Write;
        file.write_all(&[0u8; 32]).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    async fn connect_fake(manager: &TorManager) -> ControlClient {
        ControlClient::connect(&manager.paths().control_socket, Duration::from_secs(5))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn full_flow_against_fake_control() {
        let root = test_root("full-flow");
        let manager = TorManager::prepare_in(&root).unwrap();
        let socket = manager.paths().control_socket.clone();
        let (handler, commands) = healthy_handler();
        let server = tokio::spawn(run_fake_control(socket, handler));

        let mut manager = manager;
        write_fake_cookie(&manager);
        manager
            .start_with_control(connect_fake(&manager).await)
            .await
            .unwrap();

        let service = manager.add_onion(80).await.unwrap();
        assert_eq!(
            service.onion_address,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"
        );
        assert_eq!(service.onion_address.len(), 62);
        assert_eq!(service.virtual_port, 80);
        assert_eq!(manager.onion(), Some(&service));

        let session_dir = manager.paths().session_dir.clone();
        manager.shutdown().await.unwrap();
        assert!(!session_dir.exists(), "session dir must be removed");

        let log = commands.lock().unwrap();
        assert!(log.iter().any(|c| c.starts_with("AUTHENTICATE")));
        assert!(log.iter().any(|c| c == "GETINFO status/bootstrap-phase"));
        assert!(
            log.iter()
                .any(|c| c.starts_with("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,unix:/")),
            "ADD_ONION must use a single NEW:ED25519-V3 key specification"
        );
        assert!(log.iter().any(|c| c.starts_with("DEL_ONION")));
        assert!(log.iter().any(|c| c == "SIGNAL SHUTDOWN"));
        server.abort();
        platform::remove_session_dir(&root);
    }

    #[tokio::test]
    async fn bootstrap_reports_observed_progress() {
        let root = test_root("bootstrap-progress");
        let manager = TorManager::prepare_in(&root).unwrap();
        let socket = manager.paths().control_socket.clone();
        let (handler, _) = healthy_handler();
        let server = tokio::spawn(run_fake_control(socket, handler));

        let mut manager = manager;
        write_fake_cookie(&manager);
        manager.control = Some(connect_fake(&manager).await);
        let mut observed = Vec::new();
        manager
            .authenticate_and_bootstrap_with_progress(|progress| observed.push(progress))
            .await
            .unwrap();

        assert_eq!(observed, vec![25, 100]);
        manager.shutdown().await.unwrap();
        server.abort();
        platform::remove_session_dir(&root);
    }

    #[test]
    fn bootstrap_progress_requires_a_bounded_numeric_field() {
        let reply = Reply {
            code: 250,
            lines: vec![
                "status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=72 TAG=loading".to_owned(),
                "OK".to_owned(),
            ],
        };
        assert_eq!(bootstrap_progress(&reply), Some(72));

        for invalid in ["PROGRESS=101", "PROGRESS=done", "XPROGRESS=100"] {
            let reply = Reply {
                code: 250,
                lines: vec![invalid.to_owned()],
            };
            assert_eq!(bootstrap_progress(&reply), None);
        }
    }

    #[tokio::test]
    async fn authentication_failure_is_reported() {
        let root = test_root("auth-fail");
        let manager = TorManager::prepare_in(&root).unwrap();
        let socket = manager.paths().control_socket.clone();
        let server = tokio::spawn(run_fake_control(
            socket,
            Box::new(|command: String| {
                if command.starts_with("AUTHENTICATE") {
                    vec!["515 Authentication failed\r\n".to_owned()]
                } else {
                    vec!["510 Unrecognized command\r\n".to_owned()]
                }
            }),
        ));

        let mut manager = manager;
        write_fake_cookie(&manager);
        let error = manager
            .start_with_control(connect_fake(&manager).await)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            TorError::Control(ControlError::AuthenticationFailed(_))
        ));
        server.abort();
        platform::remove_session_dir(&root);
    }

    #[tokio::test]
    async fn add_onion_failure_is_reported() {
        let root = test_root("onion-fail");
        let manager = TorManager::prepare_in(&root).unwrap();
        let socket = manager.paths().control_socket.clone();
        let server = tokio::spawn(run_fake_control(
            socket,
            Box::new(|command: String| {
                if command.starts_with("AUTHENTICATE") {
                    vec!["250 OK\r\n".to_owned()]
                } else if command == "GETINFO status/bootstrap-phase" {
                    vec![
                        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n"
                            .to_owned(),
                        "250 OK\r\n".to_owned(),
                    ]
                } else if command.starts_with("ADD_ONION") {
                    vec!["512 syntax error in argument\r\n".to_owned()]
                } else {
                    vec!["510 Unrecognized command\r\n".to_owned()]
                }
            }),
        ));

        let mut manager = manager;
        write_fake_cookie(&manager);
        manager
            .start_with_control(connect_fake(&manager).await)
            .await
            .unwrap();
        let error = manager.add_onion(80).await.unwrap_err();
        assert!(matches!(error, TorError::CommandFailed { .. }));
        let message = error.to_string();
        assert!(
            message.contains("code 512"),
            "the failure message must carry Tor's response code: {message}"
        );
        assert!(
            message.contains("syntax error in argument"),
            "the failure message must carry Tor's full response text: {message}"
        );
        server.abort();
        platform::remove_session_dir(&root);
    }

    #[tokio::test]
    async fn bootstrap_timeout_is_reported() {
        let root = test_root("bootstrap-timeout");
        let config = TorConfig {
            bootstrap_timeout: Duration::from_millis(600),
            control_connect_timeout: Duration::from_secs(5),
            ..TorConfig::default()
        };
        let mut manager = TorManager::prepare_with(&root, config).unwrap();
        let socket = manager.paths().control_socket.clone();
        let server = tokio::spawn(run_fake_control(
            socket,
            Box::new(|command: String| {
                if command.starts_with("AUTHENTICATE") {
                    vec!["250 OK\r\n".to_owned()]
                } else if command == "GETINFO status/bootstrap-phase" {
                    vec![
                        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=25 TAG=handshake\r\n"
                            .to_owned(),
                        "250 OK\r\n".to_owned(),
                    ]
                } else {
                    vec!["510 Unrecognized command\r\n".to_owned()]
                }
            }),
        ));

        write_fake_cookie(&manager);
        let error = manager
            .start_with_control(connect_fake(&manager).await)
            .await
            .unwrap_err();
        assert!(matches!(error, TorError::BootstrapTimeout { .. }));
        server.abort();
        platform::remove_session_dir(&root);
    }

    #[tokio::test]
    async fn invalid_service_id_is_reported() {
        let root = test_root("bad-service-id");
        let manager = TorManager::prepare_in(&root).unwrap();
        let socket = manager.paths().control_socket.clone();
        let server = tokio::spawn(run_fake_control(
            socket,
            Box::new(|command: String| {
                if command.starts_with("AUTHENTICATE") {
                    vec!["250 OK\r\n".to_owned()]
                } else if command == "GETINFO status/bootstrap-phase" {
                    vec![
                        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n"
                            .to_owned(),
                        "250 OK\r\n".to_owned(),
                    ]
                } else if command.starts_with("ADD_ONION") {
                    // A reply without a ServiceID line.
                    vec!["250-ServiceID=\r\n".to_owned(), "250 OK\r\n".to_owned()]
                } else {
                    vec!["510 Unrecognized command\r\n".to_owned()]
                }
            }),
        ));

        let mut manager = manager;
        write_fake_cookie(&manager);
        manager
            .start_with_control(connect_fake(&manager).await)
            .await
            .unwrap();
        let error = manager.add_onion(80).await.unwrap_err();
        assert!(matches!(error, TorError::InvalidServiceId));
        server.abort();
        platform::remove_session_dir(&root);
    }
}
