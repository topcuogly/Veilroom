//! Real Tor end-to-end test (instructions section 41.4 / 13).
//!
//! Not part of the default suite:
//!
//! ```bash
//! cargo test --test tor_e2e -- --ignored
//! ```
//!
//! Requires a `tor` binary on `PATH` and network access. The test launches
//! an isolated Tor subprocess, creates an ephemeral v3 onion service,
//! connects through the session's SOCKS socket, round-trips data through
//! the onion to the app-level Unix socket, and verifies controlled cleanup.

use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use veilroom::tor::{TorConfig, TorManager};

fn tor_available() -> bool {
    StdCommand::new("tor").arg("--version").output().is_ok()
}

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("veilroom-tor-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[tokio::test]
#[ignore = "requires a real tor binary and network access"]
async fn real_tor_end_to_end() {
    if !tor_available() {
        eprintln!("skipping: `tor` binary not found on PATH");
        return;
    }

    let root = temp_root("main");
    let config = TorConfig {
        bootstrap_timeout: Duration::from_secs(120),
        ..TorConfig::default()
    };
    let mut manager = TorManager::prepare_with(&root, config).expect("session prepare");
    manager.start().await.expect("tor subprocess start");
    // Production sessions do not create file logs.
    assert!(
        !manager.paths().tor_log.exists(),
        "normal Tor operation must not create a file log"
    );
    let service = manager.add_onion(80).await.expect("ADD_ONION");
    assert!(service.onion_address.ends_with(".onion"));
    assert_eq!(service.onion_address.len(), 62);
    assert!(
        service
            .onion_address
            .bytes()
            .take(56)
            .all(|b| b"abcdefghijklmnopqrstuvwxyz234567".contains(&b))
    );

    // The app-level listener that the onion forwards to.
    let chat_socket = manager.paths().chat_socket.clone();
    let listener = UnixListener::bind(&chat_socket).expect("bind chat.sock");
    let app = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("onion connect");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.expect("read from onion");
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        stream
            .write_all(b"pong")
            .await
            .expect("reply through onion");
        text
    });

    // Connect through the session's SOCKS socket, like a participant.
    let socks_path = manager.paths().socks_socket.clone();
    let socks_phase = async {
        let mut socks =
            veilroom::net::socks::connect_via_socks(&socks_path, &service.onion_address, 80)
                .await
                .expect("SOCKS tunnel");

        socks.write_all(b"ping").await.expect("send through onion");
        let mut response = [0u8; 4];
        socks
            .read_exact(&mut response)
            .await
            .expect("receive through onion");
        assert_eq!(&response, b"pong");
    };

    tokio::time::timeout(Duration::from_secs(90), socks_phase)
        .await
        .expect("onion round trip timed out");

    let received = app.await.expect("app listener task");
    assert_eq!(received, "ping");

    let session_dir = manager.paths().session_dir.clone();
    manager.shutdown().await.expect("controlled shutdown");
    assert!(
        !session_dir.exists(),
        "session dir must be removed after shutdown"
    );

    std::fs::remove_dir_all(&root).ok();
}
