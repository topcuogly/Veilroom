//! The application supervisor (architecture decision 14, section 34.2).
//!
//! The supervisor owns the application lifecycle: the terminal session,
//! the main menu, host and join sessions, the Tor subprocess, the room
//! task, and the network adapters. It is the only component that wires the
//! TUI to the room actor and the transport; it restores the terminal and
//! shuts Tor down on every exit path.
//!
//! The host session runs the real flow end to end: Tor onion, room actor,
//! Unix-socket listener, admission gates, epoch wraps, and chat relay. The
//! join session connects through the session's SOCKS socket.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::mpsc;

use crate::admission::JoinPolicy;
use crate::admission::client::ClientAdmission;
use crate::admission::guard::PasswordGuard;
use crate::admission::host::{HostAdmission, HostAdmissionReply, HostState};
use crate::chat::session::ChatSession;
use crate::command::SlashCommand;
use crate::crypto::SecretBytes;
use crate::crypto::identity::{HostIdentity, MemberIdentity};
use crate::crypto::password::PasswordVerifier;
use crate::event::{ConnectionId, HostCommand, MemberCommand, MemberId, RoomEvent};
use crate::limits::{Limits, TimeoutKind, Timeouts};
use crate::net::client::ClientNetwork;
use crate::net::conn::PeerSendError;
use crate::net::host::HostNetwork;
use crate::protocol::ids::ErrorCode;
use crate::protocol::messages::{ErrorMessage, Message};
use crate::protocol::session::RoomSessionId;
use crate::room::action::{HostNotice, RoomAction};
use crate::room::actor::{HOST_CONNECTION, RoomActor};
use crate::room::task::RoomTask;
use crate::tor::manager::TorManager;
use crate::ui::app::{App, AppAction, RoomUiAction};
use crate::ui::render;
use crate::ui::room_view::{MemberLine, RequestKind, RequestLine, RoomView};
use crate::ui::screen::{JoinFormModel, Screen};
use crate::ui::terminal::TerminalGuard;
use crate::uri::Invitation;

/// The virtual port of the onion service.
const VIRTUAL_PORT: u16 = 80;

/// How a session ended.
enum SessionEnd {
    /// Return to the main menu.
    Menu,
    /// Quit the application.
    Quit,
    /// Show a message, then return to the main menu.
    Failed(String),
}

/// Runs the application to completion.
pub async fn run() -> std::process::ExitCode {
    run_with_tor_binary(None).await
}

/// Runs the application with an optional explicit Tor executable.
pub async fn run_with_tor_binary(tor_binary: Option<std::path::PathBuf>) -> std::process::ExitCode {
    let Ok(mut tui) = TerminalGuard::enter() else {
        eprintln!("veilroom: could not enter the terminal session");
        return std::process::ExitCode::FAILURE;
    };
    let (key_tx, mut key_rx) = mpsc::channel::<TerminalInput>(128);
    let stop = Arc::new(AtomicBool::new(false));
    let reader = spawn_key_reader(key_tx, stop.clone());

    let mut app = App::new();
    let outcome = menu_loop(&mut tui, &mut app, &mut key_rx, tor_binary.as_deref()).await;

    stop.store(true, Ordering::Relaxed);
    drop(tui);
    let _ = reader.join();
    match outcome {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(()) => std::process::ExitCode::FAILURE,
    }
}

/// Input events accepted from the terminal reader.
enum TerminalInput {
    Key(KeyEvent),
    Paste(String),
}

/// Reads terminal key events on a background thread.
fn spawn_key_reader(
    key_tx: mpsc::Sender<TerminalInput>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match crossterm::event::poll(std::time::Duration::from_millis(100)) {
                Ok(false) => continue,
                Err(_) => return,
                Ok(true) => {}
            }
            match crossterm::event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                    if key_tx.blocking_send(TerminalInput::Key(key)).is_err() {
                        return;
                    }
                }
                Ok(Event::Paste(text)) => {
                    if key_tx.blocking_send(TerminalInput::Paste(text)).is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    })
}

/// The main menu loop.
///
/// Returns `Ok(true)` when the user quit cleanly, `Ok(false)` when the
/// loop ended without a clean quit, and `Err(())` on a render failure.
async fn menu_loop(
    tui: &mut TerminalGuard,
    app: &mut App,
    keys: &mut mpsc::Receiver<TerminalInput>,
    tor_binary: Option<&std::path::Path>,
) -> Result<bool, ()> {
    loop {
        if draw(tui, app) {
            return Err(());
        }
        let Some(input) = keys.recv().await else {
            return Ok(false);
        };
        let TerminalInput::Key(key) = input else {
            if let TerminalInput::Paste(text) = input {
                app.on_paste(&text);
            }
            continue;
        };
        if is_quit_key(&key) {
            return Ok(true);
        }
        let action = app.on_key(key);
        match action {
            AppAction::Quit => return Ok(true),
            AppAction::HostSetupSubmitted { password, nickname } => {
                match run_host_session(tui, app, keys, password, nickname, tor_binary).await {
                    SessionEnd::Quit => return Ok(true),
                    SessionEnd::Failed(message) => app.show_message(message),
                    SessionEnd::Menu => app.back_to_menu(),
                }
            }
            AppAction::JoinSetupSubmitted {
                invitation,
                password,
            } => match run_join_session(tui, app, keys, &invitation, password, tor_binary).await {
                SessionEnd::Quit => return Ok(true),
                SessionEnd::Failed(message) => app.show_message(message),
                SessionEnd::Menu => app.back_to_menu(),
            },
            AppAction::Room(_) | AppAction::JoinFormSubmitted { .. } | AppAction::None => {}
        }
    }
}

/// Whether the key is a hard quit (Ctrl-C).
fn is_quit_key(key: &KeyEvent) -> bool {
    key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'C'))
}

/// Draws the current screen; returns `true` on a render failure.
fn draw(tui: &mut TerminalGuard, app: &App) -> bool {
    tui.terminal()
        .draw(|frame| render::draw(frame, app))
        .is_err()
}

/// Starts Tor while keeping its real bootstrap percentage visible.
async fn start_tor_with_progress(
    tui: &mut TerminalGuard,
    app: &mut App,
    tor: &mut TorManager,
) -> Result<(), SessionEnd> {
    app.begin_tor_connection();
    if draw(tui, app) {
        return Err(SessionEnd::Quit);
    }

    let mut render_failed = false;
    let outcome = tor
        .start_with_progress(|progress| {
            app.set_tor_progress(progress);
            render_failed |= draw(tui, app);
        })
        .await;
    if render_failed {
        return Err(SessionEnd::Quit);
    }
    outcome.map_err(|error| SessionEnd::Failed(format!("Tor could not be started: {error}")))
}

// ---------------------------------------------------------------------------
// Host session
// ---------------------------------------------------------------------------

/// One live connection on the host side.
struct HostConnection<'a> {
    admission: HostAdmission<'a>,
    stage_since: std::time::Instant,
    last_seen: std::time::Instant,
    admitted: bool,
}

/// Runs a host session until it ends.
async fn run_host_session(
    tui: &mut TerminalGuard,
    app: &mut App,
    keys: &mut mpsc::Receiver<TerminalInput>,
    password: SecretBytes,
    nickname: String,
    tor_binary: Option<&std::path::Path>,
) -> SessionEnd {
    let verifier = match PasswordVerifier::derive(&password) {
        Ok(verifier) => verifier,
        Err(error) => {
            return SessionEnd::Failed(format!(
                "the password verifier could not be derived: {error}"
            ));
        }
    };
    let mut tor =
        match TorManager::prepare_with_binary(tor_binary.map(std::path::Path::to_path_buf)) {
            Ok(tor) => tor,
            Err(error) => return SessionEnd::Failed(format!("Tor could not be prepared: {error}")),
        };
    let outcome = host_session_body(tui, app, keys, &mut tor, verifier, nickname).await;
    let _ = tor.shutdown().await;
    outcome
}

/// Sleeps until the nearest message-specific deadline, or indefinitely when
/// no displayed line currently has an expiry.
async fn wait_for_message_expiry(deadline: Option<std::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
        None => std::future::pending::<()>().await,
    }
}

/// The host session body; Tor is shut down by the caller.
async fn host_session_body(
    tui: &mut TerminalGuard,
    app: &mut App,
    keys: &mut mpsc::Receiver<TerminalInput>,
    tor: &mut TorManager,
    verifier: PasswordVerifier,
    nickname: String,
) -> SessionEnd {
    if let Err(end) = start_tor_with_progress(tui, app, tor).await {
        return end;
    }
    let onion = match tor.add_onion(VIRTUAL_PORT).await {
        Ok(onion) => onion,
        Err(error) => {
            return SessionEnd::Failed(format!("the onion service could not be created: {error}"));
        }
    };
    let host_identity = match HostIdentity::generate() {
        Ok(identity) => identity,
        Err(error) => {
            return SessionEnd::Failed(format!(
                "the host identity could not be generated: {error}"
            ));
        }
    };
    let host_client_identity = match MemberIdentity::generate() {
        Ok(identity) => identity,
        Err(error) => {
            return SessionEnd::Failed(format!(
                "the host identity could not be generated: {error}"
            ));
        }
    };
    let limits = Limits::default();
    let timeouts = Timeouts::default();
    let actor = match RoomActor::create(
        &limits,
        HOST_CONNECTION,
        nickname.clone(),
        host_identity.clone(),
        host_client_identity.clone(),
        &timeouts,
    ) {
        Ok(actor) => actor,
        Err(error) => return SessionEnd::Failed(format!("the room could not be created: {error}")),
    };
    let session_id = *actor.session_id().as_bytes();
    let (mut room, initial) = match RoomTask::spawn_started(actor) {
        Ok(parts) => parts,
        Err(error) => return SessionEnd::Failed(format!("the room could not be started: {error}")),
    };
    let mut network = match HostNetwork::listen(&tor.paths().chat_socket, limits).await {
        Ok(network) => network,
        Err(error) => {
            return SessionEnd::Failed(format!("the room listener could not be bound: {error}"));
        }
    };
    let (mut connects, mut inbound) = network.take_receivers();

    let mut host_chat = ChatSession::new(
        session_id,
        host_identity.ed25519_pubkey(),
        host_identity.x25519_pubkey(),
        MemberId::new(0),
    );
    host_chat.install_member(crate::chat::MemberView {
        member_id: MemberId::new(0),
        nickname: nickname.clone(),
        color: crate::command::ColorChoice::default(),
        is_host: true,
        ed25519_pubkey: host_client_identity.ed25519_pubkey(),
    });
    // The invitation token is a bearer secret: a zeroizing buffer so a
    // token rotated by `/newid` does not survive in freed memory.
    let mut token = SecretBytes::default();
    let mut policy = JoinPolicy::Open;
    let mut connections: HashMap<ConnectionId, HostConnection<'_>> = HashMap::new();
    // Reconnecting is free for a peer that holds the invitation token, and
    // the host pays no Argon2id cost per proof, so the per-connection cap is
    // not by itself an anti-guessing measure (section 10).
    let mut password_guard = PasswordGuard::new();

    app.enter_room(RoomView::host(nickname));
    let view = app.room_view_mut().expect("the room view exists");
    view.push_system("Starting the room...");
    if let Err(error) = handle_host_actions(
        view,
        &mut host_chat,
        &host_client_identity,
        &host_identity,
        &session_id,
        &mut token,
        &mut policy,
        &mut connections,
        &network,
        &room,
        &onion.onion_address,
        initial,
    )
    .await
    {
        return SessionEnd::Failed(error);
    }

    let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if draw(tui, app) {
            return SessionEnd::Quit;
        }
        // Handshake timeout enforcement for connections that never
        // completed the admission flow (section 20).
        let now = std::time::Instant::now();
        let stale: Vec<ConnectionId> = connections
            .iter()
            .filter(|(_, conn)| {
                let stage_timeout = match conn.admission.state() {
                    HostState::AwaitingHello => timeouts.get(TimeoutKind::ProtocolHandshake),
                    HostState::AwaitingToken => timeouts.get(TimeoutKind::TokenValidation),
                    HostState::AwaitingProof => timeouts.get(TimeoutKind::PasswordVerification),
                    HostState::AwaitingJoinForm => timeouts.get(TimeoutKind::JoinFormSubmission),
                    HostState::Decided if !conn.admitted => timeouts.get(TimeoutKind::HostDecision),
                    HostState::Decided => timeouts.get(TimeoutKind::Keepalive) * 3,
                };
                let since = if conn.admitted {
                    conn.last_seen
                } else {
                    conn.stage_since
                };
                now.duration_since(since) > stage_timeout
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            connections.remove(&id);
            network.close(id);
            let _ = room
                .send(RoomEvent::ConnectionLost { connection: id })
                .await;
            if let Some(view) = app.room_view_mut() {
                view.push_system(format!("connection {id} timed out"));
            }
        }
        tokio::select! {
            _ = maintenance.tick() => {
                match tor.has_exited() {
                    Ok(true) => {
                        let _ = room.send(RoomEvent::TorStopped).await;
                        return SessionEnd::Failed("Tor stopped unexpectedly".to_owned());
                    }
                    Err(error) => return SessionEnd::Failed(format!("Tor status failed: {error}")),
                    Ok(false) => {}
                }
                let _ = room.send(RoomEvent::EpochMaintenance).await;
            }
            _ = wait_for_message_expiry(
                app.room_view().and_then(RoomView::next_message_expiry)
            ) => {
                if let Some(view) = app.room_view_mut() {
                    view.tick_message_timeout();
                }
            }
            maybe = keys.recv() => {
                let Some(input) = maybe else { break };
                let TerminalInput::Key(key) = input else {
                    if let TerminalInput::Paste(text) = input { app.on_paste(&text); }
                    continue;
                };
                if is_quit_key(&key) {
                    return SessionEnd::Quit;
                }
                let action = app.on_key(key);
                match action {
                    AppAction::Quit | AppAction::Room(RoomUiAction::Exit) => {
                        let _ = room.send(RoomEvent::CloseRequested).await;
                        break;
                    }
                    // The host never sends chat from this pane (the TUI
                    // rejects host chat lines); this arm is a safety net so
                    // the message can never be transmitted from the host
                    // connection even if an action slips through.
                    AppAction::Room(RoomUiAction::Chat(text)) => {
                        let _ = text;
                        if let Some(view) = app.room_view_mut() {
                            view.push_error(
                                "the host cannot send chat messages; join the room from a \
                                 second tab to chat",
                            );
                        }
                    }
                    AppAction::Room(RoomUiAction::Command(command)) => {
                        handle_host_command(app, &room, &mut host_chat, &host_client_identity, command).await;
                    }
                    AppAction::Room(RoomUiAction::Error(text)) => {
                        if let Some(view) = app.room_view_mut() {
                            view.push_error(text);
                        }
                    }
                    AppAction::Room(RoomUiAction::CopyInvitation(uri)) => {
                        copy_invitation_to_clipboard(app, &uri).await;
                    }
                    AppAction::Room(RoomUiAction::Leave) => {}
                    _ => {}
                }
            }
            maybe = room.next_actions() => {
                let Some(actions) = maybe else { break };
                let view = app.room_view_mut().expect("the room view exists");
                if let Err(error) = handle_host_actions(
                    view,
                    &mut host_chat,
                    &host_client_identity,
                    &host_identity,
                    &session_id,
                    &mut token,
                    &mut policy,
                    &mut connections,
                    &network,
                    &room,
                    &onion.onion_address,
                    actions,
                ).await {
                    return SessionEnd::Failed(error);
                }
            }
            maybe = connects.recv() => {
                let Some(id) = maybe else { break };
                if let Some(remaining) = password_guard.remaining(std::time::Instant::now()) {
                    // Too many failed password proofs in this room: refuse new
                    // admission flows until the back-off window ends. Admitted
                    // members keep their connections.
                    let _ = network.send_to(id, error_message(
                        ErrorCode::RateLimited,
                        "too many failed password attempts; try again later",
                    ));
                    network.close(id);
                    if let Some(view) = app.room_view_mut() {
                        view.push_system(format!(
                            "connection {id} refused: password lockout active for {} more seconds",
                            remaining.as_secs() + 1
                        ));
                    }
                    continue;
                }
                let admission = match HostAdmission::new(
                    RoomSessionId::from(session_id),
                    token.clone(),
                    verifier.clone(),
                    &host_identity,
                    onion.onion_address.clone(),
                ) {
                    Ok(admission) => admission,
                    Err(_) => {
                        network.close(id);
                        continue;
                    }
                };
                connections.insert(id, HostConnection {
                    admission,
                    stage_since: std::time::Instant::now(),
                    last_seen: std::time::Instant::now(),
                    admitted: false,
                });
                let _ = room.send(RoomEvent::ClientConnected { connection: id }).await;
                if let Some(view) = app.room_view_mut() {
                    view.push_system(format!("connection {id} connected"));
                }
            }
            maybe = inbound.recv() => {
                let Some((id, maybe_message)) = maybe else { break };
                match maybe_message {
                    Some(message) => {
                        if let Some(connection) = connections.get_mut(&id) {
                            connection.last_seen = std::time::Instant::now();
                        }
                        match handle_host_message(
                            &mut connections, id, message, policy, &network, &room,
                        ).await {
                            Ok(()) => {}
                            Err(error) => {
                                if error.0 == ErrorCode::InvalidPasswordProof {
                                    let started = password_guard
                                        .record_failure(std::time::Instant::now());
                                    let failures = password_guard.failures();
                                    if let Some(window) = started {
                                        if let Some(view) = app.room_view_mut() {
                                            view.notice(format!(
                                                "{failures} failed password attempts; new join attempts are blocked for {} seconds",
                                                window.as_secs()
                                            ));
                                        }
                                    }
                                }
                                let _ = network.send_to(id, error_message(error.0, &error.1));
                                network.close(id);
                                connections.remove(&id);
                                let _ = room.send(RoomEvent::ConnectionLost { connection: id }).await;
                            }
                        }
                    }
                    None => {
                        connections.remove(&id);
                        network.close(id);
                        let _ = room.send(RoomEvent::ConnectionLost { connection: id }).await;
                        if let Some(view) = app.room_view_mut() {
                            view.push_system(format!("connection {id} lost"));
                        }
                    }
                }
            }
        }
    }

    // Graceful host exit: close the room and deliver the shutdown frames
    // before the connections are torn down.
    let _ = room.send(RoomEvent::CloseRequested).await;
    if let Some(actions) = room.next_actions().await {
        for action in actions {
            match action {
                RoomAction::SendTo {
                    connection,
                    message,
                } => {
                    let _ = network.send_to(connection, message);
                }
                RoomAction::CloseConnection { connection } => {
                    network.close(connection);
                }
                RoomAction::NotifyHost(_) => {}
            }
        }
    }
    session_cleanup(&network, room, SessionEnd::Menu)
}

/// Shuts the network and the room task down, then returns `end`.
fn session_cleanup(network: &HostNetwork, room: RoomTask, end: SessionEnd) -> SessionEnd {
    network.close_all();
    network.stop();
    drop(room);
    end
}

/// Copies the full invitation URI to the clipboard and reports the result
/// in the room view.
///
/// The value passed here is always the complete stored URI, never the
/// shortened preview.
async fn copy_invitation_to_clipboard(app: &mut App, uri: &str) {
    let result = crate::platform::clipboard::copy_to_clipboard_async(uri.to_owned()).await;
    if let Some(view) = app.room_view_mut() {
        match result {
            Ok(()) => view.push_system("the full invitation was copied to the clipboard"),
            Err(error) => view.push_error(error.to_string()),
        }
    }
}

/// Handles a batch of room actions on the host side.
#[allow(clippy::too_many_arguments)]
async fn handle_host_actions(
    view: &mut RoomView,
    host_chat: &mut ChatSession,
    host_client_identity: &MemberIdentity,
    host_identity: &HostIdentity,
    session_id: &[u8; 32],
    token: &mut SecretBytes,
    policy: &mut JoinPolicy,
    connections: &mut HashMap<ConnectionId, HostConnection<'_>>,
    network: &HostNetwork,
    room: &RoomTask,
    onion_address: &str,
    actions: Vec<RoomAction>,
) -> Result<(), String> {
    for action in actions {
        match action {
            RoomAction::SendTo {
                connection,
                message,
            } if connection == HOST_CONNECTION => match message {
                Message::EpochWrap(wrap) => {
                    let wrap_key = match host_client_identity.try_wrap_key_for(
                        &host_identity.x25519_pubkey(),
                        session_id,
                        MemberId::new(0).as_u64(),
                    ) {
                        Ok(key) => key,
                        Err(error) => {
                            view.push_error(error.to_string());
                            continue;
                        }
                    };
                    match crate::crypto::identity::unwrap_epoch_key(
                        &wrap_key,
                        wrap.epoch,
                        session_id,
                        &wrap.nonce,
                        &wrap.ciphertext,
                    ) {
                        Ok(epoch_key) => {
                            host_chat.install_epoch(wrap.epoch, epoch_key);
                            let _ = room
                                .send(RoomEvent::EpochAck {
                                    connection: HOST_CONNECTION,
                                    epoch: wrap.epoch,
                                })
                                .await;
                            view.set_status(format!("epoch {}", wrap.epoch));
                        }
                        Err(error) => view.push_error(error.to_string()),
                    }
                }
                Message::Shutdown(_) => {
                    view.push_system("the room is closing");
                }
                Message::ChatMessage(envelope) => match host_chat.receive_chat(&envelope) {
                    Ok(text) => {
                        let member = host_chat.member(MemberId::new(envelope.sender_id));
                        let nickname = member
                            .map(|member| member.nickname.clone())
                            .unwrap_or_else(|| format!("member {}", envelope.sender_id));
                        let color = member.map(|member| member.color).unwrap_or_default();
                        view.push_chat(&nickname, color, &text);
                    }
                    Err(error) => view.push_error(error.to_string()),
                },
                Message::ColorChange(envelope) => {
                    match host_chat.receive_color(&envelope) {
                        Ok(color) => {
                            if let Some(mut member) =
                                host_chat.member(MemberId::new(envelope.sender_id)).cloned()
                            {
                                member.color = color;
                                host_chat.install_member(member);
                            }
                        }
                        Err(error) => view.push_error(error.to_string()),
                    }
                    sync_members_from_session(view, host_chat);
                }
                other => {
                    if let Err(error) = host_chat.handle_membership_message(&other) {
                        view.push_error(error.to_string());
                    } else {
                        sync_members_from_session(view, host_chat);
                    }
                }
            },
            RoomAction::SendTo {
                connection,
                message,
            } => {
                let accepted = matches!(message, Message::JoinAccepted(_));
                match network.send_to(connection, message) {
                    Ok(()) => {
                        if accepted {
                            // The connection leaves the pre-auth budget.
                            network.mark_admitted(connection);
                            if let Some(entry) = connections.get_mut(&connection) {
                                entry.admitted = true;
                                entry.last_seen = std::time::Instant::now();
                            }
                        }
                    }
                    Err(PeerSendError::QueueFull) | Err(PeerSendError::Closed) => {
                        // Slow client: close it without blocking the room.
                        network.close(connection);
                        let _ = room.send(RoomEvent::ConnectionLost { connection }).await;
                    }
                }
            }
            RoomAction::CloseConnection { connection } => {
                network.close(connection);
                connections.remove(&connection);
            }
            RoomAction::NotifyHost(notice) => match notice {
                HostNotice::InvitationRotated { token: new_token } => {
                    let uri_token = new_token.to_vec();
                    *token = new_token;
                    match Invitation::new(onion_address.to_owned(), VIRTUAL_PORT, uri_token) {
                        Ok(invitation) => {
                            let uri = invitation.to_uri_string();
                            view.set_invitation(uri.clone());
                            // The full URI is shown; the panel wraps it so
                            // nothing is clipped. It is also copied verbatim
                            // with Ctrl-Y or /copy.
                            view.push_muted(format!("Invitation: {uri}"));
                            view.push_muted("press Ctrl-Y or run /copy to copy the invitation");
                        }
                        Err(_) => view.push_error("the invitation could not be built"),
                    }
                }
                HostNotice::JoinRequestPending {
                    request_id,
                    nickname,
                    introduction,
                    ..
                } => {
                    view.notice(format!(
                        "join request {request_id} from {nickname}{}",
                        introduction
                            .map(|intro| format!(": {intro}"))
                            .unwrap_or_default()
                    ));
                    refresh_host_requests(room).await;
                }
                HostNotice::JoinRequestWithdrawn { request_id } => {
                    view.notice(format!("join request {request_id} withdrawn"));
                    refresh_host_requests(room).await;
                }
                HostNotice::TimeoutRequestPending {
                    request_id,
                    member_id,
                    nickname,
                    seconds,
                } => {
                    view.notice(format!(
                        "timeout request {request_id} from {nickname} (id {}): {seconds} seconds — /accept {request_id} or /reject {request_id}",
                        member_id.as_u64()
                    ));
                    refresh_host_requests(room).await;
                }
                HostNotice::TimeoutRequestAccepted {
                    request_id,
                    seconds,
                } => {
                    match host_chat.send_timeout_changed(host_client_identity, Some(seconds)) {
                        Ok(Message::TimeoutChanged(envelope)) => {
                            let _ = room
                                .send(RoomEvent::ChatReceived {
                                    connection: HOST_CONNECTION,
                                    message_type: 0x43,
                                    envelope,
                                })
                                .await;
                            view.set_message_timeout(Some(seconds));
                            view.notice(format!(
                                "timeout request {request_id} accepted; room timeout is now {seconds} seconds"
                            ));
                        }
                        Ok(_) => {}
                        Err(error) => view.push_error(error.to_string()),
                    }
                    refresh_host_requests(room).await;
                }
                HostNotice::TimeoutRequestRejected { request_id } => {
                    view.notice(format!(
                        "timeout request {request_id} rejected or withdrawn"
                    ));
                    refresh_host_requests(room).await;
                }
                HostNotice::TimeoutRebroadcast { seconds } => {
                    match host_chat.send_timeout_changed(host_client_identity, Some(seconds)) {
                        Ok(Message::TimeoutChanged(envelope)) => {
                            let _ = room
                                .send(RoomEvent::ChatReceived {
                                    connection: HOST_CONNECTION,
                                    message_type: 0x43,
                                    envelope,
                                })
                                .await;
                        }
                        Ok(_) => {}
                        Err(error) => view.push_error(error.to_string()),
                    }
                }
                HostNotice::MemberJoined {
                    member_id,
                    nickname,
                } => {
                    view.push_system(format!("{nickname} (id {}) joined", member_id.as_u64()));
                    refresh_host_members(room).await;
                }
                HostNotice::MemberLeft {
                    member_id,
                    nickname,
                } => {
                    view.push_system(format!("{nickname} (id {}) left", member_id.as_u64()));
                    refresh_host_members(room).await;
                }
                HostNotice::MemberKicked {
                    member_id,
                    nickname,
                } => {
                    view.push_system(format!("{nickname} (id {}) was kicked", member_id.as_u64()));
                    refresh_host_members(room).await;
                }
                HostNotice::JoinPolicyChanged { policy: new_policy } => {
                    *policy = new_policy;
                    view.set_status(format!("join policy: {new_policy:?}"));
                    view.push_system(format!("join requests are now {new_policy:?}"));
                }
                HostNotice::RequestsSnapshot {
                    join_requests,
                    timeout_requests,
                } => {
                    let mut requests = Vec::with_capacity(
                        join_requests.len().saturating_add(timeout_requests.len()),
                    );
                    requests.extend(join_requests.into_iter().map(|request| RequestLine {
                        request_id: request.request_id,
                        nickname: request.nickname,
                        kind: RequestKind::Join {
                            introduction: request.introduction,
                        },
                    }));
                    requests.extend(timeout_requests.into_iter().map(|request| RequestLine {
                        request_id: request.request_id,
                        nickname: request.nickname,
                        kind: RequestKind::Timeout {
                            seconds: request.seconds,
                        },
                    }));
                    requests.sort_by_key(|request| request.request_id.as_u64());
                    view.show_requests(requests);
                }
                HostNotice::ListSnapshot(members) => {
                    view.set_members(
                        members
                            .into_iter()
                            .map(|member| MemberLine {
                                member_id: member.member_id,
                                nickname: member.nickname,
                                color: member.color,
                                is_host: member.is_host,
                            })
                            .collect(),
                    );
                }
                HostNotice::WhoisResult(member) => {
                    view.push_system(format!(
                        "{} (id {}): {}",
                        member.nickname,
                        member.member_id.as_u64(),
                        if member.is_host { "host" } else { "member" }
                    ));
                }
                HostNotice::RoomClosed => {
                    view.push_system("the room is closed");
                }
                HostNotice::Error { message } => {
                    view.push_error(message);
                }
            },
        }
    }
    Ok(())
}

/// Rebuilds the member panel from the host chat session.
fn sync_members_from_session(view: &mut RoomView, session: &ChatSession) {
    view.set_members(
        session
            .members()
            .iter()
            .map(|member| MemberLine {
                member_id: member.member_id,
                nickname: member.nickname.clone(),
                color: member.color,
                is_host: member.is_host,
            })
            .collect(),
    );
}

/// Issues a `/requests` snapshot refresh.
async fn refresh_host_requests(room: &RoomTask) {
    let _ = room
        .send(RoomEvent::HostCommand(HostCommand::Requests))
        .await;
}

/// Issues a `/list` snapshot refresh.
async fn refresh_host_members(room: &RoomTask) {
    let _ = room
        .send(RoomEvent::MemberCommand {
            connection: HOST_CONNECTION,
            command: MemberCommand::List,
        })
        .await;
}

/// Handles a slash command from the host's input line.
async fn handle_host_command(
    app: &mut App,
    room: &RoomTask,
    host_chat: &mut ChatSession,
    host_client_identity: &MemberIdentity,
    command: SlashCommand,
) {
    match command {
        SlashCommand::Timeout(interval) => {
            match host_chat.send_timeout_changed(host_client_identity, interval) {
                Ok(Message::TimeoutChanged(envelope)) => {
                    let _ = room
                        .send(RoomEvent::ChatReceived {
                            connection: HOST_CONNECTION,
                            message_type: 0x43,
                            envelope,
                        })
                        .await;
                    if let Some(view) = app.room_view_mut() {
                        view.set_message_timeout(interval);
                        match interval {
                            Some(seconds) => view.push_system(format!(
                                "each room message will expire after {seconds} second{}",
                                if seconds == 1 { "" } else { "s" }
                            )),
                            None => view.push_system("room message expiry is disabled"),
                        }
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    if let Some(view) = app.room_view_mut() {
                        view.push_error(error.to_string());
                    }
                }
            }
        }
        SlashCommand::Color(color) => match host_chat.send_color(host_client_identity, color) {
            Ok(Message::ColorChange(envelope)) => {
                let _ = room
                    .send(RoomEvent::ChatReceived {
                        connection: HOST_CONNECTION,
                        message_type: 0x41,
                        envelope,
                    })
                    .await;
                if let Some(view) = app.room_view_mut() {
                    view.push_system(format!("color changed to {color:?}"));
                }
                if let Some(mut member) = host_chat.member(MemberId::new(0)).cloned() {
                    member.color = color;
                    host_chat.install_member(member);
                }
                if let Some(view) = app.room_view_mut() {
                    sync_members_from_session(view, host_chat);
                }
            }
            Ok(_) => {}
            Err(error) => {
                if let Some(view) = app.room_view_mut() {
                    view.push_error(error.to_string());
                }
            }
        },
        other => {
            if let Some(host_command) = other.clone().into_host_command() {
                let refresh_requests = matches!(
                    &host_command,
                    HostCommand::Accept { .. } | HostCommand::Reject { .. }
                );
                let _ = room.send(RoomEvent::HostCommand(host_command)).await;
                if refresh_requests {
                    refresh_host_requests(room).await;
                }
            } else if let Some(member_command) = other.into_member_command() {
                let _ = room
                    .send(RoomEvent::MemberCommand {
                        connection: HOST_CONNECTION,
                        command: member_command,
                    })
                    .await;
            }
        }
    }
}

/// Handles one inbound message from a client connection.
async fn handle_host_message(
    connections: &mut HashMap<ConnectionId, HostConnection<'_>>,
    id: ConnectionId,
    message: Message,
    policy: JoinPolicy,
    network: &HostNetwork,
    room: &RoomTask,
) -> Result<(), (ErrorCode, String)> {
    let connection = connections.get_mut(&id).ok_or_else(|| {
        (
            ErrorCode::ProtocolViolation,
            "unknown connection".to_owned(),
        )
    })?;
    if policy == JoinPolicy::Locked && !connection.admitted {
        return Err((
            ErrorCode::RoomLocked,
            "the room is not accepting join requests".to_owned(),
        ));
    }
    let state = match connection.admission.state() {
        HostState::AwaitingHello => crate::state::ConnectionState::ProtocolHandshake,
        HostState::AwaitingToken | HostState::AwaitingProof => {
            crate::state::ConnectionState::PreAuth
        }
        HostState::AwaitingJoinForm => crate::state::ConnectionState::PasswordVerified,
        HostState::Decided if connection.admitted => crate::state::ConnectionState::Active,
        HostState::Decided => crate::state::ConnectionState::JoinPending,
    };
    if !state.accepts(message.message_type().class()) {
        return Err((
            ErrorCode::ProtocolViolation,
            "message is invalid for the current connection state".to_owned(),
        ));
    }
    let previous_state = connection.admission.state();
    match message {
        Message::ClientHello(hello) => {
            let reply = connection
                .admission
                .on_client_hello(&hello, VIRTUAL_PORT)
                .map_err(|error| (error.error_code(), error.to_string()))?;
            network
                .send_to(id, reply)
                .map_err(|_| (ErrorCode::Internal, "connection closed".to_owned()))?;
        }
        Message::TokenVerify(_) | Message::ChallengeProof(_) | Message::JoinRequest(_) => {
            match connection
                .admission
                .on_message(&message, policy)
                .map_err(|error| (error.error_code(), error.to_string()))?
            {
                Some(HostAdmissionReply::Message(reply)) => {
                    network
                        .send_to(id, reply)
                        .map_err(|_| (ErrorCode::Internal, "connection closed".to_owned()))?;
                }
                Some(HostAdmissionReply::JoinRequested(application)) => {
                    let _ = room
                        .send(RoomEvent::JoinRequested {
                            connection: id,
                            nickname: application.nickname,
                            introduction: application.introduction,
                            ed25519_pubkey: application.ed25519_pubkey,
                            x25519_pubkey: application.x25519_pubkey,
                            signature: application.signature,
                        })
                        .await;
                }
                None => {
                    // The password proof validated.
                    let _ = room
                        .send(RoomEvent::PasswordVerified { connection: id })
                        .await;
                }
            }
        }
        Message::EpochAck(ack) => {
            let _ = room
                .send(RoomEvent::EpochAck {
                    connection: id,
                    epoch: ack.epoch,
                })
                .await;
        }
        Message::ChatMessage(envelope) => {
            let _ = room
                .send(RoomEvent::ChatReceived {
                    connection: id,
                    message_type: 0x40,
                    envelope,
                })
                .await;
        }
        Message::ColorChange(envelope) => {
            let _ = room
                .send(RoomEvent::ChatReceived {
                    connection: id,
                    message_type: 0x41,
                    envelope,
                })
                .await;
        }
        Message::TimeoutRequest(envelope) => {
            let _ = room
                .send(RoomEvent::ChatReceived {
                    connection: id,
                    message_type: 0x42,
                    envelope,
                })
                .await;
        }
        Message::TimeoutChanged(envelope) => {
            let _ = room
                .send(RoomEvent::ChatReceived {
                    connection: id,
                    message_type: 0x43,
                    envelope,
                })
                .await;
        }
        Message::Keepalive(_) => {}
        Message::Shutdown(_) | Message::Error(_) => {
            return Err((
                ErrorCode::ProtocolViolation,
                "peer ended the connection".to_owned(),
            ));
        }
        other => {
            return Err((
                ErrorCode::ProtocolViolation,
                format!("unexpected message from connection {id}: {other:?}"),
            ));
        }
    }
    if connection.admission.state() != previous_state {
        connection.stage_since = std::time::Instant::now();
    }
    Ok(())
}

/// Builds an error message for a host-side failure.
fn error_message(code: ErrorCode, reason: &str) -> Message {
    Message::Error(
        ErrorMessage::new(code, Some(reason.to_owned())).unwrap_or_else(|_| {
            ErrorMessage::new(code, None).expect("a reason-less error is always valid")
        }),
    )
}

// ---------------------------------------------------------------------------
// Join session
// ---------------------------------------------------------------------------

/// Runs a join session until it ends.
async fn run_join_session(
    tui: &mut TerminalGuard,
    app: &mut App,
    keys: &mut mpsc::Receiver<TerminalInput>,
    invitation_text: &str,
    password: SecretBytes,
    tor_binary: Option<&std::path::Path>,
) -> SessionEnd {
    let invitation = match crate::uri::parse_invitation(invitation_text) {
        Ok(invitation) => invitation,
        Err(error) => return SessionEnd::Failed(format!("The invitation is invalid: {error}")),
    };
    let mut tor =
        match TorManager::prepare_with_binary(tor_binary.map(std::path::Path::to_path_buf)) {
            Ok(tor) => tor,
            Err(error) => return SessionEnd::Failed(format!("Tor could not be prepared: {error}")),
        };
    if let Err(end) = start_tor_with_progress(tui, app, &mut tor).await {
        let _ = tor.shutdown().await;
        return end;
    }
    let limits = Limits::default();
    let mut network = match ClientNetwork::connect(
        &tor.paths().socks_socket,
        invitation.onion_address(),
        invitation.port(),
        limits,
    )
    .await
    {
        Ok(network) => network,
        Err(error) => {
            let _ = tor.shutdown().await;
            return SessionEnd::Failed(format!("the room could not be reached: {error}"));
        }
    };
    let admission = match ClientAdmission::new(invitation, password) {
        Ok(admission) => admission,
        Err(error) => {
            let _ = tor.shutdown().await;
            return SessionEnd::Failed(format!("the client session could not be created: {error}"));
        }
    };
    let outcome = join_session_body(tui, app, keys, &mut network, admission, &mut tor).await;
    drop(network);
    let _ = tor.shutdown().await;
    outcome
}

/// The join session body.
async fn join_session_body(
    tui: &mut TerminalGuard,
    app: &mut App,
    keys: &mut mpsc::Receiver<TerminalInput>,
    network: &mut ClientNetwork,
    mut admission: ClientAdmission,
    tor: &mut TorManager,
) -> SessionEnd {
    let mut pending_form: Option<(String, Option<String>)> = None;
    let mut own_nickname: Option<String> = None;
    let timeouts = Timeouts::default();
    let mut stage_since = std::time::Instant::now();
    let mut last_seen = stage_since;
    let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    if let Err(error) = network.send(admission.first_message()) {
        return SessionEnd::Failed(format!("the connection failed: {error}"));
    }
    app.set_screen(Screen::JoinForm(JoinFormModel::new()));
    loop {
        if draw(tui, app) {
            return SessionEnd::Quit;
        }
        tokio::select! {
            _ = maintenance.tick() => {
                match tor.has_exited() {
                    Ok(true) => return SessionEnd::Failed("Tor stopped unexpectedly".to_owned()),
                    Err(error) => return SessionEnd::Failed(format!("Tor status failed: {error}")),
                    Ok(false) => {}
                }
                let kind = admission.timeout_kind();
                let allowed = if kind == TimeoutKind::Keepalive {
                    timeouts.get(kind) * 3
                } else {
                    timeouts.get(kind)
                };
                let since = if kind == TimeoutKind::Keepalive { last_seen } else { stage_since };
                if since.elapsed() > allowed {
                    return SessionEnd::Failed("the room connection timed out".to_owned());
                }
            }
            _ = wait_for_message_expiry(
                app.room_view().and_then(RoomView::next_message_expiry)
            ) => {
                if let Some(view) = app.room_view_mut() {
                    view.tick_message_timeout();
                }
            }
            maybe = keys.recv() => {
                let Some(input) = maybe else { break };
                let TerminalInput::Key(key) = input else {
                    if let TerminalInput::Paste(text) = input { app.on_paste(&text); }
                    continue;
                };
                if is_quit_key(&key) {
                    return SessionEnd::Quit;
                }
                let action = app.on_key(key);
                match action {
                    AppAction::Quit => return SessionEnd::Quit,
                    AppAction::JoinFormSubmitted { nickname, introduction } => {
                        app.show_join_pending();
                        own_nickname = Some(nickname.clone());
                        match admission.join_request(nickname.clone(), introduction.clone()) {
                            Ok(join_message) => {
                                stage_since = std::time::Instant::now();
                                if network.send(join_message).is_err() {
                                    return SessionEnd::Failed("the connection failed".to_owned());
                                }
                            }
                            Err(_) => {
                                // The handshake is still in flight; the form
                                // is submitted once the challenge is answered.
                                pending_form = Some((nickname, introduction));
                            }
                        }
                    }
                    AppAction::Room(RoomUiAction::Chat(text)) => {
                        match admission.send_chat(&text) {
                            Ok(message) => {
                                if network.send(message).is_err() {
                                    return SessionEnd::Failed("the connection failed".to_owned());
                                }
                                if let Some(view) = app.room_view_mut() {
                                    view.push_own(&text);
                                }
                            }
                            Err(error) => {
                                if let Some(view) = app.room_view_mut() {
                                    view.push_error(error.to_string());
                                }
                            }
                        }
                    }
                    AppAction::Room(RoomUiAction::Command(command)) => {
                        match command {
                            SlashCommand::Color(color) => {
                                match admission.send_color(color) {
                                    Ok(message) => {
                                        if network.send(message).is_err() {
                                            return SessionEnd::Failed("the connection failed".to_owned());
                                        }
                                        // The host relays the change to the
                                        // other members but never back to the
                                        // sender, so the local member table is
                                        // updated here; otherwise the sender's
                                        // own messages would keep the default
                                        // color.
                                        admission.set_own_color(color);
                                        sync_join_members(app, &admission);
                                        if let Some(view) = app.room_view_mut() {
                                            view.push_system(format!("color changed to {color:?}"));
                                        }
                                    }
                                    Err(error) => {
                                        if let Some(view) = app.room_view_mut() {
                                            view.push_error(error.to_string());
                                        }
                                    }
                                }
                            }
                            SlashCommand::List => {
                                sync_join_members(app, &admission);
                                if let Some(view) = app.room_view_mut() {
                                    view.push_system(format!(
                                        "{} active member(s)",
                                        admission.chat().map_or(0, |chat| chat.members().len())
                                    ));
                                }
                            }
                            SlashCommand::Whois(target) => {
                                let found = admission.chat().and_then(|chat| {
                                    chat.members().iter().find(|member| {
                                        member.nickname == target
                                            || member.member_id.as_u64().to_string() == target
                                    })
                                });
                                if let Some(view) = app.room_view_mut() {
                                    match found {
                                        Some(member) => view.push_system(format!(
                                            "{} (id {}): {}",
                                            member.nickname,
                                            member.member_id.as_u64(),
                                            if member.is_host { "host" } else { "member" }
                                        )),
                                        None => view.push_error(format!(
                                            "no active member matches `{target}`"
                                        )),
                                    }
                                }
                            }
                            SlashCommand::TimeoutRequest(seconds) => {
                                match admission.send_timeout_request(seconds) {
                                    Ok(message) => {
                                        if network.send(message).is_err() {
                                            return SessionEnd::Failed(
                                                "the connection failed".to_owned(),
                                            );
                                        }
                                        if let Some(view) = app.room_view_mut() {
                                            view.push_system(format!(
                                                "requested a room timeout of {seconds} seconds"
                                            ));
                                        }
                                    }
                                    Err(error) => {
                                        if let Some(view) = app.room_view_mut() {
                                            view.push_error(error.to_string());
                                        }
                                    }
                                }
                            }
                            other => {
                                let _ = other;
                                if let Some(view) = app.room_view_mut() {
                                    view.push_error("that command is only available to the host");
                                }
                            }
                        }
                    }
                    AppAction::Room(RoomUiAction::Error(text)) => {
                        if let Some(view) = app.room_view_mut() {
                            view.push_error(text);
                        }
                    }
                    AppAction::Room(RoomUiAction::CopyInvitation(uri)) => {
                        // A participant has no invitation; copy is harmless
                        // but almost always unreachable.
                        copy_invitation_to_clipboard(app, &uri).await;
                    }
                    AppAction::Room(RoomUiAction::Leave) => {
                        // Leaving: close the connection; the host treats
                        // the EOF as a member left.
                        return SessionEnd::Menu;
                    }
                    AppAction::Room(RoomUiAction::Exit) => return SessionEnd::Quit,
                    _ => {}
                }
            }
            maybe = network.recv() => {
                let Some(maybe_message) = maybe else {
                    return SessionEnd::Failed("the room connection was lost".to_owned());
                };
                let Some(message) = maybe_message else {
                    return SessionEnd::Failed("the room connection was lost".to_owned());
                };
                last_seen = std::time::Instant::now();
                let previous_kind = admission.timeout_kind();
                match handle_join_message(
                    app, network, &mut admission, message, &mut pending_form, &mut own_nickname,
                ).await {
                    JoinMessageResult::Continue => {
                        if admission.timeout_kind() != previous_kind {
                            stage_since = std::time::Instant::now();
                        }
                    }
                    JoinMessageResult::End(end) => return end,
                }
            }
        }
    }
    SessionEnd::Menu
}

/// The outcome of one inbound join-session message.
enum JoinMessageResult {
    /// Keep looping.
    Continue,
    /// End the session.
    End(SessionEnd),
}

/// Handles one inbound message on the participant side.
async fn handle_join_message(
    app: &mut App,
    network: &mut ClientNetwork,
    admission: &mut ClientAdmission,
    message: Message,
    pending_form: &mut Option<(String, Option<String>)>,
    own_nickname: &mut Option<String>,
) -> JoinMessageResult {
    match message {
        Message::Keepalive(_) => JoinMessageResult::Continue,
        Message::Shutdown(_) => {
            if let Some(view) = app.room_view_mut() {
                view.push_system("the host closed the room");
            }
            JoinMessageResult::End(SessionEnd::Menu)
        }
        // A recoverable error rejects one message; the host keeps the
        // connection, so the room session must survive it. Ending here
        // would drop the member back to the menu and force a full Tor
        // bootstrap, handshake, and re-admission for a single fast burst.
        Message::Error(error) if admission.is_admitted() && error.code.is_recoverable() => {
            if let Some(view) = app.room_view_mut() {
                view.push_error(
                    error
                        .reason
                        .unwrap_or_else(|| "the room rejected that message".to_owned()),
                );
            }
            JoinMessageResult::Continue
        }
        Message::Error(error) => JoinMessageResult::End(SessionEnd::Failed(format!(
            "the host rejected the connection: {}",
            error.reason.unwrap_or_else(|| "protocol error".to_owned())
        ))),
        Message::EpochWrap(wrap) => match admission.on_epoch_wrap(&wrap) {
            Ok(ack) => {
                if network.send(ack).is_err() {
                    return JoinMessageResult::End(SessionEnd::Failed(
                        "the connection failed".to_owned(),
                    ));
                }
                if let Some(view) = app.room_view_mut() {
                    view.push_system(format!("epoch {} active", wrap.epoch));
                }
                JoinMessageResult::Continue
            }
            Err(_) => JoinMessageResult::End(SessionEnd::Failed(
                "the epoch key could not be unwrapped".to_owned(),
            )),
        },
        Message::ChatMessage(envelope) => {
            match admission.on_member_message(0x40, &envelope) {
                Ok(Some(text)) => {
                    let member = admission.member_view(MemberId::new(envelope.sender_id));
                    let nickname = member
                        .map(|member| member.nickname.clone())
                        .unwrap_or_else(|| format!("member {}", envelope.sender_id));
                    let color = member.map(|member| member.color).unwrap_or_default();
                    if let Some(view) = app.room_view_mut() {
                        view.push_chat(&nickname, color, &text);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    if let Some(view) = app.room_view_mut() {
                        view.push_error(error.to_string());
                    }
                }
            }
            JoinMessageResult::Continue
        }
        Message::ColorChange(envelope) => {
            let _ = admission.on_member_message(0x41, &envelope);
            sync_join_members(app, admission);
            JoinMessageResult::Continue
        }
        Message::TimeoutChanged(envelope) => {
            let result = admission
                .chat_mut()
                .ok_or(crate::chat::ChatError::NoEpochKey)
                .and_then(|chat| chat.receive_timeout_changed(&envelope));
            if let Some(view) = app.room_view_mut() {
                match result {
                    Ok(interval) => {
                        view.set_message_timeout(interval);
                        match interval {
                            Some(seconds) => view.notice(format!(
                                "room message lifetime changed to {seconds} seconds"
                            )),
                            None => view.notice("room message expiry was disabled"),
                        }
                    }
                    Err(error) => view.push_error(error.to_string()),
                }
            }
            JoinMessageResult::Continue
        }
        Message::MemberJoined(_)
        | Message::MemberLeft(_)
        | Message::MemberKicked(_)
        | Message::JoinPolicyChanged(_)
        | Message::MemberSnapshot(_) => {
            let joined_nickname = match &message {
                Message::MemberJoined(event) => Some(event.nickname.clone()),
                _ => None,
            };
            match admission.on_membership_message(&message) {
                Ok(()) => {
                    sync_join_members(app, admission);
                    if let Some(view) = app.room_view_mut() {
                        if let Some(nickname) = joined_nickname {
                            view.push_system(format!("{nickname} joined"));
                        }
                        if let Message::JoinPolicyChanged(event) = &message {
                            view.set_status(if event.open {
                                "join policy: open"
                            } else {
                                "join policy: locked"
                            });
                        }
                    }
                    JoinMessageResult::Continue
                }
                Err(error) => {
                    if let Some(view) = app.room_view_mut() {
                        view.push_error(error.to_string());
                    }
                    JoinMessageResult::Continue
                }
            }
        }
        other => match admission.on_host_message(&other) {
            Ok(replies) => {
                for reply in replies {
                    let is_challenge_answer = matches!(reply, Message::ChallengeProof(_));
                    if network.send(reply).is_err() {
                        return JoinMessageResult::End(SessionEnd::Failed(
                            "the connection failed".to_owned(),
                        ));
                    }
                    // The challenge answer was sent; the join form, if it
                    // was already submitted, can now be sent.
                    if is_challenge_answer {
                        if let Some((nickname, introduction)) = pending_form.take() {
                            if let Ok(join_message) = admission.join_request(nickname, introduction)
                            {
                                if network.send(join_message).is_err() {
                                    return JoinMessageResult::End(SessionEnd::Failed(
                                        "the connection failed".to_owned(),
                                    ));
                                }
                            }
                        }
                    }
                }
                if admission.is_admitted() {
                    // The join was accepted; move into the room view.
                    let nickname = own_nickname.take().unwrap_or_else(|| "you".to_owned());
                    app.enter_room(RoomView::participant(nickname));
                }
                JoinMessageResult::Continue
            }
            Err(crate::admission::AdmissionError::Rejected { reason }) => {
                let reason = reason.unwrap_or_else(|| "no reason given".to_owned());
                JoinMessageResult::End(SessionEnd::Failed(format!(
                    "the host rejected the join request: {reason}"
                )))
            }
            Err(error) => JoinMessageResult::End(SessionEnd::Failed(error.to_string())),
        },
    }
}

/// Rebuilds the member panel from the participant chat session.
fn sync_join_members(app: &mut App, admission: &ClientAdmission) {
    let Some(session) = admission.chat() else {
        return;
    };
    if let Some(view) = app.room_view_mut() {
        view.set_members(
            session
                .members()
                .iter()
                .map(|member| MemberLine {
                    member_id: member.member_id,
                    nickname: member.nickname.clone(),
                    color: member.color,
                    is_host: member.is_host,
                })
                .collect(),
        );
    }
}
