//! In-memory end-to-end flow over a real Unix socket (section 41.3).
//!
//! This test drives the complete host/participant scenario exactly as the
//! supervisor does — Tor is replaced by a loopback connection to the
//! host's `chat.sock`, the same seam the ignored real-Tor test uses. It
//! exercises the frame codec, the connection tasks, the admission gates,
//! the room actor, epoch wrapping, and encrypted chat over actual bytes.

use std::path::PathBuf;
use std::time::Duration;

use tokio::net::UnixStream;

use veilroom::admission::JoinPolicy;
use veilroom::admission::client::ClientAdmission;
use veilroom::admission::host::{HostAdmission, HostAdmissionReply};
use veilroom::chat::session::ChatSession;
use veilroom::crypto::identity::{HostIdentity, MemberIdentity};
use veilroom::crypto::password::PasswordVerifier;
use veilroom::event::{ConnectionId, HostCommand, MemberId, RequestId, RoomEvent};
use veilroom::limits::Limits;
use veilroom::net::client::ClientNetwork;
use veilroom::net::host::HostNetwork;
use veilroom::protocol::messages::Message;
use veilroom::room::action::{HostNotice, RoomAction};
use veilroom::room::actor::{HOST_CONNECTION, RoomActor};
use veilroom::room::task::RoomTask;
use veilroom::tor::manager::TorManager;
use veilroom::uri::Invitation;

const VIRTUAL_PORT: u16 = 80;
const ROOM_PASSWORD: &[u8] = b"test-room-password";

/// A valid-onion-grammar address for the invitation.
fn onion() -> String {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion".to_owned()
}

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("veilroom-netflow-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// Waits for the next room action batch.
async fn next_actions(room: &mut RoomTask) -> Vec<RoomAction> {
    tokio::time::timeout(Duration::from_secs(5), room.next_actions())
        .await
        .expect("room actions arrive")
        .expect("room task alive")
}

/// Waits for the next accepted connection id.
async fn next_connection(network: &mut HostNetwork) -> ConnectionId {
    tokio::time::timeout(Duration::from_secs(5), network.connects().recv())
        .await
        .expect("connection arrives")
        .expect("channel open")
}

/// Waits for the next inbound `(connection, message)`, skipping keepalives.
async fn next_message(network: &mut HostNetwork) -> (ConnectionId, Message) {
    loop {
        let (id, message) = tokio::time::timeout(Duration::from_secs(5), network.inbound().recv())
            .await
            .expect("message arrives")
            .expect("channel open");
        if let Some(message) = message {
            if matches!(message, Message::Keepalive(_)) {
                continue;
            }
            return (id, message);
        }
    }
}

/// Waits for the teardown marker of a connection.
async fn next_teardown(network: &mut HostNetwork) -> ConnectionId {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(5), network.inbound().recv())
            .await
            .expect("teardown arrives")
            .expect("channel open");
        if let (id, None) = item {
            return id;
        }
    }
}

/// Waits for the next inbound client message, skipping keepalives.
async fn next_client_message(network: &mut ClientNetwork) -> Message {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(5), network.recv())
            .await
            .expect("message arrives")
            .expect("channel open")
            .expect("a message, not teardown");
        if matches!(item, Message::Keepalive(_)) {
            continue;
        }
        return item;
    }
}

#[tokio::test]
async fn full_host_participant_flow_over_a_unix_socket() {
    let root = temp_root("flow");
    let chat_socket = root.join("chat.sock");
    let limits = Limits::default();

    // ---- host setup ------------------------------------------------------
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = HostIdentity::generate().unwrap();
    let host_client_identity = MemberIdentity::generate().unwrap();
    let actor = RoomActor::create(
        &limits,
        HOST_CONNECTION,
        "host".to_owned(),
        host_identity.clone(),
        host_client_identity.clone(),
        &veilroom::limits::Timeouts::default(),
    )
    .unwrap();
    let session_id = *actor.session_id().as_bytes();
    let (mut room, initial) = RoomTask::spawn_started(actor).unwrap();
    let mut network = HostNetwork::listen(&chat_socket, limits).await.unwrap();

    let mut host_chat = ChatSession::new(
        session_id,
        host_identity.ed25519_pubkey(),
        host_identity.x25519_pubkey(),
        MemberId::new(0),
    );
    let mut token = Vec::new();

    // The initial batch: invitation notice + the host's epoch wrap.
    for action in initial {
        match action {
            RoomAction::NotifyHost(HostNotice::InvitationRotated { token: new_token }) => {
                token = new_token.to_vec();
            }
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } if connection == HOST_CONNECTION => {
                let wrap_key = host_client_identity.wrap_key_for(
                    &host_identity.x25519_pubkey(),
                    &session_id,
                    0,
                );
                let epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
                    &wrap_key,
                    wrap.epoch,
                    &session_id,
                    &wrap.nonce,
                    &wrap.ciphertext,
                )
                .unwrap();
                host_chat.install_epoch(wrap.epoch, epoch_key);
                room.send(RoomEvent::EpochAck {
                    connection: HOST_CONNECTION,
                    epoch: wrap.epoch,
                })
                .await
                .unwrap();
            }
            other => panic!("unexpected initial action: {other:?}"),
        }
    }

    // ---- participant setup -----------------------------------------------
    let invitation = Invitation::new(onion(), VIRTUAL_PORT, token.clone()).unwrap();
    let client_stream = UnixStream::connect(&chat_socket).await.unwrap();
    let mut client_network = ClientNetwork::from_stream(client_stream, limits);
    let mut admission = ClientAdmission::new(
        invitation,
        veilroom::crypto::SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();
    client_network.send(admission.first_message()).unwrap();

    // ---- admission handshake ---------------------------------------------
    let id = next_connection(&mut network).await;
    let mut admission_host = HostAdmission::new(
        veilroom::protocol::session::RoomSessionId::from(session_id),
        veilroom::crypto::SecretBytes::from(token.clone()),
        verifier.clone(),
        &host_identity,
        onion(),
    )
    .unwrap();
    room.send(RoomEvent::ClientConnected { connection: id })
        .await
        .unwrap();

    // ClientHello -> HostHello.
    let (mid, Message::ClientHello(hello)) = next_message(&mut network).await else {
        panic!("expected a client hello");
    };
    assert_eq!(mid, id);
    let hello_reply = admission_host
        .on_client_hello(&hello, VIRTUAL_PORT)
        .unwrap();
    network.send_to(id, hello_reply).unwrap();

    // HostHello -> TokenVerify.
    let host_hello = next_client_message(&mut client_network).await;
    let replies = admission.on_host_message(&host_hello).unwrap();
    assert_eq!(replies.len(), 1);
    client_network.send(replies[0].clone()).unwrap();

    // TokenVerify -> PasswordChallenge.
    let (_, token_verify) = next_message(&mut network).await;
    assert!(matches!(token_verify, Message::TokenVerify(_)));
    let challenge = admission_host
        .on_message(&token_verify, JoinPolicy::Open)
        .unwrap()
        .expect("a challenge reply");
    let HostAdmissionReply::Message(challenge) = challenge else {
        panic!("expected a challenge");
    };
    network.send_to(id, challenge.clone()).unwrap();

    // PasswordChallenge -> ChallengeProof.
    let challenge_msg = next_client_message(&mut client_network).await;
    let proof_replies = admission.on_host_message(&challenge_msg).unwrap();
    assert_eq!(proof_replies.len(), 1);
    client_network.send(proof_replies[0].clone()).unwrap();

    // ChallengeProof validated: no reply, the room is told.
    let (_, challenge_proof) = next_message(&mut network).await;
    assert!(matches!(challenge_proof, Message::ChallengeProof(_)));
    assert!(
        admission_host
            .on_message(&challenge_proof, JoinPolicy::Open)
            .unwrap()
            .is_none()
    );
    room.send(RoomEvent::PasswordVerified { connection: id })
        .await
        .unwrap();

    // ---- join form and decision ------------------------------------------
    let join_message = admission
        .join_request("deniz".to_owned(), Some("merhaba".to_owned()))
        .unwrap();
    client_network.send(join_message.clone()).unwrap();

    let (_, join_request) = next_message(&mut network).await;
    assert!(matches!(join_request, Message::JoinRequest(_)));
    let application = match admission_host
        .on_message(&join_request, JoinPolicy::Open)
        .unwrap()
    {
        Some(HostAdmissionReply::JoinRequested(application)) => application,
        _ => panic!("expected a join application"),
    };
    room.send(RoomEvent::JoinRequested {
        connection: id,
        nickname: application.nickname,
        introduction: application.introduction,
        ed25519_pubkey: application.ed25519_pubkey,
        x25519_pubkey: application.x25519_pubkey,
        signature: application.signature,
    })
    .await
    .unwrap();
    let notice_actions = next_actions(&mut room).await;
    let request_id = notice_actions
        .iter()
        .find_map(|action| match action {
            RoomAction::NotifyHost(HostNotice::JoinRequestPending { request_id, .. }) => {
                Some(*request_id)
            }
            _ => None,
        })
        .expect("a pending-request notice");

    // The host accepts; the client receives JOIN_ACCEPTED and its epoch wrap.
    room.send(RoomEvent::HostCommand(HostCommand::Accept {
        request_id: RequestId::new(request_id.as_u64()),
    }))
    .await
    .unwrap();
    let accepted = next_actions(&mut room).await;
    let mut join_accepted = None;
    let mut client_wrap = None;
    let mut host_wrap = None;
    for action in &accepted {
        match action {
            RoomAction::SendTo {
                connection,
                message: Message::JoinAccepted(accepted),
            } if *connection == id => join_accepted = Some(*accepted),
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } if *connection == id => client_wrap = Some(wrap.clone()),
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } if *connection == HOST_CONNECTION => host_wrap = Some(wrap.clone()),
            _ => {}
        }
    }
    let join_accepted = join_accepted.expect("the client must receive JOIN_ACCEPTED");
    let client_wrap = client_wrap.expect("the client must receive its epoch wrap");
    let host_wrap = host_wrap.expect("the host must receive its own epoch wrap");

    // The host installs its own epoch key and acknowledges.
    let host_wrap_key =
        host_client_identity.wrap_key_for(&host_identity.x25519_pubkey(), &session_id, 0);
    let host_epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
        &host_wrap_key,
        host_wrap.epoch,
        &session_id,
        &host_wrap.nonce,
        &host_wrap.ciphertext,
    )
    .unwrap();
    host_chat.install_epoch(host_wrap.epoch, host_epoch_key);
    room.send(RoomEvent::EpochAck {
        connection: HOST_CONNECTION,
        epoch: host_wrap.epoch,
    })
    .await
    .unwrap();

    network
        .send_to(id, Message::JoinAccepted(join_accepted))
        .unwrap();
    network
        .send_to(id, Message::EpochWrap(client_wrap.clone()))
        .unwrap();

    // The client processes the decision and acknowledges the epoch.
    let decision = next_client_message(&mut client_network).await;
    admission.on_host_message(&decision).unwrap();
    assert!(admission.is_admitted());
    let wrap_msg = next_client_message(&mut client_network).await;
    let Message::EpochWrap(wrap) = wrap_msg else {
        panic!("expected an epoch wrap");
    };
    let ack = admission.on_epoch_wrap(&wrap).unwrap();
    client_network.send(ack.clone()).unwrap();

    // The client's acknowledgement completes the transition; the host
    // receives the membership broadcast and the new member the snapshot.
    let (_, Message::EpochAck(_)) = next_message(&mut network).await else {
        panic!("expected an epoch ack");
    };
    room.send(RoomEvent::EpochAck {
        connection: id,
        epoch: wrap.epoch,
    })
    .await
    .unwrap();
    let activation = next_actions(&mut room).await;
    let mut host_joined_seen = false;
    let mut snapshot_seen = false;
    for action in &activation {
        match action {
            RoomAction::SendTo {
                connection,
                message: Message::MemberJoined(event),
            } if *connection == HOST_CONNECTION => {
                host_chat.handle_member_joined(event).unwrap();
                host_joined_seen = true;
            }
            RoomAction::SendTo {
                connection,
                message: Message::MemberSnapshot(snapshot),
            } if *connection == id => {
                network
                    .send_to(id, Message::MemberSnapshot(snapshot.clone()))
                    .unwrap();
                snapshot_seen = true;
            }
            _ => {}
        }
    }
    assert!(host_joined_seen, "the host must learn the new member");
    assert!(snapshot_seen, "the new member must receive its snapshot");
    let snapshot_msg = next_client_message(&mut client_network).await;
    admission.on_membership_message(&snapshot_msg).unwrap();
    assert!(
        admission.member_view(MemberId::new(0)).is_some(),
        "the participant knows the host"
    );
    assert!(
        admission.member_view(MemberId::new(1)).is_some(),
        "the participant knows itself"
    );
    assert!(
        host_chat.member(MemberId::new(1)).is_some(),
        "the host knows the participant"
    );

    // ---- encrypted chat both ways ----------------------------------------
    // Participant -> host.
    let client_chat = admission.send_chat("selam host").unwrap();
    client_network.send(client_chat.clone()).unwrap();
    let mid = id;
    let (mid2, Message::ChatMessage(envelope)) = next_message(&mut network).await else {
        panic!("expected a chat message");
    };
    assert_eq!(mid, mid2);
    room.send(RoomEvent::ChatReceived {
        connection: id,
        message_type: 0x40,
        envelope: envelope.clone(),
    })
    .await
    .unwrap();
    let relay = next_actions(&mut room).await;
    let relayed = relay
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(envelope),
            } if *connection == HOST_CONNECTION => Some(envelope.clone()),
            _ => None,
        })
        .expect("the host must receive the participant's message");
    assert_eq!(
        host_chat.receive_chat(&relayed).unwrap(),
        "selam host",
        "the host decrypts the participant's message"
    );

    // Host -> participant.
    let host_message = host_chat
        .send_chat(&host_client_identity, "merhaba deniz")
        .unwrap();
    let Message::ChatMessage(envelope) = host_message else {
        panic!("expected a chat message");
    };
    room.send(RoomEvent::ChatReceived {
        connection: HOST_CONNECTION,
        message_type: 0x40,
        envelope,
    })
    .await
    .unwrap();
    let relay = next_actions(&mut room).await;
    let relayed = relay
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(envelope),
            } if *connection == id => Some(envelope.clone()),
            _ => None,
        })
        .expect("the participant must receive the host's message");
    network
        .send_to(id, Message::ChatMessage(relayed.clone()))
        .unwrap();
    let incoming = next_client_message(&mut client_network).await;
    let Message::ChatMessage(envelope) = incoming else {
        panic!("expected a chat message");
    };
    assert_eq!(
        admission.on_member_message(0x40, &envelope).unwrap(),
        Some("merhaba deniz".to_owned()),
        "the participant decrypts the host's message"
    );

    // ---- participant leaves ----------------------------------------------
    drop(client_network);
    let left_id = next_teardown(&mut network).await;
    assert_eq!(left_id, id);
    network.close(id);
    room.send(RoomEvent::ConnectionLost { connection: id })
        .await
        .unwrap();
    let after = next_actions(&mut room).await;
    assert!(
        after.iter().any(|action| matches!(
            action,
            RoomAction::NotifyHost(HostNotice::MemberLeft { .. })
        )),
        "the room notices the leaving member"
    );

    network.close_all();
    network.stop();
    let _ = std::fs::remove_dir_all(&root);
}

/// The full host/participant scenario over real Tor (section 41.4).
///
/// Identical to the in-memory flow above, except the participant connects
/// through the session's real SOCKS socket to the real ephemeral onion
/// service. Requires a `tor` binary on `PATH` and network access.
#[tokio::test]
#[ignore = "requires a real tor binary and network access"]
async fn real_tor_full_host_participant_flow() {
    use std::process::Command as StdCommand;

    if StdCommand::new("tor").arg("--version").output().is_err() {
        eprintln!("skipping: `tor` binary not found on PATH");
        return;
    }

    let root = temp_root("realtor");
    let limits = Limits::default();

    // Tor: the host's own subprocess and onion service.
    let mut tor = TorManager::prepare_with(
        &root,
        veilroom::tor::manager::TorConfig {
            bootstrap_timeout: Duration::from_secs(120),
            ..veilroom::tor::manager::TorConfig::default()
        },
    )
    .expect("session prepare");
    tor.start().await.expect("tor subprocess start");
    let onion = tor.add_onion(VIRTUAL_PORT).await.expect("ADD_ONION");
    let socks_socket = tor.paths().socks_socket.clone();
    let chat_socket = tor.paths().chat_socket.clone();

    // Host side, exactly as in the in-memory flow.
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = HostIdentity::generate().unwrap();
    let host_client_identity = MemberIdentity::generate().unwrap();
    let actor = RoomActor::create(
        &limits,
        HOST_CONNECTION,
        "host".to_owned(),
        host_identity.clone(),
        host_client_identity.clone(),
        &veilroom::limits::Timeouts::default(),
    )
    .unwrap();
    let session_id = *actor.session_id().as_bytes();
    let (mut room, initial) = RoomTask::spawn_started(actor).unwrap();
    let mut network = HostNetwork::listen(&chat_socket, limits).await.unwrap();
    let mut host_chat = ChatSession::new(
        session_id,
        host_identity.ed25519_pubkey(),
        host_identity.x25519_pubkey(),
        MemberId::new(0),
    );
    let mut token = Vec::new();
    for action in initial {
        match action {
            RoomAction::NotifyHost(HostNotice::InvitationRotated { token: new_token }) => {
                token = new_token.to_vec();
            }
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } if connection == HOST_CONNECTION => {
                let wrap_key = host_client_identity.wrap_key_for(
                    &host_identity.x25519_pubkey(),
                    &session_id,
                    0,
                );
                let epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
                    &wrap_key,
                    wrap.epoch,
                    &session_id,
                    &wrap.nonce,
                    &wrap.ciphertext,
                )
                .unwrap();
                host_chat.install_epoch(wrap.epoch, epoch_key);
                room.send(RoomEvent::EpochAck {
                    connection: HOST_CONNECTION,
                    epoch: wrap.epoch,
                })
                .await
                .unwrap();
            }
            other => panic!("unexpected initial action: {other:?}"),
        }
    }

    // The participant connects through Tor: the real SOCKS socket to the
    // real onion address.
    let invitation =
        Invitation::new(onion.onion_address.clone(), VIRTUAL_PORT, token.clone()).unwrap();
    let mut client_network = ClientNetwork::connect(
        &socks_socket,
        invitation.onion_address(),
        invitation.port(),
        limits,
    )
    .await
    .expect("SOCKS connect through Tor");
    let mut admission = ClientAdmission::new(
        invitation,
        veilroom::crypto::SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();
    client_network.send(admission.first_message()).unwrap();

    // The admission handshake.
    let id = next_connection(&mut network).await;
    let mut admission_host = HostAdmission::new(
        veilroom::protocol::session::RoomSessionId::from(session_id),
        veilroom::crypto::SecretBytes::from(token.clone()),
        verifier.clone(),
        &host_identity,
        onion.onion_address.clone(),
    )
    .unwrap();
    room.send(RoomEvent::ClientConnected { connection: id })
        .await
        .unwrap();

    let (mid, Message::ClientHello(hello)) = next_message(&mut network).await else {
        panic!("expected a client hello");
    };
    assert_eq!(mid, id);
    let hello_reply = admission_host
        .on_client_hello(&hello, VIRTUAL_PORT)
        .unwrap();
    network.send_to(id, hello_reply).unwrap();

    let host_hello = next_client_message(&mut client_network).await;
    let replies = admission.on_host_message(&host_hello).unwrap();
    client_network.send(replies[0].clone()).unwrap();

    let (_, token_verify) = next_message(&mut network).await;
    let challenge = admission_host
        .on_message(&token_verify, JoinPolicy::Open)
        .unwrap()
        .expect("a challenge reply");
    let HostAdmissionReply::Message(challenge) = challenge else {
        panic!("expected a challenge");
    };
    network.send_to(id, challenge.clone()).unwrap();

    let challenge_msg = next_client_message(&mut client_network).await;
    let proof_replies = admission.on_host_message(&challenge_msg).unwrap();
    client_network.send(proof_replies[0].clone()).unwrap();

    let (_, challenge_proof) = next_message(&mut network).await;
    assert!(
        admission_host
            .on_message(&challenge_proof, JoinPolicy::Open)
            .unwrap()
            .is_none()
    );
    room.send(RoomEvent::PasswordVerified { connection: id })
        .await
        .unwrap();

    // The join form and the host decision.
    let join_message = admission
        .join_request("deniz".to_owned(), Some("merhaba".to_owned()))
        .unwrap();
    client_network.send(join_message.clone()).unwrap();

    let (_, join_request) = next_message(&mut network).await;
    let application = match admission_host
        .on_message(&join_request, JoinPolicy::Open)
        .unwrap()
    {
        Some(HostAdmissionReply::JoinRequested(application)) => application,
        _ => panic!("expected a join application"),
    };
    room.send(RoomEvent::JoinRequested {
        connection: id,
        nickname: application.nickname,
        introduction: application.introduction,
        ed25519_pubkey: application.ed25519_pubkey,
        x25519_pubkey: application.x25519_pubkey,
        signature: application.signature,
    })
    .await
    .unwrap();
    let notice_actions = next_actions(&mut room).await;
    let request_id = notice_actions
        .iter()
        .find_map(|action| match action {
            RoomAction::NotifyHost(HostNotice::JoinRequestPending { request_id, .. }) => {
                Some(*request_id)
            }
            _ => None,
        })
        .expect("a pending-request notice");
    room.send(RoomEvent::HostCommand(HostCommand::Accept {
        request_id: RequestId::new(request_id.as_u64()),
    }))
    .await
    .unwrap();
    let accepted = next_actions(&mut room).await;
    let mut join_accepted = None;
    let mut client_wrap = None;
    let mut host_wrap = None;
    for action in &accepted {
        match action {
            RoomAction::SendTo {
                connection,
                message: Message::JoinAccepted(accepted),
            } if *connection == id => join_accepted = Some(*accepted),
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } if *connection == id => client_wrap = Some(wrap.clone()),
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } if *connection == HOST_CONNECTION => host_wrap = Some(wrap.clone()),
            _ => {}
        }
    }
    let host_wrap = host_wrap.expect("the host must receive its own epoch wrap");
    let host_wrap_key =
        host_client_identity.wrap_key_for(&host_identity.x25519_pubkey(), &session_id, 0);
    let host_epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
        &host_wrap_key,
        host_wrap.epoch,
        &session_id,
        &host_wrap.nonce,
        &host_wrap.ciphertext,
    )
    .unwrap();
    host_chat.install_epoch(host_wrap.epoch, host_epoch_key);
    room.send(RoomEvent::EpochAck {
        connection: HOST_CONNECTION,
        epoch: host_wrap.epoch,
    })
    .await
    .unwrap();
    network
        .send_to(
            id,
            Message::JoinAccepted(join_accepted.expect("join accepted")),
        )
        .unwrap();
    network
        .send_to(
            id,
            Message::EpochWrap(client_wrap.expect("client wrap").clone()),
        )
        .unwrap();

    let decision = next_client_message(&mut client_network).await;
    admission.on_host_message(&decision).unwrap();
    assert!(admission.is_admitted());
    let wrap_msg = next_client_message(&mut client_network).await;
    let Message::EpochWrap(wrap) = wrap_msg else {
        panic!("expected an epoch wrap");
    };
    let ack = admission.on_epoch_wrap(&wrap).unwrap();
    client_network.send(ack.clone()).unwrap();

    let (_, Message::EpochAck(_)) = next_message(&mut network).await else {
        panic!("expected an epoch ack");
    };
    room.send(RoomEvent::EpochAck {
        connection: id,
        epoch: wrap.epoch,
    })
    .await
    .unwrap();
    let activation = next_actions(&mut room).await;
    let mut snapshot_seen = false;
    for action in &activation {
        match action {
            RoomAction::SendTo {
                connection,
                message: Message::MemberJoined(event),
            } if *connection == HOST_CONNECTION => {
                host_chat.handle_member_joined(event).unwrap();
            }
            RoomAction::SendTo {
                connection,
                message: Message::MemberSnapshot(snapshot),
            } if *connection == id => {
                network
                    .send_to(id, Message::MemberSnapshot(snapshot.clone()))
                    .unwrap();
                snapshot_seen = true;
            }
            _ => {}
        }
    }
    assert!(snapshot_seen, "the new member must receive its snapshot");
    let snapshot_msg = next_client_message(&mut client_network).await;
    admission.on_membership_message(&snapshot_msg).unwrap();

    // Encrypted chat over real Tor, both directions.
    let client_chat = admission.send_chat("selam host").unwrap();
    client_network.send(client_chat.clone()).unwrap();
    let (_, Message::ChatMessage(envelope)) = next_message(&mut network).await else {
        panic!("expected a chat message");
    };
    room.send(RoomEvent::ChatReceived {
        connection: id,
        message_type: 0x40,
        envelope: envelope.clone(),
    })
    .await
    .unwrap();
    let relay = next_actions(&mut room).await;
    let relayed = relay
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(envelope),
            } if *connection == HOST_CONNECTION => Some(envelope.clone()),
            _ => None,
        })
        .expect("the host must receive the participant's message");
    assert_eq!(host_chat.receive_chat(&relayed).unwrap(), "selam host");

    let host_message = host_chat
        .send_chat(&host_client_identity, "merhaba deniz")
        .unwrap();
    let Message::ChatMessage(envelope) = host_message else {
        panic!("expected a chat message");
    };
    room.send(RoomEvent::ChatReceived {
        connection: HOST_CONNECTION,
        message_type: 0x40,
        envelope,
    })
    .await
    .unwrap();
    let relay = next_actions(&mut room).await;
    let relayed = relay
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(envelope),
            } if *connection == id => Some(envelope.clone()),
            _ => None,
        })
        .expect("the participant must receive the host's message");
    network
        .send_to(id, Message::ChatMessage(relayed.clone()))
        .unwrap();
    let incoming = next_client_message(&mut client_network).await;
    let Message::ChatMessage(envelope) = incoming else {
        panic!("expected a chat message");
    };
    assert_eq!(
        admission.on_member_message(0x40, &envelope).unwrap(),
        Some("merhaba deniz".to_owned())
    );

    // Cleanup: the participant leaves, the host shuts Tor down.
    drop(client_network);
    let left_id = next_teardown(&mut network).await;
    assert_eq!(left_id, id);
    let session_dir = tor.paths().session_dir.clone();
    network.close_all();
    network.stop();
    drop(room);
    tor.shutdown().await.expect("controlled shutdown");
    assert!(
        !session_dir.exists(),
        "the session directory must be removed after shutdown"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The pre-auth connection budget (section 28) must be released when an
/// admitted member's connection closes.
///
/// A cumulative "admitted" counter would leak budget on every departure, so
/// after enough join/leave churn an unauthenticated peer could hold far more
/// than `max_pre_auth_connections` sockets open on the host.
#[tokio::test]
async fn admitted_members_release_the_pre_auth_budget_when_they_close() {
    use tokio::io::AsyncReadExt;

    let root = temp_root("preauth");
    let chat_socket = root.join("chat.sock");
    let limits = Limits::default();
    let max_pre_auth = limits.max_pre_auth_connections();
    let mut network = HostNetwork::listen(&chat_socket, limits).await.unwrap();

    // One connection is admitted as a member, then leaves.
    let admitted_stream = UnixStream::connect(&chat_socket).await.unwrap();
    let admitted_id = next_connection(&mut network).await;
    assert_eq!(network.pre_auth_connections(), 1);
    network.mark_admitted(admitted_id);
    assert_eq!(
        network.pre_auth_connections(),
        0,
        "an admitted member must not consume pre-auth budget"
    );
    network.close(admitted_id);
    drop(admitted_stream);
    assert_eq!(network.pre_auth_connections(), 0);

    // The budget must be exactly `max_pre_auth` again, not `max_pre_auth + 1`.
    let mut held = Vec::new();
    for _ in 0..max_pre_auth {
        held.push(UnixStream::connect(&chat_socket).await.unwrap());
        let _ = next_connection(&mut network).await;
    }
    assert_eq!(network.pre_auth_connections(), max_pre_auth);

    // One more is refused: the listener drops the stream, so the peer sees EOF.
    let mut refused = UnixStream::connect(&chat_socket).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), refused.read(&mut byte))
        .await
        .expect("the refused connection resolves instead of hanging");
    assert!(
        matches!(read, Ok(0)),
        "a connection past the pre-auth cap must be closed, got {read:?}"
    );
    assert_eq!(network.pre_auth_connections(), max_pre_auth);

    drop(held);
    network.close_all();
    network.stop();
    let _ = std::fs::remove_dir_all(&root);
}
