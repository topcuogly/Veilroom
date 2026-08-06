//! Room-actor chat relay, replay, rate limiting, and membership broadcasts
//! (Stage 7, sections 5, 16, 17 and 29).

use std::time::Duration;

use veilroom::admission::{ClientAdmission, HostAdmission, HostAdmissionReply, JoinPolicy};
use veilroom::chat::session::ChatSession;
use veilroom::command::ColorChoice;
use veilroom::crypto::SecretBytes;
use veilroom::crypto::identity::{HostIdentity, MemberIdentity};
use veilroom::crypto::password::PasswordVerifier;
use veilroom::event::{ConnectionId, HostCommand, MemberId, MemberRef, RoomEvent};
use veilroom::limits::Limits;
use veilroom::protocol::chat::EncryptedEnvelope;
use veilroom::protocol::ids::ErrorCode;
use veilroom::protocol::{FrameDecoder, Message, decode_message, encode_message};
use veilroom::room::action::{HostNotice, RoomAction};
use veilroom::room::actor::RoomActor;
use veilroom::room::{HOST_CONNECTION, RoomError};
use veilroom::state::RoomState;
use veilroom::uri::Invitation;

const HOST: ConnectionId = HOST_CONNECTION;
const ROOM_PASSWORD: &[u8] = b"correct horse battery staple";

fn onion() -> String {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion".to_owned()
}

fn limits() -> Limits {
    Limits::default()
}

fn host_identity() -> HostIdentity {
    HostIdentity::from_seed([0x21; 32], [0x22; 32])
}

fn host_client_identity() -> MemberIdentity {
    MemberIdentity::from_seed([0x23; 32], [0x24; 32])
}

fn over_the_wire(message: &Message) -> Message {
    let bytes = encode_message(message, &limits()).unwrap();
    let mut decoder = FrameDecoder::new(limits());
    let frames = decoder.feed(&bytes).unwrap();
    assert_eq!(frames.len(), 1);
    decode_message(&frames[0], &limits()).unwrap()
}

/// Starts a room and acknowledges the host participant's first epoch.
fn start_room() -> RoomActor {
    let mut actor = RoomActor::create(
        &limits(),
        HOST,
        "host".to_owned(),
        host_identity(),
        host_client_identity(),
        &veilroom::limits::Timeouts::default(),
    )
    .unwrap();
    let actions = actor.start().unwrap();
    let wraps: Vec<&Message> = actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message,
            } if *connection == HOST => matches!(message, Message::EpochWrap(_)).then_some(message),
            _ => None,
        })
        .collect();
    assert_eq!(wraps.len(), 1);
    let Message::EpochWrap(wrap) = wraps[0] else {
        panic!()
    };
    let session = *actor.session_id();
    let wrap_key = host_client_identity().wrap_key_for(
        &host_identity().x25519_pubkey(),
        session.as_bytes(),
        0,
    );
    let epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
        &wrap_key,
        wrap.epoch,
        session.as_bytes(),
        &wrap.nonce,
        &wrap.ciphertext,
    )
    .unwrap();
    let _ = epoch_key;
    actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: wrap.epoch,
        })
        .unwrap();
    assert_eq!(actor.state(), RoomState::Open);
    actor
}

/// Drives a participant through admission and returns the accepted client
/// together with the host's actions of the accept (the epoch wraps).
///
/// The new epoch is NOT acknowledged: the room is left in
/// `RoomState::EpochTransition` with this member pending.
fn admit_member_unacked(
    actor: &mut RoomActor,
    token: &[u8],
    connection: ConnectionId,
    nickname: &str,
) -> (ClientAdmission, Vec<RoomAction>) {
    let session = *actor.session_id();
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host = host_identity();
    let mut host = HostAdmission::new(
        session,
        SecretBytes::from(token.to_vec()),
        verifier,
        &host,
        onion(),
    )
    .unwrap();
    let mut client = ClientAdmission::new(
        Invitation::new(onion(), 80, token.to_vec()).unwrap(),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();

    let hello = over_the_wire(&client.first_message());
    let host_hello = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap();
    let token_verify = client.on_host_message(&over_the_wire(&host_hello)).unwrap();
    let challenge = host
        .on_message(&over_the_wire(&token_verify[0]), JoinPolicy::Open)
        .unwrap();
    let challenge = match challenge {
        Some(HostAdmissionReply::Message(message)) => message,
        _ => panic!(),
    };
    let proof = client.on_host_message(&over_the_wire(&challenge)).unwrap();
    host.on_message(&over_the_wire(&proof[0]), JoinPolicy::Open)
        .unwrap();
    let join_request = client.join_request(nickname.to_owned(), None).unwrap();
    let application = match host
        .on_message(&over_the_wire(&join_request), JoinPolicy::Open)
        .unwrap()
    {
        Some(HostAdmissionReply::JoinRequested(application)) => application,
        _ => panic!(),
    };

    actor
        .handle_event(RoomEvent::ClientConnected { connection })
        .unwrap();
    actor
        .handle_event(RoomEvent::PasswordVerified { connection })
        .unwrap();
    let request_actions = actor
        .handle_event(RoomEvent::JoinRequested {
            connection,
            nickname: nickname.to_owned(),
            introduction: None,
            ed25519_pubkey: application.ed25519_pubkey,
            x25519_pubkey: application.x25519_pubkey,
            signature: application.signature,
        })
        .unwrap();
    let request_id = match &request_actions[0] {
        RoomAction::NotifyHost(HostNotice::JoinRequestPending { request_id, .. }) => *request_id,
        _ => panic!("expected a pending-request notice"),
    };

    let accept_actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();
    // The room assigns the member id in its JOIN_ACCEPTED message.
    let member_id = accept_actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection: c,
                message: Message::JoinAccepted(accepted),
            } if *c == connection => Some(accepted.member_id),
            _ => None,
        })
        .expect("the accepted member must receive JOIN_ACCEPTED");
    client
        .on_host_message(&Message::JoinAccepted(
            veilroom::protocol::JoinAccepted::new(member_id),
        ))
        .unwrap();
    (client, accept_actions)
}

/// Drives a participant through admission and returns the admitted client.
///
/// `members` holds the previously admitted clients so their epoch wraps
/// from this transition can be delivered and acknowledged.
fn admit_member(
    actor: &mut RoomActor,
    token: &[u8],
    connection: ConnectionId,
    nickname: &str,
    members: &mut [(ConnectionId, ClientAdmission)],
) -> ClientAdmission {
    let (mut client, accept_actions) = admit_member_unacked(actor, token, connection, nickname);

    // The client unwraps its epoch wrap and acknowledges.
    let wraps: Vec<&Message> = accept_actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection: c,
                message,
            } if *c == connection => matches!(message, Message::EpochWrap(_)).then_some(message),
            _ => None,
        })
        .collect();
    assert_eq!(wraps.len(), 1);
    let Message::EpochWrap(wrap) = wraps[0] else {
        panic!()
    };
    let ack = client.on_epoch_wrap(wrap).unwrap();
    let Message::EpochAck(ack) = ack else {
        panic!()
    };
    actor
        .handle_event(RoomEvent::EpochAck {
            connection,
            epoch: ack.epoch,
        })
        .unwrap();

    // The new member receives its own membership snapshot and broadcast.
    for action in &accept_actions {
        if let RoomAction::SendTo {
            connection: other,
            message,
        } = action
        {
            if *other == connection
                && matches!(
                    message,
                    Message::MemberSnapshot(_) | Message::MemberJoined(_)
                )
            {
                client.on_membership_message(message).unwrap();
            }
        }
    }

    // Every other wrap recipient must receive its new epoch key and
    // acknowledge before the epoch activates. The final acknowledgement
    // returns the membership broadcasts, which are delivered to the
    // member clients (including the new member).
    let mut activation_actions = Vec::new();
    for action in &accept_actions {
        let RoomAction::SendTo {
            connection: other,
            message: Message::EpochWrap(other_wrap),
        } = action
        else {
            continue;
        };
        if *other == connection {
            continue;
        }
        if *other == HOST {
            activation_actions.extend(
                actor
                    .handle_event(RoomEvent::EpochAck {
                        connection: HOST,
                        epoch: other_wrap.epoch,
                    })
                    .unwrap(),
            );
            continue;
        }
        let Some((_, existing)) = members.iter_mut().find(|(c, _)| c == other) else {
            activation_actions.extend(
                actor
                    .handle_event(RoomEvent::EpochAck {
                        connection: *other,
                        epoch: other_wrap.epoch,
                    })
                    .unwrap(),
            );
            continue;
        };
        let ack = existing.on_epoch_wrap(other_wrap).unwrap();
        let Message::EpochAck(ack) = ack else {
            panic!()
        };
        activation_actions.extend(
            actor
                .handle_event(RoomEvent::EpochAck {
                    connection: *other,
                    epoch: ack.epoch,
                })
                .unwrap(),
        );
    }
    // Deliver the membership broadcasts to every member client.
    for action in &activation_actions {
        let RoomAction::SendTo {
            connection: other,
            message,
        } = action
        else {
            continue;
        };
        if !matches!(
            message,
            Message::MemberJoined(_)
                | Message::MemberSnapshot(_)
                | Message::MemberLeft(_)
                | Message::MemberKicked(_)
        ) {
            continue;
        }
        if *other == connection {
            client.on_membership_message(message).unwrap();
        } else if let Some((_, existing)) = members.iter_mut().find(|(c, _)| c == other) {
            existing.on_membership_message(message).unwrap();
        }
    }
    assert_eq!(actor.state(), RoomState::Open);
    client
}

/// Borrows the client of a member from the test's member list.
fn member_client(
    members: &mut [(ConnectionId, ClientAdmission)],
    connection: ConnectionId,
) -> &mut ClientAdmission {
    let (_, client) = members
        .iter_mut()
        .find(|(c, _)| *c == connection)
        .expect("member client exists");
    client
}

fn chat_event(connection: ConnectionId, envelope: &EncryptedEnvelope) -> RoomEvent {
    RoomEvent::ChatReceived {
        connection,
        message_type: 0x40,
        envelope: envelope.clone(),
    }
}

fn timeout_request_event(connection: ConnectionId, envelope: &EncryptedEnvelope) -> RoomEvent {
    RoomEvent::ChatReceived {
        connection,
        message_type: 0x42,
        envelope: envelope.clone(),
    }
}

#[test]
fn member_timeout_request_waits_for_host_acceptance() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));

    let message = member_client(&mut members, ConnectionId::new(1))
        .send_timeout_request(30)
        .unwrap();
    let Message::TimeoutRequest(envelope) = message else {
        panic!("expected timeout request")
    };
    let actions = actor
        .handle_event(timeout_request_event(ConnectionId::new(1), &envelope))
        .unwrap();
    let request_id = actions
        .iter()
        .find_map(|action| match action {
            RoomAction::NotifyHost(HostNotice::TimeoutRequestPending {
                request_id,
                nickname,
                seconds,
                ..
            }) if nickname == "alice" && *seconds == 30 => Some(*request_id),
            _ => None,
        })
        .expect("the host receives an actionable timeout request");
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, RoomAction::SendTo { .. })),
        "the setting is not broadcast before host acceptance"
    );

    let pending = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Requests))
        .unwrap();
    let (join_requests, timeout_requests) = notices(&pending)
        .into_iter()
        .find_map(|notice| match notice {
            HostNotice::RequestsSnapshot {
                join_requests,
                timeout_requests,
            } => Some((join_requests, timeout_requests)),
            _ => None,
        })
        .expect("the shared requests snapshot is emitted");
    assert!(join_requests.is_empty());
    assert_eq!(timeout_requests.len(), 1);
    assert_eq!(timeout_requests[0].request_id, request_id);
    assert_eq!(timeout_requests[0].nickname, "alice");
    assert_eq!(timeout_requests[0].seconds, 30);

    let accepted = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Accept { request_id }))
        .unwrap();
    assert!(accepted.iter().any(|action| matches!(
        action,
        RoomAction::NotifyHost(HostNotice::TimeoutRequestAccepted {
            request_id: id,
            seconds: 30,
        }) if *id == request_id
    )));

    let refreshed = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Requests))
        .unwrap();
    let timeout_requests = notices(&refreshed)
        .into_iter()
        .find_map(|notice| match notice {
            HostNotice::RequestsSnapshot {
                timeout_requests, ..
            } => Some(timeout_requests),
            _ => None,
        })
        .expect("the refreshed requests snapshot is emitted");
    assert!(
        timeout_requests.is_empty(),
        "accepted timeout requests must leave the pending panel"
    );

    // The host turns the accepted value into an authenticated room-wide
    // setting, which the actor relays to every other member.
    let mut host_chat = ChatSession::new(
        *actor.session_id().as_bytes(),
        host_identity().ed25519_pubkey(),
        host_identity().x25519_pubkey(),
        MemberId::new(0),
    );
    host_chat.install_epoch(
        actor.epoch(),
        veilroom::crypto::identity::EpochKey::from_bytes(*actor.epoch_key().unwrap().as_bytes()),
    );
    let setting = host_chat
        .send_timeout_changed(&host_client_identity(), Some(30))
        .unwrap();
    let Message::TimeoutChanged(setting) = setting else {
        panic!("expected timeout setting")
    };
    let relayed = actor
        .handle_event(RoomEvent::ChatReceived {
            connection: HOST,
            message_type: 0x43,
            envelope: setting,
        })
        .unwrap()
        .into_iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::TimeoutChanged(envelope),
            } if connection == ConnectionId::new(1) => Some(envelope),
            _ => None,
        })
        .expect("the accepted timeout is relayed to the member");
    let applied = member_client(&mut members, ConnectionId::new(1))
        .chat_mut()
        .unwrap()
        .receive_timeout_changed(&relayed)
        .unwrap();
    assert_eq!(applied, Some(30));
}

#[test]
fn chat_is_relayed_to_every_member_except_the_sender() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(2),
        "bob",
        &mut members,
    );
    members.push((ConnectionId::new(2), client));

    let message = member_client(&mut members, ConnectionId::new(1))
        .send_chat("merhaba dünya")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };

    let actions = actor
        .handle_event(chat_event(ConnectionId::new(1), &envelope))
        .unwrap();
    let destinations: Vec<ConnectionId> = actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(_),
            } => Some(*connection),
            _ => None,
        })
        .collect();
    assert_eq!(destinations, vec![HOST, ConnectionId::new(2)]);

    // The relayed envelope is the original: signature and ciphertext intact.
    let relayed = actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(e),
            } if *connection == ConnectionId::new(2) => Some(e.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(relayed, envelope);

    // Bob receives the message.
    let text = member_client(&mut members, ConnectionId::new(2))
        .on_member_message(0x40, &relayed)
        .unwrap();
    assert_eq!(text, Some("merhaba dünya".to_owned()));
}

#[test]
fn old_epoch_chat_is_rejected() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(2),
        "bob",
        &mut members,
    );
    members.push((ConnectionId::new(2), client));
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_chat("old")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };

    // Rotate the epoch away (kick bob) so alice's message is obsolete.
    let actions = actor
        .handle_event(RoomEvent::HostCommand(veilroom::event::HostCommand::Kick {
            target: MemberRef::Id(MemberId::new(2)),
        }))
        .unwrap();
    let host_wraps: Vec<&Message> = actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message,
            } if *connection == HOST => matches!(message, Message::EpochWrap(_)).then_some(message),
            _ => None,
        })
        .collect();
    let Message::EpochWrap(wrap) = host_wraps[0] else {
        panic!()
    };
    // Both remaining members (host and alice) acknowledge the rotation.
    for action in &actions {
        if let RoomAction::SendTo {
            connection: other,
            message: Message::EpochWrap(other_wrap),
        } = action
        {
            actor
                .handle_event(RoomEvent::EpochAck {
                    connection: *other,
                    epoch: other_wrap.epoch,
                })
                .unwrap();
        }
    }
    let _ = wrap;
    assert_eq!(actor.state(), RoomState::Open);
    assert_eq!(actor.epoch(), 4);

    // Alice's epoch-3 message is obsolete after the kick.
    let error = actor
        .handle_event(chat_event(ConnectionId::new(1), &envelope))
        .unwrap_err();
    assert!(matches!(
        error,
        RoomError::OldEpoch {
            found: 3,
            current: 4
        }
    ));
}

#[test]
fn replayed_chat_is_rejected() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_chat("once")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    actor
        .handle_event(chat_event(ConnectionId::new(1), &envelope))
        .unwrap();
    let error = actor
        .handle_event(chat_event(ConnectionId::new(1), &envelope))
        .unwrap_err();
    assert!(matches!(
        error,
        RoomError::ReplayRejected {
            sender: 1,
            sequence: 1
        }
    ));
}

#[test]
fn tampered_chat_is_rejected_and_not_relayed() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    let mut tampered =
        EncryptedEnvelope::new(2, 1, 1, [0x11; 24], vec![0x22; 17], [0x33; 64]).unwrap();
    tampered.ciphertext[0] ^= 0x01;
    let error = actor
        .handle_event(chat_event(ConnectionId::new(1), &tampered))
        .unwrap_err();
    assert!(matches!(error, RoomError::Chat(_)));
}

#[test]
fn chat_from_a_non_member_is_rejected() {
    let mut actor = start_room();
    let envelope = EncryptedEnvelope::new(1, 9, 1, [0x11; 24], vec![0x22; 17], [0x33; 64]).unwrap();
    let error = actor
        .handle_event(chat_event(ConnectionId::new(9), &envelope))
        .unwrap_err();
    assert!(matches!(error, RoomError::NotAMember { .. }));
}

#[test]
fn chat_during_an_epoch_transition_is_rejected() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(2),
        "bob",
        &mut members,
    );
    members.push((ConnectionId::new(2), client));
    // Kick bob: rotate the epoch, but do not acknowledge.
    let _ = actor
        .handle_event(RoomEvent::HostCommand(veilroom::event::HostCommand::Kick {
            target: MemberRef::Id(MemberId::new(2)),
        }))
        .unwrap();
    assert_eq!(actor.state(), RoomState::EpochTransition);

    // Alice has not acknowledged the rotated epoch yet. Her message cannot
    // be relayed (it is sealed under the retired key) and cannot be
    // re-sealed by the host, so it is dropped — but she is told, because
    // her client already echoed the line locally.
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_chat("too late")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event(chat_event(ConnectionId::new(1), &envelope))
        .expect("a transition drop is not a protocol violation");
    assert!(
        actions.iter().any(|action| matches!(
            action,
            RoomAction::SendTo {
                connection,
                message: Message::Error(error),
            } if *connection == ConnectionId::new(1)
                && error.code == ErrorCode::RateLimited
                && error.reason.is_some()
        )),
        "the sender must learn the message was not delivered: {actions:?}"
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, RoomAction::CloseConnection { .. })),
        "a transition drop must never close the connection"
    );
}

#[test]
fn acked_members_can_chat_while_another_member_stalls_the_transition() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));

    // Bob joins but withholds his epoch acknowledgement: the room stays in
    // EpochTransition with bob pending.
    let (mut bob, bob_actions) =
        admit_member_unacked(&mut actor, &token, ConnectionId::new(2), "bob");
    assert_eq!(actor.state(), RoomState::EpochTransition);

    // Host and alice install the new key and acknowledge; bob withholds.
    for action in &bob_actions {
        let RoomAction::SendTo {
            connection: other,
            message: Message::EpochWrap(other_wrap),
        } = action
        else {
            continue;
        };
        if *other == HOST {
            actor
                .handle_event(RoomEvent::EpochAck {
                    connection: HOST,
                    epoch: other_wrap.epoch,
                })
                .unwrap();
        } else if *other == ConnectionId::new(1) {
            let ack = member_client(&mut members, ConnectionId::new(1))
                .on_epoch_wrap(other_wrap)
                .unwrap();
            let Message::EpochAck(ack) = ack else {
                panic!()
            };
            actor
                .handle_event(RoomEvent::EpochAck {
                    connection: ConnectionId::new(1),
                    epoch: ack.epoch,
                })
                .unwrap();
        }
    }
    assert_eq!(actor.state(), RoomState::EpochTransition);

    // Alice (who acknowledged) can still chat: the room is not frozen by
    // bob's withheld acknowledgement.
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_chat("still here")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event(chat_event(ConnectionId::new(1), &envelope))
        .unwrap();
    let destinations: Vec<ConnectionId> = actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(_),
            } => Some(*connection),
            _ => None,
        })
        .collect();
    assert_eq!(destinations, vec![HOST, ConnectionId::new(2)]);

    // Bob's client has already received the wrap, so it holds the pending
    // key and can produce messages for the new epoch.
    let bob_wrap = bob_actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } if *connection == ConnectionId::new(2) => Some(wrap),
            _ => None,
        })
        .unwrap();
    let _ = bob.on_epoch_wrap(bob_wrap).unwrap();

    // Bob's own messages are still held back while he is pending, and he is
    // told to send them again rather than losing them silently.
    let message = bob.send_chat("held").unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event(chat_event(ConnectionId::new(2), &envelope))
        .expect("a transition drop is not a protocol violation");
    assert!(
        actions.iter().any(|action| matches!(
            action,
            RoomAction::SendTo {
                connection,
                message: Message::Error(error),
            } if *connection == ConnectionId::new(2)
                && error.code == ErrorCode::RateLimited
        )),
        "the pending sender must be told to resend: {actions:?}"
    );
}

#[test]
fn rate_limiting_rejects_bursts_and_terminates_abusers() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    // The first five messages pass; the sixth is rate-limited.
    for i in 1..=5 {
        let message = member_client(&mut members, ConnectionId::new(1))
            .send_chat(&format!("message {i}"))
            .unwrap();
        let Message::ChatMessage(envelope) = message else {
            panic!()
        };
        let actions = actor
            .handle_event(chat_event(ConnectionId::new(1), &envelope))
            .unwrap();
        assert!(!actions.is_empty(), "message {i} must be relayed");
    }

    let message = member_client(&mut members, ConnectionId::new(1))
        .send_chat("burst overflow")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event_at(chat_event(ConnectionId::new(1), &envelope), Duration::ZERO)
        .unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { message: Message::Error(error), .. }
            if error.code == ErrorCode::RateLimited
    )));

    // The rejection is a recoverable one, and it carries a reason: a bare
    // RateLimited renders on the member's screen as "protocol error" and
    // reads like the host refused the connection.
    assert!(ErrorCode::RateLimited.is_recoverable());
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { message: Message::Error(error), .. }
            if error.reason.as_deref().is_some_and(|text| text.contains("rate limit"))
    )));

    // Being rate-limited must not close the connection: the member stays in
    // the room and only this message is refused.
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, RoomAction::CloseConnection { .. })),
        "a single burst must not evict the member"
    );

    // The envelope was not relayed.
    assert!(!actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo {
            message: Message::ChatMessage(_),
            ..
        }
    )));

    // Persistent abuse at the same instant terminates the connection.
    let mut terminated = false;
    for _ in 0..10 {
        let message = member_client(&mut members, ConnectionId::new(1))
            .send_chat("abuse")
            .unwrap();
        let Message::ChatMessage(envelope) = message else {
            panic!()
        };
        let actions = actor
            .handle_event_at(chat_event(ConnectionId::new(1), &envelope), Duration::ZERO)
            .unwrap();
        if actions.iter().any(|action| {
            matches!(
                action,
                RoomAction::CloseConnection { connection } if *connection == ConnectionId::new(1)
            )
        }) {
            terminated = true;
            break;
        }
    }
    assert!(terminated, "persistent abuse must terminate the connection");
}

#[test]
fn color_changes_are_relayed_and_applied() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_color(ColorChoice::Magenta)
        .unwrap();
    let Message::ColorChange(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event(RoomEvent::ChatReceived {
            connection: ConnectionId::new(1),
            message_type: 0x41,
            envelope,
        })
        .unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::ColorChange(_) }
            if *connection == HOST
    )));
    let member = actor
        .members()
        .find(|m| m.member_id == MemberId::new(1))
        .unwrap();
    assert_eq!(member.color, ColorChoice::Magenta);
}

#[test]
fn sender_applies_its_own_color_locally() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(2),
        "bob",
        &mut members,
    );
    members.push((ConnectionId::new(2), client));

    // Alice changes her color. The host relays the change to every member
    // except the sender, so Alice never receives her own change back.
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_color(ColorChoice::Magenta)
        .unwrap();
    let Message::ColorChange(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event(RoomEvent::ChatReceived {
            connection: ConnectionId::new(1),
            message_type: 0x41,
            envelope,
        })
        .unwrap();
    let recipients: Vec<ConnectionId> = actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ColorChange(_),
            } => Some(*connection),
            _ => None,
        })
        .collect();
    assert_eq!(recipients, vec![HOST, ConnectionId::new(2)]);

    // Alice's own session still carries the default color because the relay
    // never returns the change to the sender.
    let alice = member_client(&mut members, ConnectionId::new(1));
    assert_eq!(
        alice.member_view(MemberId::new(1)).unwrap().color,
        ColorChoice::default()
    );

    // The TUI applies the change locally after a successful send.
    let alice = member_client(&mut members, ConnectionId::new(1));
    alice.set_own_color(ColorChoice::Magenta);
    assert_eq!(
        alice.member_view(MemberId::new(1)).unwrap().color,
        ColorChoice::Magenta
    );

    // The other member sees the change through the relay.
    let relayed = actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ColorChange(e),
            } if *connection == ConnectionId::new(2) => Some(e.clone()),
            _ => None,
        })
        .unwrap();
    let bob = member_client(&mut members, ConnectionId::new(2));
    assert_eq!(bob.on_member_message(0x41, &relayed).unwrap(), None);
    assert_eq!(
        bob.member_view(MemberId::new(1)).unwrap().color,
        ColorChoice::Magenta
    );
}

#[test]
fn color_changes_share_the_message_rate_limit() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));

    // The first five color changes pass; the sixth is rate-limited and is
    // not relayed, like chat.
    for index in 0..5 {
        let message = member_client(&mut members, ConnectionId::new(1))
            .send_color(ColorChoice::Cyan)
            .unwrap();
        let Message::ColorChange(envelope) = message else {
            panic!()
        };
        let actions = actor
            .handle_event_at(
                RoomEvent::ChatReceived {
                    connection: ConnectionId::new(1),
                    message_type: 0x41,
                    envelope,
                },
                Duration::ZERO,
            )
            .unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, RoomAction::SendTo { .. })),
            "color change {index} must be relayed"
        );
    }
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_color(ColorChoice::Yellow)
        .unwrap();
    let Message::ColorChange(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event_at(
            RoomEvent::ChatReceived {
                connection: ConnectionId::new(1),
                message_type: 0x41,
                envelope,
            },
            Duration::ZERO,
        )
        .unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { message: Message::Error(error), .. }
            if error.code == veilroom::protocol::ids::ErrorCode::RateLimited
    )));
    assert!(!actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo {
            message: Message::ColorChange(_),
            ..
        }
    )));

    // A chat message now is also limited: chat and color share one bucket.
    let message = member_client(&mut members, ConnectionId::new(1))
        .send_chat("still limited")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    let actions = actor
        .handle_event_at(chat_event(ConnectionId::new(1), &envelope), Duration::ZERO)
        .unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { message: Message::Error(error), .. }
            if error.code == veilroom::protocol::ids::ErrorCode::RateLimited
    )));
}

#[test]
fn membership_broadcasts_follow_accept_and_kick() {
    let mut actor = start_room();

    // Accept: after activation, the host gets MEMBER_JOINED and the new
    // member gets a signed snapshot.
    actor
        .handle_event(RoomEvent::ClientConnected {
            connection: ConnectionId::new(1),
        })
        .unwrap();
    actor
        .handle_event(RoomEvent::PasswordVerified {
            connection: ConnectionId::new(1),
        })
        .unwrap();
    let application = veilroom::admission::queue::JoinApplication {
        nickname: "alice".to_owned(),
        introduction: None,
        ed25519_pubkey: MemberIdentity::generate().unwrap().ed25519_pubkey(),
        x25519_pubkey: MemberIdentity::generate().unwrap().x25519_pubkey(),
        signature: [0u8; 64],
    };
    let request_actions = actor
        .handle_event(RoomEvent::JoinRequested {
            connection: ConnectionId::new(1),
            nickname: application.nickname.clone(),
            introduction: None,
            ed25519_pubkey: application.ed25519_pubkey,
            x25519_pubkey: application.x25519_pubkey,
            signature: application.signature,
        })
        .unwrap();
    let request_id = match &request_actions[0] {
        RoomAction::NotifyHost(HostNotice::JoinRequestPending { request_id, .. }) => *request_id,
        _ => panic!("expected a pending-request notice"),
    };

    let accept_actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();
    let host_wraps: Vec<&Message> = accept_actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message,
            } if *connection == HOST => matches!(message, Message::EpochWrap(_)).then_some(message),
            _ => None,
        })
        .collect();
    let Message::EpochWrap(_) = host_wraps[0] else {
        panic!()
    };
    let client_wraps: Vec<&Message> = accept_actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message,
            } if *connection == ConnectionId::new(1) => {
                matches!(message, Message::EpochWrap(_)).then_some(message)
            }
            _ => None,
        })
        .collect();
    let Message::EpochWrap(wrap) = client_wraps[0] else {
        panic!()
    };

    // No broadcasts before the transition activates.
    assert!(!accept_actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo {
            message: Message::MemberJoined(_),
            ..
        }
    )));

    actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: wrap.epoch,
        })
        .unwrap();
    let activation = actor
        .handle_event(RoomEvent::EpochAck {
            connection: ConnectionId::new(1),
            epoch: wrap.epoch,
        })
        .unwrap();

    // The host receives the signed MEMBER_JOINED broadcast.
    let joined = activation
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::MemberJoined(event),
            } if *connection == HOST => Some(event.clone()),
            _ => None,
        })
        .expect("host must receive MEMBER_JOINED");
    assert_eq!(joined.member_id, 1);
    assert_eq!(joined.nickname, "alice");

    // The new member receives a signed snapshot.
    let snapshot = activation
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::MemberSnapshot(event),
            } if *connection == ConnectionId::new(1) => Some(event.clone()),
            _ => None,
        })
        .expect("new member must receive MEMBER_SNAPSHOT");
    assert_eq!(snapshot.members.len(), 2);

    // Kick: after activation, the host receives MEMBER_KICKED.
    let kick_actions = actor
        .handle_event(RoomEvent::HostCommand(veilroom::event::HostCommand::Kick {
            target: MemberRef::Id(MemberId::new(1)),
        }))
        .unwrap();
    let host_wraps: Vec<&Message> = kick_actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message,
            } if *connection == HOST => matches!(message, Message::EpochWrap(_)).then_some(message),
            _ => None,
        })
        .collect();
    let Message::EpochWrap(wrap) = host_wraps[0] else {
        panic!()
    };
    let activation = actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: wrap.epoch,
        })
        .unwrap();
    assert!(activation.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::MemberKicked(event) }
            if *connection == HOST && event.member_id == 1
    )));
}

#[test]
fn requests_snapshot_works_after_chat_setup() {
    let token = vec![0x77; 16];
    let mut actor = start_room();
    let mut members: Vec<(ConnectionId, ClientAdmission)> = Vec::new();
    let client = admit_member(
        &mut actor,
        &token,
        ConnectionId::new(1),
        "alice",
        &mut members,
    );
    members.push((ConnectionId::new(1), client));
    // The room is stable; a host request listing works.
    let actions = actor
        .handle_event(RoomEvent::HostCommand(
            veilroom::event::HostCommand::Requests,
        ))
        .unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::RequestsSnapshot { .. }))
    );
}

fn notices(actions: &[RoomAction]) -> Vec<&HostNotice> {
    actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::NotifyHost(notice) => Some(notice),
            _ => None,
        })
        .collect()
}
