//! End-to-end epoch lifecycle test (Stage 6, sections 14, 15 and 18).
//!
//! A participant joins through the real admission flows; the room wraps
//! every epoch key for every member; members unwrap with their per-member
//! wrapping keys and acknowledge; an epoch activates only after every
//! member acknowledged; a kicked member can no longer unwrap later keys.

use veilroom::admission::queue::JoinRequestQueue;
use veilroom::admission::{ClientAdmission, HostAdmission, HostAdmissionReply, JoinPolicy};
use veilroom::crypto::SecretBytes;
use veilroom::crypto::identity::{HostIdentity, MemberIdentity};
use veilroom::crypto::password::PasswordVerifier;
use veilroom::event::{ConnectionId, MemberId, MemberRef, RoomEvent};
use veilroom::limits::{Limits, Timeouts};
use veilroom::protocol::session::RoomSessionId;
use veilroom::protocol::{FrameDecoder, Message, decode_message, encode_message};
use veilroom::room::action::RoomAction;
use veilroom::room::actor::RoomActor;
use veilroom::room::{HOST_CONNECTION, RoomError};
use veilroom::state::RoomState;
use veilroom::uri::Invitation;

const HOST: ConnectionId = HOST_CONNECTION;
const CLIENT: ConnectionId = ConnectionId::new(1);
const ROOM_PASSWORD: &[u8] = b"correct horse battery staple";
const HOST_MEMBER_ID: u64 = 0;

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

/// Extracts the epoch wraps the actor produced for one connection.
fn wraps_for(actions: &[RoomAction], connection: ConnectionId) -> Vec<&Message> {
    actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection: target,
                message,
            } if *target == connection && matches!(message, Message::EpochWrap(_)) => Some(message),
            _ => None,
        })
        .collect()
}

/// Unwraps an epoch wrap with a member identity and returns the ack.
fn unwrap_and_ack(
    identity: &MemberIdentity,
    session: &RoomSessionId,
    member_id: u64,
    wrap: &Message,
) -> Message {
    let Message::EpochWrap(wrap) = wrap else {
        panic!("expected an epoch wrap");
    };
    let wrap_key = identity.wrap_key_for(
        &host_identity().x25519_pubkey(),
        session.as_bytes(),
        member_id,
    );
    let epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
        &wrap_key,
        wrap.epoch,
        session.as_bytes(),
        &wrap.nonce,
        &wrap.ciphertext,
    )
    .expect("a member must be able to unwrap its own epoch key");
    let _ = epoch_key;
    Message::EpochAck(veilroom::protocol::EpochAck::new(wrap.epoch))
}

fn ack(actor: &mut RoomActor, connection: ConnectionId, epoch: u64) {
    actor
        .handle_event(RoomEvent::EpochAck { connection, epoch })
        .unwrap();
}

/// Drives a participant through the real admission flows and returns the
/// admitted client plus the accepted application.
fn join_through_admission(
    session_id: &RoomSessionId,
    token: &[u8],
) -> (ClientAdmission, veilroom::admission::queue::JoinApplication) {
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        *session_id,
        SecretBytes::from(token.to_vec()),
        verifier,
        &host_identity,
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
    let join_request = client.join_request("deniz".to_owned(), None).unwrap();
    let application = match host
        .on_message(&over_the_wire(&join_request), JoinPolicy::Open)
        .unwrap()
    {
        Some(HostAdmissionReply::JoinRequested(application)) => application,
        _ => panic!(),
    };
    (client, application)
}

#[test]
fn epochs_wrap_for_every_member_and_activate_after_full_acknowledgement() {
    let token = vec![0x77; 16];

    let mut actor = RoomActor::create(
        &limits(),
        HOST,
        "host".to_owned(),
        host_identity(),
        host_client_identity(),
        &Timeouts::default(),
    )
    .unwrap();
    let session = *actor.session_id();

    // Room start wraps epoch 1 for the host participant only.
    let actions = actor.start().unwrap();
    assert_eq!(actor.state(), RoomState::EpochTransition);
    let wraps = wraps_for(&actions, HOST);
    assert_eq!(wraps.len(), 1);
    let Message::EpochWrap(wrap) = wraps[0] else {
        panic!()
    };
    assert_eq!(wrap.epoch, 1);

    // The host participant unwraps with its own identity and acknowledges.
    let host_ack = unwrap_and_ack(&host_client_identity(), &session, HOST_MEMBER_ID, wraps[0]);
    let Message::EpochAck(host_ack) = host_ack else {
        panic!()
    };
    ack(&mut actor, HOST, host_ack.epoch);
    assert_eq!(actor.state(), RoomState::Open);
    assert_eq!(actor.epoch(), 1);
    assert!(actor.epoch_key().is_some());

    // A participant joins; the epoch rotates to 2 for host + member.
    let (mut client, application) = join_through_admission(&session, &token);
    actor
        .handle_event(RoomEvent::ClientConnected { connection: CLIENT })
        .unwrap();
    actor
        .handle_event(RoomEvent::PasswordVerified { connection: CLIENT })
        .unwrap();
    let mut queue = JoinRequestQueue::new(&limits());
    let request_id = queue.push(CLIENT, application).unwrap();
    actor
        .handle_event(RoomEvent::JoinRequested {
            connection: CLIENT,
            nickname: "deniz".to_owned(),
            introduction: None,
            ed25519_pubkey: queue.pending()[0].application.ed25519_pubkey,
            x25519_pubkey: queue.pending()[0].application.x25519_pubkey,
            signature: queue.pending()[0].application.signature,
        })
        .unwrap();
    let _ = queue.take(request_id).unwrap();
    let accept_actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();

    assert_eq!(actor.state(), RoomState::EpochTransition);
    assert_eq!(actor.epoch(), 2);
    let host_wraps = wraps_for(&accept_actions, HOST);
    let client_wraps = wraps_for(&accept_actions, CLIENT);
    assert_eq!(host_wraps.len(), 1);
    assert_eq!(client_wraps.len(), 1);

    // The new member's JOIN_ACCEPTED arrives alongside the wraps.
    assert!(accept_actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::JoinAccepted(_) }
            if *connection == CLIENT
    )));
    client
        .on_host_message(&Message::JoinAccepted(
            veilroom::protocol::JoinAccepted::new(1),
        ))
        .unwrap();
    assert_eq!(client.member_id(), Some(MemberId::new(1)));

    // The member unwraps epoch 2 and acknowledges.
    let client_ack = client.on_epoch_wrap(match client_wraps[0] {
        Message::EpochWrap(wrap) => wrap,
        _ => panic!(),
    });
    let Message::EpochAck(client_ack) = client_ack.unwrap() else {
        panic!()
    };
    assert_eq!(client_ack.epoch, 2);
    assert_eq!(client.chat().unwrap().current_epoch(), Some(2));

    // One acknowledgement is not enough.
    let host_ack = unwrap_and_ack(
        &host_client_identity(),
        &session,
        HOST_MEMBER_ID,
        host_wraps[0],
    );
    let Message::EpochAck(host_ack) = host_ack else {
        panic!()
    };
    ack(&mut actor, HOST, host_ack.epoch);
    assert_eq!(actor.state(), RoomState::EpochTransition);

    // The last acknowledgement activates epoch 2.
    ack(&mut actor, CLIENT, client_ack.epoch);
    assert_eq!(actor.state(), RoomState::Open);
    assert_eq!(actor.epoch(), 2);

    // A kick rotates to epoch 3, wrapped for the host participant only.
    let kick_actions = actor
        .handle_event(RoomEvent::HostCommand(veilroom::event::HostCommand::Kick {
            target: MemberRef::Id(MemberId::new(1)),
        }))
        .unwrap();
    let host_wraps = wraps_for(&kick_actions, HOST);
    let client_wraps = wraps_for(&kick_actions, CLIENT);
    assert_eq!(host_wraps.len(), 1);
    assert!(
        client_wraps.is_empty(),
        "a kicked member receives no new key"
    );
    let Message::EpochWrap(wrap) = host_wraps[0] else {
        panic!()
    };
    assert_eq!(wrap.epoch, 3);

    let host_ack = unwrap_and_ack(
        &host_client_identity(),
        &session,
        HOST_MEMBER_ID,
        host_wraps[0],
    );
    let Message::EpochAck(host_ack) = host_ack else {
        panic!()
    };
    ack(&mut actor, HOST, host_ack.epoch);
    assert_eq!(actor.state(), RoomState::Open);
    assert_eq!(actor.epoch(), 3);

    // The kicked member cannot unwrap the new key with its own wrap key.
    let error = client.on_epoch_wrap(match host_wraps[0] {
        Message::EpochWrap(wrap) => wrap,
        _ => panic!(),
    });
    assert!(error.is_err());

    // Closing the room is still possible.
    let close_actions = actor.handle_event(RoomEvent::CloseRequested).unwrap();
    assert!(close_actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::Shutdown(_) }
            if *connection == HOST
    )));
    assert_eq!(actor.state(), RoomState::Destroyed);
    assert!(matches!(
        actor.handle_event(RoomEvent::ClientConnected { connection: CLIENT }),
        Err(RoomError::RoomClosed)
    ));
}

#[test]
fn host_and_participant_exchange_encrypted_chat() {
    use veilroom::chat::session::ChatSession;
    use veilroom::command::ColorChoice;

    let token = vec![0x77; 16];
    let mut actor = RoomActor::create(
        &limits(),
        HOST,
        "host".to_owned(),
        host_identity(),
        host_client_identity(),
        &Timeouts::default(),
    )
    .unwrap();
    let session = *actor.session_id();

    // The host participant's chat session (member 0).
    let host_key = host_identity();
    let mut host_session = ChatSession::new(
        *session.as_bytes(),
        host_key.ed25519_pubkey(),
        host_key.x25519_pubkey(),
        MemberId::new(0),
    );
    host_session.install_member(veilroom::chat::session::MemberView {
        member_id: MemberId::new(0),
        nickname: "host".to_owned(),
        color: ColorChoice::default(),
        is_host: true,
        ed25519_pubkey: host_client_identity().ed25519_pubkey(),
    });

    // Room start: the host unwraps epoch 1 and acknowledges.
    let actions = actor.start().unwrap();
    let wraps = wraps_for(&actions, HOST);
    let Message::EpochWrap(wrap) = wraps[0] else {
        panic!()
    };
    let host_key = host_identity();
    let wrap_key =
        host_client_identity().wrap_key_for(&host_key.x25519_pubkey(), session.as_bytes(), 0);
    let epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
        &wrap_key,
        wrap.epoch,
        session.as_bytes(),
        &wrap.nonce,
        &wrap.ciphertext,
    )
    .unwrap();
    host_session.install_epoch(wrap.epoch, epoch_key);
    ack(&mut actor, HOST, wrap.epoch);
    assert_eq!(actor.state(), RoomState::Open);

    // A participant joins through the real admission flows.
    let (mut client, application) = join_through_admission(&session, &token);
    actor
        .handle_event(RoomEvent::ClientConnected { connection: CLIENT })
        .unwrap();
    actor
        .handle_event(RoomEvent::PasswordVerified { connection: CLIENT })
        .unwrap();
    let mut queue = JoinRequestQueue::new(&limits());
    let request_id = queue.push(CLIENT, application).unwrap();
    actor
        .handle_event(RoomEvent::JoinRequested {
            connection: CLIENT,
            nickname: "deniz".to_owned(),
            introduction: None,
            ed25519_pubkey: queue.pending()[0].application.ed25519_pubkey,
            x25519_pubkey: queue.pending()[0].application.x25519_pubkey,
            signature: queue.pending()[0].application.signature,
        })
        .unwrap();
    let _ = queue.take(request_id).unwrap();
    let accept_actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();
    let member_id = accept_actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::JoinAccepted(accepted),
            } if *connection == CLIENT => Some(accepted.member_id),
            _ => None,
        })
        .unwrap();
    client
        .on_host_message(&Message::JoinAccepted(
            veilroom::protocol::JoinAccepted::new(member_id),
        ))
        .unwrap();

    // Epoch 2 wraps for the host and the participant.
    let participant_wrap = wraps_for(&accept_actions, CLIENT);
    let host_wrap = wraps_for(&accept_actions, HOST);
    let Message::EpochWrap(wrap) = participant_wrap[0] else {
        panic!()
    };
    let participant_ack = client.on_epoch_wrap(wrap).unwrap();
    let Message::EpochAck(participant_ack) = participant_ack else {
        panic!()
    };
    ack(&mut actor, CLIENT, participant_ack.epoch);

    let Message::EpochWrap(wrap) = host_wrap[0] else {
        panic!()
    };
    let wrap_key =
        host_client_identity().wrap_key_for(&host_key.x25519_pubkey(), session.as_bytes(), 0);
    let epoch_key = veilroom::crypto::identity::unwrap_epoch_key(
        &wrap_key,
        wrap.epoch,
        session.as_bytes(),
        &wrap.nonce,
        &wrap.ciphertext,
    )
    .unwrap();
    host_session.install_epoch(wrap.epoch, epoch_key);
    let activation = actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: wrap.epoch,
        })
        .unwrap();
    assert_eq!(actor.state(), RoomState::Open);

    // Membership broadcasts are delivered to both sides: the participant
    // receives the snapshot, the host receives the MEMBER_JOINED event.
    for action in &activation {
        if let RoomAction::SendTo {
            connection,
            message,
        } = action
            && matches!(
                message,
                Message::MemberJoined(_)
                    | Message::MemberLeft(_)
                    | Message::MemberKicked(_)
                    | Message::MemberSnapshot(_)
            )
        {
            match *connection {
                CLIENT => client.on_membership_message(message).unwrap(),
                HOST => host_session.handle_membership_message(message).unwrap(),
                _ => {}
            }
        }
    }
    assert!(client.member_view(MemberId::new(0)).is_some());
    assert!(
        host_session
            .members()
            .iter()
            .any(|m| m.member_id == MemberId::new(1))
    );

    // The host sends chat; the actor relays it to the participant.
    let host_message = host_session
        .send_chat(&host_client_identity(), "merhaba deniz")
        .unwrap();
    let Message::ChatMessage(envelope) = host_message else {
        panic!()
    };
    let actions = actor
        .handle_event(RoomEvent::ChatReceived {
            connection: HOST,
            message_type: 0x40,
            envelope: envelope.clone(),
        })
        .unwrap();
    let relayed = actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(e),
            } if *connection == CLIENT => Some(e.clone()),
            _ => None,
        })
        .expect("the participant must receive the host's message");
    let received = client.on_member_message(0x40, &relayed).unwrap();
    assert_eq!(received, Some("merhaba deniz".to_owned()));

    // The participant replies; the host receives it.
    let reply = client.send_chat("selam host").unwrap();
    let Message::ChatMessage(envelope) = reply else {
        panic!()
    };
    let actions = actor
        .handle_event(RoomEvent::ChatReceived {
            connection: CLIENT,
            message_type: 0x40,
            envelope,
        })
        .unwrap();
    let relayed = actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ChatMessage(e),
            } if *connection == HOST => Some(e.clone()),
            _ => None,
        })
        .expect("the host must receive the participant's reply");
    let text = host_session.receive_chat(&relayed).unwrap();
    assert_eq!(text, "selam host");

    // A color change flows in both directions.
    let color = host_session
        .send_color(&host_client_identity(), ColorChoice::Green)
        .unwrap();
    let Message::ColorChange(envelope) = color else {
        panic!()
    };
    let actions = actor
        .handle_event(RoomEvent::ChatReceived {
            connection: HOST,
            message_type: 0x41,
            envelope,
        })
        .unwrap();
    let relayed = actions
        .iter()
        .find_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::ColorChange(e),
            } if *connection == CLIENT => Some(e.clone()),
            _ => None,
        })
        .expect("color change must reach the participant");
    client.on_member_message(0x41, &relayed).unwrap();
    assert_eq!(
        client.member_view(MemberId::new(0)).unwrap().color,
        ColorChoice::Green
    );
}
