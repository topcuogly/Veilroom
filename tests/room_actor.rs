//! Room-actor lifecycle and race-condition tests (instructions section 41.2).
//!
//! The actor is synchronous and deterministic, so the accept/disconnect,
//! kick/disconnect, nickname, and epoch-acknowledgement races are tested
//! without a scheduler.

use std::time::Duration;

use veilroom::admission::JoinPolicy;
use veilroom::command::ColorChoice;
use veilroom::crypto::identity::{HostIdentity, MemberIdentity};
use veilroom::event::{
    ConnectionId, HostCommand, MemberCommand, MemberId, MemberRef, RequestId, RoomEvent,
};
use veilroom::limits::{Limits, TimeoutKind, Timeouts};
use veilroom::protocol::messages::Message;
use veilroom::room::action::{HostNotice, RoomAction};
use veilroom::room::actor::RoomActor;
use veilroom::room::{HOST_CONNECTION, RoomError};
use veilroom::state::RoomState;

const HOST: ConnectionId = HOST_CONNECTION;
const CLIENT: ConnectionId = ConnectionId::new(1);
const CLIENT_B: ConnectionId = ConnectionId::new(2);

fn host_actor() -> RoomActor {
    RoomActor::create(
        &Limits::default(),
        HOST,
        "host".to_owned(),
        HostIdentity::from_seed([0x01; 32], [0x02; 32]),
        MemberIdentity::from_seed([0x03; 32], [0x04; 32]),
        &veilroom::limits::Timeouts::default(),
    )
    .unwrap()
}

fn join_request(connection: ConnectionId, nickname: &str) -> RoomEvent {
    RoomEvent::JoinRequested {
        connection,
        nickname: nickname.to_owned(),
        introduction: None,
        ed25519_pubkey: [0x11; 32],
        x25519_pubkey: [0x12; 32],
        signature: [0x13; 64],
    }
}

fn connect(connection: ConnectionId) -> RoomEvent {
    RoomEvent::ClientConnected { connection }
}

fn lost(connection: ConnectionId) -> RoomEvent {
    RoomEvent::ConnectionLost { connection }
}

fn epoch_wraps(actions: &[RoomAction]) -> Vec<(ConnectionId, u64)> {
    actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::SendTo {
                connection,
                message: Message::EpochWrap(wrap),
            } => Some((*connection, wrap.epoch)),
            _ => None,
        })
        .collect()
}

/// Acknowledges every epoch wrap in the actions, returning the epoch.
fn ack_transition(actor: &mut RoomActor, actions: &[RoomAction]) -> u64 {
    let wraps = epoch_wraps(actions);
    assert!(!wraps.is_empty(), "expected epoch wraps in the actions");
    let epoch = wraps[0].1;
    for (connection, wrap_epoch) in wraps {
        assert_eq!(wrap_epoch, epoch);
        actor
            .handle_event(RoomEvent::EpochAck {
                connection,
                epoch: wrap_epoch,
            })
            .unwrap();
    }
    epoch
}

/// Starts the room and acknowledges the initial epoch (1).
fn started_actor() -> RoomActor {
    let mut actor = host_actor();
    let actions = actor.start().unwrap();
    let epoch = ack_transition(&mut actor, &actions);
    assert_eq!(epoch, 1);
    assert_eq!(actor.state(), RoomState::Open);
    actor
}

/// Drives a connection through submission and returns the request id.
fn submit_request(actor: &mut RoomActor, connection: ConnectionId, nickname: &str) -> RequestId {
    actor.handle_event(connect(connection)).unwrap();
    actor
        .handle_event(RoomEvent::PasswordVerified { connection })
        .unwrap();
    let actions = actor
        .handle_event(join_request(connection, nickname))
        .unwrap();
    match actions[0] {
        RoomAction::NotifyHost(HostNotice::JoinRequestPending { request_id, .. }) => request_id,
        _ => panic!("expected a pending-request notice"),
    }
}

/// Accepts a request and acknowledges the resulting epoch transition, if any.
fn accept(actor: &mut RoomActor, request_id: RequestId) -> Vec<RoomAction> {
    let actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();
    if !epoch_wraps(&actions).is_empty() {
        ack_transition(actor, &actions);
    }
    actions
}

/// Kicks a member and acknowledges the resulting epoch transition.
fn kick(actor: &mut RoomActor, target: MemberRef) -> Result<Vec<RoomAction>, RoomError> {
    let actions = actor.handle_event(RoomEvent::HostCommand(HostCommand::Kick { target }))?;
    if !epoch_wraps(&actions).is_empty() {
        ack_transition(actor, &actions);
    }
    Ok(actions)
}

/// Loses a connection and acknowledges the resulting epoch transition, if any.
fn lose(actor: &mut RoomActor, connection: ConnectionId) -> Vec<RoomAction> {
    let actions = actor.handle_event(lost(connection)).unwrap();
    if !epoch_wraps(&actions).is_empty() {
        ack_transition(actor, &actions);
    }
    actions
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

// ---- lifecycle -----------------------------------------------------------

#[test]
fn creation_and_start_emit_the_invitation_and_first_epoch() {
    let mut actor = host_actor();
    assert_eq!(actor.state(), RoomState::Creating);
    assert_eq!(actor.epoch(), 0);
    let actions = actor.start().unwrap();
    assert_eq!(actor.state(), RoomState::EpochTransition);
    assert_eq!(actor.token().len(), 32);

    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::InvitationRotated { .. }))
    );
    assert_eq!(epoch_wraps(&actions), vec![(HOST, 1)]);

    // The host participant must acknowledge before the room opens.
    ack_transition(&mut actor, &actions);
    assert_eq!(actor.state(), RoomState::Open);
    assert_eq!(actor.epoch(), 1);
    assert!(actor.epoch_key().is_some());
    assert!(actor.policy().allows_join_requests());

    // The host is member 0 with the host client identity keys.
    let host = actor.members().find(|m| m.is_host).expect("host member");
    assert_eq!(host.member_id, MemberId::new(0));
    assert_eq!(host.nickname, "host");
}

#[test]
fn starting_twice_is_an_error() {
    let mut actor = started_actor();
    assert!(matches!(actor.start(), Err(RoomError::RoomClosed)));
}

// ---- full admission lifecycle ----------------------------------------------

#[test]
fn full_member_lifecycle() {
    let mut actor = started_actor();

    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    let actions = accept(&mut actor, request_id);

    // The accepted member gets JOIN_ACCEPTED, the host gets a notice.
    let accepted = actions.iter().find_map(|action| match action {
        RoomAction::SendTo {
            connection,
            message,
        } if *connection == CLIENT => Some(message.clone()),
        _ => None,
    });
    assert!(matches!(accepted, Some(Message::JoinAccepted(_))));
    assert!(notices(&actions).iter().any(|notice| {
        matches!(notice, HostNotice::MemberJoined { member_id, nickname } if
            *member_id == MemberId::new(1) && nickname == "deniz")
    }));

    assert_eq!(actor.epoch(), 2);
    assert_eq!(actor.room_sequence(), 5); // transition + distinct signed membership events

    let member = actor.members().find(|m| !m.is_host).expect("joined member");
    assert_eq!(member.member_id, MemberId::new(1));
    assert_eq!(member.joined_epoch, 2);
}

// ---- nickname races ----------------------------------------------------------

#[test]
fn nickname_collision_between_pending_requests_rejects_the_second() {
    let mut actor = started_actor();
    let first = submit_request(&mut actor, CLIENT, "deniz");
    let second = submit_request(&mut actor, CLIENT_B, "deniz");

    // First accept wins.
    let actions = accept(&mut actor, first);
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::MemberJoined { .. }))
    );

    // Second accept fails: the applicant is rejected and closed.
    let actions = accept(&mut actor, second);
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::CloseConnection { connection } if *connection == CLIENT_B
    )));
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::JoinRejected(_) }
            if *connection == CLIENT_B
    )));
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::Error { .. }))
    );

    // Only one non-host member exists, and the epoch advanced exactly once.
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 1);
    assert_eq!(actor.epoch(), 2);
}

#[test]
fn nickname_collision_with_an_active_member_rejects_the_request() {
    let mut actor = started_actor();
    let first = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, first);

    let second = submit_request(&mut actor, CLIENT_B, "deniz");
    let actions = accept(&mut actor, second);
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::JoinRejected(_) }
            if *connection == CLIENT_B
    )));
}

// ---- accept / disconnect races ------------------------------------------------

#[test]
fn connection_lost_after_accept_removes_the_member() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);
    assert_eq!(actor.epoch(), 2);

    let actions = lose(&mut actor, CLIENT);
    assert!(notices(&actions).iter().any(|notice| {
        matches!(notice, HostNotice::MemberLeft { member_id, nickname } if
            *member_id == MemberId::new(1) && nickname == "deniz")
    }));
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 0);
    assert_eq!(actor.epoch(), 3);
}

#[test]
fn connection_lost_before_accept_withdraws_the_request() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");

    let actions = actor.handle_event(lost(CLIENT)).unwrap();
    assert!(notices(&actions).iter().any(|notice| {
        matches!(notice, HostNotice::JoinRequestWithdrawn { request_id: id } if *id == request_id)
    }));

    // The later accept finds nothing.
    assert!(matches!(
        actor.handle_event(RoomEvent::HostAccepted { request_id }),
        Err(RoomError::UnknownRequest { .. })
    ));
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 0);
}

#[test]
fn timeout_expired_is_treated_as_connection_loss() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    let actions = actor
        .handle_event(RoomEvent::TimeoutExpired {
            connection: CLIENT,
            kind: TimeoutKind::Keepalive,
        })
        .unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::MemberLeft { .. }))
    );
    ack_transition(&mut actor, &actions);
    assert_eq!(actor.epoch(), 3);
}

#[test]
fn epoch_maintenance_never_removes_the_host_in_open_or_locked_rooms() {
    let mut actor = started_actor();

    let actions = actor.handle_event(RoomEvent::EpochMaintenance).unwrap();
    assert!(actions.is_empty());
    assert_eq!(actor.state(), RoomState::Open);
    assert!(
        actor
            .members()
            .any(|member| member.member_id == MemberId::new(0) && member.is_host)
    );

    actor
        .handle_event(RoomEvent::HostCommand(HostCommand::ReqOff))
        .unwrap();
    assert_eq!(actor.state(), RoomState::Locked);
    let actions = actor.handle_event(RoomEvent::EpochMaintenance).unwrap();
    assert!(actions.is_empty());
    assert_eq!(actor.state(), RoomState::Locked);
    assert!(
        actor
            .members()
            .any(|member| member.member_id == MemberId::new(0) && member.is_host)
    );
}

#[test]
fn losing_the_host_connection_closes_the_room_instead_of_removing_member_zero() {
    let mut actor = started_actor();
    let actions = actor
        .handle_event(RoomEvent::ConnectionLost { connection: HOST })
        .unwrap();

    assert_eq!(actor.state(), RoomState::Destroyed);
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::RoomClosed))
    );
    assert!(!notices(&actions).iter().any(|notice| matches!(
        notice,
        HostNotice::MemberLeft { member_id, .. } if *member_id == MemberId::new(0)
    )));
    assert!(
        actor
            .members()
            .any(|member| member.member_id == MemberId::new(0) && member.is_host)
    );
}

// ---- kick / disconnect races ----------------------------------------------------

#[test]
fn kick_then_connection_loss_rotates_the_epoch_once() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    let actions = kick(&mut actor, MemberRef::Id(MemberId::new(1))).unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::CloseConnection { connection } if *connection == CLIENT
    )));
    assert!(notices(&actions).iter().any(|notice| {
        matches!(notice, HostNotice::MemberKicked { member_id, .. } if *member_id == MemberId::new(1))
    }));
    assert_eq!(actor.epoch(), 3);

    // The later connection loss is a no-op: no second epoch rotation.
    let actions = actor.handle_event(lost(CLIENT)).unwrap();
    assert!(actions.is_empty());
    assert_eq!(actor.epoch(), 3);
}

#[test]
fn connection_loss_then_kick_is_an_error() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    lose(&mut actor, CLIENT);
    assert_eq!(actor.epoch(), 3);
    // The kick finds no member and does not rotate the epoch again.
    assert!(matches!(
        kick(&mut actor, MemberRef::Id(MemberId::new(1))),
        Err(RoomError::UnknownMember { .. })
    ));
    assert_eq!(actor.epoch(), 3);
}

// ---- reqoff / newid ----------------------------------------------------------------

#[test]
fn reqoff_drains_pending_requests_and_locks_the_room() {
    let mut actor = started_actor();
    submit_request(&mut actor, CLIENT, "alice");
    submit_request(&mut actor, CLIENT_B, "bob");

    let actions = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::ReqOff))
        .unwrap();
    assert_eq!(actor.state(), RoomState::Locked);
    assert!(!actor.policy().allows_join_requests());

    // Both pending connections are closed and their requests withdrawn.
    let closed: Vec<ConnectionId> = actions
        .iter()
        .filter_map(|action| match action {
            RoomAction::CloseConnection { connection } => Some(*connection),
            _ => None,
        })
        .collect();
    assert_eq!(closed, vec![CLIENT, CLIENT_B]);
    let withdrawn = notices(&actions)
        .iter()
        .filter(|notice| matches!(notice, HostNotice::JoinRequestWithdrawn { .. }))
        .count();
    assert_eq!(withdrawn, 2);

    // New submissions are refused while locked.
    assert!(matches!(
        actor.handle_event(join_request(CLIENT, "carol")),
        Err(RoomError::PolicyLocked)
    ));

    // /reqon reopens the room.
    let actions = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::ReqOn))
        .unwrap();
    assert!(notices(&actions).iter().any(|notice| {
        matches!(
            notice,
            HostNotice::JoinPolicyChanged {
                policy: JoinPolicy::Open
            }
        )
    }));
    assert!(actor.policy().allows_join_requests());
}

#[test]
fn newid_rotates_the_token_and_closes_admission_only() {
    let mut actor = started_actor();
    let old_token = actor.token().to_vec();
    let request_id = submit_request(&mut actor, CLIENT, "alice");
    let member_request = submit_request(&mut actor, CLIENT_B, "bob");
    accept(&mut actor, member_request);

    let actions = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::NewId))
        .unwrap();

    // The token rotated.
    assert_ne!(actor.token(), old_token);
    assert!(notices(&actions).iter().any(|notice| {
        matches!(notice, HostNotice::InvitationRotated { token } if token.as_slice() == actor.token())
    }));

    // The pending request was closed and withdrawn.
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::CloseConnection { connection } if *connection == CLIENT
    )));
    assert!(notices(&actions).iter().any(|notice| {
        matches!(notice, HostNotice::JoinRequestWithdrawn { request_id: id } if *id == request_id)
    }));

    // The active member is untouched, and no epoch rotation happened.
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 1);
    assert_eq!(actor.epoch(), 2);
}

// ---- member commands ---------------------------------------------------------------

#[test]
fn leave_by_member_removes_the_member() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    let actions = actor
        .handle_event(RoomEvent::MemberCommand {
            connection: CLIENT,
            command: MemberCommand::Leave,
        })
        .unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::Shutdown(_) }
            if *connection == CLIENT
    )));
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::CloseConnection { connection } if *connection == CLIENT
    )));
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::MemberLeft { .. }))
    );
    ack_transition(&mut actor, &actions);
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 0);
    assert_eq!(actor.epoch(), 3);
}

#[test]
fn leave_by_host_is_an_error() {
    let mut actor = started_actor();
    let error = actor
        .handle_event(RoomEvent::MemberCommand {
            connection: HOST,
            command: MemberCommand::Leave,
        })
        .unwrap_err();
    assert!(matches!(error, RoomError::HostCannotLeave));
}

#[test]
fn kick_accepts_ids_and_unique_nicknames() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    let actions = kick(&mut actor, MemberRef::Nickname("deniz".to_owned())).unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::MemberKicked { .. }))
    );

    // Kicking the departed member is an error.
    assert!(matches!(
        kick(&mut actor, MemberRef::Nickname("deniz".to_owned())),
        Err(RoomError::UnknownMember { .. })
    ));
}

#[test]
fn kick_unknown_member_and_empty_nickname_are_errors() {
    let mut actor = started_actor();
    assert!(matches!(
        kick(&mut actor, MemberRef::Id(MemberId::new(99))),
        Err(RoomError::UnknownMember { .. })
    ));
    assert!(matches!(
        actor.handle_event(RoomEvent::HostCommand(HostCommand::Kick {
            target: MemberRef::Nickname(String::new()),
        })),
        Err(RoomError::EmptyMemberRef)
    ));
}

#[test]
fn kick_host_is_an_error() {
    let mut actor = started_actor();
    assert!(matches!(
        actor.handle_event(RoomEvent::HostCommand(HostCommand::Kick {
            target: MemberRef::Id(MemberId::new(0)),
        })),
        Err(RoomError::CannotKickHost)
    ));
}

#[test]
fn list_and_whois_report_members() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    let actions = actor
        .handle_event(RoomEvent::MemberCommand {
            connection: HOST,
            command: MemberCommand::List,
        })
        .unwrap();
    let snapshot = notices(&actions)
        .iter()
        .find_map(|notice| match notice {
            HostNotice::ListSnapshot(snapshot) => Some(snapshot),
            _ => None,
        })
        .expect("list snapshot");
    assert_eq!(snapshot.len(), 2);
    assert!(
        snapshot
            .iter()
            .any(|info| info.is_host && info.nickname == "host")
    );
    assert!(
        snapshot
            .iter()
            .any(|info| !info.is_host && info.nickname == "deniz")
    );

    let actions = actor
        .handle_event(RoomEvent::MemberCommand {
            connection: HOST,
            command: MemberCommand::Whois("deniz".to_owned()),
        })
        .unwrap();
    let whois = notices(&actions)
        .iter()
        .find_map(|notice| match notice {
            HostNotice::WhoisResult(info) => Some(info),
            _ => None,
        })
        .expect("whois result");
    assert_eq!(whois.nickname, "deniz");

    assert!(matches!(
        actor.handle_event(RoomEvent::MemberCommand {
            connection: HOST,
            command: MemberCommand::Whois("nobody".to_owned()),
        }),
        Err(RoomError::UnknownMember { .. })
    ));
}

#[test]
fn color_change_applies_and_shows_up_in_whois() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    actor
        .handle_event(RoomEvent::MemberCommand {
            connection: CLIENT,
            command: MemberCommand::Color(ColorChoice::Cyan),
        })
        .unwrap();
    let member = actor.members().find(|m| !m.is_host).unwrap();
    assert_eq!(member.color, ColorChoice::Cyan);
}

#[test]
fn member_command_from_non_member_is_an_error() {
    let mut actor = started_actor();
    let error = actor
        .handle_event(RoomEvent::MemberCommand {
            connection: CLIENT,
            command: MemberCommand::Color(ColorChoice::Red),
        })
        .unwrap_err();
    assert!(matches!(error, RoomError::NotAMember { .. }));
}

// ---- epoch transitions --------------------------------------------------------------

#[test]
fn epoch_transition_waits_for_all_acknowledgements() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    let actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();

    assert_eq!(actor.state(), RoomState::EpochTransition);
    assert_eq!(actor.epoch(), 2);
    assert_eq!(epoch_wraps(&actions).len(), 2); // host + new member

    // One acknowledgement is not enough.
    actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: 2,
        })
        .unwrap();
    assert_eq!(actor.state(), RoomState::EpochTransition);

    // The last acknowledgement activates the epoch.
    actor
        .handle_event(RoomEvent::EpochAck {
            connection: CLIENT,
            epoch: 2,
        })
        .unwrap();
    assert_eq!(actor.state(), RoomState::Open);
    assert!(actor.epoch_key().is_some());
}

#[test]
fn stale_epoch_acknowledgements_are_ignored() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    let actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();

    // An ack for the wrong epoch does not progress the transition.
    let actions_before = actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: 99,
        })
        .unwrap();
    assert!(actions_before.is_empty());
    assert_eq!(actor.state(), RoomState::EpochTransition);
    ack_transition(&mut actor, &actions);
    assert_eq!(actor.state(), RoomState::Open);

    // An ack from a non-member is ignored.
    let actions = actor
        .handle_event(RoomEvent::EpochAck {
            connection: CLIENT_B,
            epoch: 2,
        })
        .unwrap();
    assert!(actions.is_empty());
}

#[test]
fn epoch_ack_timeout_evicts_the_non_acking_member_after_the_deadline() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();
    assert_eq!(actor.state(), RoomState::EpochTransition);

    // The host acknowledges, the client does not.
    actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: 2,
        })
        .unwrap();

    // Before the configured deadline no member is evicted: the timeout is
    // only an eviction trigger once the acknowledgement window elapsed.
    let before = actor
        .handle_event_at(
            RoomEvent::TimeoutExpired {
                connection: CLIENT,
                kind: TimeoutKind::EpochAcknowledgement,
            },
            Duration::from_secs(29),
        )
        .unwrap();
    assert!(before.is_empty());
    assert_eq!(actor.state(), RoomState::EpochTransition);

    // After the deadline the client is removed and a new transition starts
    // for the remaining members.
    let actions = actor
        .handle_event_at(
            RoomEvent::TimeoutExpired {
                connection: CLIENT,
                kind: TimeoutKind::EpochAcknowledgement,
            },
            Duration::from_secs(31),
        )
        .unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::MemberLeft { .. }))
    );
    assert_eq!(actor.epoch(), 3);
    assert_eq!(epoch_wraps(&actions).len(), 1); // only the host remains
    ack_transition(&mut actor, &actions);
    assert_eq!(actor.state(), RoomState::Open);
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 0);
}

#[test]
fn epoch_ack_timeout_uses_the_configured_timeout() {
    let timeouts = Timeouts {
        epoch_acknowledgement: Duration::from_millis(500),
        ..Timeouts::default()
    };
    let mut actor = RoomActor::create(
        &Limits::default(),
        HOST,
        "host".to_owned(),
        HostIdentity::from_seed([0x01; 32], [0x02; 32]),
        MemberIdentity::from_seed([0x03; 32], [0x04; 32]),
        &timeouts,
    )
    .unwrap();
    let actions = actor.start().unwrap();
    ack_transition(&mut actor, &actions);

    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    let accept_actions = actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();
    actor
        .handle_event(RoomEvent::EpochAck {
            connection: HOST,
            epoch: 2,
        })
        .unwrap();

    // 0.4s is within the configured 0.5s window: nothing happens.
    let early = actor
        .handle_event_at(
            RoomEvent::TimeoutExpired {
                connection: CLIENT,
                kind: TimeoutKind::EpochAcknowledgement,
            },
            Duration::from_millis(400),
        )
        .unwrap();
    assert!(early.is_empty());

    // 0.6s exceeds the configured window: the member is evicted even
    // though the default 30 s timeout would not have elapsed.
    let actions = actor
        .handle_event_at(
            RoomEvent::TimeoutExpired {
                connection: CLIENT,
                kind: TimeoutKind::EpochAcknowledgement,
            },
            Duration::from_millis(600),
        )
        .unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::MemberLeft { .. }))
    );
    let _ = accept_actions;
}

#[test]
fn mutations_are_rejected_but_request_snapshots_remain_available_during_transition() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    actor
        .handle_event(RoomEvent::HostAccepted { request_id })
        .unwrap();
    assert_eq!(actor.state(), RoomState::EpochTransition);

    assert!(matches!(
        actor.handle_event(join_request(CLIENT_B, "bob")),
        Err(RoomError::EpochTransitionInProgress)
    ));
    let actions = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Requests))
        .unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::RequestsSnapshot { .. }))
    );
    assert!(matches!(
        actor.handle_event(RoomEvent::HostCommand(HostCommand::ReqOff)),
        Err(RoomError::EpochTransitionInProgress)
    ));
}

// ---- duplicates, errors, shutdown ------------------------------------------------

#[test]
fn duplicate_accept_is_an_error() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);
    assert!(matches!(
        actor.handle_event(RoomEvent::HostAccepted { request_id }),
        Err(RoomError::UnknownRequest { .. })
    ));
}

#[test]
fn member_table_capacity_rejects_overflow_applicants() {
    let limits = Limits::with_max_active_members(2); // host + one member
    let mut actor = RoomActor::create(
        &limits,
        HOST,
        "host".to_owned(),
        HostIdentity::from_seed([0x01; 32], [0x02; 32]),
        MemberIdentity::from_seed([0x03; 32], [0x04; 32]),
        &veilroom::limits::Timeouts::default(),
    )
    .unwrap();
    let actions = actor.start().unwrap();
    ack_transition(&mut actor, &actions);
    let first = submit_request(&mut actor, CLIENT, "alice");
    accept(&mut actor, first);

    let second = submit_request(&mut actor, CLIENT_B, "bob");
    let actions = accept(&mut actor, second);
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::JoinRejected(_) }
            if *connection == CLIENT_B
    )));
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 1);
}

#[test]
fn chat_received_from_a_non_member_is_rejected() {
    let mut actor = started_actor();
    let envelope =
        veilroom::protocol::EncryptedEnvelope::new(1, 1, 1, [0x21; 24], vec![0x33; 17], [0x34; 64])
            .unwrap();
    assert!(matches!(
        actor.handle_event(RoomEvent::ChatReceived {
            connection: CLIENT,
            message_type: 0x40,
            envelope,
        }),
        Err(RoomError::NotAMember { .. })
    ));
}

#[test]
fn unknown_connection_loss_is_a_no_op() {
    let mut actor = started_actor();
    let actions = actor.handle_event(lost(ConnectionId::new(42))).unwrap();
    assert!(actions.is_empty());
}

#[test]
fn close_requested_notifies_members_and_destroys_the_room() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);

    let actions = actor.handle_event(RoomEvent::CloseRequested).unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::Shutdown(_) }
            if *connection == CLIENT
    )));
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::RoomClosed))
    );
    assert_eq!(actor.state(), RoomState::Destroyed);

    // The room rejects further events.
    assert!(matches!(
        actor.handle_event(join_request(CLIENT, "late")),
        Err(RoomError::RoomClosed)
    ));
}

#[test]
fn tor_stopped_closes_the_room() {
    let mut actor = started_actor();
    let actions = actor.handle_event(RoomEvent::TorStopped).unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::RoomClosed))
    );
    assert_eq!(actor.state(), RoomState::Destroyed);
}

#[test]
fn member_left_event_removes_the_member() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    accept(&mut actor, request_id);
    let actions = actor
        .handle_event(RoomEvent::MemberLeft {
            member: MemberId::new(1),
        })
        .unwrap();
    assert!(
        notices(&actions)
            .iter()
            .any(|notice| matches!(notice, HostNotice::MemberLeft { .. }))
    );
    ack_transition(&mut actor, &actions);
    assert_eq!(actor.members().filter(|m| !m.is_host).count(), 0);
}

#[test]
fn join_requested_when_locked_is_an_error() {
    let mut actor = started_actor();
    actor
        .handle_event(RoomEvent::HostCommand(HostCommand::ReqOff))
        .unwrap();
    assert!(matches!(
        actor.handle_event(join_request(CLIENT, "deniz")),
        Err(RoomError::PolicyLocked)
    ));
}

#[test]
fn reject_closes_the_applicant() {
    let mut actor = started_actor();
    let request_id = submit_request(&mut actor, CLIENT, "deniz");
    let actions = actor
        .handle_event(RoomEvent::HostRejected { request_id })
        .unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo { connection, message: Message::JoinRejected(_) }
            if *connection == CLIENT
    )));
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::CloseConnection { connection } if *connection == CLIENT
    )));
    assert_eq!(actor.epoch(), 1, "a rejection must not rotate the epoch");
}

#[test]
fn requests_snapshot_lists_pending_applications() {
    let mut actor = started_actor();
    submit_request(&mut actor, CLIENT, "alice");
    submit_request(&mut actor, CLIENT_B, "bob");
    let actions = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Requests))
        .unwrap();
    let snapshot = notices(&actions)
        .iter()
        .find_map(|notice| match notice {
            HostNotice::RequestsSnapshot { join_requests, .. } => Some(join_requests),
            _ => None,
        })
        .expect("requests snapshot");
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0].request_id, RequestId::new(0));
    assert_eq!(snapshot[1].request_id, RequestId::new(1));
}

#[test]
fn request_id_from_snapshot_can_be_used_to_accept_the_application() {
    let mut actor = started_actor();
    submit_request(&mut actor, CLIENT, "alice");
    let snapshot_actions = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Requests))
        .unwrap();
    let request_id = notices(&snapshot_actions)
        .iter()
        .find_map(|notice| match notice {
            HostNotice::RequestsSnapshot { join_requests, .. } => {
                join_requests.first().map(|request| request.request_id)
            }
            _ => None,
        })
        .expect("the snapshot exposes the pending request id");

    let actions = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Accept { request_id }))
        .unwrap();
    assert!(actions.iter().any(|action| matches!(
        action,
        RoomAction::SendTo {
            connection,
            message: Message::JoinAccepted(_)
        } if *connection == CLIENT
    )));

    // Acceptance starts an epoch transition. The UI queues its refresh
    // immediately after the accept command, so this read-only snapshot must
    // remain available during that transition and must not retain the
    // accepted application as pending.
    let refreshed = actor
        .handle_event(RoomEvent::HostCommand(HostCommand::Requests))
        .unwrap();
    let join_requests = notices(&refreshed)
        .iter()
        .find_map(|notice| match notice {
            HostNotice::RequestsSnapshot { join_requests, .. } => Some(join_requests),
            _ => None,
        })
        .expect("requests can be refreshed during the epoch transition");
    assert!(join_requests.is_empty());
}
