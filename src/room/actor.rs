//! The room actor (sections 13, 23, 32, 33, and 34.1).
//!
//! `RoomActor` is the sole writer of room state. It owns the room lifecycle,
//! the active members, the pending requests, the invitation token, the join
//! policy, the epoch counter, and the room sequence number. Everything else
//! talks to it through typed [`RoomEvent`] values and receives typed
//! [`RoomAction`] values back.
//!
//! The actor is synchronous and deterministic so that race conditions can be
//! tested without a scheduler; the async [`RoomTask`](crate::room::task::RoomTask)
//! wraps it with the event and action channels.
//!
//! Stage 6 plugs the cryptographic membership in: the epoch counter and the
//! transient `EPOCH_TRANSITION` state are managed here, while key
//! generation, per-member wrapping, and `EPOCH_ACK` handling are added
//! there. Until then a membership change advances the epoch synchronously.

use crate::admission::JoinPolicy;
use crate::admission::queue::{JoinApplication, JoinRequestQueue, QueueError};
use std::collections::HashMap;
use std::time::Duration;

use crate::chat::{ChatError, RateLimiter, ReplayTracker};
use crate::command::ColorChoice;
use crate::crypto::chat::open_envelope;
use crate::crypto::identity::{EpochKey, HostIdentity, MemberIdentity, wrap_epoch_key};
use crate::crypto::transcript::{
    SnapshotBodyMember, join_policy_body, member_gone_body, member_joined_body,
    member_snapshot_body, room_event_transcript,
};
use crate::crypto::{CryptoError, SecretBytes, random_bytes};
use crate::event::{
    ConnectionId, HostCommand, MemberCommand, MemberId, MemberRef, RequestId, RoomEvent,
};
use crate::limits::{Limits, TimeoutKind, Timeouts};
use crate::protocol::chat::EncryptedEnvelope;
use crate::protocol::epoch::EpochWrap;
use crate::protocol::handshake::{JoinAccepted, JoinRejected};
use crate::protocol::membership::{
    JoinPolicyChanged, MemberJoined, MemberKicked, MemberLeft, MemberSnapshot, SnapshotMember,
};
use crate::protocol::messages::Message;
use crate::protocol::session::RoomSessionId;
use crate::room::action::{HostNotice, RequestInfo, RoomAction, TimeoutRequestInfo};
use crate::room::connections::Connections;
use crate::room::member::{Member, MemberInfo, MemberTable};
use crate::state::RoomState;
use crate::validation::{contains_control_char, validate_nickname};

/// The host's connection id.
pub const HOST_CONNECTION: ConnectionId = ConnectionId::new(0);

/// Message type of `CHAT_MESSAGE` (0x40).
const MSG_CHAT: u8 = 0x40;
/// Message type of `COLOR_CHANGE` (0x41).
const MSG_COLOR: u8 = 0x41;
const MSG_TIMEOUT_REQUEST: u8 = 0x42;
const MSG_TIMEOUT_CHANGED: u8 = 0x43;
/// Member id of the new member in a joined broadcast.
const MSG_MEMBER_JOINED: u8 = 0x20;
const MSG_MEMBER_LEFT: u8 = 0x21;
const MSG_MEMBER_KICKED: u8 = 0x22;
const MSG_MEMBER_SNAPSHOT: u8 = 0x24;
/// Consecutive rate-limit violations before a connection is terminated.
const RATE_LIMIT_TERMINATION: u32 = 10;

/// Errors produced by the room actor.
#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    /// The join-request queue rejected the application.
    #[error(transparent)]
    Queue(#[from] QueueError),

    /// The member table rejected the member.
    #[error(transparent)]
    Member(#[from] crate::room::member::MemberError),

    /// No pending request carries the given id.
    #[error("no pending join request with id {id}")]
    UnknownRequest {
        /// The unknown request id.
        id: RequestId,
    },

    /// No active member matches the target.
    #[error("no active member matches `{target:?}`")]
    UnknownMember {
        /// The unresolved target.
        target: MemberRef,
    },

    /// The connection is not known to the room.
    #[error("unknown connection {connection}")]
    UnknownConnection {
        /// The unknown connection id.
        connection: ConnectionId,
    },

    /// The host participant cannot leave the room.
    #[error("the host cannot leave the room; use /exit to close it")]
    HostCannotLeave,

    /// The host cannot be kicked.
    #[error("the host cannot be kicked")]
    CannotKickHost,

    /// The kick target is an empty nickname.
    #[error("a member reference must not be empty")]
    EmptyMemberRef,

    /// The room is not accepting join requests.
    #[error("the room is not accepting join requests")]
    PolicyLocked,

    /// A member command came from a connection that is not a member.
    #[error("connection {connection} is not an active member")]
    NotAMember {
        /// The offending connection id.
        connection: ConnectionId,
    },

    /// The room is closing or closed.
    #[error("the room is closing or closed")]
    RoomClosed,

    /// The event is not processed while an epoch transition is pending.
    #[error("an epoch transition is in progress")]
    EpochTransitionInProgress,

    /// A chat message belongs to an obsolete epoch.
    #[error("chat message epoch {found} is not the current epoch {current}")]
    OldEpoch {
        /// The epoch carried by the message.
        found: u64,
        /// The current epoch.
        current: u64,
    },

    /// A chat message replayed a sender sequence.
    #[error("replayed chat message from member {sender} with sequence {sequence}")]
    ReplayRejected {
        /// The sender member id.
        sender: u64,
        /// The replayed sequence number.
        sequence: u64,
    },

    /// A chat message failed verification or authentication.
    #[error(transparent)]
    Chat(#[from] ChatError),

    /// A color payload carried an unknown palette index.
    #[error("unknown color index {index}")]
    UnknownColor {
        /// The invalid index.
        index: u8,
    },

    /// The event cannot be processed in this stage.
    #[error("unsupported room event in this stage")]
    UnsupportedEvent,

    /// The nickname failed validation.
    #[error("invalid nickname: {0}")]
    InvalidNickname(#[from] crate::error::ValidationError),

    /// A protocol-level construction failed.
    #[error(transparent)]
    Protocol(#[from] crate::protocol::messages::ProtocolError),

    /// Secure randomness failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl RoomError {
    /// Whether this error is a transient state-machine rejection.
    ///
    /// Transient errors (for example a chat message during an epoch
    /// transition) are caused by room timing, not by the connection's
    /// behavior; the connection must not be terminated for them.
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::EpochTransitionInProgress)
    }
}

/// The room's state machine and state ownership.
#[derive(Debug)]
pub struct RoomActor {
    session_id: RoomSessionId,
    token: SecretBytes,
    state: RoomState,
    policy: JoinPolicy,
    members: MemberTable,
    connections: Connections,
    requests: JoinRequestQueue,
    timeout_requests: Vec<PendingTimeoutRequest>,
    room_timeout: Option<u64>,
    host_connection: ConnectionId,
    host_identity: HostIdentity,
    timeouts: Timeouts,
    epoch: u64,
    epoch_key: Option<EpochKey>,
    pending_epoch: Option<PendingEpoch>,
    room_sequence: u64,
    chat_replay: ReplayTracker,
    rate_limits: HashMap<MemberId, RateLimiter>,
    pending_membership: Vec<RoomAction>,
    now: Duration,
}

/// An epoch transition awaiting acknowledgements (section 18).
#[derive(Debug)]
struct PendingEpoch {
    /// The epoch awaiting activation.
    epoch: u64,
    /// The key that becomes active once every member acknowledges.
    key: EpochKey,
    /// The members that have not acknowledged yet.
    awaiting: Vec<MemberId>,
    /// When this transition began on the actor's monotonic clock.
    started_at: Duration,
}

#[derive(Debug, Clone)]
struct PendingTimeoutRequest {
    request_id: RequestId,
    connection: ConnectionId,
    member_id: MemberId,
    nickname: String,
    seconds: u64,
}

impl RoomActor {
    /// Creates a room in the `Creating` state.
    ///
    /// Generates the room session id and the invitation token, registers
    /// the host connection, and adds the host participant as member 0.
    pub fn create(
        limits: &Limits,
        host_connection: ConnectionId,
        host_nickname: String,
        host_identity: HostIdentity,
        host_client_identity: MemberIdentity,
        timeouts: &Timeouts,
    ) -> Result<Self, RoomError> {
        let host_nickname = validate_nickname(&host_nickname, limits)?;
        let mut members = MemberTable::new(limits);
        let host = members.add_host(
            host_connection,
            host_nickname,
            host_client_identity.ed25519_pubkey(),
            host_client_identity.x25519_pubkey(),
        );
        debug_assert!(host.is_host);
        Ok(Self {
            session_id: RoomSessionId::generate()?,
            token: SecretBytes::from(random_bytes::<32>()?.to_vec()),
            state: RoomState::Creating,
            policy: JoinPolicy::Open,
            members,
            connections: Connections::new(),
            requests: JoinRequestQueue::new(limits),
            timeout_requests: Vec::new(),
            room_timeout: None,
            host_connection,
            host_identity,
            timeouts: timeouts.clone(),
            epoch: 0,
            epoch_key: None,
            pending_epoch: None,
            room_sequence: 0,
            chat_replay: ReplayTracker::new(),
            rate_limits: HashMap::new(),
            pending_membership: Vec::new(),
            now: Duration::ZERO,
        })
    }

    /// Starts the room: `Creating -> Open`, emitting the initial invitation.
    pub fn start(&mut self) -> Result<Vec<RoomAction>, RoomError> {
        if self.state != RoomState::Creating {
            return Err(RoomError::RoomClosed);
        }
        self.connections.register(self.host_connection);
        self.connections
            .promote(self.host_connection, MemberId::new(0));
        let mut actions = vec![RoomAction::NotifyHost(HostNotice::InvitationRotated {
            token: self.token.clone(),
        })];
        self.begin_epoch_transition(&mut actions)?;
        Ok(actions)
    }

    /// The room session id.
    pub const fn session_id(&self) -> &RoomSessionId {
        &self.session_id
    }

    /// The current invitation token.
    pub fn token(&self) -> &[u8] {
        &self.token[..]
    }

    /// The room lifecycle state.
    pub const fn state(&self) -> RoomState {
        self.state
    }

    /// The join policy.
    pub const fn policy(&self) -> JoinPolicy {
        self.policy
    }

    /// The current epoch number.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The active epoch key, once the current transition has completed.
    pub const fn epoch_key(&self) -> Option<&EpochKey> {
        self.epoch_key.as_ref()
    }

    /// The current room sequence number.
    pub const fn room_sequence(&self) -> u64 {
        self.room_sequence
    }

    /// The host's connection id.
    pub const fn host_connection(&self) -> ConnectionId {
        self.host_connection
    }

    /// The host's room-lifetime identity (public keys and signing).
    pub const fn host_identity(&self) -> &HostIdentity {
        &self.host_identity
    }

    /// The active members.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.iter()
    }

    /// Handles one typed room event and returns the resulting actions.
    ///
    /// Uses the room's internal monotonic clock, which is only advanced by
    /// [`RoomActor::handle_event_at`]; tests that never advance it observe
    /// burst-limited rate limiting, which is deterministic.
    pub fn handle_event(&mut self, event: RoomEvent) -> Result<Vec<RoomAction>, RoomError> {
        self.handle_event_at(event, self.now)
    }

    /// Handles one typed room event at monotonic time `now` (the elapsed
    /// time since the room was created).
    pub fn handle_event_at(
        &mut self,
        event: RoomEvent,
        now: Duration,
    ) -> Result<Vec<RoomAction>, RoomError> {
        self.now = now;
        if matches!(self.state, RoomState::Closing | RoomState::Destroyed) {
            return Err(RoomError::RoomClosed);
        }
        // During an epoch transition only acknowledgements, connection
        // losses, timeouts, shutdown, and read-only request snapshots are
        // processed (section 18). Chat from a member that already
        // acknowledged the pending epoch is still relayed so a single
        // stalling member cannot freeze the room (the pending key is
        // already in every member's hands).
        if matches!(self.state, RoomState::EpochTransition) {
            return match event {
                RoomEvent::EpochAck { connection, epoch } => self.on_epoch_ack(connection, epoch),
                RoomEvent::ConnectionLost { connection } => self.on_connection_lost(connection),
                RoomEvent::TimeoutExpired { connection, kind } => {
                    if kind == TimeoutKind::EpochAcknowledgement {
                        self.on_epoch_timeout()
                    } else {
                        self.on_connection_lost(connection)
                    }
                }
                RoomEvent::EpochMaintenance => self.on_epoch_timeout(),
                RoomEvent::CloseRequested | RoomEvent::TorStopped => self.close_room(),
                RoomEvent::HostCommand(HostCommand::Requests) => {
                    self.on_host_command(HostCommand::Requests)
                }
                RoomEvent::ChatReceived {
                    connection,
                    message_type,
                    envelope,
                } => {
                    if self.member_has_acked_pending_epoch(connection) {
                        self.on_chat_received(connection, message_type, &envelope)
                    } else {
                        // The message was sealed under the previous epoch
                        // key, so it cannot be relayed and cannot be
                        // re-sealed by the host either. Dropping it is
                        // unavoidable; dropping it *silently* is not, since
                        // the sender has already echoed the line locally
                        // and would believe it was delivered.
                        self.reject_during_transition(connection)
                    }
                }
                _ => Err(RoomError::EpochTransitionInProgress),
            };
        }
        match event {
            RoomEvent::ClientConnected { connection } => {
                self.connections.register(connection);
                Ok(Vec::new())
            }
            RoomEvent::PasswordVerified { connection } => {
                self.connections.mark_password_verified(connection);
                Ok(Vec::new())
            }
            RoomEvent::EpochAck { connection, epoch } => self.on_epoch_ack(connection, epoch),
            RoomEvent::JoinRequested {
                connection,
                nickname,
                introduction,
                ed25519_pubkey,
                x25519_pubkey,
                signature,
            } => self.on_join_requested(
                connection,
                JoinApplication {
                    nickname,
                    introduction,
                    ed25519_pubkey,
                    x25519_pubkey,
                    signature,
                },
            ),
            RoomEvent::HostCommand(command) => self.on_host_command(command),
            RoomEvent::MemberCommand {
                connection,
                command,
            } => self.on_member_command(connection, command),
            RoomEvent::HostAccepted { request_id } => self.on_accept(request_id),
            RoomEvent::HostRejected { request_id } => self.on_reject(request_id),
            RoomEvent::ConnectionLost { connection } => self.on_connection_lost(connection),
            RoomEvent::TimeoutExpired { connection, .. } => self.on_connection_lost(connection),
            RoomEvent::EpochMaintenance => Ok(Vec::new()),
            RoomEvent::MemberLeft { member } => self.on_member_left(member),
            RoomEvent::ChatReceived {
                connection,
                message_type,
                envelope,
            } => self.on_chat_received(connection, message_type, &envelope),
            RoomEvent::TorStopped | RoomEvent::CloseRequested => self.close_room(),
        }
    }

    /// Closes the room: notify members, close every connection, destroy.
    pub fn close_room(&mut self) -> Result<Vec<RoomAction>, RoomError> {
        if matches!(self.state, RoomState::Destroyed) {
            return Err(RoomError::RoomClosed);
        }
        self.state = RoomState::Closing;
        let mut actions = Vec::new();
        for connection in self.connections.ids() {
            actions.push(RoomAction::SendTo {
                connection,
                message: Message::Shutdown(crate::protocol::messages::Shutdown),
            });
            actions.push(RoomAction::CloseConnection { connection });
        }
        self.state = RoomState::Destroyed;
        actions.push(RoomAction::NotifyHost(HostNotice::RoomClosed));
        Ok(actions)
    }

    fn on_join_requested(
        &mut self,
        connection: ConnectionId,
        application: JoinApplication,
    ) -> Result<Vec<RoomAction>, RoomError> {
        if !self.policy.allows_join_requests() {
            return Err(RoomError::PolicyLocked);
        }
        let entry = self
            .connections
            .get(connection)
            .ok_or(RoomError::UnknownConnection { connection })?;
        if !entry.password_verified
            || !matches!(
                entry.role,
                crate::room::connections::ConnectionRole::Admission
            )
        {
            return Err(RoomError::NotAMember { connection });
        }
        let nickname = application.nickname.clone();
        let introduction = application.introduction.clone();
        let request_id = self.requests.push(connection, application)?;
        self.connections
            .attach_request(connection, request_id)
            .ok_or(RoomError::UnknownConnection { connection })?;
        self.room_sequence += 1;
        Ok(vec![RoomAction::NotifyHost(
            HostNotice::JoinRequestPending {
                request_id,
                connection,
                nickname,
                introduction,
            },
        )])
    }

    fn on_host_command(&mut self, command: HostCommand) -> Result<Vec<RoomAction>, RoomError> {
        match command {
            HostCommand::Kick { target } => self.on_kick(target),
            HostCommand::NewId => self.on_new_id(),
            HostCommand::ReqOn => self.set_policy(JoinPolicy::Open),
            HostCommand::ReqOff => self.set_policy(JoinPolicy::Locked),
            HostCommand::Requests => {
                Ok(vec![RoomAction::NotifyHost(HostNotice::RequestsSnapshot {
                    join_requests: self
                        .requests
                        .pending()
                        .iter()
                        .map(|request| RequestInfo {
                            request_id: request.id,
                            connection: request.connection,
                            nickname: request.application.nickname.clone(),
                            introduction: request.application.introduction.clone(),
                        })
                        .collect(),
                    timeout_requests: self
                        .timeout_requests
                        .iter()
                        .map(|request| TimeoutRequestInfo {
                            request_id: request.request_id,
                            member_id: request.member_id,
                            nickname: request.nickname.clone(),
                            seconds: request.seconds,
                        })
                        .collect(),
                })])
            }
            HostCommand::Accept { request_id } => self.on_accept(request_id),
            HostCommand::Reject { request_id } => self.on_reject(request_id),
        }
    }

    fn on_accept(&mut self, request_id: RequestId) -> Result<Vec<RoomAction>, RoomError> {
        if let Some(index) = self
            .timeout_requests
            .iter()
            .position(|request| request.request_id == request_id)
        {
            let request = self.timeout_requests.remove(index);
            return Ok(vec![RoomAction::NotifyHost(
                HostNotice::TimeoutRequestAccepted {
                    request_id,
                    seconds: request.seconds,
                },
            )]);
        }
        let request = self.take_request(request_id)?;
        let connection = request.connection;
        let application = request.application;

        // The member table is the only source of truth for admission.
        match self.members.add(
            connection,
            application.nickname.clone(),
            application.ed25519_pubkey,
            application.x25519_pubkey,
            self.epoch + 1,
        ) {
            Ok(member) => {
                // Make sure the connection is tracked even if its
                // ClientConnected event has not been processed yet.
                self.connections.register(connection);
                self.connections.promote(connection, member.member_id);
                let mut actions = vec![
                    RoomAction::SendTo {
                        connection,
                        message: Message::JoinAccepted(JoinAccepted::new(
                            member.member_id.as_u64(),
                        )),
                    },
                    RoomAction::NotifyHost(HostNotice::MemberJoined {
                        member_id: member.member_id,
                        nickname: member.nickname.clone(),
                    }),
                ];
                self.begin_epoch_transition(&mut actions)?;
                self.queue_member_joined(&member);
                Ok(actions)
            }
            Err(error) => {
                // Capacity or nickname collision: the application cannot be
                // admitted; reject it and close the connection.
                let rejected = rejected_message(Some(&error.to_string()));
                let mut actions = vec![
                    RoomAction::SendTo {
                        connection,
                        message: rejected,
                    },
                    RoomAction::CloseConnection { connection },
                    RoomAction::NotifyHost(HostNotice::Error {
                        message: error.to_string(),
                    }),
                ];
                if let Some(request_id) = self.connections.request_id(connection) {
                    actions.push(RoomAction::NotifyHost(HostNotice::JoinRequestWithdrawn {
                        request_id,
                    }));
                }
                self.connections.remove(connection);
                Ok(actions)
            }
        }
    }

    fn on_reject(&mut self, request_id: RequestId) -> Result<Vec<RoomAction>, RoomError> {
        if let Some(index) = self
            .timeout_requests
            .iter()
            .position(|request| request.request_id == request_id)
        {
            self.timeout_requests.remove(index);
            return Ok(vec![RoomAction::NotifyHost(
                HostNotice::TimeoutRequestRejected { request_id },
            )]);
        }
        let request = self.take_request(request_id)?;
        let connection = request.connection;
        self.connections.remove(connection);
        Ok(vec![
            RoomAction::SendTo {
                connection,
                message: rejected_message(None),
            },
            RoomAction::CloseConnection { connection },
        ])
    }

    /// Removes a request, mapping a missing request to a typed error.
    fn take_request(
        &mut self,
        request_id: RequestId,
    ) -> Result<crate::admission::queue::JoinRequest, RoomError> {
        self.requests.take(request_id).map_err(|error| match error {
            QueueError::Unknown { id } => RoomError::UnknownRequest { id },
            other => RoomError::Queue(other),
        })
    }

    fn on_member_command(
        &mut self,
        connection: ConnectionId,
        command: MemberCommand,
    ) -> Result<Vec<RoomAction>, RoomError> {
        match command {
            MemberCommand::Leave => self.on_leave(connection),
            MemberCommand::Color(color) => self.on_color(connection, color),
            MemberCommand::List => Ok(vec![RoomAction::NotifyHost(HostNotice::ListSnapshot(
                self.members.iter().map(MemberInfo::from).collect(),
            ))]),
            MemberCommand::Whois(target) => {
                let member = self.resolve_member(&MemberRef::Nickname(target))?;
                Ok(vec![RoomAction::NotifyHost(HostNotice::WhoisResult(
                    MemberInfo::from(member),
                ))])
            }
        }
    }

    fn on_leave(&mut self, connection: ConnectionId) -> Result<Vec<RoomAction>, RoomError> {
        if connection == self.host_connection {
            return Err(RoomError::HostCannotLeave);
        }
        let member_id = self
            .connections
            .member_id(connection)
            .ok_or(RoomError::NotAMember { connection })?;
        let mut actions = Vec::new();
        let Some(member) = self.remove_member(member_id, MSG_MEMBER_LEFT, &mut actions)? else {
            return Ok(Vec::new());
        };
        actions.push(RoomAction::SendTo {
            connection,
            message: Message::Shutdown(crate::protocol::messages::Shutdown),
        });
        actions.push(RoomAction::CloseConnection { connection });
        actions.push(RoomAction::NotifyHost(HostNotice::MemberLeft {
            member_id,
            nickname: member.nickname,
        }));
        Ok(actions)
    }

    fn on_color(
        &mut self,
        connection: ConnectionId,
        color: ColorChoice,
    ) -> Result<Vec<RoomAction>, RoomError> {
        let member_id = match self.connections.member_id(connection) {
            Some(member_id) => member_id,
            None if connection == self.host_connection => MemberId::new(0),
            None => return Err(RoomError::NotAMember { connection }),
        };
        if let Some(member) = self.members.by_id_mut(member_id) {
            // Stage 7 broadcasts the color change to the other members.
            member.color = color;
        }
        Ok(Vec::new())
    }

    fn on_kick(&mut self, target: MemberRef) -> Result<Vec<RoomAction>, RoomError> {
        let member_id = self.resolve_member(&target)?.member_id;
        let member = self
            .members
            .by_id(member_id)
            .ok_or(RoomError::UnknownMember { target })?;
        if member.is_host {
            return Err(RoomError::CannotKickHost);
        }
        let connection = member.connection;
        let mut actions = Vec::new();
        let Some(member) = self.remove_member(member_id, MSG_MEMBER_KICKED, &mut actions)? else {
            return Ok(Vec::new());
        };
        actions.push(RoomAction::CloseConnection { connection });
        actions.push(RoomAction::NotifyHost(HostNotice::MemberKicked {
            member_id,
            nickname: member.nickname,
        }));
        Ok(actions)
    }

    fn on_connection_lost(
        &mut self,
        connection: ConnectionId,
    ) -> Result<Vec<RoomAction>, RoomError> {
        // The host owns the room lifecycle and must never be demoted into a
        // normal MEMBER_LEFT transition. A genuine loss of the local host
        // connection closes the room for everyone.
        if connection == self.host_connection {
            return self.close_room();
        }
        let mut actions = Vec::new();
        let withdrawn_timeout_ids: Vec<RequestId> = self
            .timeout_requests
            .iter()
            .filter(|request| request.connection == connection)
            .map(|request| request.request_id)
            .collect();
        self.timeout_requests
            .retain(|request| request.connection != connection);
        actions.extend(withdrawn_timeout_ids.into_iter().map(|request_id| {
            RoomAction::NotifyHost(HostNotice::TimeoutRequestRejected { request_id })
        }));
        let member_id = self
            .connections
            .member_id(connection)
            .or_else(|| self.members.by_connection(connection).map(|m| m.member_id));
        if let Some(member_id) = member_id {
            if let Some(member) = self.remove_member(member_id, MSG_MEMBER_LEFT, &mut actions)? {
                actions.push(RoomAction::NotifyHost(HostNotice::MemberLeft {
                    member_id,
                    nickname: member.nickname,
                }));
            }
        } else if let Some(request_id) = self.connections.request_id(connection) {
            if self.requests.take(request_id).is_ok() {
                actions.push(RoomAction::NotifyHost(HostNotice::JoinRequestWithdrawn {
                    request_id,
                }));
            }
        }
        self.connections.remove(connection);
        Ok(actions)
    }

    fn on_member_left(&mut self, member_id: MemberId) -> Result<Vec<RoomAction>, RoomError> {
        let mut actions = Vec::new();
        let Some(member) = self.remove_member(member_id, MSG_MEMBER_LEFT, &mut actions)? else {
            return Ok(Vec::new());
        };
        actions.push(RoomAction::NotifyHost(HostNotice::MemberLeft {
            member_id,
            nickname: member.nickname,
        }));
        Ok(actions)
    }

    fn on_new_id(&mut self) -> Result<Vec<RoomAction>, RoomError> {
        // The previous token buffer is zeroized when the new value replaces
        // it.
        self.token = SecretBytes::from(random_bytes::<32>()?.to_vec());
        self.room_sequence += 1;
        let mut actions = Vec::new();
        // Reject every pending application and close every admission flow
        // that used the old invitation; active members are untouched.
        for request in self.requests.drain() {
            actions.push(RoomAction::CloseConnection {
                connection: request.connection,
            });
            actions.push(RoomAction::NotifyHost(HostNotice::JoinRequestWithdrawn {
                request_id: request.id,
            }));
            self.connections.remove(request.connection);
        }
        for connection in self.connections.non_member_ids() {
            actions.push(RoomAction::CloseConnection { connection });
            self.connections.remove(connection);
        }
        actions.push(RoomAction::NotifyHost(HostNotice::InvitationRotated {
            token: self.token.clone(),
        }));
        Ok(actions)
    }

    fn set_policy(&mut self, policy: JoinPolicy) -> Result<Vec<RoomAction>, RoomError> {
        let mut actions = Vec::new();
        if policy == JoinPolicy::Locked {
            for request in self.requests.drain() {
                actions.push(RoomAction::CloseConnection {
                    connection: request.connection,
                });
                actions.push(RoomAction::NotifyHost(HostNotice::JoinRequestWithdrawn {
                    request_id: request.id,
                }));
                self.connections.remove(request.connection);
            }
            for connection in self.connections.non_member_ids() {
                actions.push(RoomAction::CloseConnection { connection });
                self.connections.remove(connection);
            }
        }
        self.policy = policy;
        self.state = if policy == JoinPolicy::Open {
            RoomState::Open
        } else {
            RoomState::Locked
        };
        self.room_sequence += 1;
        let body = join_policy_body(policy == JoinPolicy::Open);
        let signature = self.host_identity.sign(&room_event_transcript(
            1,
            self.session_id.as_bytes(),
            self.room_sequence,
            self.epoch,
            0x23,
            &body,
        ));
        for member in self.members.iter().filter(|member| !member.is_host) {
            actions.push(RoomAction::SendTo {
                connection: member.connection,
                message: Message::JoinPolicyChanged(JoinPolicyChanged {
                    sequence: self.room_sequence,
                    epoch: self.epoch,
                    open: policy == JoinPolicy::Open,
                    signature,
                }),
            });
        }
        actions.push(RoomAction::NotifyHost(HostNotice::JoinPolicyChanged {
            policy,
        }));
        Ok(actions)
    }

    fn resolve_member(&self, target: &MemberRef) -> Result<&Member, RoomError> {
        match target {
            MemberRef::Id(id) => self
                .members
                .by_id(*id)
                .ok_or_else(|| RoomError::UnknownMember {
                    target: target.clone(),
                }),
            MemberRef::Nickname(nickname) if nickname.is_empty() => Err(RoomError::EmptyMemberRef),
            MemberRef::Nickname(nickname) => {
                self.members
                    .by_nickname(nickname)
                    .ok_or_else(|| RoomError::UnknownMember {
                        target: target.clone(),
                    })
            }
        }
    }

    /// Removes a member and starts a new epoch transition for the
    /// remaining members (section 18).
    ///
    /// The transition's actions are appended to `actions`; if the removal
    /// fails (member already gone) no transition is started.
    fn remove_member(
        &mut self,
        member_id: MemberId,
        event_type: u8,
        actions: &mut Vec<RoomAction>,
    ) -> Result<Option<Member>, RoomError> {
        // Central invariant: member 0 is the room owner and cannot leave via
        // member-removal paths (timeout, rate limit, leave, or kick).
        if member_id == MemberId::new(0) {
            return Err(RoomError::HostCannotLeave);
        }
        let Some(member) = self.members.remove(member_id) else {
            return Ok(None);
        };
        self.connections.remove(member.connection);
        self.rate_limits.remove(&member_id);
        self.begin_epoch_transition(actions)?;
        self.queue_member_gone(member_id, event_type);
        Ok(Some(member))
    }

    /// Begins an epoch transition (section 18): advances the epoch, generates
    /// a fresh group key, wraps it for every member, and waits for
    /// acknowledgements.
    fn begin_epoch_transition(&mut self, actions: &mut Vec<RoomAction>) -> Result<(), RoomError> {
        self.epoch += 1;
        // Replay state of previous epochs is obsolete; prune it so the host
        // side never grows without bound over a long room lifetime.
        self.chat_replay.retain_epoch(self.epoch);
        self.room_sequence += 1;
        let key = EpochKey::generate()?;
        let session = *self.session_id.as_bytes();
        let mut awaiting = Vec::new();
        for member in self.members.iter() {
            let wrap_key = self.host_identity.try_wrap_key_for(
                &member.x25519_pubkey,
                &session,
                member.member_id.as_u64(),
            )?;
            let envelope = wrap_epoch_key(&wrap_key, &key, self.epoch, &session)?;
            actions.push(RoomAction::SendTo {
                connection: member.connection,
                message: Message::EpochWrap(EpochWrap::new(
                    self.epoch,
                    envelope.nonce,
                    envelope.ciphertext,
                )?),
            });
            awaiting.push(member.member_id);
        }
        self.state = RoomState::EpochTransition;
        self.pending_epoch = Some(PendingEpoch {
            epoch: self.epoch,
            key,
            awaiting,
            started_at: self.now,
        });
        Ok(())
    }

    /// Handles an epoch acknowledgement; activates the epoch once every
    /// member has acknowledged.
    fn on_epoch_ack(
        &mut self,
        connection: ConnectionId,
        epoch: u64,
    ) -> Result<Vec<RoomAction>, RoomError> {
        let Some(pending) = self.pending_epoch.as_mut() else {
            return Ok(Vec::new());
        };
        if epoch != pending.epoch {
            // A stale acknowledgement from an earlier epoch is ignored.
            return Ok(Vec::new());
        }
        let Some(member_id) = self.connections.member_id(connection) else {
            return Ok(Vec::new());
        };
        let before = pending.awaiting.len();
        pending.awaiting.retain(|id| *id != member_id);
        if pending.awaiting.len() == before {
            return Ok(Vec::new());
        }
        if pending.awaiting.is_empty() {
            let completed = self.pending_epoch.take().expect("pending epoch exists");
            self.epoch_key = Some(completed.key);
            self.state = if self.policy == JoinPolicy::Open {
                RoomState::Open
            } else {
                RoomState::Locked
            };
            let mut actions = std::mem::take(&mut self.pending_membership);
            if let Some(seconds) = self.room_timeout {
                actions.push(RoomAction::NotifyHost(HostNotice::TimeoutRebroadcast {
                    seconds,
                }));
            }
            return Ok(actions);
        }
        Ok(Vec::new())
    }

    /// Removes members that withheld an epoch acknowledgement and starts a
    /// fresh transition for the remaining room.
    ///
    /// The deadline is always enforced: a stalled member is only evicted
    /// once the configured epoch-acknowledgement timeout has elapsed since
    /// the transition began.
    fn on_epoch_timeout(&mut self) -> Result<Vec<RoomAction>, RoomError> {
        let Some(pending) = self.pending_epoch.as_ref() else {
            return Ok(Vec::new());
        };
        if self.now.saturating_sub(pending.started_at)
            < self.timeouts.get(TimeoutKind::EpochAcknowledgement)
        {
            return Ok(Vec::new());
        }
        let timed_out = pending.awaiting.clone();
        self.pending_epoch = None;
        if timed_out.contains(&MemberId::new(0)) {
            return self.close_room();
        }
        let mut removed = Vec::new();
        let mut actions = Vec::new();
        for member_id in timed_out {
            if let Some(member) = self.members.remove(member_id) {
                self.connections.remove(member.connection);
                self.rate_limits.remove(&member_id);
                actions.push(RoomAction::CloseConnection {
                    connection: member.connection,
                });
                actions.push(RoomAction::NotifyHost(HostNotice::MemberLeft {
                    member_id,
                    nickname: member.nickname,
                }));
                removed.push(member_id);
            }
        }
        self.begin_epoch_transition(&mut actions)?;
        for member_id in removed {
            self.queue_member_gone(member_id, MSG_MEMBER_LEFT);
        }
        Ok(actions)
    }

    // ---- chat relay -----------------------------------------------------

    /// Tells a sender that its message was dropped by an epoch transition
    /// and must be sent again.
    ///
    /// This is a rejection of one message, never of the connection: the
    /// member did nothing wrong, it just sent while the room was rotating
    /// keys. `RateLimited` is the V1 code for "this message was refused,
    /// retry"; the reason text carries the actual cause.
    fn reject_during_transition(
        &self,
        connection: ConnectionId,
    ) -> Result<Vec<RoomAction>, RoomError> {
        if connection == self.host_connection {
            return Ok(vec![RoomAction::NotifyHost(HostNotice::Error {
                message: "the room was rotating keys; that action was not applied".to_owned(),
            })]);
        }
        Ok(vec![RoomAction::SendTo {
            connection,
            message: Message::Error(crate::protocol::messages::ErrorMessage::new(
                crate::protocol::ids::ErrorCode::RateLimited,
                Some(
                    "the room was rotating keys; that message was not delivered, \
                     please send it again"
                        .to_owned(),
                ),
            )?),
        }])
    }

    /// Whether `connection` has already acknowledged the pending epoch, so
    /// its chat can be relayed during a transition. Unknown connections and
    /// members that have not acknowledged are not allowed.
    fn member_has_acked_pending_epoch(&self, connection: ConnectionId) -> bool {
        let Some(pending) = self.pending_epoch.as_ref() else {
            return true;
        };
        let Some(member_id) = self.connections.member_id(connection) else {
            return false;
        };
        !pending.awaiting.contains(&member_id)
    }

    fn on_chat_received(
        &mut self,
        connection: ConnectionId,
        message_type: u8,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<RoomAction>, RoomError> {
        if !matches!(
            message_type,
            MSG_CHAT | MSG_COLOR | MSG_TIMEOUT_REQUEST | MSG_TIMEOUT_CHANGED
        ) {
            return Err(RoomError::Chat(ChatError::InvalidPlaintext(
                "not a chat-type message".to_owned(),
            )));
        }
        let sender_id = self
            .connections
            .member_id(connection)
            .ok_or(RoomError::NotAMember { connection })?;
        if envelope.sender_id != sender_id.as_u64() {
            return Err(RoomError::Chat(ChatError::UnknownSender {
                sender_id: envelope.sender_id,
            }));
        }
        self.members
            .by_id(sender_id)
            .ok_or(RoomError::NotAMember { connection })?;

        // Member-authored encrypted actions share one rate-limit bucket.
        // Host timeout broadcasts are administrative state, not chat.
        if matches!(message_type, MSG_CHAT | MSG_COLOR | MSG_TIMEOUT_REQUEST) {
            let (allowed, abusive) = {
                let limiter = self
                    .rate_limits
                    .entry(sender_id)
                    .or_insert_with(|| RateLimiter::new(5, 1));
                let allowed = limiter.allow(self.now);
                (
                    allowed,
                    !allowed && limiter.is_abusive(RATE_LIMIT_TERMINATION),
                )
            };
            if !allowed {
                let mut actions = vec![
                    RoomAction::SendTo {
                        connection,
                        message: Message::Error(crate::protocol::messages::ErrorMessage::new(
                            crate::protocol::ids::ErrorCode::RateLimited,
                            // The reason is what the member actually sees;
                            // a bare RateLimited renders as "protocol
                            // error" and reads like a rejection.
                            Some(
                                "the room rate limit rejected that message; \
                                 send more slowly"
                                    .to_owned(),
                            ),
                        )?),
                    },
                    RoomAction::NotifyHost(HostNotice::Error {
                        message: "member exceeded the message rate limit".to_owned(),
                    }),
                ];
                if abusive {
                    if let Some(member) =
                        self.remove_member(sender_id, MSG_MEMBER_KICKED, &mut actions)?
                    {
                        actions.push(RoomAction::CloseConnection { connection });
                        actions.push(RoomAction::NotifyHost(HostNotice::MemberKicked {
                            member_id: sender_id,
                            nickname: member.nickname,
                        }));
                    }
                }
                return Ok(actions);
            }
        }

        // Epoch and replay checks first, then signature and AEAD. The
        // replay sequence is only recorded after a successful open.
        if envelope.epoch != self.epoch {
            return Err(RoomError::OldEpoch {
                found: envelope.epoch,
                current: self.epoch,
            });
        }
        if let Some(last) = self.chat_replay.last_accepted(sender_id, self.epoch) {
            if envelope.sender_sequence <= last {
                return Err(RoomError::ReplayRejected {
                    sender: envelope.sender_id,
                    sequence: envelope.sender_sequence,
                });
            }
        }
        let plaintext = self.chat_plaintext(sender_id, message_type, envelope)?;
        self.chat_replay
            .accept(sender_id, self.epoch, envelope.sender_sequence);

        let message = match message_type {
            MSG_COLOR => {
                if plaintext.len() != 1 {
                    return Err(RoomError::Chat(ChatError::InvalidPlaintext(
                        "color payload must be one byte".to_owned(),
                    )));
                }
                let color =
                    ColorChoice::from_index(plaintext[0]).ok_or(RoomError::UnknownColor {
                        index: plaintext[0],
                    })?;
                if let Some(member) = self.members.by_id_mut(sender_id) {
                    member.color = color;
                }
                Message::ColorChange(envelope.clone())
            }
            MSG_TIMEOUT_REQUEST => {
                if sender_id == MemberId::new(0) {
                    return Err(RoomError::Chat(ChatError::InvalidPlaintext(
                        "the host cannot submit a timeout request".to_owned(),
                    )));
                }
                let bytes: [u8; 8] = plaintext.try_into().map_err(|_| {
                    RoomError::Chat(ChatError::InvalidPlaintext(
                        "timeout request must contain eight bytes".to_owned(),
                    ))
                })?;
                let seconds = u64::from_be_bytes(bytes);
                if !(1..=crate::command::MAX_MESSAGE_TIMEOUT_SECONDS).contains(&seconds) {
                    return Err(RoomError::Chat(ChatError::InvalidPlaintext(
                        "timeout request is out of range".to_owned(),
                    )));
                }
                if self.requests.len() + self.timeout_requests.len() >= self.requests.limit() {
                    return Err(RoomError::Queue(QueueError::Full {
                        max: self.requests.limit(),
                    }));
                }
                let member = self
                    .members
                    .by_id(sender_id)
                    .expect("the sender was validated as a member");
                let nickname = member.nickname.clone();
                let request_id = self.requests.allocate_id();
                self.timeout_requests.push(PendingTimeoutRequest {
                    request_id,
                    connection,
                    member_id: sender_id,
                    nickname: nickname.clone(),
                    seconds,
                });
                return Ok(vec![RoomAction::NotifyHost(
                    HostNotice::TimeoutRequestPending {
                        request_id,
                        member_id: sender_id,
                        nickname,
                        seconds,
                    },
                )]);
            }
            MSG_TIMEOUT_CHANGED => {
                if sender_id != MemberId::new(0) {
                    return Err(RoomError::Chat(ChatError::InvalidPlaintext(
                        "only the host can change the room timeout".to_owned(),
                    )));
                }
                let bytes: [u8; 9] = plaintext.try_into().map_err(|_| {
                    RoomError::Chat(ChatError::InvalidPlaintext(
                        "timeout setting must contain nine bytes".to_owned(),
                    ))
                })?;
                let valid = match bytes[0] {
                    0 => bytes[1..].iter().all(|byte| *byte == 0),
                    1 => (1..=crate::command::MAX_MESSAGE_TIMEOUT_SECONDS).contains(
                        &u64::from_be_bytes(bytes[1..].try_into().expect("eight-byte slice")),
                    ),
                    _ => false,
                };
                if !valid {
                    return Err(RoomError::Chat(ChatError::InvalidPlaintext(
                        "invalid timeout setting".to_owned(),
                    )));
                }
                self.room_timeout = match bytes[0] {
                    0 => None,
                    1 => Some(u64::from_be_bytes(
                        bytes[1..].try_into().expect("eight-byte slice"),
                    )),
                    _ => unreachable!("the flag was validated above"),
                };
                Message::TimeoutChanged(envelope.clone())
            }
            MSG_CHAT => {
                let text = String::from_utf8(plaintext).map_err(|_| {
                    RoomError::Chat(ChatError::InvalidPlaintext("not UTF-8".to_owned()))
                })?;
                let limits = crate::limits::Limits::default();
                crate::validation::validate_chat_text(&text, &limits).map_err(|error| {
                    RoomError::Chat(ChatError::InvalidPlaintext(error.to_string()))
                })?;
                Message::ChatMessage(envelope.clone())
            }
            _ => unreachable!("message type was validated above"),
        };

        // Relay to every member except the sender.
        let mut actions = Vec::new();
        for member in self.members.iter() {
            if member.connection != connection {
                actions.push(RoomAction::SendTo {
                    connection: member.connection,
                    message: message.clone(),
                });
            }
        }
        Ok(actions)
    }

    /// Opens the envelope to validate the plaintext (the relay forwards the
    /// original ciphertext; the plaintext is only needed for validation).
    fn chat_plaintext(
        &self,
        sender_id: MemberId,
        message_type: u8,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, RoomError> {
        // During an epoch transition the pending key is used (members that
        // already acknowledged it hold it); otherwise the active key. The
        // active key must NOT be used while a transition is in flight: it
        // is the previous epoch's key and would fail to open.
        let (epoch, epoch_key) = match (&self.pending_epoch, &self.epoch_key) {
            (Some(pending), _) => (pending.epoch, &pending.key),
            (None, Some(key)) => (self.epoch, key),
            (None, None) => return Err(RoomError::Chat(ChatError::NoEpochKey)),
        };
        let sender_pubkey = self
            .members
            .by_id(sender_id)
            .map(|member| member.ed25519_pubkey)
            .ok_or(RoomError::Chat(ChatError::UnknownSender {
                sender_id: envelope.sender_id,
            }))?;
        open_envelope(
            epoch_key,
            &sender_pubkey,
            1,
            self.session_id.as_bytes(),
            epoch,
            envelope.sender_id,
            envelope.sender_sequence,
            message_type,
            &envelope.nonce,
            &envelope.ciphertext,
            &envelope.signature,
        )
        .map_err(|error| match error {
            crate::crypto::chat::ChatOpenError::InvalidSignature => {
                RoomError::Chat(ChatError::InvalidSignature)
            }
            crate::crypto::chat::ChatOpenError::Decrypt(_) => {
                RoomError::Chat(ChatError::InvalidCiphertext)
            }
        })
    }

    // ---- signed membership broadcasts -------------------------------------

    /// Queues the `MEMBER_JOINED` broadcast and the new member's snapshot,
    /// emitted when the epoch transition activates.
    fn queue_member_joined(&mut self, member: &Member) {
        self.room_sequence += 1;
        let session = *self.session_id.as_bytes();
        let body = member_joined_body(
            member.member_id.as_u64(),
            &member.nickname,
            &member.ed25519_pubkey,
        );
        let transcript = room_event_transcript(
            1,
            &session,
            self.room_sequence,
            self.epoch,
            MSG_MEMBER_JOINED,
            &body,
        );
        let signature = self.host_identity.sign(&transcript);
        for other in self.members.iter() {
            if other.member_id != member.member_id {
                self.pending_membership.push(RoomAction::SendTo {
                    connection: other.connection,
                    message: Message::MemberJoined(MemberJoined {
                        sequence: self.room_sequence,
                        epoch: self.epoch,
                        member_id: member.member_id.as_u64(),
                        nickname: member.nickname.clone(),
                        ed25519_pubkey: member.ed25519_pubkey,
                        signature,
                    }),
                });
            }
        }
        self.queue_member_snapshot(member.connection);
    }

    /// Queues a `MEMBER_LEFT` (0x21) or `MEMBER_KICKED` (0x22) broadcast.
    fn queue_member_gone(&mut self, member_id: MemberId, event_type: u8) {
        self.room_sequence += 1;
        let session = *self.session_id.as_bytes();
        let body = member_gone_body(member_id.as_u64());
        let transcript = room_event_transcript(
            1,
            &session,
            self.room_sequence,
            self.epoch,
            event_type,
            &body,
        );
        let signature = self.host_identity.sign(&transcript);
        let message = if event_type == MSG_MEMBER_KICKED {
            Message::MemberKicked(MemberKicked {
                sequence: self.room_sequence,
                epoch: self.epoch,
                member_id: member_id.as_u64(),
                signature,
            })
        } else {
            Message::MemberLeft(MemberLeft {
                sequence: self.room_sequence,
                epoch: self.epoch,
                member_id: member_id.as_u64(),
                signature,
            })
        };
        for member in self.members.iter() {
            self.pending_membership.push(RoomAction::SendTo {
                connection: member.connection,
                message: message.clone(),
            });
        }
    }

    /// Queues a `MEMBER_SNAPSHOT` for one connection.
    fn queue_member_snapshot(&mut self, connection: ConnectionId) {
        self.room_sequence += 1;
        let snapshot_members: Vec<SnapshotMember> = self
            .members
            .iter()
            .map(|member| SnapshotMember {
                member_id: member.member_id.as_u64(),
                nickname: member.nickname.clone(),
                color: member.color.as_index(),
                is_host: member.is_host,
                ed25519_pubkey: member.ed25519_pubkey,
            })
            .collect();
        let body_members: Vec<SnapshotBodyMember> = snapshot_members
            .iter()
            .map(|member| SnapshotBodyMember {
                member_id: member.member_id,
                nickname: member.nickname.clone(),
                color_index: member.color,
                is_host: member.is_host,
                ed25519_pubkey: member.ed25519_pubkey,
            })
            .collect();
        let session = *self.session_id.as_bytes();
        let body = member_snapshot_body(&body_members);
        let transcript = room_event_transcript(
            1,
            &session,
            self.room_sequence,
            self.epoch,
            MSG_MEMBER_SNAPSHOT,
            &body,
        );
        let signature = self.host_identity.sign(&transcript);
        self.pending_membership.push(RoomAction::SendTo {
            connection,
            message: Message::MemberSnapshot(MemberSnapshot {
                sequence: self.room_sequence,
                epoch: self.epoch,
                members: snapshot_members,
                signature,
            }),
        });
    }
}

/// Builds a `JOIN_REJECTED` message, falling back to a bare rejection when
/// the reason would be invalid.
fn rejected_message(reason: Option<&str>) -> Message {
    let reason =
        reason.filter(|text| text.len() <= 256 && !contains_control_char(text) && !text.is_empty());
    match reason {
        Some(text) => {
            JoinRejected::new(Some(text.to_owned())).unwrap_or(JoinRejected { reason: None })
        }
        None => JoinRejected { reason: None },
    }
    .into()
}

impl From<JoinRejected> for Message {
    fn from(message: JoinRejected) -> Self {
        Message::JoinRejected(message)
    }
}
