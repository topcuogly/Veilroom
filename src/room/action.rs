//! Outputs of the room actor (sections 34.1 and 31).
//!
//! `RoomTask` is the sole writer of room state; its outputs are typed
//! actions that later stages wire to connections, the Tor manager, and the
//! TUI. Messages destined for the network are produced here and carried by
//! [`RoomAction::SendTo`].

use crate::admission::JoinPolicy;
use crate::event::{ConnectionId, RequestId};
use crate::protocol::messages::Message;
use crate::room::member::MemberInfo;

/// One output of the room actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomAction {
    /// Send a message to a connection (wired to the network in Stage 7).
    SendTo {
        /// The destination connection.
        connection: ConnectionId,
        /// The message to send.
        message: Message,
    },
    /// Close a connection (the connection layer tears it down).
    CloseConnection {
        /// The connection to close.
        connection: ConnectionId,
    },
    /// A notice for the host UI.
    NotifyHost(HostNotice),
}

/// Notices produced for the host UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostNotice {
    /// A join application arrived.
    JoinRequestPending {
        /// The assigned request id.
        request_id: RequestId,
        /// The submitting connection.
        connection: ConnectionId,
        /// The requested nickname.
        nickname: String,
        /// The optional introduction message.
        introduction: Option<String>,
    },
    /// A pending application was withdrawn (connection lost, `/reqoff`, or
    /// `/newid`).
    JoinRequestWithdrawn {
        /// The withdrawn request id.
        request_id: RequestId,
    },
    /// A member requested a room-wide timeout change.
    TimeoutRequestPending {
        /// The room-wide request id used by `/accept` and `/reject`.
        request_id: RequestId,
        /// The requesting member.
        member_id: crate::event::MemberId,
        /// The requesting nickname.
        nickname: String,
        /// The requested per-message lifetime in seconds.
        seconds: u64,
    },
    /// The host accepted a timeout request and should broadcast the setting.
    TimeoutRequestAccepted {
        /// The accepted request id.
        request_id: RequestId,
        /// The accepted per-message lifetime in seconds.
        seconds: u64,
    },
    /// The host rejected a timeout request.
    TimeoutRequestRejected {
        /// The rejected request id.
        request_id: RequestId,
    },
    /// A new epoch became active; rebroadcast the current timeout to members.
    TimeoutRebroadcast {
        /// The active room-wide per-message lifetime in seconds.
        seconds: u64,
    },
    /// A member joined.
    MemberJoined {
        /// The assigned member id.
        member_id: crate::event::MemberId,
        /// The member's nickname.
        nickname: String,
    },
    /// A member left.
    MemberLeft {
        /// The member id.
        member_id: crate::event::MemberId,
        /// The member's nickname.
        nickname: String,
    },
    /// A member was kicked.
    MemberKicked {
        /// The member id.
        member_id: crate::event::MemberId,
        /// The member's nickname.
        nickname: String,
    },
    /// The join policy changed.
    JoinPolicyChanged {
        /// The new policy.
        policy: JoinPolicy,
    },
    /// The invitation token was rotated (or the room was created); the
    /// token is host-only material used to render the invitation URI.
    InvitationRotated {
        /// The current invitation token.
        ///
        /// A bearer secret: held in a zeroizing buffer so a rotated token
        /// does not linger in freed memory for the rest of the session.
        token: crate::crypto::SecretBytes,
    },
    /// The atomic join-and-timeout snapshot for `/requests` and the host panel.
    RequestsSnapshot {
        /// Pending admission applications.
        join_requests: Vec<RequestInfo>,
        /// Pending room-timeout requests.
        timeout_requests: Vec<TimeoutRequestInfo>,
    },
    /// The snapshot for `/list`.
    ListSnapshot(Vec<MemberInfo>),
    /// The result of `/whois`.
    WhoisResult(MemberInfo),
    /// The room closed.
    RoomClosed,
    /// A command failed or produced an error condition.
    Error {
        /// A human-readable description.
        message: String,
    },
}

/// A pending join request as shown to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestInfo {
    /// The request id.
    pub request_id: RequestId,
    /// The submitting connection.
    pub connection: ConnectionId,
    /// The requested nickname.
    pub nickname: String,
    /// The optional introduction message.
    pub introduction: Option<String>,
}

/// A pending room-timeout request as shown to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutRequestInfo {
    /// The request id shared with admission requests.
    pub request_id: RequestId,
    /// The requesting member.
    pub member_id: crate::event::MemberId,
    /// The requesting nickname.
    pub nickname: String,
    /// The requested per-message lifetime in seconds.
    pub seconds: u64,
}
