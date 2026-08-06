//! Typed events that flow between tasks (architecture decisions 14, 31, and 34.1).
//!
//! These are pure data. The enums are `#[non_exhaustive]` because later stages
//! extend them without breaking exhaustive matches in existing code.

use std::fmt;

use crate::command::ColorChoice;
use crate::limits::TimeoutKind;

/// Opaque identifier of an ephemeral connection to the room.
///
/// Unique within one room lifetime, monotonically assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Creates a connection id.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying numeric id.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Room-lifetime identifier of an active member (architecture decision 32).
///
/// Assigned atomically when a join request is accepted. The protocol always
/// refers to members by this id, never by nickname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId(u64);

impl MemberId {
    /// Creates a member id.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying numeric id.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Monotonically increasing identifier of a pending join request (section 13.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// Creates a request id.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying numeric id.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Events submitted to the `RoomTask` through its typed event queue.
///
/// `RoomTask` is the sole writer of room state; every other task communicates
/// exclusively through these events (architecture decision 14, section 34.1).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomEvent {
    /// A new TCP connection was accepted and entered the handshake state.
    ClientConnected {
        /// The identifier of the new connection.
        connection: ConnectionId,
    },

    /// The connection completed the password challenge-response.
    PasswordVerified {
        /// The identifier of the verified connection.
        connection: ConnectionId,
    },

    /// A verified connection submitted a join application.
    JoinRequested {
        /// The identifier of the submitting connection.
        connection: ConnectionId,
        /// The requested display nickname (NFC-normalized).
        nickname: String,
        /// The optional introduction message, visible only to the host.
        introduction: Option<String>,
        /// The participant's ephemeral Ed25519 public key (Stage 6).
        ed25519_pubkey: [u8; 32],
        /// The participant's ephemeral X25519 public key (Stage 6).
        x25519_pubkey: [u8; 32],
        /// The participant's join-request signature (verified in Stage 6).
        signature: [u8; 64],
    },

    /// The host accepted a pending join request.
    HostAccepted {
        /// The id of the accepted request.
        request_id: RequestId,
    },

    /// The host rejected a pending join request.
    HostRejected {
        /// The id of the rejected request.
        request_id: RequestId,
    },

    /// A chat or color message was received from a member.
    ///
    /// The envelope is validated by the room (epoch, signature, replay)
    /// and relayed to the other members.
    ChatReceived {
        /// The connection that delivered the message.
        connection: ConnectionId,
        /// The frame message type (0x40 chat or 0x41 color), bound into
        /// the AEAD additional data and the signature transcript.
        message_type: u8,
        /// The encrypted envelope.
        envelope: crate::protocol::chat::EncryptedEnvelope,
    },

    /// An active member left the room.
    MemberLeft {
        /// The member that left.
        member: MemberId,
    },

    /// An active connection was lost.
    ConnectionLost {
        /// The connection that was lost.
        connection: ConnectionId,
    },

    /// A host administration command issued from the local TUI.
    ///
    /// Host commands travel through this local typed channel, never through
    /// the remote protocol (architecture decision 13).
    HostCommand(HostCommand),

    /// A member command issued from the local TUI.
    ///
    /// Member commands also travel through the local typed channel; remote
    /// member commands arrive as protocol messages in later stages.
    MemberCommand {
        /// The connection that issued the command.
        connection: ConnectionId,
        /// The parsed member command.
        command: MemberCommand,
    },

    /// A member acknowledged a new epoch key.
    EpochAck {
        /// The acknowledging connection.
        connection: ConnectionId,
        /// The acknowledged epoch number.
        epoch: u64,
    },

    /// The supervisor requested a graceful room shutdown (host `/exit`).
    CloseRequested,

    /// A per-state timeout fired for a connection.
    TimeoutExpired {
        /// The connection whose timeout fired.
        connection: ConnectionId,
        /// The kind of timeout that fired.
        kind: TimeoutKind,
    },

    /// Periodic room maintenance used to enforce an epoch-acknowledgement
    /// deadline. This is deliberately not associated with a connection.
    EpochMaintenance,

    /// The Tor subprocess ended or failed to start.
    TorStopped,
}

/// Host administration commands delivered from the host TUI to `RoomTask`.
///
/// Only the host may execute these; the server validates every protocol
/// message against connection state and role (section 31).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCommand {
    /// `/kick <member>`: remove an active member and rotate the epoch.
    Kick {
        /// The member to remove, by id or by unique nickname.
        target: MemberRef,
    },
    /// `/newid`: rotate the invitation token and invalidate old invitations.
    NewId,
    /// `/reqon`: enable join requests.
    ReqOn,
    /// `/reqoff`: disable join requests and reject pending applications.
    ReqOff,
    /// `/requests`: list pending join and timeout requests.
    Requests,
    /// `/accept <request-id>`: admit a member or approve a timeout change.
    Accept {
        /// The id of the request to accept.
        request_id: RequestId,
    },
    /// `/reject <request-id>`: deny a join or timeout request.
    Reject {
        /// The id of the request to reject.
        request_id: RequestId,
    },
}

/// A reference to a member from a command target (section 32).
///
/// The protocol always uses the full `member_id`; a nickname is accepted as
/// a convenience only when it matches exactly one active member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRef {
    /// A room-lifetime member id.
    Id(MemberId),
    /// A nickname, resolved by the room only when unambiguous.
    Nickname(String),
}

/// Member-originated room commands (sections 31 and 33).
///
/// Parsed only by the local TUI; raw command text is never sent over the
/// network. Remote member commands arrive as protocol messages in later
/// stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberCommand {
    /// `/leave`: leave the room (not available to the host).
    Leave,
    /// `/color <color>`: set the display color from the fixed palette.
    Color(ColorChoice),
    /// `/list`: list active members.
    List,
    /// `/whois <member>`: show information about a member.
    Whois(String),
}

/// Events produced by the TUI.
///
/// The variant set is provisional; it is refined when the TUI is implemented
/// in a later stage. The TUI must not contain core business logic.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiEvent {
    /// The user selected an entry in the main menu.
    MenuChoiceSelected(MenuChoice),

    /// The user submitted a slash command or chat line.
    CommandSubmitted(String),

    /// The user submitted plain chat text.
    ChatSubmitted(String),

    /// The current session ended and the application should return to the menu.
    SessionEnded,
}

/// Main-menu selection of the application (section 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuChoice {
    /// Create a new room as host.
    Host,
    /// Join an existing room as a participant.
    Join,
    /// Show project purpose and authorship information.
    About,
    /// Quit the application.
    Exit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_opaque_and_comparable() {
        assert_eq!(MemberId::new(7), MemberId::new(7));
        assert_ne!(MemberId::new(7), MemberId::new(8));
        assert!(MemberId::new(1) < MemberId::new(2));
        assert_eq!(MemberId::new(7).as_u64(), 7);
        assert_eq!(RequestId::new(3).as_u64(), 3);
        assert_eq!(ConnectionId::new(5).as_u64(), 5);
    }

    #[test]
    fn all_room_events_are_constructible() {
        let events = [
            RoomEvent::ClientConnected {
                connection: ConnectionId::new(1),
            },
            RoomEvent::PasswordVerified {
                connection: ConnectionId::new(1),
            },
            RoomEvent::JoinRequested {
                connection: ConnectionId::new(1),
                nickname: "deniz".to_owned(),
                introduction: Some("hello".to_owned()),
                ed25519_pubkey: [0x11; 32],
                x25519_pubkey: [0x12; 32],
                signature: [0x13; 64],
            },
            RoomEvent::HostAccepted {
                request_id: RequestId::new(1),
            },
            RoomEvent::HostRejected {
                request_id: RequestId::new(1),
            },
            RoomEvent::ChatReceived {
                connection: ConnectionId::new(1),
                message_type: 0x40,
                envelope: crate::protocol::chat::EncryptedEnvelope::new(
                    1,
                    1,
                    1,
                    [0x21; 24],
                    vec![0x33; 17],
                    [0x34; 64],
                )
                .unwrap(),
            },
            RoomEvent::MemberLeft {
                member: MemberId::new(2),
            },
            RoomEvent::ConnectionLost {
                connection: ConnectionId::new(3),
            },
            RoomEvent::HostCommand(HostCommand::Kick {
                target: MemberRef::Id(MemberId::new(2)),
            }),
            RoomEvent::MemberCommand {
                connection: ConnectionId::new(1),
                command: MemberCommand::Color(ColorChoice::Blue),
            },
            RoomEvent::CloseRequested,
            RoomEvent::TimeoutExpired {
                connection: ConnectionId::new(1),
                kind: TimeoutKind::Keepalive,
            },
            RoomEvent::EpochMaintenance,
            RoomEvent::TorStopped,
        ];
        assert_eq!(events.len(), 14);
    }

    #[test]
    fn all_host_commands_are_constructible() {
        let commands = [
            HostCommand::Kick {
                target: MemberRef::Id(MemberId::new(2)),
            },
            HostCommand::Kick {
                target: MemberRef::Nickname("alice".to_owned()),
            },
            HostCommand::NewId,
            HostCommand::ReqOn,
            HostCommand::ReqOff,
            HostCommand::Requests,
            HostCommand::Accept {
                request_id: RequestId::new(1),
            },
            HostCommand::Reject {
                request_id: RequestId::new(1),
            },
        ];
        assert_eq!(commands.len(), 8);
    }

    #[test]
    fn all_member_commands_are_constructible() {
        let commands = [
            MemberCommand::Leave,
            MemberCommand::Color(ColorChoice::Green),
            MemberCommand::List,
            MemberCommand::Whois("deniz".to_owned()),
        ];
        assert_eq!(commands.len(), 4);
    }

    #[test]
    fn ui_events_and_menu_choices_are_constructible() {
        let events = [
            UiEvent::MenuChoiceSelected(MenuChoice::Host),
            UiEvent::CommandSubmitted("/list".to_owned()),
            UiEvent::ChatSubmitted("hello".to_owned()),
            UiEvent::SessionEnded,
        ];
        assert_eq!(events.len(), 4);
        assert_ne!(MenuChoice::Host, MenuChoice::Join);
        assert_ne!(MenuChoice::Join, MenuChoice::About);
        assert_ne!(MenuChoice::About, MenuChoice::Exit);
        assert_ne!(MenuChoice::Join, MenuChoice::Exit);
    }

    #[test]
    fn events_compare_by_value() {
        let envelope = crate::protocol::chat::EncryptedEnvelope::new(
            1,
            1,
            1,
            [0x21; 24],
            vec![0x33; 17],
            [0x34; 64],
        )
        .unwrap();
        let a = RoomEvent::ChatReceived {
            connection: ConnectionId::new(1),
            message_type: 0x40,
            envelope: envelope.clone(),
        };
        let b = RoomEvent::ChatReceived {
            connection: ConnectionId::new(1),
            message_type: 0x40,
            envelope,
        };
        assert_eq!(a, b);
    }
}
