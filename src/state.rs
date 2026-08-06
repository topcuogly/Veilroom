//! Connection and room state machines (architecture decision 7, section 13).
//!
//! Stage 1 defines the states themselves; Stage 2 adds the message-class
//! acceptance table that validates which messages are legal in which
//! connection state (section 13.1).

use crate::protocol::ids::MessageClass;

/// States of a single client connection (section 13.1).
///
/// Only messages valid for the current state are accepted; a chat message
/// received during `PreAuth`, for example, is a protocol violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// No connection exists.
    Disconnected,
    /// Connecting to the onion service through the Tor SOCKS proxy.
    TorConnecting,
    /// Performing the version and host-hello handshake.
    ProtocolHandshake,
    /// Verifying the invitation token and completing the password
    /// challenge-response.
    PreAuth,
    /// Password proven; submitting the join form (nickname and introduction).
    PasswordVerified,
    /// Join application submitted; waiting for the host decision.
    JoinPending,
    /// Admitted member; may send and receive room messages.
    Active,
    /// Closing; no new application operations are accepted.
    Closing,
}

/// States of the room (section 13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomState {
    /// The room and onion service are being created.
    Creating,
    /// New join flows are allowed.
    Open,
    /// Join flows are disabled; existing members are unaffected.
    Locked,
    /// A membership change is in progress; chat transmission is suspended.
    EpochTransition,
    /// The invitation token is being rotated.
    InviteRotating,
    /// The room is shutting down.
    Closing,
    /// The room is gone; runtime resources are released.
    Destroyed,
}

impl ConnectionState {
    /// Whether a message of `class` is valid in this connection state
    /// (section 13.1).
    ///
    /// Only control messages (keepalive, error, shutdown) are valid in every
    /// state after the handshake has begun. Chat, membership, and epoch
    /// messages require `Active`; the join form requires `PasswordVerified`;
    /// no message at all is accepted before the socket is up.
    pub const fn accepts(self, class: MessageClass) -> bool {
        matches!(
            (self, class),
            (
                Self::ProtocolHandshake,
                MessageClass::Handshake | MessageClass::Control
            ) | (
                Self::PreAuth,
                MessageClass::Authentication | MessageClass::Control
            ) | (
                Self::PasswordVerified,
                MessageClass::Join | MessageClass::Control
            ) | (Self::JoinPending, MessageClass::Control)
                | (
                    Self::Active,
                    MessageClass::Membership
                        | MessageClass::Chat
                        | MessageClass::Epoch
                        | MessageClass::Control
                )
                | (Self::Closing, MessageClass::Control)
        )
    }
}

impl RoomState {
    /// Whether the room currently accepts new join flows (section 7).
    ///
    /// Only `Open` accepts join requests; `Locked`, `Closing`, and transient
    /// states do not.
    pub const fn accepts_join_requests(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_connection_states_are_constructible() {
        let states = [
            ConnectionState::Disconnected,
            ConnectionState::TorConnecting,
            ConnectionState::ProtocolHandshake,
            ConnectionState::PreAuth,
            ConnectionState::PasswordVerified,
            ConnectionState::JoinPending,
            ConnectionState::Active,
            ConnectionState::Closing,
        ];
        assert_eq!(states.len(), 8);
        assert_ne!(states[0], states[1]);
    }

    #[test]
    fn all_room_states_are_constructible() {
        let states = [
            RoomState::Creating,
            RoomState::Open,
            RoomState::Locked,
            RoomState::EpochTransition,
            RoomState::InviteRotating,
            RoomState::Closing,
            RoomState::Destroyed,
        ];
        assert_eq!(states.len(), 7);
    }

    #[test]
    fn only_open_accepts_join_requests() {
        assert!(RoomState::Open.accepts_join_requests());
        assert!(!RoomState::Creating.accepts_join_requests());
        assert!(!RoomState::Locked.accepts_join_requests());
        assert!(!RoomState::EpochTransition.accepts_join_requests());
        assert!(!RoomState::InviteRotating.accepts_join_requests());
        assert!(!RoomState::Closing.accepts_join_requests());
        assert!(!RoomState::Destroyed.accepts_join_requests());
    }

    #[test]
    fn active_accepts_room_messages_only() {
        let active = ConnectionState::Active;
        assert!(active.accepts(MessageClass::Membership));
        assert!(active.accepts(MessageClass::Chat));
        assert!(active.accepts(MessageClass::Epoch));
        assert!(active.accepts(MessageClass::Control));
        assert!(!active.accepts(MessageClass::Handshake));
        assert!(!active.accepts(MessageClass::Authentication));
        assert!(!active.accepts(MessageClass::Join));
    }

    #[test]
    fn handshake_accepts_handshake_and_control_only() {
        let handshake = ConnectionState::ProtocolHandshake;
        assert!(handshake.accepts(MessageClass::Handshake));
        assert!(handshake.accepts(MessageClass::Control));
        assert!(!handshake.accepts(MessageClass::Chat));
        assert!(!handshake.accepts(MessageClass::Join));
        assert!(!handshake.accepts(MessageClass::Epoch));
    }

    #[test]
    fn pre_auth_accepts_authentication_and_control_only() {
        let pre_auth = ConnectionState::PreAuth;
        assert!(pre_auth.accepts(MessageClass::Authentication));
        assert!(pre_auth.accepts(MessageClass::Control));
        assert!(!pre_auth.accepts(MessageClass::Chat));
        assert!(!pre_auth.accepts(MessageClass::Join));
        assert!(!pre_auth.accepts(MessageClass::Membership));
        assert!(!pre_auth.accepts(MessageClass::Handshake));
    }

    #[test]
    fn password_verified_accepts_the_join_form() {
        let verified = ConnectionState::PasswordVerified;
        assert!(verified.accepts(MessageClass::Join));
        assert!(verified.accepts(MessageClass::Control));
        assert!(!verified.accepts(MessageClass::Chat));
    }

    #[test]
    fn join_pending_accepts_control_only() {
        let pending = ConnectionState::JoinPending;
        assert!(pending.accepts(MessageClass::Control));
        assert!(!pending.accepts(MessageClass::Chat));
        assert!(!pending.accepts(MessageClass::Join));
        assert!(!pending.accepts(MessageClass::Epoch));
    }

    #[test]
    fn closing_accepts_control_only() {
        let closing = ConnectionState::Closing;
        assert!(closing.accepts(MessageClass::Control));
        assert!(!closing.accepts(MessageClass::Chat));
        assert!(!closing.accepts(MessageClass::Membership));
    }

    #[test]
    fn disconnected_and_connecting_accept_nothing() {
        assert!(!ConnectionState::Disconnected.accepts(MessageClass::Control));
        assert!(!ConnectionState::TorConnecting.accepts(MessageClass::Control));
        assert!(!ConnectionState::Disconnected.accepts(MessageClass::Handshake));
        assert!(!ConnectionState::TorConnecting.accepts(MessageClass::Chat));
    }
}
