//! Wire protocol: message types, message classes, and stable error codes.
//!
//! The numeric message IDs of V1 are fixed (architecture decision 17,
//! section 40) and are never reused for another meaning. New message
//! *payloads* are introduced in later stages, but the registry below is
//! final for V1.

/// V1 message types with their fixed numeric IDs.
///
/// Ranges (section 40):
///
/// ```text
/// 0x01-0x1F  Handshake and authentication
/// 0x20-0x3F  Membership and room events
/// 0x40-0x5F  Chat messages
/// 0x60-0x7F  Epoch and key management
/// 0x80-0x8F  Keepalive and shutdown
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// 0x01: host hello (host -> client), Stage 4.
    HostHello,
    /// 0x02: client hello (client -> host), Stage 4.
    ClientHello,
    /// 0x03: invitation token verification (client -> host), Stage 4.
    TokenVerify,
    /// 0x04: password challenge (host -> client), Stage 4.
    PasswordChallenge,
    /// 0x05: password challenge proof (client -> host), Stage 4.
    ChallengeProof,
    /// 0x06: join request with nickname, introduction, and signature (client -> host), Stage 4.
    JoinRequest,
    /// 0x07: join accepted (host -> client), Stage 4.
    JoinAccepted,
    /// 0x08: join rejected (host -> client), Stage 4.
    JoinRejected,
    /// 0x20: a member joined (host -> members), Stage 5.
    MemberJoined,
    /// 0x21: a member left (host -> members), Stage 5.
    MemberLeft,
    /// 0x22: a member was kicked (host -> members), Stage 5.
    MemberKicked,
    /// 0x23: join policy changed between open and locked (host -> members), Stage 5.
    JoinPolicyChanged,
    /// 0x24: full member snapshot for `/list` (host -> members), Stage 5.
    MemberSnapshot,
    /// 0x40: encrypted chat message (member -> host -> members), Stage 7.
    ChatMessage,
    /// 0x41: member color change (member -> host -> members), Stage 7.
    ColorChange,
    /// 0x42: encrypted room-timeout request (member -> host).
    TimeoutRequest,
    /// 0x43: encrypted accepted room-timeout setting (host -> members).
    TimeoutChanged,
    /// 0x60: per-member wrapped epoch key (host -> member), Stage 6.
    EpochWrap,
    /// 0x61: epoch acknowledgement (member -> host), Stage 6.
    EpochAck,
    /// 0x80: keepalive, Stage 2.
    Keepalive,
    /// 0x81: protocol error with a stable error code, Stage 2.
    Error,
    /// 0x82: room shutdown notification (host -> client), Stage 2.
    Shutdown,
}

impl MessageType {
    /// Returns the message type for a numeric ID, or `None` for unused or
    /// out-of-range IDs.
    pub const fn from_u8(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(Self::HostHello),
            0x02 => Some(Self::ClientHello),
            0x03 => Some(Self::TokenVerify),
            0x04 => Some(Self::PasswordChallenge),
            0x05 => Some(Self::ChallengeProof),
            0x06 => Some(Self::JoinRequest),
            0x07 => Some(Self::JoinAccepted),
            0x08 => Some(Self::JoinRejected),
            0x20 => Some(Self::MemberJoined),
            0x21 => Some(Self::MemberLeft),
            0x22 => Some(Self::MemberKicked),
            0x23 => Some(Self::JoinPolicyChanged),
            0x24 => Some(Self::MemberSnapshot),
            0x40 => Some(Self::ChatMessage),
            0x41 => Some(Self::ColorChange),
            0x42 => Some(Self::TimeoutRequest),
            0x43 => Some(Self::TimeoutChanged),
            0x60 => Some(Self::EpochWrap),
            0x61 => Some(Self::EpochAck),
            0x80 => Some(Self::Keepalive),
            0x81 => Some(Self::Error),
            0x82 => Some(Self::Shutdown),
            _ => None,
        }
    }

    /// Returns the numeric ID of this message type.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::HostHello => 0x01,
            Self::ClientHello => 0x02,
            Self::TokenVerify => 0x03,
            Self::PasswordChallenge => 0x04,
            Self::ChallengeProof => 0x05,
            Self::JoinRequest => 0x06,
            Self::JoinAccepted => 0x07,
            Self::JoinRejected => 0x08,
            Self::MemberJoined => 0x20,
            Self::MemberLeft => 0x21,
            Self::MemberKicked => 0x22,
            Self::JoinPolicyChanged => 0x23,
            Self::MemberSnapshot => 0x24,
            Self::ChatMessage => 0x40,
            Self::ColorChange => 0x41,
            Self::TimeoutRequest => 0x42,
            Self::TimeoutChanged => 0x43,
            Self::EpochWrap => 0x60,
            Self::EpochAck => 0x61,
            Self::Keepalive => 0x80,
            Self::Error => 0x81,
            Self::Shutdown => 0x82,
        }
    }

    /// The message class used by the connection state machine.
    pub const fn class(self) -> MessageClass {
        match self {
            Self::HostHello | Self::ClientHello => MessageClass::Handshake,
            Self::TokenVerify | Self::PasswordChallenge | Self::ChallengeProof => {
                MessageClass::Authentication
            }
            Self::JoinRequest | Self::JoinAccepted | Self::JoinRejected => MessageClass::Join,
            Self::MemberJoined
            | Self::MemberLeft
            | Self::MemberKicked
            | Self::JoinPolicyChanged
            | Self::MemberSnapshot => MessageClass::Membership,
            Self::ChatMessage | Self::ColorChange | Self::TimeoutRequest | Self::TimeoutChanged => {
                MessageClass::Chat
            }
            Self::EpochWrap | Self::EpochAck => MessageClass::Epoch,
            Self::Keepalive | Self::Error | Self::Shutdown => MessageClass::Control,
        }
    }
}

/// Category of a message, used by the connection state machine to decide
/// which messages are valid in which state (section 13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    /// Handshake messages.
    Handshake,
    /// Token and password verification messages.
    Authentication,
    /// Join application and decision messages.
    Join,
    /// Membership and room-event messages.
    Membership,
    /// Chat messages.
    Chat,
    /// Epoch and key-management messages.
    Epoch,
    /// Keepalive, error, and shutdown messages.
    Control,
}

/// Stable protocol error codes carried by the `Error` message (section 40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// A message was sent that is invalid for the current protocol state.
    ProtocolViolation,
    /// The peer speaks an unsupported protocol version.
    UnsupportedVersion,
    /// The invitation URI or token is invalid.
    InvalidInvitation,
    /// The room is not accepting join requests.
    RoomLocked,
    /// The password proof did not verify.
    InvalidPasswordProof,
    /// The connection timed out.
    ConnectionTimeout,
    /// The room is closing or has closed.
    RoomClosed,
    /// One message was refused and the sender should send it again later.
    ///
    /// Covers the chat rate limit and transient room states (an epoch
    /// transition in flight). It never refuses the connection itself; see
    /// [`ErrorCode::is_recoverable`].
    RateLimited,
    /// An internal error occurred.
    Internal,
}

impl ErrorCode {
    /// Returns the error code for a numeric value, or `None` for unknown codes.
    pub const fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ProtocolViolation),
            2 => Some(Self::UnsupportedVersion),
            3 => Some(Self::InvalidInvitation),
            4 => Some(Self::RoomLocked),
            5 => Some(Self::InvalidPasswordProof),
            6 => Some(Self::ConnectionTimeout),
            7 => Some(Self::RoomClosed),
            8 => Some(Self::RateLimited),
            9 => Some(Self::Internal),
            _ => None,
        }
    }

    /// Whether an admitted member may stay in the room after this error.
    ///
    /// A recoverable error rejects one message and nothing else: the host
    /// keeps the connection open, so the member must keep its session
    /// instead of tearing the room down and re-running the whole join
    /// flow. Every other code accompanies a connection the host is
    /// closing, so the session ends with it.
    pub const fn is_recoverable(self) -> bool {
        matches!(self, Self::RateLimited)
    }

    /// Returns the numeric value of this error code.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ProtocolViolation => 1,
            Self::UnsupportedVersion => 2,
            Self::InvalidInvitation => 3,
            Self::RoomLocked => 4,
            Self::InvalidPasswordProof => 5,
            Self::ConnectionTimeout => 6,
            Self::RoomClosed => 7,
            Self::RateLimited => 8,
            Self::Internal => 9,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_refused_message_is_recoverable() {
        // Recoverable means the host kept the connection open, so the member
        // must keep its session instead of re-running the whole join flow.
        assert!(ErrorCode::RateLimited.is_recoverable());
        for fatal in [
            ErrorCode::ProtocolViolation,
            ErrorCode::UnsupportedVersion,
            ErrorCode::InvalidInvitation,
            ErrorCode::RoomLocked,
            ErrorCode::InvalidPasswordProof,
            ErrorCode::ConnectionTimeout,
            ErrorCode::RoomClosed,
            ErrorCode::Internal,
        ] {
            assert!(
                !fatal.is_recoverable(),
                "{fatal:?} accompanies a closing connection"
            );
        }
    }

    #[test]
    fn every_registered_id_roundtrips() {
        for id in [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x20, 0x21, 0x22, 0x23, 0x24, 0x40,
            0x41, 0x42, 0x43, 0x60, 0x61, 0x80, 0x81, 0x82,
        ] {
            let msg_type = MessageType::from_u8(id).unwrap_or_else(|| panic!("id {id:#04x}"));
            assert_eq!(msg_type.as_u8(), id);
        }
    }

    #[test]
    fn unregistered_ids_are_rejected() {
        for id in [0x00, 0x09, 0x1f, 0x25, 0x44, 0x62, 0x83, 0x8f, 0x90, 0xff] {
            assert!(MessageType::from_u8(id).is_none(), "id {id:#04x}");
        }
    }

    #[test]
    fn message_classes_are_assigned() {
        assert_eq!(MessageType::Keepalive.class(), MessageClass::Control);
        assert_eq!(MessageType::Error.class(), MessageClass::Control);
        assert_eq!(MessageType::Shutdown.class(), MessageClass::Control);
        assert_eq!(MessageType::HostHello.class(), MessageClass::Handshake);
        assert_eq!(
            MessageType::ChallengeProof.class(),
            MessageClass::Authentication
        );
        assert_eq!(MessageType::JoinRequest.class(), MessageClass::Join);
        assert_eq!(MessageType::MemberJoined.class(), MessageClass::Membership);
        assert_eq!(MessageType::ChatMessage.class(), MessageClass::Chat);
        assert_eq!(MessageType::EpochWrap.class(), MessageClass::Epoch);
    }

    #[test]
    fn every_error_code_roundtrips() {
        for code in 1..=9 {
            let error_code = ErrorCode::from_u8(code).unwrap();
            assert_eq!(error_code.as_u8(), code);
        }
        assert!(ErrorCode::from_u8(0).is_none());
        assert!(ErrorCode::from_u8(10).is_none());
        assert!(ErrorCode::from_u8(255).is_none());
    }
}
