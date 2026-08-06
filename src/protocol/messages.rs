//! Typed protocol messages (Stages 2 and 4).
//!
//! Stage 2 defined the connection-level control messages (`Keepalive`,
//! `ErrorMessage`, `Shutdown`); Stage 4 adds the handshake and admission
//! messages (`0x01..=0x08`, schemas in `crate::protocol::handshake`).
//! Membership, chat, and epoch messages arrive in later stages using the
//! same pattern.
//!
//! Encoding is hand-written and deterministic: definite-length CBOR maps
//! with keys in ascending field-number order. Decoding is hand-written on
//! top of [`StrictDecoder`] so that unknown fields, duplicate keys, and
//! malformed input are rejected (derived decoding would silently ignore
//! unknown fields, which section 30 forbids).

use minicbor::Encoder;

use crate::limits::Limits;
use crate::protocol::chat::EncryptedEnvelope;
use crate::protocol::epoch::{EpochAck, EpochWrap};
use crate::protocol::frame::{Frame, FrameError, encode_frame};
use crate::protocol::handshake::{
    ChallengeProof, ClientHello, HostHello, JoinAccepted, JoinRejected, JoinRequest,
    PasswordChallenge, TokenVerify,
};
use crate::protocol::ids::{ErrorCode, MessageType};
use crate::protocol::membership::{
    JoinPolicyChanged, MemberJoined, MemberKicked, MemberLeft, MemberSnapshot,
};
use crate::protocol::strict::{StrictDecoder, StrictError};
use crate::validation::contains_control_char;

/// Maximum length of an `ErrorMessage` reason text in bytes.
pub const MAX_ERROR_REASON_BYTES: usize = 256;

/// A typed protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Keepalive frame (0x80), empty map payload.
    Keepalive(Keepalive),
    /// Protocol error frame (0x81) with a stable error code.
    Error(ErrorMessage),
    /// Room shutdown notification (0x82), empty map payload.
    Shutdown(Shutdown),
    /// Host hello (0x01), host -> client.
    HostHello(HostHello),
    /// Client hello (0x02), client -> host.
    ClientHello(ClientHello),
    /// Invitation token verification (0x03), client -> host.
    TokenVerify(TokenVerify),
    /// Password challenge (0x04), host -> client.
    PasswordChallenge(PasswordChallenge),
    /// Password challenge proof (0x05), client -> host.
    ChallengeProof(ChallengeProof),
    /// Join application (0x06), client -> host.
    JoinRequest(JoinRequest),
    /// Join accepted (0x07), host -> client.
    JoinAccepted(JoinAccepted),
    /// Join rejected (0x08), host -> client.
    JoinRejected(JoinRejected),
    /// Wrapped epoch key (0x60), host -> member.
    EpochWrap(EpochWrap),
    /// Epoch acknowledgement (0x61), member -> host.
    EpochAck(EpochAck),
    /// A member joined (0x20), host -> members.
    MemberJoined(MemberJoined),
    /// A member left (0x21), host -> members.
    MemberLeft(MemberLeft),
    /// A member was kicked (0x22), host -> members.
    MemberKicked(MemberKicked),
    /// The host opened or locked new join flows (0x23).
    JoinPolicyChanged(JoinPolicyChanged),
    /// Full member snapshot (0x24), host -> member.
    MemberSnapshot(MemberSnapshot),
    /// Encrypted chat message (0x40), member -> host -> members.
    ChatMessage(EncryptedEnvelope),
    /// Encrypted color change (0x41), member -> host -> members.
    ColorChange(EncryptedEnvelope),
    /// Encrypted room-timeout request (0x42), member -> host.
    TimeoutRequest(EncryptedEnvelope),
    /// Encrypted accepted room-timeout setting (0x43), host -> members.
    TimeoutChanged(EncryptedEnvelope),
}

impl Message {
    /// The message type of this message.
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Keepalive(_) => MessageType::Keepalive,
            Self::Error(_) => MessageType::Error,
            Self::Shutdown(_) => MessageType::Shutdown,
            Self::HostHello(_) => MessageType::HostHello,
            Self::ClientHello(_) => MessageType::ClientHello,
            Self::TokenVerify(_) => MessageType::TokenVerify,
            Self::PasswordChallenge(_) => MessageType::PasswordChallenge,
            Self::ChallengeProof(_) => MessageType::ChallengeProof,
            Self::JoinRequest(_) => MessageType::JoinRequest,
            Self::JoinAccepted(_) => MessageType::JoinAccepted,
            Self::JoinRejected(_) => MessageType::JoinRejected,
            Self::EpochWrap(_) => MessageType::EpochWrap,
            Self::EpochAck(_) => MessageType::EpochAck,
            Self::MemberJoined(_) => MessageType::MemberJoined,
            Self::MemberLeft(_) => MessageType::MemberLeft,
            Self::MemberKicked(_) => MessageType::MemberKicked,
            Self::JoinPolicyChanged(_) => MessageType::JoinPolicyChanged,
            Self::MemberSnapshot(_) => MessageType::MemberSnapshot,
            Self::ChatMessage(_) => MessageType::ChatMessage,
            Self::ColorChange(_) => MessageType::ColorChange,
            Self::TimeoutRequest(_) => MessageType::TimeoutRequest,
            Self::TimeoutChanged(_) => MessageType::TimeoutChanged,
        }
    }

    /// Encodes the message into a complete frame.
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, ProtocolError> {
        let mut body = Vec::new();
        self.encode_body(&mut body)?;
        Ok(encode_frame(self.message_type(), &body, limits)?)
    }

    /// Decodes a frame into a typed message using strict CBOR rules.
    ///
    /// Message types whose payloads belong to later stages return
    /// [`ProtocolError::UnsupportedMessage`].
    pub fn decode(frame: &Frame, limits: &Limits) -> Result<Self, ProtocolError> {
        match frame.message_type() {
            MessageType::Keepalive => {
                let message = decode_message_body(frame, Keepalive::strict_decode, limits)?;
                Ok(Self::Keepalive(message))
            }
            MessageType::Error => {
                let message = decode_message_body(frame, ErrorMessage::strict_decode, limits)?;
                Ok(Self::Error(message))
            }
            MessageType::Shutdown => {
                let message = decode_message_body(frame, Shutdown::strict_decode, limits)?;
                Ok(Self::Shutdown(message))
            }
            MessageType::HostHello => {
                let message = decode_message_body(frame, HostHello::strict_decode, limits)?;
                Ok(Self::HostHello(message))
            }
            MessageType::ClientHello => {
                let message = decode_message_body(frame, ClientHello::strict_decode, limits)?;
                Ok(Self::ClientHello(message))
            }
            MessageType::TokenVerify => {
                let message = decode_message_body(frame, TokenVerify::strict_decode, limits)?;
                Ok(Self::TokenVerify(message))
            }
            MessageType::PasswordChallenge => {
                let message = decode_message_body(frame, PasswordChallenge::strict_decode, limits)?;
                Ok(Self::PasswordChallenge(message))
            }
            MessageType::ChallengeProof => {
                let message = decode_message_body(frame, ChallengeProof::strict_decode, limits)?;
                Ok(Self::ChallengeProof(message))
            }
            MessageType::JoinRequest => {
                let message = decode_message_body(frame, JoinRequest::strict_decode, limits)?;
                Ok(Self::JoinRequest(message))
            }
            MessageType::JoinAccepted => {
                let message = decode_message_body(frame, JoinAccepted::strict_decode, limits)?;
                Ok(Self::JoinAccepted(message))
            }
            MessageType::JoinRejected => {
                let message = decode_message_body(frame, JoinRejected::strict_decode, limits)?;
                Ok(Self::JoinRejected(message))
            }
            MessageType::EpochWrap => {
                let message = decode_message_body(frame, EpochWrap::strict_decode, limits)?;
                Ok(Self::EpochWrap(message))
            }
            MessageType::EpochAck => {
                let message = decode_message_body(frame, EpochAck::strict_decode, limits)?;
                Ok(Self::EpochAck(message))
            }
            MessageType::MemberJoined => {
                let message = decode_message_body(frame, MemberJoined::strict_decode, limits)?;
                Ok(Self::MemberJoined(message))
            }
            MessageType::MemberLeft => {
                let message = decode_message_body(frame, MemberLeft::strict_decode, limits)?;
                Ok(Self::MemberLeft(message))
            }
            MessageType::MemberKicked => {
                let message = decode_message_body(frame, MemberKicked::strict_decode, limits)?;
                Ok(Self::MemberKicked(message))
            }
            MessageType::JoinPolicyChanged => {
                let message = decode_message_body(frame, JoinPolicyChanged::strict_decode, limits)?;
                Ok(Self::JoinPolicyChanged(message))
            }
            MessageType::MemberSnapshot => {
                let message = decode_message_body(frame, MemberSnapshot::strict_decode, limits)?;
                Ok(Self::MemberSnapshot(message))
            }
            MessageType::ChatMessage => {
                let message = decode_message_body(frame, EncryptedEnvelope::strict_decode, limits)?;
                Ok(Self::ChatMessage(message))
            }
            MessageType::ColorChange => {
                let message = decode_message_body(frame, EncryptedEnvelope::strict_decode, limits)?;
                Ok(Self::ColorChange(message))
            }
            MessageType::TimeoutRequest => {
                let message = decode_message_body(frame, EncryptedEnvelope::strict_decode, limits)?;
                Ok(Self::TimeoutRequest(message))
            }
            MessageType::TimeoutChanged => {
                let message = decode_message_body(frame, EncryptedEnvelope::strict_decode, limits)?;
                Ok(Self::TimeoutChanged(message))
            }
        }
    }

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        let mut encoder = Encoder::new(out);
        match self {
            Self::Keepalive(message) => message.encode(&mut encoder),
            Self::Error(message) => message.encode(&mut encoder),
            Self::Shutdown(message) => message.encode(&mut encoder),
            Self::HostHello(message) => message.encode(&mut encoder),
            Self::ClientHello(message) => message.encode(&mut encoder),
            Self::TokenVerify(message) => message.encode(&mut encoder),
            Self::PasswordChallenge(message) => message.encode(&mut encoder),
            Self::ChallengeProof(message) => message.encode(&mut encoder),
            Self::JoinRequest(message) => message.encode(&mut encoder),
            Self::JoinAccepted(message) => message.encode(&mut encoder),
            Self::JoinRejected(message) => message.encode(&mut encoder),
            Self::EpochWrap(message) => message.encode(&mut encoder),
            Self::EpochAck(message) => message.encode(&mut encoder),
            Self::MemberJoined(message) => message.encode(&mut encoder),
            Self::MemberLeft(message) => message.encode(&mut encoder),
            Self::MemberKicked(message) => message.encode(&mut encoder),
            Self::JoinPolicyChanged(message) => message.encode(&mut encoder),
            Self::MemberSnapshot(message) => message.encode(&mut encoder),
            Self::ChatMessage(message) => message.encode(&mut encoder),
            Self::ColorChange(message) => message.encode(&mut encoder),
            Self::TimeoutRequest(message) => message.encode(&mut encoder),
            Self::TimeoutChanged(message) => message.encode(&mut encoder),
        }
    }
}

/// Decodes the body of a frame with a strict schema decoder and verifies
/// that the payload is fully consumed.
fn decode_message_body<T>(
    frame: &Frame,
    schema: fn(&mut StrictDecoder<'_>) -> Result<T, ProtocolError>,
    limits: &Limits,
) -> Result<T, ProtocolError> {
    let mut decoder = StrictDecoder::new(frame.payload(), limits);
    let value = schema(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

/// `Keepalive` message (0x80).
///
/// Payload: an empty CBOR map (`0xA0`). No fields are defined; any field is
/// a protocol violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive;

impl Keepalive {
    /// Strictly decodes a keepalive payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        decoder.map_entries(|_, key| Err(ProtocolError::UnknownField { field: key }))?;
        Ok(Self)
    }

    fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(0)?;
        Ok(())
    }
}

/// `Shutdown` message (0x82).
///
/// Payload: an empty CBOR map (`0xA0`). Sent by the host to notify members
/// that the room is closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shutdown;

impl Shutdown {
    /// Strictly decodes a shutdown payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        decoder.map_entries(|_, key| Err(ProtocolError::UnknownField { field: key }))?;
        Ok(Self)
    }

    fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(0)?;
        Ok(())
    }
}

/// `ErrorMessage` message (0x81).
///
/// CBOR map with fields:
///
/// ```text
/// 1: code   (uint8, ErrorCode)
/// 2: reason (text, optional, at most MAX_ERROR_REASON_BYTES bytes,
///            no control characters)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    /// The stable protocol error code.
    pub code: ErrorCode,
    /// An optional human-readable reason.
    pub reason: Option<String>,
}

impl ErrorMessage {
    /// Constructs an error message, validating the reason text.
    ///
    /// An empty reason is normalized to `None`.
    pub fn new(code: ErrorCode, reason: Option<String>) -> Result<Self, ProtocolError> {
        let reason = match reason {
            Some(reason) if reason.is_empty() => None,
            Some(reason) => {
                validate_reason(&reason)?;
                Some(reason)
            }
            None => None,
        };
        Ok(Self { code, reason })
    }

    /// Strictly decodes an error-message payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut code: Option<ErrorCode> = None;
        let mut reason: Option<String> = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                let raw = decoder.u8()?;
                code = Some(
                    ErrorCode::from_u8(raw).ok_or(ProtocolError::UnknownErrorCode { code: raw })?,
                );
                Ok(())
            }
            2 => {
                let text = decoder.str()?.to_owned();
                validate_reason(&text)?;
                reason = Some(text);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        let code = code.ok_or(ProtocolError::MissingField { field: 1 })?;
        Ok(Self { code, reason })
    }

    fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        let entries = if self.reason.is_some() { 2 } else { 1 };
        encoder.map(entries)?.u8(1)?.u8(self.code.as_u8())?;
        if let Some(reason) = &self.reason {
            encoder.u8(2)?.str(reason)?;
        }
        Ok(())
    }
}

/// Validates the reason text of an error message.
fn validate_reason(reason: &str) -> Result<(), ProtocolError> {
    if reason.len() > MAX_ERROR_REASON_BYTES {
        return Err(ProtocolError::ReasonTooLong {
            length: reason.len(),
            max: MAX_ERROR_REASON_BYTES,
        });
    }
    if contains_control_char(reason) {
        return Err(ProtocolError::InvalidReasonText);
    }
    Ok(())
}

/// Errors produced while encoding or decoding messages.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The frame layer rejected the frame.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// The strict CBOR decoder rejected the payload.
    #[error(transparent)]
    Cbor(#[from] StrictError),

    /// Encoding into the in-memory buffer failed.
    ///
    /// Writing CBOR into a `Vec<u8>` cannot fail, so this variant cannot
    /// occur at runtime.
    #[error(transparent)]
    Encode(#[from] minicbor::encode::Error<core::convert::Infallible>),

    /// The payload contains a field the message schema does not define.
    #[error("unknown field {field} in message")]
    UnknownField {
        /// The unknown field number.
        field: u64,
    },

    /// A required field is absent from the payload.
    #[error("missing required field {field} in message")]
    MissingField {
        /// The number of the missing field.
        field: u64,
    },

    /// A field carries a value with the wrong shape or size.
    #[error("invalid value for field {field}: {detail}")]
    InvalidField {
        /// The number of the offending field.
        field: u64,
        /// A description of why the value is invalid.
        detail: String,
    },

    /// A textual field failed application-level validation.
    #[error("field validation failed: {0}")]
    Validation(#[from] crate::error::ValidationError),

    /// The error-code field carries an unregistered value.
    #[error("unknown error code 0x{code:02x}")]
    UnknownErrorCode {
        /// The unregistered code value.
        code: u8,
    },

    /// The reason text contains control characters or ANSI escape sequences.
    #[error("error reason contains control characters or ANSI escape sequences")]
    InvalidReasonText,

    /// The reason text exceeds the configured limit.
    #[error("error reason is {length} bytes, maximum is {max}")]
    ReasonTooLong {
        /// The length of the reason text in bytes.
        length: usize,
        /// The configured maximum reason length in bytes.
        max: usize,
    },

    /// The message type is registered in V1 but its payload is not
    /// decodable in the current stage.
    #[error("message type 0x{id:02x} is not supported in this stage")]
    UnsupportedMessage {
        /// The registered message-type ID.
        id: u8,
    },
}

/// Convenience wrapper: encodes a message into a complete frame.
pub fn encode_message(message: &Message, limits: &Limits) -> Result<Vec<u8>, ProtocolError> {
    message.encode(limits)
}

/// Convenience wrapper: decodes a frame into a typed message.
pub fn decode_message(frame: &Frame, limits: &Limits) -> Result<Message, ProtocolError> {
    Message::decode(frame, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frame::FrameDecoder;

    fn limits() -> Limits {
        Limits::default()
    }

    fn decode_body(body: &[u8], msg_type: MessageType) -> Result<Message, ProtocolError> {
        let limits = Limits::default();
        Message::decode(&Frame::new(msg_type, body.to_vec()), &limits)
    }

    #[test]
    fn keepalive_encodes_to_an_empty_map() {
        let message = Message::Keepalive(Keepalive);
        let bytes = message.encode(&limits()).unwrap();
        assert_eq!(
            bytes,
            [0x00, 0x00, 0x00, 0x05, 0x01, 0x80, 0x00, 0x00, 0xa0]
        );
    }

    #[test]
    fn shutdown_encodes_to_an_empty_map() {
        let message = Message::Shutdown(Shutdown);
        let bytes = message.encode(&limits()).unwrap();
        assert_eq!(
            bytes,
            [0x00, 0x00, 0x00, 0x05, 0x01, 0x82, 0x00, 0x00, 0xa0]
        );
    }

    #[test]
    fn error_message_encodes_deterministically() {
        let message =
            Message::Error(ErrorMessage::new(ErrorCode::UnsupportedVersion, None).unwrap());
        let bytes = message.encode(&limits()).unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x07, 0x01, 0x81, 0x00, 0x00, 0xa1, 0x01, 0x02
            ]
        );

        let message = Message::Error(
            ErrorMessage::new(ErrorCode::RoomLocked, Some("locked".to_owned())).unwrap(),
        );
        let bytes = message.encode(&limits()).unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x00, 0x00, 0x0f, 0x01, 0x81, 0x00, 0x00, 0xa2, 0x01, 0x04, 0x02, 0x66, 0x6c,
                0x6f, 0x63, 0x6b, 0x65, 0x64
            ]
        );
    }

    #[test]
    fn messages_roundtrip() {
        for message in [
            Message::Keepalive(Keepalive),
            Message::Shutdown(Shutdown),
            Message::Error(ErrorMessage::new(ErrorCode::Internal, None).unwrap()),
            Message::Error(
                ErrorMessage::new(ErrorCode::RateLimited, Some("slow down".to_owned())).unwrap(),
            ),
        ] {
            let bytes = message.encode(&limits()).unwrap();
            let mut decoder = FrameDecoder::new(limits());
            let frames = decoder.feed(&bytes).unwrap();
            assert_eq!(frames.len(), 1);
            let decoded = Message::decode(&frames[0], &limits()).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn keepalive_rejects_any_field() {
        // map { 1: 2 } as keepalive payload.
        assert!(matches!(
            decode_body(&[0xa1, 0x01, 0x02], MessageType::Keepalive),
            Err(ProtocolError::UnknownField { field: 1 })
        ));
    }

    #[test]
    fn error_message_rejects_unknown_fields() {
        // map { 3: 2 }.
        assert!(matches!(
            decode_body(&[0xa1, 0x03, 0x02], MessageType::Error),
            Err(ProtocolError::UnknownField { field: 3 })
        ));
    }

    #[test]
    fn error_message_rejects_duplicate_fields() {
        // map { 1: 2, 1: 3 }.
        assert!(matches!(
            decode_body(&[0xa2, 0x01, 0x02, 0x01, 0x03], MessageType::Error),
            Err(ProtocolError::Cbor(StrictError::DuplicateMapKey { key: 1 }))
        ));
    }

    #[test]
    fn error_message_requires_code() {
        // map { 2: "why" } - no code.
        assert!(matches!(
            decode_body(&[0xa1, 0x02, 0x63, b'w', b'h', b'y'], MessageType::Error),
            Err(ProtocolError::MissingField { field: 1 })
        ));
    }

    #[test]
    fn error_message_rejects_unknown_codes() {
        // map { 1: 0x0F }.
        assert!(matches!(
            decode_body(&[0xa1, 0x01, 0x0f], MessageType::Error),
            Err(ProtocolError::UnknownErrorCode { code: 0x0f })
        ));
    }

    #[test]
    fn error_message_rejects_control_characters_in_reason() {
        let message = ErrorMessage::new(ErrorCode::Internal, Some("bad\u{1b}reason".to_owned()));
        assert!(matches!(message, Err(ProtocolError::InvalidReasonText)));
        // map { 1: 9, 2: "a\u{1b}b" }.
        assert!(matches!(
            decode_body(
                &[0xa2, 0x01, 0x09, 0x02, 0x63, b'a', 0x1b, b'b'],
                MessageType::Error
            ),
            Err(ProtocolError::InvalidReasonText)
        ));
    }

    #[test]
    fn error_message_rejects_oversized_reasons() {
        let long = "x".repeat(257);
        let message = ErrorMessage::new(ErrorCode::Internal, Some(long));
        assert!(matches!(
            message,
            Err(ProtocolError::ReasonTooLong {
                length: 257,
                max: 256
            })
        ));
        let empty = "".to_owned();
        assert_eq!(
            ErrorMessage::new(ErrorCode::Internal, Some(empty))
                .unwrap()
                .reason,
            None
        );
    }

    #[test]
    fn non_map_payload_is_rejected() {
        // Payload 0x05 (an integer) is not a map.
        assert!(matches!(
            decode_body(&[0x05], MessageType::Keepalive),
            Err(ProtocolError::Cbor(StrictError::Cbor(_)))
        ));
        // Payload with an indefinite map is rejected.
        assert!(matches!(
            decode_body(&[0xbf, 0x01, 0x02, 0xff], MessageType::Keepalive),
            Err(ProtocolError::Cbor(StrictError::IndefiniteNotAllowed))
        ));
    }

    #[test]
    fn trailing_payload_bytes_are_rejected() {
        // Empty map plus trailing byte.
        assert!(matches!(
            decode_body(&[0xa0, 0x00], MessageType::Keepalive),
            Err(ProtocolError::Cbor(StrictError::TrailingData))
        ));
    }

    #[test]
    fn oversized_frame_payload_is_rejected() {
        let huge = vec![0xa0u8; 16381];
        let err = encode_frame(MessageType::Keepalive, &huge, &limits()).unwrap_err();
        assert_eq!(
            err,
            FrameError::PayloadTooLarge {
                length: 16385,
                max: 16384
            }
        );
    }

    #[test]
    fn empty_reason_normalizes_to_none() {
        let message = ErrorMessage::new(ErrorCode::Internal, Some(String::new())).unwrap();
        assert_eq!(message.reason, None);
    }
}
