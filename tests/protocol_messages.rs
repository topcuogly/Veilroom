//! Public-API tests for message schemas and the connection state machine.

use veilroom::limits::Limits;
use veilroom::protocol::ids::{ErrorCode, MessageClass, MessageType};
use veilroom::protocol::{
    EncryptedEnvelope, ErrorMessage, JoinPolicyChanged, Keepalive, Message, ProtocolError,
    Shutdown, StrictError, decode_message, encode_message,
};
use veilroom::state::{ConnectionState, RoomState};

fn limits() -> Limits {
    Limits::default()
}

fn decode_body(body: &[u8], msg_type: MessageType) -> Result<Message, ProtocolError> {
    let frame = veilroom::protocol::Frame::new(msg_type, body.to_vec());
    decode_message(&frame, &limits())
}

#[test]
fn all_control_messages_roundtrip_through_the_public_api() {
    let messages = [
        Message::Keepalive(Keepalive),
        Message::Shutdown(Shutdown),
        Message::Error(ErrorMessage::new(ErrorCode::ConnectionTimeout, None).unwrap()),
        Message::Error(
            ErrorMessage::new(
                ErrorCode::RoomLocked,
                Some("join requests are disabled".to_owned()),
            )
            .unwrap(),
        ),
    ];
    for message in messages {
        let bytes = encode_message(&message, &limits()).unwrap();
        let mut decoder = veilroom::protocol::FrameDecoder::new(limits());
        let frames = decoder.feed(&bytes).unwrap();
        assert_eq!(frames.len(), 1);
        let decoded = decode_message(&frames[0], &limits()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.message_type(), message.message_type());
    }
}

#[test]
fn timeout_envelopes_roundtrip_through_the_public_api() {
    let envelope =
        EncryptedEnvelope::new(9, 4, 12, [0x22; 24], vec![0x33; 24], [0x44; 64]).unwrap();
    for message in [
        Message::TimeoutRequest(envelope.clone()),
        Message::TimeoutChanged(envelope.clone()),
    ] {
        let bytes = encode_message(&message, &limits()).unwrap();
        let decoded = decode_message(&frames(&bytes)[0], &limits()).unwrap();
        assert_eq!(decoded, message);
    }
}

#[test]
fn keepalive_and_shutdown_payloads_are_exactly_an_empty_map() {
    for (message, type_byte) in [
        (Message::Keepalive(Keepalive), 0x80u8),
        (Message::Shutdown(Shutdown), 0x82),
    ] {
        let bytes = encode_message(&message, &limits()).unwrap();
        assert_eq!(
            bytes,
            [0x00, 0x00, 0x00, 0x05, 0x01, type_byte, 0x00, 0x00, 0xa0]
        );
    }
}

#[test]
fn error_message_without_reason_is_an_identity_map() {
    let message = Message::Error(ErrorMessage::new(ErrorCode::UnsupportedVersion, None).unwrap());
    let bytes = encode_message(&message, &limits()).unwrap();
    assert_eq!(
        bytes,
        [
            0x00, 0x00, 0x00, 0x07, 0x01, 0x81, 0x00, 0x00, 0xa1, 0x01, 0x02
        ]
    );
    assert_eq!(
        decode_message(&frames(&bytes)[0], &limits()).unwrap(),
        message
    );
}

fn frames(bytes: &[u8]) -> Vec<veilroom::protocol::Frame> {
    let mut decoder = veilroom::protocol::FrameDecoder::new(limits());
    decoder.feed(bytes).unwrap()
}

#[test]
fn strict_decoder_rejects_every_malformed_class() {
    let cases: Vec<(Vec<u8>, MessageType)> = vec![
        // Truncated CBOR.
        (vec![0xa1, 0x01], MessageType::Error),
        // Indefinite map.
        (vec![0xbf, 0x01, 0x02, 0xff], MessageType::Keepalive),
        // Duplicate key.
        (vec![0xa2, 0x01, 0x02, 0x01, 0x03], MessageType::Error),
        // Unknown field.
        (vec![0xa1, 0x63, 0x01], MessageType::Error),
        // Trailing data.
        (vec![0xa0, 0x00], MessageType::Keepalive),
        // Not a map at all.
        (vec![0x81, 0x01], MessageType::Shutdown),
        // Unknown error code.
        (vec![0xa1, 0x01, 0x63], MessageType::Error),
        // Control character in the reason.
        (vec![0xa2, 0x01, 0x09, 0x02, 0x61, 0x1b], MessageType::Error),
        // Oversized reason (257 bytes).
        (
            vec![0xa2, 0x01, 0x09, 0x02, 0x79, 0x01, 0x01],
            MessageType::Error,
        ),
    ];
    for (body, msg_type) in cases {
        let result = decode_body(&body, msg_type);
        assert!(
            result.is_err(),
            "payload {body:02x?} as {msg_type:?} was accepted"
        );
    }
}

#[test]
fn unknown_message_ids_are_rejected_at_the_frame_layer() {
    let mut decoder = veilroom::protocol::FrameDecoder::new(limits());
    let bytes = [0x00, 0x00, 0x00, 0x05, 0x01, 0x63, 0x00, 0x00, 0xa0];
    assert!(decoder.feed(&bytes).is_err());
}

#[test]
fn every_registered_message_type_decodes() {
    // All V1 message types are implemented by Stage 7; every registered id
    // must decode (an empty map decodes to a missing-field or unknown-field
    // error, never to UnsupportedMessage).
    for id in [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x20, 0x21, 0x22, 0x23, 0x24, 0x40, 0x41,
        0x42, 0x43, 0x60, 0x61, 0x80, 0x81, 0x82,
    ] {
        let msg_type = MessageType::from_u8(id).unwrap();
        let result = decode_body(&[0xa0], msg_type);
        assert!(
            !matches!(result, Err(ProtocolError::UnsupportedMessage { .. })),
            "id 0x{id:02x} must be decodable"
        );
    }
}

#[test]
fn join_policy_change_roundtrips() {
    let message = Message::JoinPolicyChanged(JoinPolicyChanged {
        sequence: 17,
        epoch: 4,
        open: false,
        signature: [0x5a; 64],
    });
    let bytes = encode_message(&message, &limits()).unwrap();
    let decoded = decode_message(&frames(&bytes)[0], &limits()).unwrap();
    assert_eq!(decoded, message);
    assert_eq!(decoded.message_type(), MessageType::JoinPolicyChanged);
}

#[test]
fn message_type_registry_covers_all_ranges() {
    let known: Vec<u8> = (0x00..=0xff)
        .filter(|b| MessageType::from_u8(*b).is_some())
        .collect();
    assert_eq!(
        known,
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x20, 0x21, 0x22, 0x23, 0x24, 0x40,
            0x41, 0x42, 0x43, 0x60, 0x61, 0x80, 0x81, 0x82
        ]
    );
}

#[test]
fn error_code_registry_is_stable() {
    assert_eq!(ErrorCode::ProtocolViolation.as_u8(), 1);
    assert_eq!(ErrorCode::UnsupportedVersion.as_u8(), 2);
    assert_eq!(ErrorCode::InvalidInvitation.as_u8(), 3);
    assert_eq!(ErrorCode::RoomLocked.as_u8(), 4);
    assert_eq!(ErrorCode::InvalidPasswordProof.as_u8(), 5);
    assert_eq!(ErrorCode::ConnectionTimeout.as_u8(), 6);
    assert_eq!(ErrorCode::RoomClosed.as_u8(), 7);
    assert_eq!(ErrorCode::RateLimited.as_u8(), 8);
    assert_eq!(ErrorCode::Internal.as_u8(), 9);
    for code in 1..=9 {
        assert_eq!(ErrorCode::from_u8(code).unwrap().as_u8(), code);
    }
}

#[test]
fn error_message_with_reason_encodes_ascending_keys() {
    let message = Message::Error(
        ErrorMessage::new(ErrorCode::RateLimited, Some("slow down".to_owned())).unwrap(),
    );
    let body = &frames(&encode_message(&message, &limits()).unwrap())[0]
        .payload()
        .to_vec();
    assert_eq!(
        body,
        &[
            0xa2, 0x01, 0x08, 0x02, 0x69, b's', b'l', b'o', b'w', b' ', b'd', b'o', b'w', b'n'
        ]
    );
}

#[test]
fn keepalive_and_shutdown_decode_equally() {
    assert_eq!(
        decode_body(&[0xa0], MessageType::Keepalive).unwrap(),
        Message::Keepalive(Keepalive)
    );
    assert_eq!(
        decode_body(&[0xa0], MessageType::Shutdown).unwrap(),
        Message::Shutdown(Shutdown)
    );
}

#[test]
fn malformed_cbor_is_reported_as_strict_error() {
    assert!(matches!(
        decode_body(&[0x1b], MessageType::Keepalive),
        Err(ProtocolError::Cbor(StrictError::Cbor(_)))
    ));
}

#[test]
fn state_table_rejects_chat_before_active() {
    let states_before_active = [
        ConnectionState::Disconnected,
        ConnectionState::TorConnecting,
        ConnectionState::ProtocolHandshake,
        ConnectionState::PreAuth,
        ConnectionState::PasswordVerified,
        ConnectionState::JoinPending,
        ConnectionState::Closing,
    ];
    for state in states_before_active {
        assert!(!state.accepts(MessageClass::Chat), "{state:?}");
    }
    assert!(ConnectionState::Active.accepts(MessageClass::Chat));
}

#[test]
fn state_table_rejects_epoch_and_membership_before_active() {
    for state in [
        ConnectionState::PreAuth,
        ConnectionState::PasswordVerified,
        ConnectionState::JoinPending,
        ConnectionState::Closing,
    ] {
        assert!(!state.accepts(MessageClass::Epoch), "{state:?}");
        assert!(!state.accepts(MessageClass::Membership), "{state:?}");
    }
    assert!(ConnectionState::Active.accepts(MessageClass::Epoch));
    assert!(ConnectionState::Active.accepts(MessageClass::Membership));
}

#[test]
fn control_messages_are_valid_wherever_the_protocol_has_started() {
    for state in [
        ConnectionState::ProtocolHandshake,
        ConnectionState::PreAuth,
        ConnectionState::PasswordVerified,
        ConnectionState::JoinPending,
        ConnectionState::Active,
        ConnectionState::Closing,
    ] {
        assert!(state.accepts(MessageClass::Control), "{state:?}");
    }
    assert!(!ConnectionState::Disconnected.accepts(MessageClass::Control));
    assert!(!ConnectionState::TorConnecting.accepts(MessageClass::Control));
}

#[test]
fn room_states_keep_join_policy_semantics() {
    assert!(RoomState::Open.accepts_join_requests());
    assert!(!RoomState::Locked.accepts_join_requests());
    assert!(!RoomState::EpochTransition.accepts_join_requests());
    assert!(!RoomState::Closing.accepts_join_requests());
}
