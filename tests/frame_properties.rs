//! Property tests for the frame codec and message schemas
//! (instructions section 13: `decode(encode(x)) == x` and arbitrary byte
//! input must never panic or allocate without bound).

use proptest::prelude::*;

use veilroom::limits::Limits;
use veilroom::protocol::ids::{ErrorCode, MessageType};
use veilroom::protocol::{
    ErrorMessage, Frame, FrameDecoder, Keepalive, Message, Shutdown, decode_message, encode_frame,
    encode_message,
};
use veilroom::validation::contains_control_char;

fn limits() -> Limits {
    Limits::default()
}

fn any_message_type() -> impl Strategy<Value = MessageType> {
    (0u8..=255)
        .prop_map(MessageType::from_u8)
        .prop_filter("known message type", |t| t.is_some())
        .prop_map(|t| t.expect("filtered to known types"))
}

fn any_error_code() -> impl Strategy<Value = ErrorCode> {
    (1u8..=9).prop_map(|c| ErrorCode::from_u8(c).expect("codes 1..=9 are registered"))
}

fn any_reason() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::range('a', 'z'), 0..=64)
        .prop_map(|chars: Vec<char>| chars.into_iter().collect::<String>())
        .prop_filter("no control characters", |s| !contains_control_char(s))
}

fn any_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        1 => Just(Message::Keepalive(Keepalive)),
        1 => Just(Message::Shutdown(Shutdown)),
        2 => (any_error_code(), proptest::option::of(any_reason()))
            .prop_map(|(code, reason)| {
                Message::Error(
                    ErrorMessage::new(code, reason).expect("generated reasons are valid"),
                )
            }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn message_roundtrip(message in any_message()) {
        let bytes = encode_message(&message, &limits()).unwrap();
        let mut decoder = FrameDecoder::new(limits());
        let frames = decoder.feed(&bytes).unwrap();
        prop_assert_eq!(frames.len(), 1);
        let decoded = decode_message(&frames[0], &limits()).unwrap();
        prop_assert_eq!(decoded, message);
    }

    #[test]
    fn frame_roundtrip(
        message_type in any_message_type(),
        payload in proptest::collection::vec(any::<u8>(), 0..=8192),
    ) {
        let bytes = encode_frame(message_type, &payload, &limits()).unwrap();
        let mut decoder = FrameDecoder::new(limits());
        let frames = decoder.feed(&bytes).unwrap();
        prop_assert_eq!(frames.len(), 1);
        prop_assert_eq!(frames[0].message_type(), message_type);
        prop_assert_eq!(frames[0].payload(), &payload[..]);
    }

    #[test]
    fn frame_boundary_encoding_is_stable(
        message_type in any_message_type(),
        payload in proptest::collection::vec(any::<u8>(), 0..=16380),
    ) {
        let bytes = encode_frame(message_type, &payload, &limits()).unwrap();
        let mut decoder = FrameDecoder::new(limits());
        let frames = decoder.feed(&bytes).unwrap();
        prop_assert_eq!(frames.len(), 1);
        let reencoded = frames[0].encode(&limits()).unwrap();
        prop_assert_eq!(reencoded, bytes);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=65536)) {
        let mut decoder = FrameDecoder::new(limits());
        let _ = decoder.feed(&bytes);
    }

    #[test]
    fn split_feeds_reassemble_identically(
        bytes in proptest::collection::vec(any::<u8>(), 0..=16384),
        split in 0usize..=16384,
    ) {
        let split = split.min(bytes.len());
        let mut decoder = FrameDecoder::new(limits());
        let first = decoder.feed(&bytes[..split]);
        let second = decoder.feed(&bytes[split..]);
        let mut single = FrameDecoder::new(limits());
        let whole = single.feed(&bytes);
        if let (Ok(a), Ok(b), Ok(c)) = (first, second, whole) {
            let mut combined = a;
            combined.extend(b);
            prop_assert_eq!(combined, c);
        }
    }

    #[test]
    fn arbitrary_message_payloads_never_panic(
        message_type in any_message_type(),
        payload in proptest::collection::vec(any::<u8>(), 0..=16384),
    ) {
        let frame = Frame::new(message_type, payload);
        let _ = decode_message(&frame, &limits());
    }

    #[test]
    fn extracted_frames_reencode_consistently(
        bytes in proptest::collection::vec(any::<u8>(), 0..=65536),
    ) {
        let mut decoder = FrameDecoder::new(limits());
        if let Ok(frames) = decoder.feed(&bytes) {
            for frame in &frames {
                let reencoded = frame.encode(&limits()).unwrap();
                let mut again = FrameDecoder::new(limits());
                let reparsed = again.feed(&reencoded).unwrap();
                prop_assert_eq!(reparsed.len(), 1);
                prop_assert_eq!(&reparsed[0], frame);
            }
        }
    }
}
