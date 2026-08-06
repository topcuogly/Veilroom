//! In-memory stream tests for the frame codec (instructions section 13).

use veilroom::limits::Limits;
use veilroom::protocol::ids::MessageType;
use veilroom::protocol::{FRAME_HEADER_LEN, Frame, FrameDecoder, FrameError, encode_frame};

fn limits() -> Limits {
    Limits::default()
}

fn keepalive_frame() -> Vec<u8> {
    encode_frame(MessageType::Keepalive, &[0xa0], &limits()).unwrap()
}

fn frames_from(bytes: &[u8]) -> Vec<Frame> {
    let mut decoder = FrameDecoder::new(limits());
    decoder.feed(bytes).unwrap()
}

#[test]
fn roundtrip_preserves_type_and_payload() {
    let payload = vec![0xa2, 0x01, 0x02, 0x02, 0x63, b'o', b'k', b'?'];
    let bytes = encode_frame(MessageType::Error, &payload, &limits()).unwrap();
    let frames = frames_from(&bytes);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].message_type(), MessageType::Error);
    assert_eq!(frames[0].payload(), &payload[..]);
}

#[test]
fn frame_header_layout_is_exact() {
    let bytes = keepalive_frame();
    assert_eq!(bytes.len(), FRAME_HEADER_LEN + 1);
    assert_eq!(&bytes[0..4], &[0x00, 0x00, 0x00, 0x05]);
    assert_eq!(bytes[4], 0x01); // protocol version
    assert_eq!(bytes[5], 0x80); // message type
    assert_eq!(&bytes[6..8], &[0x00, 0x00]); // reserved flags
    assert_eq!(bytes[8], 0xa0);
}

#[test]
fn byte_by_byte_feeding_assembles_the_frame() {
    let bytes = keepalive_frame();
    let mut decoder = FrameDecoder::new(limits());
    let mut collected = Vec::new();
    for byte in &bytes {
        collected.extend(decoder.feed(&[*byte]).unwrap());
    }
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0], frames_from(&bytes)[0]);
}

#[test]
fn every_split_point_reassembles_identically() {
    let bytes = keepalive_frame();
    let expected = frames_from(&bytes);
    for split in 0..=bytes.len() {
        let mut decoder = FrameDecoder::new(limits());
        let first = decoder.feed(&bytes[..split]).unwrap();
        let second = decoder.feed(&bytes[split..]).unwrap();
        let mut all = first;
        all.extend(second);
        assert_eq!(all, expected, "split at byte {split}");
    }
}

#[test]
fn multiple_frames_in_one_feed_are_extracted_in_order() {
    let mut stream = Vec::new();
    stream.extend(keepalive_frame());
    stream.extend(encode_frame(MessageType::Shutdown, &[0xa0], &limits()).unwrap());
    stream.extend(encode_frame(MessageType::Error, &[0xa1, 0x01, 0x09], &limits()).unwrap());
    let frames = frames_from(&stream);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].message_type(), MessageType::Keepalive);
    assert_eq!(frames[1].message_type(), MessageType::Shutdown);
    assert_eq!(frames[2].message_type(), MessageType::Error);
}

#[test]
fn frames_straddling_feed_boundaries_are_handled() {
    let bytes = keepalive_frame();
    let mut decoder = FrameDecoder::new(limits());
    // Feed only the 4-byte length header.
    assert!(decoder.feed(&bytes[..4]).unwrap().is_empty());
    // Feed half of the rest.
    let mut frames = decoder.feed(&bytes[4..6]).unwrap();
    assert!(frames.is_empty());
    // Feed the remainder.
    frames.extend(decoder.feed(&bytes[6..]).unwrap());
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0], frames_from(&bytes)[0]);
    assert!(decoder.finish().is_ok());
}

#[test]
fn oversized_declared_length_is_rejected_before_payload() {
    // Declared length 0x0000_4001 (16385) with a plausible version byte.
    let mut bytes = vec![0x00, 0x00, 0x40, 0x01, 0x01];
    bytes.extend_from_slice(&[0xa0; 16]);
    let mut decoder = FrameDecoder::new(limits());
    assert_eq!(
        decoder.feed(&bytes).unwrap_err(),
        FrameError::FrameTooLarge {
            declared: 16385,
            max: 16384
        }
    );
}

#[test]
fn maximum_legitimate_frame_is_accepted() {
    let max_payload = limits().max_frame_size() - 4;
    let payload = vec![0xa0; max_payload];
    let bytes = encode_frame(MessageType::Keepalive, &payload, &limits()).unwrap();
    let frames = frames_from(&bytes);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].payload().len(), max_payload);
}

#[test]
fn one_byte_over_the_limit_is_rejected_at_encode() {
    let max_payload = limits().max_frame_size() - 4;
    let payload = vec![0xa0; max_payload + 1];
    assert!(encode_frame(MessageType::Keepalive, &payload, &limits()).is_err());
}

#[test]
fn declared_length_maximum_uint32_is_rejected() {
    let bytes = [0xff, 0xff, 0xff, 0xff, 0x01, 0x80, 0x00, 0x00, 0xa0];
    let mut decoder = FrameDecoder::new(limits());
    assert_eq!(
        decoder.feed(&bytes).unwrap_err(),
        FrameError::FrameTooLarge {
            declared: 0xffff_ffff,
            max: 16384
        }
    );
}

#[test]
fn body_shorter_than_header_fields_is_rejected() {
    for declared in 0..4u32 {
        // Complete 8-byte header with a body length below the 4-byte minimum.
        let bytes = [
            declared.to_be_bytes()[0],
            declared.to_be_bytes()[1],
            declared.to_be_bytes()[2],
            declared.to_be_bytes()[3],
            0x01,
            0x80,
            0x00,
            0x00,
        ];
        let mut decoder = FrameDecoder::new(limits());
        assert_eq!(
            decoder.feed(&bytes).unwrap_err(),
            FrameError::FrameTooShort { min: 4 },
            "declared {declared}"
        );
    }
}

#[test]
fn version_mismatch_is_rejected() {
    // Keepalive frame with version 2.
    let mut bytes = keepalive_frame();
    bytes[4] = 0x02;
    let mut decoder = FrameDecoder::new(limits());
    assert_eq!(
        decoder.feed(&bytes).unwrap_err(),
        FrameError::UnsupportedVersion { found: 2 }
    );
}

#[test]
fn unknown_message_type_is_rejected() {
    // Keepalive frame with type 0xE5.
    let mut bytes = keepalive_frame();
    bytes[5] = 0xe5;
    let mut decoder = FrameDecoder::new(limits());
    assert_eq!(
        decoder.feed(&bytes).unwrap_err(),
        FrameError::UnknownMessageType { id: 0xe5 }
    );
}

#[test]
fn nonzero_flags_are_rejected() {
    // Keepalive frame with flags 0x0001.
    let mut bytes = keepalive_frame();
    bytes[7] = 0x01;
    let mut decoder = FrameDecoder::new(limits());
    assert_eq!(
        decoder.feed(&bytes).unwrap_err(),
        FrameError::NonZeroFlags { flags: 0x0001 }
    );

    // Flags 0x8000.
    let mut bytes = keepalive_frame();
    bytes[6] = 0x80;
    let mut decoder = FrameDecoder::new(limits());
    assert_eq!(
        decoder.feed(&bytes).unwrap_err(),
        FrameError::NonZeroFlags { flags: 0x8000 }
    );
}

#[test]
fn eof_with_incomplete_frame_is_an_error() {
    let bytes = keepalive_frame();
    let mut decoder = FrameDecoder::new(limits());
    decoder.feed(&bytes[..7]).unwrap();
    assert_eq!(decoder.finish(), Err(FrameError::UnexpectedEof));

    // Empty stream is a clean end.
    let decoder = FrameDecoder::new(limits());
    assert_eq!(decoder.finish(), Ok(()));
}

#[test]
fn header_only_without_body_is_eof_error() {
    let mut decoder = FrameDecoder::new(limits());
    decoder.feed(&[0x00, 0x00, 0x00, 0x05]).unwrap();
    assert_eq!(decoder.finish(), Err(FrameError::UnexpectedEof));
}

#[test]
fn empty_feeds_are_no_ops() {
    let mut decoder = FrameDecoder::new(limits());
    assert!(decoder.feed(&[]).unwrap().is_empty());
    assert!(decoder.feed(&[]).unwrap().is_empty());
    assert_eq!(decoder.finish(), Ok(()));
}

#[test]
fn frame_constructed_directly_encodes() {
    let frame = Frame::new(MessageType::Keepalive, vec![0xa0]);
    let bytes = frame.encode(&limits()).unwrap();
    assert_eq!(frames_from(&bytes)[0], frame);
}
