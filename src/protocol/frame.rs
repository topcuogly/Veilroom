//! Length-prefixed binary frame codec (architecture decision 6, section 11).
//!
//! Wire format (all integers big-endian):
//!
//! ```text
//! uint32 frame_length   // length of the body, in bytes
//! uint8  protocol_version
//! uint8  message_type
//! uint16 flags          // reserved in V1, must be zero
//! bytes  payload        // strict CBOR, validated by the message layer
//! ```
//!
//! `frame_length` covers the version, type, flags, and payload (minimum 4
//! bytes). A declared length above `Limits::max_frame_size` terminates the
//! connection before the payload is read. The decoder never panics, never
//! allocates without bound, and buffers at most one incomplete frame.

use crate::constants::PROTOCOL_MAJOR_VERSION;
use crate::limits::Limits;
use crate::protocol::ids::MessageType;

/// Size of the frame header (length + version + type + flags).
pub const FRAME_HEADER_LEN: usize = 8;

/// Size of the body-length prefix.
pub const LENGTH_FIELD_LEN: usize = 4;

/// Minimum body size: version, type, and flags.
pub const MIN_FRAME_BODY_LEN: usize = 4;

/// Errors produced by the frame codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// The declared body length exceeds the global frame limit.
    #[error("declared frame length {declared} exceeds the maximum of {max} bytes")]
    FrameTooLarge {
        /// The declared body length in bytes.
        declared: u64,
        /// The configured maximum body length in bytes.
        max: usize,
    },

    /// The payload does not fit into the frame limit.
    #[error("frame payload of {length} bytes exceeds the maximum of {max} bytes")]
    PayloadTooLarge {
        /// The payload length including the header fields.
        length: usize,
        /// The configured maximum body length in bytes.
        max: usize,
    },

    /// The body is shorter than version + type + flags.
    #[error("frame body is shorter than the minimum of {min} bytes")]
    FrameTooShort {
        /// The minimum body length in bytes.
        min: usize,
    },

    /// The stream ended while a frame header or body was incomplete.
    #[error("unexpected end of stream while reading a frame")]
    UnexpectedEof,

    /// The frame header carries a protocol version this build does not speak.
    #[error("unsupported protocol version {found}")]
    UnsupportedVersion {
        /// The protocol version found in the frame header.
        found: u8,
    },

    /// The frame header carries an unregistered message type.
    #[error("unknown message type 0x{id:02x}")]
    UnknownMessageType {
        /// The message-type byte found in the frame header.
        id: u8,
    },

    /// V1 reserves the flags field and requires it to be zero.
    #[error("frame flags must be zero, got 0x{flags:04x}")]
    NonZeroFlags {
        /// The flags value found in the frame header.
        flags: u16,
    },
}

/// A validated frame: a message type and its raw CBOR payload.
///
/// The payload is decoded into a typed message by the message layer
/// (`crate::protocol::messages`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    message_type: MessageType,
    payload: Vec<u8>,
}

impl Frame {
    /// Constructs a frame from a message type and payload bytes.
    ///
    /// No size validation happens here; [`Frame::encode`] validates the
    /// payload against the frame limit. This constructor exists for the
    /// message layer and for tests.
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            message_type,
            payload,
        }
    }

    /// The message type of this frame.
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// The raw CBOR payload of this frame.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes this frame into wire bytes.
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, FrameError> {
        encode_frame(self.message_type, &self.payload, limits)
    }
}

/// Encodes a message type and payload into a complete frame.
pub fn encode_frame(
    message_type: MessageType,
    payload: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>, FrameError> {
    let body_len = payload.len() + MIN_FRAME_BODY_LEN;
    if body_len > limits.max_frame_size() {
        return Err(FrameError::PayloadTooLarge {
            length: body_len,
            max: limits.max_frame_size(),
        });
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out.push(PROTOCOL_MAJOR_VERSION);
    out.push(message_type.as_u8());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Incremental, bounded frame decoder for a single byte stream.
///
/// Feed arbitrary chunks with [`FrameDecoder::feed`]; complete frames are
/// returned as they become available. Any error is terminal: the connection
/// must be closed, and the decoder must not be reused.
///
/// The internal buffer never grows beyond one incomplete frame (header and
/// body) plus the largest chunk passed to [`FrameDecoder::feed`]; declared
/// lengths are validated before the payload is buffered.
pub struct FrameDecoder {
    buf: Vec<u8>,
    max_frame_size: usize,
}

impl FrameDecoder {
    /// Creates a decoder bound to the frame limit of `limits`.
    pub fn new(limits: Limits) -> Self {
        Self {
            buf: Vec::with_capacity(FRAME_HEADER_LEN),
            max_frame_size: limits.max_frame_size(),
        }
    }

    /// Feeds bytes and returns every complete frame contained in them.
    ///
    /// Returns an error for a frame that violates the protocol; the error is
    /// terminal and the decoder must not be used afterwards.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Frame>, FrameError> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        loop {
            if self.buf.len() < FRAME_HEADER_LEN {
                break;
            }
            let declared =
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as u64;
            if declared > self.max_frame_size as u64 {
                return Err(FrameError::FrameTooLarge {
                    declared,
                    max: self.max_frame_size,
                });
            }
            if declared < MIN_FRAME_BODY_LEN as u64 {
                return Err(FrameError::FrameTooShort {
                    min: MIN_FRAME_BODY_LEN,
                });
            }
            // `declared` excludes the length prefix, so the frame occupies
            // LENGTH_FIELD_LEN + declared bytes in the stream; the body
            // (version, type, flags, payload) starts right after the prefix.
            let total = LENGTH_FIELD_LEN as u64 + declared;
            if self.buf.len() < total as usize {
                break;
            }
            let body = &self.buf[LENGTH_FIELD_LEN..total as usize];
            let version = body[0];
            if version != PROTOCOL_MAJOR_VERSION {
                return Err(FrameError::UnsupportedVersion { found: version });
            }
            let message_type = MessageType::from_u8(body[1])
                .ok_or(FrameError::UnknownMessageType { id: body[1] })?;
            let flags = u16::from_be_bytes([body[2], body[3]]);
            if flags != 0 {
                return Err(FrameError::NonZeroFlags { flags });
            }
            frames.push(Frame {
                message_type,
                payload: body[4..].to_vec(),
            });
            self.buf.drain(..total as usize);
        }
        Ok(frames)
    }

    /// Signals end of stream.
    ///
    /// Returns an error if the stream ended with an incomplete frame.
    pub fn finish(&self) -> Result<(), FrameError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(FrameError::UnexpectedEof)
        }
    }
}
