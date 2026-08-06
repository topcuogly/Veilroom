//! Chat-layer components (Stage 7, sections 16, 17, 18 and 29).
//!
//! `ReplayTracker` enforces the per-sender monotonic sequence rule,
//! `RateLimiter` implements the token-bucket chat policy, `OutboundQueue`
//! models the bounded per-connection outgoing queue with
//! disconnect-instead-of-drop semantics, and `ChatSession` is the
//! participant-side chat state: member table, replay tracking, sender
//! sequence, epoch key, and the send/receive operations for chat, color, and
//! room-wide message-timeout control.

pub mod outbound;
pub mod ratelimit;
pub mod replay;
pub mod session;

pub use outbound::{OutboundQueue, QueueFull};
pub use ratelimit::RateLimiter;
pub use replay::ReplayTracker;
pub use session::{ChatSession, MemberView};

/// Errors produced by the chat layer.
#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    /// No active epoch key is installed yet.
    #[error("no active epoch key")]
    NoEpochKey,

    /// The message belongs to an obsolete epoch.
    #[error("message epoch {found} is not the current epoch {current}")]
    OldEpoch {
        /// The epoch carried by the message.
        found: u64,
        /// The current epoch.
        current: u64,
    },

    /// The sender is not a known member.
    #[error("unknown sender member {sender_id}")]
    UnknownSender {
        /// The unknown member id.
        sender_id: u64,
    },

    /// The sender sequence is not newer than the last accepted one.
    #[error("replayed message from member {sender_id} with sequence {sequence}")]
    ReplayRejected {
        /// The sender member id.
        sender_id: u64,
        /// The replayed sequence number.
        sequence: u64,
    },

    /// The sender's signature did not verify.
    #[error("invalid chat signature")]
    InvalidSignature,

    /// The AEAD authentication failed.
    #[error("chat decryption failed")]
    InvalidCiphertext,

    /// The decrypted plaintext failed validation.
    #[error("invalid chat plaintext: {0}")]
    InvalidPlaintext(String),

    /// The color index is not part of the fixed palette.
    #[error("unknown color index {index}")]
    UnknownColor {
        /// The invalid index.
        index: u8,
    },
}
