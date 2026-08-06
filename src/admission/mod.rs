//! Admission gate (Stage 4, architecture decisions 4A, 5 and 7).
//!
//! Implements the pure logic of the join flow: the join policy
//! (`/reqon`, `/reqoff`), the bounded join-request queue with monotonic
//! request ids (`/requests`, `/accept`, `/reject`), and the per-connection
//! host- and client-side admission state machines.
//!
//! The flows exchange typed [`Message`] values; the wire transport is wired
//! in later stages. Signature verification over the transcripts is Stage 6;
//! everything that is not cryptographic is enforced here.

pub mod client;
pub mod guard;
pub mod host;
pub mod queue;

pub use client::{ClientAdmission, HostHelloInfo};
pub use guard::PasswordGuard;
pub use host::{HostAdmission, HostAdmissionReply, HostState};
pub use queue::{JoinApplication, JoinRequest, JoinRequestQueue, QueueError};

use crate::protocol::ids::ErrorCode;
use crate::protocol::messages::ProtocolError;

/// The join policy of a room (architecture decision 4A, section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinPolicy {
    /// New join flows are allowed.
    Open,
    /// New join flows are disabled; pending requests are rejected.
    Locked,
}

impl JoinPolicy {
    /// Whether new join flows are allowed.
    pub const fn allows_join_requests(self) -> bool {
        matches!(self, Self::Open)
    }
}

/// Errors produced by the admission logic.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// The room is not accepting join requests.
    #[error("the room is not accepting join requests")]
    RoomLocked,

    /// The pending-request queue is full.
    #[error("the join-request queue is full")]
    QueueFull,

    /// No pending request carries the given id.
    #[error("no pending join request with id {id}")]
    UnknownRequest {
        /// The unknown request id.
        id: crate::event::RequestId,
    },

    /// The presented invitation token does not match the room token.
    #[error("invalid invitation token")]
    InvalidToken,

    /// The password proof did not verify.
    #[error("invalid password proof")]
    InvalidPasswordProof,

    /// The host-hello signature did not verify against the transcript.
    #[error("invalid host-hello signature")]
    InvalidHostSignature,

    /// The join-request signature did not verify against the transcript.
    #[error("invalid join-request signature")]
    InvalidJoinSignature,

    /// A message arrived that is invalid for the current admission state.
    #[error("unexpected message for the current admission state")]
    UnexpectedMessage,

    /// The peer offered an unsupported protocol version.
    #[error("unsupported protocol version {found}")]
    UnsupportedVersion {
        /// The offered version.
        found: u8,
    },

    /// The peer offered unsupported feature bits.
    #[error("unsupported feature bits 0x{features:08x}")]
    UnsupportedFeatures {
        /// The offered feature bits.
        features: u32,
    },

    /// The host rejected the application.
    #[error("join request rejected: {reason:?}")]
    Rejected {
        /// The optional rejection reason.
        reason: Option<String>,
    },

    /// The host sent an error message.
    #[error("host error {code:?}: {reason:?}")]
    HostError {
        /// The error code from the host.
        code: ErrorCode,
        /// The optional reason from the host.
        reason: Option<String>,
    },

    /// A protocol-level failure.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// A cryptographic failure.
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

impl AdmissionError {
    /// The stable error code a host should report for this failure.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::RoomLocked => ErrorCode::RoomLocked,
            Self::InvalidToken => ErrorCode::InvalidInvitation,
            Self::InvalidPasswordProof => ErrorCode::InvalidPasswordProof,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
            Self::QueueFull
            | Self::UnexpectedMessage
            | Self::UnknownRequest { .. }
            | Self::UnsupportedFeatures { .. }
            | Self::Rejected { .. }
            | Self::HostError { .. }
            | Self::Protocol(_)
            | Self::Crypto(_)
            | Self::InvalidHostSignature
            | Self::InvalidJoinSignature => ErrorCode::ProtocolViolation,
        }
    }
}
