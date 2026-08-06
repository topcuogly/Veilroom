//! Wire protocol layer: message IDs, frames, strict CBOR decoding, the
//! Stage 2 control messages, and the Stage 4 handshake and admission
//! messages.
//!
//! Raw bytes and generic CBOR values never leave this module; room logic
//! receives typed, validated messages (section 34.4).

pub mod chat;
pub mod epoch;
pub mod frame;
pub mod handshake;
pub mod ids;
pub mod membership;
pub mod messages;
pub mod session;
pub mod strict;

pub use chat::EncryptedEnvelope;
pub use epoch::{EpochAck, EpochWrap};
pub use frame::{
    FRAME_HEADER_LEN, Frame, FrameDecoder, FrameError, MIN_FRAME_BODY_LEN, encode_frame,
};
pub use handshake::{
    ChallengeProof, ClientHello, HostHello, JoinAccepted, JoinRejected, JoinRequest,
    PasswordChallenge, TokenVerify,
};
pub use ids::{ErrorCode, MessageClass, MessageType};
pub use membership::{
    JoinPolicyChanged, MemberJoined, MemberKicked, MemberLeft, MemberSnapshot, SnapshotMember,
};
pub use messages::{
    ErrorMessage, Keepalive, MAX_ERROR_REASON_BYTES, Message, ProtocolError, Shutdown,
    decode_message, encode_message,
};
pub use session::RoomSessionId;
pub use strict::{StrictDecoder, StrictError};
