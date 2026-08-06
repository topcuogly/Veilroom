//! Veilroom - a terminal-based ephemeral group chat that runs over Tor.
//!
//! Stages 1-8: pure types, parsers, the wire protocol layer, the Tor
//! runtime, the handshake/admission gate, the room actor, cryptographic
//! membership, encrypted messaging, the transport layer, and the Ratatui
//! interface.
//!
//! This crate contains: typed error enums, state enums, typed events,
//! resource limits, the slash-command parser, the invitation-URI parser,
//! the frame codec, the strict CBOR decoder, the control and
//! handshake/admission/epoch messages, the Argon2id password verifier with
//! HMAC-SHA-256 challenge-response, canonical signature transcripts,
//! ephemeral Ed25519/X25519 identities with real signing and verification,
//! per-member epoch-key wrapping with XChaCha20-Poly1305, the admission
//! gate, the room actor and room task (members, request queue, token, join
//! policy, epoch transitions with acknowledgement), the Tor subprocess
//! manager, the encrypted chat sessions, the transport layer (SOCKS
//! client, host listener, per-connection tasks), the interactive Ratatui
//! application with its supervisor, golden test vectors, and the
//! `.deb`/`.rpm` packaging metadata.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod admission;
pub mod app;
pub mod chat;
pub mod command;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod event;
pub mod limits;
pub mod net;
pub mod platform;
pub mod protocol;
pub mod room;
pub mod state;
pub mod tor;
pub mod ui;
pub mod uri;
pub mod validation;

pub use command::{ColorChoice, KickTarget, ParsedLine, SlashCommand, parse_line};
pub use error::{CommandError, InvalidLimits, UriError, ValidationError};
pub use event::{ConnectionId, HostCommand, MemberId, MenuChoice, RequestId, RoomEvent, UiEvent};
pub use limits::{Limits, RateLimit, TimeoutKind, Timeouts};
pub use state::{ConnectionState, RoomState};
pub use uri::{Invitation, parse_invitation};
pub use validation::{
    contains_control_char, validate_chat_text, validate_intro, validate_nickname,
};
