//! The transport layer (architecture decision 14).
//!
//! Stage 8 wires the typed protocol to real sockets: a SOCKS5 client for
//! participants, the host-side Unix-socket listener that the ephemeral
//! onion service forwards to, and per-connection reader/writer tasks with a
//! bounded outbound queue (section 29). The room actor never touches the
//! network; every connection is a [`conn::PeerConnection`] that translates
//! typed [`Message`]s to and from frames.
//!
//! The transport is socket-agnostic: the host listener and the participant
//! connection both use `UnixStream`, so the full protocol can be exercised
//! in memory without Tor; real Tor only changes how the streams are
//! obtained (`socks::connect_via_socks`).

pub mod client;
pub mod conn;
pub mod host;
pub mod socks;

pub use client::ClientNetwork;
pub use conn::PeerConnection;
pub use host::HostNetwork;
pub use socks::connect_via_socks;

/// The capacity of the bounded per-connection outbound queue.
pub const OUTBOUND_QUEUE_CAPACITY: usize = 64;
/// Capacity of inbound/control queues between transport and supervisor.
pub const INBOUND_QUEUE_CAPACITY: usize = 64;
