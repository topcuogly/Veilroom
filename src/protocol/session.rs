//! Room session identity (section 36).
//!
//! The room session id is a random 256-bit value generated at room creation
//! and stable for the lifetime of the room. It binds every message and
//! transcript to this specific room.

use crate::constants::ROOM_SESSION_ID_LEN;
use crate::crypto::{CryptoError, random_bytes};

/// The 256-bit identifier of one room session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomSessionId([u8; ROOM_SESSION_ID_LEN]);

impl RoomSessionId {
    /// Generates a fresh random session id.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random_bytes::<ROOM_SESSION_ID_LEN>()?))
    }

    /// The raw bytes of the session id.
    pub const fn as_bytes(&self) -> &[u8; ROOM_SESSION_ID_LEN] {
        &self.0
    }
}

impl From<[u8; ROOM_SESSION_ID_LEN]> for RoomSessionId {
    fn from(bytes: [u8; ROOM_SESSION_ID_LEN]) -> Self {
        Self(bytes)
    }
}
