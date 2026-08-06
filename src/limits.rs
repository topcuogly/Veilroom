//! Resource limits, per-state timeouts, and rate-limit policy (sections 28 and 29).
//!
//! All default values in this module must match `docs/protocol-v1.md` and the
//! architecture specification. Limits are pure data in Stage 1; enforcement
//! arrives with the network stages.

use std::time::Duration;

use crate::error::InvalidLimits;

/// The kind of a per-state timeout (section 28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeoutKind {
    /// Completing the protocol handshake.
    ProtocolHandshake,
    /// Verifying the invitation token.
    TokenValidation,
    /// Completing the password challenge-response.
    PasswordVerification,
    /// Submitting the nickname and introduction form.
    JoinFormSubmission,
    /// Waiting for the host's accept or reject decision.
    HostDecision,
    /// Acknowledging a new epoch key.
    EpochAcknowledgement,
    /// Keepalive interval between liveness frames.
    Keepalive,
    /// Graceful shutdown of connections and Tor.
    GracefulShutdown,
}

/// Single structure holding every resource limit of the room (section 28).
///
/// All limits belong to one structure; values are validated for internal
/// consistency with [`Limits::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    max_active_members: usize,
    max_pending_requests: usize,
    max_pre_auth_connections: usize,
    max_frame_size: usize,
    max_chat_text_bytes: usize,
    max_nickname_scalars: usize,
    max_intro_scalars: usize,
    max_cbor_nesting_depth: usize,
    max_cbor_map_entries: usize,
    max_cbor_array_entries: usize,
    max_cbor_text_bytes: usize,
    max_cbor_bytes_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_active_members: 16,
            max_pending_requests: 8,
            max_pre_auth_connections: 16,
            max_frame_size: 16 * 1024,
            max_chat_text_bytes: 4096,
            max_nickname_scalars: 32,
            max_intro_scalars: 160,
            max_cbor_nesting_depth: 8,
            max_cbor_map_entries: 64,
            max_cbor_array_entries: 256,
            max_cbor_text_bytes: 4096,
            max_cbor_bytes_len: 4096,
        }
    }
}

impl Limits {
    /// Maximum number of simultaneously active members.
    pub const fn max_active_members(&self) -> usize {
        self.max_active_members
    }

    /// Maximum combined number of pending join and timeout requests.
    pub const fn max_pending_requests(&self) -> usize {
        self.max_pending_requests
    }

    /// Maximum number of connections that have not yet been admitted.
    pub const fn max_pre_auth_connections(&self) -> usize {
        self.max_pre_auth_connections
    }

    /// Maximum frame body size in bytes.
    pub const fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Maximum chat message size in UTF-8 bytes.
    pub const fn max_chat_text_bytes(&self) -> usize {
        self.max_chat_text_bytes
    }

    /// Maximum nickname length in Unicode scalar values.
    pub const fn max_nickname_scalars(&self) -> usize {
        self.max_nickname_scalars
    }

    /// Maximum introduction message length in Unicode scalar values.
    pub const fn max_intro_scalars(&self) -> usize {
        self.max_intro_scalars
    }

    /// Maximum CBOR nesting depth of a message payload.
    pub const fn max_cbor_nesting_depth(&self) -> usize {
        self.max_cbor_nesting_depth
    }

    /// Maximum number of entries in a CBOR map.
    pub const fn max_cbor_map_entries(&self) -> usize {
        self.max_cbor_map_entries
    }

    /// Maximum number of elements in a CBOR array.
    pub const fn max_cbor_array_entries(&self) -> usize {
        self.max_cbor_array_entries
    }

    /// Maximum length of a CBOR text string in bytes.
    pub const fn max_cbor_text_bytes(&self) -> usize {
        self.max_cbor_text_bytes
    }

    /// Maximum length of a CBOR byte string in bytes.
    pub const fn max_cbor_bytes_len(&self) -> usize {
        self.max_cbor_bytes_len
    }

    /// Checks the limits for internal consistency.
    ///
    /// No limit may be zero, and the frame limit must be able to carry a
    /// maximum-size chat message.
    pub fn validate(&self) -> Result<(), InvalidLimits> {
        if self.max_active_members == 0 {
            return Err(InvalidLimits(
                "max_active_members must be greater than zero".to_owned(),
            ));
        }
        if self.max_pending_requests == 0 {
            return Err(InvalidLimits(
                "max_pending_requests must be greater than zero".to_owned(),
            ));
        }
        if self.max_pre_auth_connections == 0 {
            return Err(InvalidLimits(
                "max_pre_auth_connections must be greater than zero".to_owned(),
            ));
        }
        if self.max_frame_size == 0 {
            return Err(InvalidLimits(
                "max_frame_size must be greater than zero".to_owned(),
            ));
        }
        if self.max_chat_text_bytes == 0 {
            return Err(InvalidLimits(
                "max_chat_text_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_nickname_scalars == 0 {
            return Err(InvalidLimits(
                "max_nickname_scalars must be greater than zero".to_owned(),
            ));
        }
        if self.max_intro_scalars == 0 {
            return Err(InvalidLimits(
                "max_intro_scalars must be greater than zero".to_owned(),
            ));
        }
        if self.max_frame_size < self.max_chat_text_bytes {
            return Err(InvalidLimits(
                "max_frame_size must be at least max_chat_text_bytes".to_owned(),
            ));
        }
        if self.max_cbor_nesting_depth == 0 {
            return Err(InvalidLimits(
                "max_cbor_nesting_depth must be greater than zero".to_owned(),
            ));
        }
        if self.max_cbor_map_entries == 0 {
            return Err(InvalidLimits(
                "max_cbor_map_entries must be greater than zero".to_owned(),
            ));
        }
        if self.max_cbor_array_entries == 0 {
            return Err(InvalidLimits(
                "max_cbor_array_entries must be greater than zero".to_owned(),
            ));
        }
        if self.max_cbor_text_bytes == 0 {
            return Err(InvalidLimits(
                "max_cbor_text_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_cbor_bytes_len == 0 {
            return Err(InvalidLimits(
                "max_cbor_bytes_len must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Per-state timeout configuration (section 28).
///
/// Initial values are tuned through testing; Tor latency must be considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeouts {
    /// Time allowed to complete the protocol handshake.
    pub protocol_handshake: Duration,
    /// Time allowed for invitation-token verification.
    pub token_validation: Duration,
    /// Time allowed for the password challenge-response.
    pub password_verification: Duration,
    /// Time allowed to submit the join form (nickname and introduction).
    pub join_form_submission: Duration,
    /// Time a pending request may wait for the host decision.
    pub host_decision: Duration,
    /// Time allowed for a member to acknowledge a new epoch.
    pub epoch_acknowledgement: Duration,
    /// Interval between keepalive frames.
    pub keepalive_interval: Duration,
    /// Time allowed for graceful shutdown.
    pub graceful_shutdown: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            protocol_handshake: Duration::from_secs(30),
            token_validation: Duration::from_secs(30),
            password_verification: Duration::from_secs(60),
            join_form_submission: Duration::from_secs(120),
            host_decision: Duration::from_secs(300),
            epoch_acknowledgement: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(30),
            graceful_shutdown: Duration::from_secs(10),
        }
    }
}

impl Timeouts {
    /// Returns the duration configured for a timeout kind.
    pub fn get(&self, kind: TimeoutKind) -> Duration {
        match kind {
            TimeoutKind::ProtocolHandshake => self.protocol_handshake,
            TimeoutKind::TokenValidation => self.token_validation,
            TimeoutKind::PasswordVerification => self.password_verification,
            TimeoutKind::JoinFormSubmission => self.join_form_submission,
            TimeoutKind::HostDecision => self.host_decision,
            TimeoutKind::EpochAcknowledgement => self.epoch_acknowledgement,
            TimeoutKind::Keepalive => self.keepalive_interval,
            TimeoutKind::GracefulShutdown => self.graceful_shutdown,
        }
    }
}

/// Token-bucket-style chat rate-limit policy for active members (section 29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Maximum burst size in messages.
    pub burst: u32,
    /// Sustained rate in messages per second.
    pub sustained_per_second: u32,
}

impl Limits {
    /// The default limits with a different member capacity.
    ///
    /// Provided for tests and embedded configurations that need a tighter
    /// member bound.
    pub fn with_max_active_members(max: usize) -> Self {
        Self {
            max_active_members: max,
            ..Self::default()
        }
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            burst: 5,
            sustained_per_second: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_specification() {
        let limits = Limits::default();
        assert_eq!(limits.max_active_members(), 16);
        assert_eq!(limits.max_pending_requests(), 8);
        assert_eq!(limits.max_pre_auth_connections(), 16);
        assert_eq!(limits.max_frame_size(), 16 * 1024);
        assert_eq!(limits.max_chat_text_bytes(), 4096);
        assert_eq!(limits.max_nickname_scalars(), 32);
        assert_eq!(limits.max_intro_scalars(), 160);
        assert_eq!(limits.max_cbor_nesting_depth(), 8);
        assert_eq!(limits.max_cbor_map_entries(), 64);
        assert_eq!(limits.max_cbor_array_entries(), 256);
        assert_eq!(limits.max_cbor_text_bytes(), 4096);
        assert_eq!(limits.max_cbor_bytes_len(), 4096);
    }

    #[test]
    fn default_limits_validate() {
        assert_eq!(Limits::default().validate(), Ok(()));
    }

    #[test]
    fn zero_limits_are_rejected() {
        let invalid = Limits {
            max_active_members: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_pending_requests: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_pre_auth_connections: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_frame_size: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_chat_text_bytes: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_nickname_scalars: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_intro_scalars: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn frame_limit_must_carry_a_chat_message() {
        let invalid = Limits {
            max_frame_size: 100,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn zero_cbor_limits_are_rejected() {
        let invalid = Limits {
            max_cbor_nesting_depth: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_cbor_map_entries: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_cbor_array_entries: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_cbor_text_bytes: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = Limits {
            max_cbor_bytes_len: 0,
            ..Limits::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn default_timeouts_are_positive() {
        let timeouts = Timeouts::default();
        assert!(timeouts.protocol_handshake > Duration::ZERO);
        assert!(timeouts.token_validation > Duration::ZERO);
        assert!(timeouts.password_verification > Duration::ZERO);
        assert!(timeouts.join_form_submission > Duration::ZERO);
        assert!(timeouts.host_decision > Duration::ZERO);
        assert!(timeouts.epoch_acknowledgement > Duration::ZERO);
        assert!(timeouts.keepalive_interval > Duration::ZERO);
        assert!(timeouts.graceful_shutdown > Duration::ZERO);
    }

    #[test]
    fn timeout_lookup_returns_configured_value() {
        let timeouts = Timeouts::default();
        assert_eq!(
            timeouts.get(TimeoutKind::Keepalive),
            timeouts.keepalive_interval
        );
        assert_eq!(
            timeouts.get(TimeoutKind::GracefulShutdown),
            timeouts.graceful_shutdown
        );
        assert_eq!(
            timeouts.get(TimeoutKind::PasswordVerification),
            timeouts.password_verification
        );
    }

    #[test]
    fn default_rate_limit_matches_specification() {
        let rate_limit = RateLimit::default();
        assert_eq!(rate_limit.burst, 5);
        assert_eq!(rate_limit.sustained_per_second, 1);
    }
}
