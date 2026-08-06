//! Single source of truth for protocol constants (architecture decision 17, section 40).

/// Protocol major version supported by the first prototype.
pub const PROTOCOL_MAJOR_VERSION: u8 = 1;

/// Scheme of the invitation URI.
pub const INVITATION_SCHEME: &str = "veilroom";

/// Query parameter carrying the protocol major version.
pub const URI_PARAM_VERSION: &str = "v";

/// Query parameter carrying the invitation token.
pub const URI_PARAM_TOKEN: &str = "token";

/// Length of the base32 body of a Tor v3 onion address, excluding the `.onion` suffix.
pub const ONION_V3_BODY_LENGTH: usize = 56;

/// Suffix of a Tor v3 onion address.
pub const ONION_V3_SUFFIX: &str = ".onion";

/// Canonical alphabet of a Tor v3 onion address body (base32, lowercase).
pub const ONION_V3_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";

/// Minimum invitation token entropy, in bytes (at least 128 bits, architecture decision 10).
pub const MIN_TOKEN_BYTES: usize = 16;

/// Maximum invitation token length, in bytes.
pub const MAX_TOKEN_BYTES: usize = 32;

/// Length of connection nonces (client, server, challenge) in bytes.
pub const NONCE_LEN: usize = 16;

/// Length of the password salt in bytes.
pub const SALT_LEN: usize = 16;

/// Length of the room session id in bytes (256 bits, section 36).
pub const ROOM_SESSION_ID_LEN: usize = 32;

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Length of an X25519 public key in bytes.
pub const X25519_PUBKEY_LEN: usize = 32;

/// Length of an HMAC-SHA-256 output in bytes.
pub const HMAC_LEN: usize = 32;

/// Length of a SHA-256 digest in bytes.
pub const SHA256_LEN: usize = 32;

/// Length of an XChaCha20-Poly1305 nonce in bytes.
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Length of the XChaCha20-Poly1305 authentication tag in bytes.
pub const XCHACHA_TAG_LEN: usize = 16;

/// Length of an epoch group key in bytes.
pub const EPOCH_KEY_LEN: usize = 32;

/// Length of a wrapped epoch key (key plus tag) in bytes.
pub const EPOCH_WRAP_CIPHERTEXT_LEN: usize = EPOCH_KEY_LEN + XCHACHA_TAG_LEN;

/// Minimum chat ciphertext length (one plaintext byte plus the tag).
pub const CHAT_MIN_CIPHERTEXT_LEN: usize = 1 + XCHACHA_TAG_LEN;

/// Maximum chat ciphertext length (max chat text plus the tag).
pub const CHAT_MAX_CIPHERTEXT_LEN: usize = 4096 + XCHACHA_TAG_LEN;

/// Argon2id memory cost in KiB (RFC 9106 recommendation, tuned by testing).
pub const ARGON2_M_COST: u32 = 19 * 1024;

/// Argon2id time cost.
pub const ARGON2_T_COST: u32 = 2;

/// Argon2id parallelism.
pub const ARGON2_P_COST: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_one() {
        let version: u8 = PROTOCOL_MAJOR_VERSION;
        let expected: u8 = 1;
        assert_eq!(version, expected);
    }

    #[test]
    fn invitation_scheme_is_veilroom() {
        let scheme: &str = INVITATION_SCHEME;
        let expected: &str = "veilroom";
        assert_eq!(scheme, expected);
    }

    #[test]
    fn onion_alphabet_matches_base32() {
        let alphabet: &str = ONION_V3_ALPHABET;
        let expected: &str = "abcdefghijklmnopqrstuvwxyz234567";
        assert_eq!(alphabet, expected);
        let len: usize = ONION_V3_ALPHABET.len();
        let expected_len: usize = 32;
        assert_eq!(len, expected_len);
    }

    #[test]
    fn token_bounds_match_specification() {
        let min: usize = MIN_TOKEN_BYTES;
        let max: usize = MAX_TOKEN_BYTES;
        assert_eq!(min, 16);
        assert_eq!(max, 32);
        assert!(max >= min);
    }
}
