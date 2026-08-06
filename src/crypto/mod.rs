//! Cryptography subsystem (sections 34.5, 35, 38).
//!
//! Stage 4 provides: the Argon2id password verifier with the HMAC-SHA-256
//! challenge-response proof, canonical signature transcripts, and secure
//! randomness helpers. Raw key material never leaves this module.
//!
//! Ed25519/X25519 signing and key exchange arrive in Stage 6; the
//! transcripts defined here are the exact bytes those signatures cover.

pub mod chat;
pub mod identity;
pub mod password;
pub mod transcript;

use std::fmt;

/// Errors produced by the cryptography subsystem.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The operating system refused to provide random data.
    #[error("failed to obtain secure randomness: {0}")]
    Randomness(#[from] getrandom::Error),

    /// Argon2id rejected the supplied parameters or failed.
    #[error("argon2id error: {0}")]
    Argon2(#[from] argon2::Error),

    /// An HMAC key of any length is accepted; this variant is unreachable
    /// for HMAC-SHA-256.
    #[error("invalid HMAC key length")]
    InvalidHmacKey,

    /// The AEAD operation failed (authentication or invalid input).
    #[error("authenticated encryption failed: {0}")]
    Aead(#[from] chacha20poly1305::Error),

    /// HKDF could not expand to the requested output length.
    #[error("HKDF expansion failed: {0}")]
    Hkdf(#[from] hkdf::InvalidLength),

    /// An unwrapped epoch key has an unexpected length.
    #[error("unwrapped epoch key has an unexpected length")]
    InvalidEpochKeyLength,
    /// X25519 produced the all-zero shared secret (a low-order public key).
    #[error("non-contributory X25519 public key")]
    NonContributoryX25519,
}

/// Secret byte material that is zeroized on drop.
///
/// Used for passwords and derived keys; never `String`, never logged.
pub type SecretBytes = zeroize::Zeroizing<Vec<u8>>;

/// Secret fixed-size byte array that is zeroized on drop.
pub type SecretArray<const N: usize> = zeroize::Zeroizing<[u8; N]>;

/// Fills a byte array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

/// A redacted secret value whose `Debug` output never leaks the bytes.
#[derive(Clone)]
pub struct RedactedBytes {
    /// The length of the redacted value.
    pub length: usize,
}

impl fmt::Debug for RedactedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedBytes")
            .field("length", &self.length)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_produce_different_values() {
        let a = random_bytes::<16>().unwrap();
        let b = random_bytes::<16>().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn redacted_bytes_do_not_leak_content() {
        let redacted = RedactedBytes { length: 32 };
        assert_eq!(format!("{redacted:?}"), "RedactedBytes { length: 32 }");
    }
}
