//! Password verification (architecture decision 5, section 10).
//!
//! The host derives an Argon2id password key once at room creation. Each
//! connection receives a fresh challenge nonce; the participant derives the
//! same key from the supplied parameters and proves knowledge with an
//! HMAC-SHA-256 value that binds the proof label, the challenge nonce, and
//! the client nonce. The host compares proofs in constant time.
//!
//! The plaintext password is never transmitted and never used as a
//! message-encryption key. Password material is held in zeroizing buffers.

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::constants::{
    ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, HMAC_LEN, NONCE_LEN, SALT_LEN,
};
use crate::crypto::{CryptoError, random_bytes};

/// Domain-separation label of the password proof.
pub const PASSWORD_PROOF_LABEL: &str = "VEILROOM-PASSWORD-PROOF-V1";

/// The length of the derived Argon2id key in bytes.
pub const DERIVED_KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Host-side password verifier, derived once at room creation.
#[derive(Debug, Clone)]
pub struct PasswordVerifier {
    salt: [u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
    derived_key: Zeroizing<[u8; DERIVED_KEY_LEN]>,
}

impl PasswordVerifier {
    /// Derives a verifier from the room password using Argon2id.
    ///
    /// A fresh random salt is generated; the parameters are the V1 defaults.
    pub fn derive(password: &[u8]) -> Result<Self, CryptoError> {
        let salt = random_bytes::<SALT_LEN>()?;
        let derived_key = derive_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
        Ok(Self {
            salt,
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            derived_key,
        })
    }

    /// The salt of this verifier.
    pub const fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The Argon2id memory cost in KiB.
    pub const fn m_cost(&self) -> u32 {
        self.m_cost
    }

    /// The Argon2id time cost.
    pub const fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// The Argon2id parallelism.
    pub const fn p_cost(&self) -> u8 {
        self.p_cost
    }

    /// Computes the expected proof for the given nonces.
    pub fn expected_proof(
        &self,
        challenge_nonce: &[u8; NONCE_LEN],
        client_nonce: &[u8; NONCE_LEN],
    ) -> [u8; HMAC_LEN] {
        compute_proof(&self.derived_key[..], challenge_nonce, client_nonce)
    }

    /// Verifies a proof in constant time.
    pub fn verify_proof(
        &self,
        challenge_nonce: &[u8; NONCE_LEN],
        client_nonce: &[u8; NONCE_LEN],
        proof: &[u8; HMAC_LEN],
    ) -> bool {
        let expected = self.expected_proof(challenge_nonce, client_nonce);
        bool::from(proof.ct_eq(&expected))
    }
}

/// Derives the Argon2id password key with explicit parameters.
///
/// Used by the host at verifier creation and by the participant after
/// receiving the challenge. The derived key is zeroized on drop.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, CryptoError> {
    let params = Params::new(m_cost, t_cost, u32::from(p_cost), Some(DERIVED_KEY_LEN))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    argon2.hash_password_into(password, salt, &mut key[..])?;
    Ok(key)
}

/// Computes the HMAC-SHA-256 password proof.
///
/// The proof binds the fixed proof label, the challenge nonce, and the
/// client nonce, so it cannot be replayed across connections or reused for
/// another purpose.
pub fn compute_proof(
    key: &[u8],
    challenge_nonce: &[u8; NONCE_LEN],
    client_nonce: &[u8; NONCE_LEN],
) -> [u8; HMAC_LEN] {
    // HMAC accepts keys of any length; the new_from_slice error is
    // unreachable for a well-formed key slice.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(PASSWORD_PROOF_LABEL.as_bytes());
    mac.update(challenge_nonce);
    mac.update(client_nonce);
    mac.finalize().into_bytes().into()
}

/// Participant-side password proof computation.
///
/// Computes the proof for a challenge using the password and the supplied
/// parameters, without ever revealing the password.
pub fn compute_password_proof(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
    challenge_nonce: &[u8; NONCE_LEN],
    client_nonce: &[u8; NONCE_LEN],
) -> Result<[u8; HMAC_LEN], CryptoError> {
    let key = derive_key(password, salt, m_cost, t_cost, p_cost)?;
    Ok(compute_proof(&key[..], challenge_nonce, client_nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_roundtrip_verifies() {
        let verifier = PasswordVerifier::derive(b"correct horse battery staple").unwrap();
        let challenge = [0x21u8; NONCE_LEN];
        let client_nonce = [0x22u8; NONCE_LEN];
        let proof = compute_password_proof(
            b"correct horse battery staple",
            verifier.salt(),
            verifier.m_cost(),
            verifier.t_cost(),
            verifier.p_cost(),
            &challenge,
            &client_nonce,
        )
        .unwrap();
        assert!(verifier.verify_proof(&challenge, &client_nonce, &proof));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let verifier = PasswordVerifier::derive(b"right").unwrap();
        let challenge = [0x31u8; NONCE_LEN];
        let client_nonce = [0x32u8; NONCE_LEN];
        let proof = compute_password_proof(
            b"wrong",
            verifier.salt(),
            verifier.m_cost(),
            verifier.t_cost(),
            verifier.p_cost(),
            &challenge,
            &client_nonce,
        )
        .unwrap();
        assert!(!verifier.verify_proof(&challenge, &client_nonce, &proof));
    }

    #[test]
    fn wrong_nonces_are_rejected() {
        let verifier = PasswordVerifier::derive(b"pw").unwrap();
        let challenge = [0x41u8; NONCE_LEN];
        let client_nonce = [0x42u8; NONCE_LEN];
        let proof = compute_password_proof(
            b"pw",
            verifier.salt(),
            verifier.m_cost(),
            verifier.t_cost(),
            verifier.p_cost(),
            &challenge,
            &client_nonce,
        )
        .unwrap();
        let other_challenge = [0x43u8; NONCE_LEN];
        let other_nonce = [0x44u8; NONCE_LEN];
        assert!(!verifier.verify_proof(&other_challenge, &client_nonce, &proof));
        assert!(!verifier.verify_proof(&challenge, &other_nonce, &proof));
    }

    #[test]
    fn each_verifier_gets_a_fresh_salt() {
        let a = PasswordVerifier::derive(b"pw").unwrap();
        let b = PasswordVerifier::derive(b"pw").unwrap();
        assert_ne!(a.salt(), b.salt());
    }

    #[test]
    fn params_match_the_v1_defaults() {
        let verifier = PasswordVerifier::derive(b"pw").unwrap();
        assert_eq!(verifier.m_cost(), ARGON2_M_COST);
        assert_eq!(verifier.t_cost(), ARGON2_T_COST);
        assert_eq!(verifier.p_cost(), ARGON2_P_COST);
    }

    #[test]
    fn proof_does_not_reveal_the_password() {
        // Two different passwords yield different proofs for the same
        // challenge, but the proof length is fixed.
        let verifier = PasswordVerifier::derive(b"pw").unwrap();
        let challenge = [0x51u8; NONCE_LEN];
        let client_nonce = [0x52u8; NONCE_LEN];
        let proof_a = compute_password_proof(
            b"pw",
            verifier.salt(),
            verifier.m_cost(),
            verifier.t_cost(),
            verifier.p_cost(),
            &challenge,
            &client_nonce,
        )
        .unwrap();
        let proof_b = compute_password_proof(
            b"pw2",
            verifier.salt(),
            verifier.m_cost(),
            verifier.t_cost(),
            verifier.p_cost(),
            &challenge,
            &client_nonce,
        )
        .unwrap();
        assert_eq!(proof_a.len(), HMAC_LEN);
        assert_ne!(proof_a, proof_b);
    }
}
