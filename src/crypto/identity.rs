//! Cryptographic membership identities (sections 6, 15, 36 and 37).
//!
//! Every room connection uses fresh ephemeral Ed25519 and X25519 key pairs
//! that are never persisted. The host's identity is created once at room
//! creation; participant identities are created per connection. Raw private
//! key bytes never leave this module.
//!
//! Per-member key channel (section 15): the host and the member derive an
//! X25519 shared secret; HKDF-SHA-256 with the room session id as salt and
//! `VEILROOM-MEMBER-WRAP-KEY-V1 || member_id` as info derives a member
//! wrapping key. Epoch keys are wrapped with XChaCha20-Poly1305, binding
//! `VEILROOM-EPOCH-WRAP-V1 || room_session_id || epoch` as additional data.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::constants::{EPOCH_KEY_LEN, XCHACHA_NONCE_LEN};
use crate::crypto::transcript::{EPOCH_WRAP_LABEL, MEMBER_WRAP_KEY_LABEL};
use crate::crypto::{CryptoError, random_bytes};

/// The room-lifetime identity of the host: an Ed25519 signing key and an
/// X25519 key-exchange key (sections 36 and 15).
#[derive(Clone)]
pub struct HostIdentity {
    ed25519: SigningKey,
    x25519: StaticSecret,
}

impl std::fmt::Debug for HostIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostIdentity { .. }")
    }
}

impl HostIdentity {
    /// Generates a fresh random host identity.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            ed25519: SigningKey::from_bytes(&random_bytes::<32>()?),
            x25519: StaticSecret::from(random_bytes::<32>()?),
        })
    }

    /// Constructs a host identity from fixed seeds (tests only; the seeds
    /// are not production secrets).
    pub fn from_seed(ed25519_seed: [u8; 32], x25519_secret: [u8; 32]) -> Self {
        Self {
            ed25519: SigningKey::from_bytes(&ed25519_seed),
            x25519: StaticSecret::from(x25519_secret),
        }
    }

    /// The host's Ed25519 public key.
    pub fn ed25519_pubkey(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }

    /// The host's X25519 public key.
    pub fn x25519_pubkey(&self) -> [u8; 32] {
        PublicKey::from(&self.x25519).to_bytes()
    }

    /// Signs a transcript with the host's Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.ed25519.sign(message).to_bytes()
    }

    /// Derives the member wrapping key for one member (section 15).
    pub fn wrap_key_for(
        &self,
        member_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> MemberWrapKey {
        self.try_wrap_key_for(member_x25519_pubkey, room_session_id, member_id)
            .expect("a generated X25519 public key is contributory")
    }

    /// Derives a wrapping key while rejecting low-order public keys.
    pub fn try_wrap_key_for(
        &self,
        member_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> Result<MemberWrapKey, CryptoError> {
        MemberWrapKey::try_derive_host(
            &self.x25519,
            member_x25519_pubkey,
            room_session_id,
            member_id,
        )
    }
}

/// The ephemeral identity of one participant connection (section 6).
#[derive(Clone)]
pub struct MemberIdentity {
    ed25519: SigningKey,
    x25519: StaticSecret,
}

impl std::fmt::Debug for MemberIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemberIdentity { .. }")
    }
}

impl MemberIdentity {
    /// Generates a fresh random participant identity.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            ed25519: SigningKey::from_bytes(&random_bytes::<32>()?),
            x25519: StaticSecret::from(random_bytes::<32>()?),
        })
    }

    /// Constructs a participant identity from fixed seeds (tests only).
    pub fn from_seed(ed25519_seed: [u8; 32], x25519_secret: [u8; 32]) -> Self {
        Self {
            ed25519: SigningKey::from_bytes(&ed25519_seed),
            x25519: StaticSecret::from(x25519_secret),
        }
    }

    /// The participant's Ed25519 public key.
    pub fn ed25519_pubkey(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }

    /// The participant's X25519 public key.
    pub fn x25519_pubkey(&self) -> [u8; 32] {
        PublicKey::from(&self.x25519).to_bytes()
    }

    /// Signs a transcript with the participant's Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.ed25519.sign(message).to_bytes()
    }

    /// Derives the member wrapping key on the participant side (section 15).
    pub fn wrap_key_for(
        &self,
        host_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> MemberWrapKey {
        self.try_wrap_key_for(host_x25519_pubkey, room_session_id, member_id)
            .expect("a generated X25519 public key is contributory")
    }

    /// Derives a wrapping key while rejecting low-order public keys.
    pub fn try_wrap_key_for(
        &self,
        host_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> Result<MemberWrapKey, CryptoError> {
        MemberWrapKey::try_derive_member(
            &self.x25519,
            host_x25519_pubkey,
            room_session_id,
            member_id,
        )
    }
}

/// The per-member wrapping key derived from the X25519 shared secret
/// (section 15). Zeroized on drop.
#[derive(Debug)]
pub struct MemberWrapKey(Zeroizing<[u8; EPOCH_KEY_LEN]>);

impl MemberWrapKey {
    /// The raw wrapping-key bytes, exposed only to tests.
    ///
    /// The production API keeps the key inside the zeroizing buffer; tests
    /// pin the HKDF output against the golden vector document.
    #[cfg(test)]
    pub(crate) fn test_bytes(&self) -> &[u8; EPOCH_KEY_LEN] {
        &self.0
    }

    /// Derives the wrapping key on the host side for one member.
    pub fn derive_host(
        host_x25519: &StaticSecret,
        member_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> Self {
        Self::try_derive_host(
            host_x25519,
            member_x25519_pubkey,
            room_session_id,
            member_id,
        )
        .expect("a generated X25519 public key is contributory")
    }

    /// Host-side derivation that rejects the X25519 all-zero result.
    pub fn try_derive_host(
        host_x25519: &StaticSecret,
        member_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> Result<Self, CryptoError> {
        let public = PublicKey::from(*member_x25519_pubkey);
        Self::derive_checked(
            &host_x25519.diffie_hellman(&public),
            room_session_id,
            member_id,
        )
    }

    /// Derives the wrapping key on the member side.
    pub fn derive_member(
        own_x25519: &StaticSecret,
        host_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> Self {
        Self::try_derive_member(own_x25519, host_x25519_pubkey, room_session_id, member_id)
            .expect("a generated X25519 public key is contributory")
    }

    /// Member-side derivation that rejects the X25519 all-zero result.
    pub fn try_derive_member(
        own_x25519: &StaticSecret,
        host_x25519_pubkey: &[u8; 32],
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> Result<Self, CryptoError> {
        let public = PublicKey::from(*host_x25519_pubkey);
        Self::derive_checked(
            &own_x25519.diffie_hellman(&public),
            room_session_id,
            member_id,
        )
    }

    fn derive_checked(
        shared: &SharedSecret,
        room_session_id: &[u8; 32],
        member_id: u64,
    ) -> Result<Self, CryptoError> {
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributoryX25519);
        }
        let mut info = Vec::with_capacity(MEMBER_WRAP_KEY_LABEL.len() + 8);
        info.extend_from_slice(MEMBER_WRAP_KEY_LABEL.as_bytes());
        info.extend_from_slice(&member_id.to_be_bytes());
        let hk = Hkdf::<Sha256>::new(Some(room_session_id), shared.as_bytes());
        let mut key = Zeroizing::new([0u8; EPOCH_KEY_LEN]);
        // 32 is a valid HKDF output length for SHA-256.
        hk.expand(&info, &mut key[..])
            .expect("32 bytes is a valid HKDF-SHA-256 output length");
        Ok(Self(key))
    }
}

/// An epoch group key (section 14). Zeroized on drop.
#[derive(Debug)]
pub struct EpochKey(Zeroizing<[u8; EPOCH_KEY_LEN]>);

impl EpochKey {
    /// Generates a fresh random 256-bit epoch key.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(Zeroizing::new(random_bytes::<EPOCH_KEY_LEN>()?)))
    }

    /// Wraps the key bytes (used when unwrapping).
    pub fn from_bytes(bytes: [u8; EPOCH_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw key bytes.
    ///
    /// The epoch key is a group key shared by every member by design;
    /// exposing the bytes allows sessions to install the same key.
    pub fn as_bytes(&self) -> &[u8; EPOCH_KEY_LEN] {
        &self.0
    }
}

/// A wrapped epoch key as carried by the `EPOCH_WRAP` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochEnvelope {
    /// The fresh per-envelope nonce.
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    /// The ciphertext (key plus authentication tag).
    pub ciphertext: Vec<u8>,
}

/// Wraps an epoch key for one member with a fresh nonce.
pub fn wrap_epoch_key(
    wrap_key: &MemberWrapKey,
    epoch_key: &EpochKey,
    epoch: u64,
    room_session_id: &[u8; 32],
) -> Result<EpochEnvelope, CryptoError> {
    let nonce = random_bytes::<XCHACHA_NONCE_LEN>()?;
    let aad = epoch_aad(epoch, room_session_id);
    let key = Key::try_from(&wrap_key.0[..])
        .expect("a wrap key has exactly the XChaCha20-Poly1305 key length");
    let cipher_nonce = XNonce::try_from(&nonce[..])
        .expect("a nonce has exactly the XChaCha20-Poly1305 nonce length");
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(
            &cipher_nonce,
            Payload {
                msg: epoch_key.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(CryptoError::Aead)?;
    Ok(EpochEnvelope { nonce, ciphertext })
}

/// Unwraps an epoch key, authenticating the tag and the bound context.
pub fn unwrap_epoch_key(
    wrap_key: &MemberWrapKey,
    epoch: u64,
    room_session_id: &[u8; 32],
    nonce: &[u8; XCHACHA_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<EpochKey, CryptoError> {
    let aad = epoch_aad(epoch, room_session_id);
    let key = Key::try_from(&wrap_key.0[..])
        .expect("a wrap key has exactly the XChaCha20-Poly1305 key length");
    let cipher_nonce = XNonce::try_from(&nonce[..])
        .expect("a nonce has exactly the XChaCha20-Poly1305 nonce length");
    let cipher = XChaCha20Poly1305::new(&key);
    let plaintext = cipher
        .decrypt(
            &cipher_nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(CryptoError::Aead)?;
    let bytes: [u8; EPOCH_KEY_LEN] = plaintext
        .try_into()
        .map_err(|_| CryptoError::InvalidEpochKeyLength)?;
    Ok(EpochKey::from_bytes(bytes))
}

/// The additional data bound into every epoch envelope.
fn epoch_aad(epoch: u64, room_session_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(EPOCH_WRAP_LABEL.len() + 32 + 8);
    aad.extend_from_slice(EPOCH_WRAP_LABEL.as_bytes());
    aad.extend_from_slice(room_session_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Verifies an Ed25519 signature over a message against a public key.
///
/// Returns `false` for malformed keys or signatures instead of failing.
pub fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(&signature[..]) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_key_matches_the_golden_vector() {
        // Fixed inputs (docs/test-vectors.md); test keys are NOT secrets.
        let host = HostIdentity::from_seed([0x51; 32], [0x52; 32]);
        let member = MemberIdentity::from_seed([0x61; 32], [0x62; 32]);
        let wrap = member.wrap_key_for(&host.x25519_pubkey(), &[0x71; 32], 5);
        let expected: [u8; EPOCH_KEY_LEN] = [
            // Pinned from docs/test-vectors.md (MEMBER_WRAP_KEY).
            0xd8, 0x2d, 0xd3, 0x68, 0x03, 0x5f, 0x97, 0x25, 0xf8, 0x06, 0xd0, 0x67, 0x9b, 0x06,
            0xfc, 0x36, 0x8f, 0x83, 0x13, 0x65, 0x8c, 0xb8, 0xf2, 0x77, 0x79, 0x49, 0xe7, 0x0f,
            0x5d, 0x90, 0x66, 0x7c,
        ];
        assert_eq!(wrap.test_bytes(), &expected);
    }

    #[test]
    fn low_order_x25519_public_keys_are_rejected() {
        let host = HostIdentity::from_seed([0x51; 32], [0x52; 32]);
        let member = MemberIdentity::from_seed([0x61; 32], [0x62; 32]);
        assert!(matches!(
            host.try_wrap_key_for(&[0; 32], &[0x71; 32], 5),
            Err(CryptoError::NonContributoryX25519)
        ));
        assert!(matches!(
            member.try_wrap_key_for(&[0; 32], &[0x71; 32], 5),
            Err(CryptoError::NonContributoryX25519)
        ));
    }

    #[test]
    fn rfc_8032_ed25519_test_vector_1() {
        // RFC 8032 TEST 1: empty message.
        let secret_key =
            hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = hex_decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let signing = SigningKey::from_bytes(&secret_key);
        assert_eq!(signing.verifying_key().to_bytes(), expected_public);
        let signature = signing.sign(b"");
        assert_eq!(signature.to_bytes(), expected_signature);
        assert!(verify_ed25519(&expected_public, b"", &expected_signature));
        assert!(!verify_ed25519(
            &expected_public,
            b"tampered",
            &expected_signature
        ));
    }

    #[test]
    fn rfc_7748_x25519_test_vector_1() {
        // RFC 7748 vector 1.
        let scalar = hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected =
            hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let secret = StaticSecret::from(scalar);
        let public = PublicKey::from(u);
        assert_eq!(secret.diffie_hellman(&public).as_bytes(), &expected);
    }

    #[test]
    fn rfc_5869_hkdf_sha256_test_case_1() {
        let ikm = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected);
    }

    #[test]
    fn xchacha20poly1305_draft_vector() {
        let key: [u8; 32] = (0x80u8..=0x9f).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 24] = (0x40u8..=0x57).collect::<Vec<u8>>().try_into().unwrap();
        let aad = [
            0x50u8, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected: Vec<u8> = hex_decode_any(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49",
        );

        let key = Key::try_from(&key[..]).expect("32-byte key");
        let nonce = XNonce::try_from(&nonce[..]).expect("24-byte nonce");
        let cipher = XChaCha20Poly1305::new(&key);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(ciphertext, expected);
        let decrypted = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrap_key_derivation_agrees_on_both_sides() {
        let session = [0x33; 32];
        let host = HostIdentity::generate().unwrap();
        let member = MemberIdentity::generate().unwrap();
        let host_side = host.wrap_key_for(&member.x25519_pubkey(), &session, 7);
        let member_side = member.wrap_key_for(&host.x25519_pubkey(), &session, 7);
        assert_eq!(host_side.0[..], member_side.0[..]);
    }

    #[test]
    fn wrap_key_binds_the_member_id() {
        let session = [0x44; 32];
        let host = HostIdentity::generate().unwrap();
        let member = MemberIdentity::generate().unwrap();
        let a = host.wrap_key_for(&member.x25519_pubkey(), &session, 7);
        let b = host.wrap_key_for(&member.x25519_pubkey(), &session, 8);
        assert_ne!(a.0[..], b.0[..]);
    }

    #[test]
    fn epoch_envelopes_roundtrip_and_tampering_fails() {
        let session = [0x55; 32];
        let host = HostIdentity::generate().unwrap();
        let member = MemberIdentity::generate().unwrap();
        let wrap_key = host.wrap_key_for(&member.x25519_pubkey(), &session, 3);
        let epoch_key = EpochKey::generate().unwrap();

        let envelope = wrap_epoch_key(&wrap_key, &epoch_key, 2, &session).unwrap();
        assert_eq!(envelope.ciphertext.len(), 48);

        let unwrapped = unwrap_epoch_key(
            &wrap_key,
            2,
            &session,
            &envelope.nonce,
            &envelope.ciphertext,
        )
        .unwrap();
        assert_eq!(unwrapped.0[..], epoch_key.0[..]);

        // A wrong epoch or session fails authentication.
        assert!(
            unwrap_epoch_key(
                &wrap_key,
                3,
                &session,
                &envelope.nonce,
                &envelope.ciphertext
            )
            .is_err()
        );
        assert!(
            unwrap_epoch_key(
                &wrap_key,
                2,
                &[0x66; 32],
                &envelope.nonce,
                &envelope.ciphertext
            )
            .is_err()
        );

        // Tampered ciphertext fails.
        let mut tampered = envelope.ciphertext.clone();
        tampered[0] ^= 0x01;
        assert!(unwrap_epoch_key(&wrap_key, 2, &session, &envelope.nonce, &tampered).is_err());
    }

    #[test]
    fn wrong_wrap_key_fails_to_unwrap() {
        let session = [0x77; 32];
        let host = HostIdentity::generate().unwrap();
        let alice = MemberIdentity::generate().unwrap();
        let bob = MemberIdentity::generate().unwrap();
        let alice_key = host.wrap_key_for(&alice.x25519_pubkey(), &session, 1);
        let bob_key = host.wrap_key_for(&bob.x25519_pubkey(), &session, 2);
        let envelope =
            wrap_epoch_key(&alice_key, &EpochKey::generate().unwrap(), 1, &session).unwrap();
        assert!(
            unwrap_epoch_key(&bob_key, 1, &session, &envelope.nonce, &envelope.ciphertext).is_err()
        );
    }

    #[test]
    fn signatures_roundtrip_and_verification_rejects_tampering() {
        let identity = HostIdentity::generate().unwrap();
        let message = b"transcript bytes";
        let signature = identity.sign(message);
        assert!(verify_ed25519(
            &identity.ed25519_pubkey(),
            message,
            &signature
        ));
        let mut tampered = signature;
        tampered[0] ^= 0x01;
        assert!(!verify_ed25519(
            &identity.ed25519_pubkey(),
            message,
            &tampered
        ));
        assert!(!verify_ed25519(
            &identity.ed25519_pubkey(),
            b"other",
            &signature
        ));
        // Malformed inputs are rejected, not panicked on.
        assert!(!verify_ed25519(&[0u8; 32], message, &signature));
    }

    fn hex_decode_any(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_decode<const N: usize>(hex: &str) -> [u8; N] {
        hex_decode_any(hex).try_into().unwrap()
    }
}
