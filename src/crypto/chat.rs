//! Chat-message cryptography (sections 16 and 38).
//!
//! Chat messages are encrypted with the current epoch key using
//! XChaCha20-Poly1305 and signed by the sender's ephemeral Ed25519 key.
//! The AEAD additional data binds the protocol version, room session id,
//! epoch, sender identity, sender sequence, and message type; the signature
//! covers the ciphertext so neither the content nor the binding can be
//! altered.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

use crate::constants::XCHACHA_NONCE_LEN;
use crate::crypto::identity::{EpochKey, MemberIdentity, verify_ed25519};
use crate::crypto::transcript::{CHAT_MESSAGE_LABEL, TranscriptBuilder};
use crate::crypto::{CryptoError, random_bytes};

/// Domain-separation label of the chat AEAD additional data.
pub const CHAT_AAD_LABEL: &str = "VEILROOM-CHAT-AAD-V1";

/// A sealed chat payload: fresh nonce, ciphertext, and signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// The fresh per-message nonce.
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    /// The ciphertext (plaintext plus authentication tag).
    pub ciphertext: Vec<u8>,
    /// The sender's Ed25519 signature over the chat transcript.
    pub signature: [u8; 64],
}

/// Errors produced while opening a chat envelope.
#[derive(Debug, thiserror::Error)]
pub enum ChatOpenError {
    /// The sender's signature did not verify.
    #[error("invalid chat signature")]
    InvalidSignature,

    /// The AEAD authentication failed or the input was malformed.
    #[error("chat decryption failed: {0}")]
    Decrypt(#[from] CryptoError),
}

/// The AEAD additional data of a chat message (section 16).
pub fn chat_aad(
    version: u8,
    room_session_id: &[u8; 32],
    epoch: u64,
    sender_id: u64,
    sender_sequence: u64,
    message_type: u8,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHAT_AAD_LABEL.len() + 1 + 32 + 8 + 8 + 8 + 1);
    aad.extend_from_slice(CHAT_AAD_LABEL.as_bytes());
    aad.push(version);
    aad.extend_from_slice(room_session_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&sender_id.to_be_bytes());
    aad.extend_from_slice(&sender_sequence.to_be_bytes());
    aad.push(message_type);
    aad
}

/// The canonical signature transcript of a chat message (section 38).
#[allow(clippy::too_many_arguments)]
pub fn chat_transcript(
    version: u8,
    room_session_id: &[u8; 32],
    epoch: u64,
    sender_id: u64,
    sender_sequence: u64,
    message_type: u8,
    nonce: &[u8; XCHACHA_NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut builder = TranscriptBuilder::new();
    builder
        .label(CHAT_MESSAGE_LABEL)
        .u8(version)
        .fixed(room_session_id)
        .u64(epoch)
        .u64(sender_id)
        .u64(sender_sequence)
        .u8(message_type)
        .fixed(nonce)
        .bytes(ciphertext);
    builder.finish()
}

/// Seals a plaintext payload into a signed, encrypted chat envelope.
#[allow(clippy::too_many_arguments)]
pub fn seal_envelope(
    epoch_key: &EpochKey,
    identity: &MemberIdentity,
    version: u8,
    room_session_id: &[u8; 32],
    epoch: u64,
    sender_id: u64,
    sender_sequence: u64,
    message_type: u8,
    plaintext: &[u8],
) -> Result<SealedEnvelope, CryptoError> {
    let nonce = random_bytes::<XCHACHA_NONCE_LEN>()?;
    let aad = chat_aad(
        version,
        room_session_id,
        epoch,
        sender_id,
        sender_sequence,
        message_type,
    );
    let key = Key::try_from(epoch_key.as_bytes()[..].as_ref())
        .expect("an epoch key has exactly the XChaCha20-Poly1305 key length");
    let cipher_nonce = XNonce::try_from(&nonce[..])
        .expect("a nonce has exactly the XChaCha20-Poly1305 nonce length");
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(
            &cipher_nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(CryptoError::Aead)?;
    let transcript = chat_transcript(
        version,
        room_session_id,
        epoch,
        sender_id,
        sender_sequence,
        message_type,
        &nonce,
        &ciphertext,
    );
    let signature = identity.sign(&transcript);
    Ok(SealedEnvelope {
        nonce,
        ciphertext,
        signature,
    })
}

/// Opens a chat envelope: verifies the signature, authenticates and
/// decrypts the ciphertext, and returns the plaintext.
#[allow(clippy::too_many_arguments)]
pub fn open_envelope(
    epoch_key: &EpochKey,
    sender_ed25519_pubkey: &[u8; 32],
    version: u8,
    room_session_id: &[u8; 32],
    epoch: u64,
    sender_id: u64,
    sender_sequence: u64,
    message_type: u8,
    nonce: &[u8; XCHACHA_NONCE_LEN],
    ciphertext: &[u8],
    signature: &[u8; 64],
) -> Result<Vec<u8>, ChatOpenError> {
    let transcript = chat_transcript(
        version,
        room_session_id,
        epoch,
        sender_id,
        sender_sequence,
        message_type,
        nonce,
        ciphertext,
    );
    if !verify_ed25519(sender_ed25519_pubkey, &transcript, signature) {
        return Err(ChatOpenError::InvalidSignature);
    }
    let aad = chat_aad(
        version,
        room_session_id,
        epoch,
        sender_id,
        sender_sequence,
        message_type,
    );
    let key = Key::try_from(epoch_key.as_bytes()[..].as_ref())
        .expect("an epoch key has exactly the XChaCha20-Poly1305 key length");
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
    Ok(plaintext)
}
