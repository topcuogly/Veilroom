//! Encrypted chat envelope schema (Stage 7, sections 16 and 17).
//!
//! `CHAT_MESSAGE` (0x40), `COLOR_CHANGE` (0x41), `TIMEOUT_REQUEST` (0x42),
//! and `TIMEOUT_CHANGED` (0x43) share one wire shape: epoch, sender id,
//! sender sequence, nonce, ciphertext, signature. The message type is bound
//! into the AEAD additional data and the signature transcript by the frame
//! type.

use minicbor::Encoder;

use crate::constants::{
    CHAT_MAX_CIPHERTEXT_LEN, CHAT_MIN_CIPHERTEXT_LEN, ED25519_SIGNATURE_LEN, XCHACHA_NONCE_LEN,
};
use crate::protocol::messages::ProtocolError;
use crate::protocol::strict::StrictDecoder;

/// The encrypted payload of a chat-layer message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    /// The epoch the message belongs to.
    pub epoch: u64,
    /// The sender's member id.
    pub sender_id: u64,
    /// The sender's monotonic sequence for this epoch.
    pub sender_sequence: u64,
    /// The fresh per-message nonce.
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    /// The ciphertext (plaintext plus authentication tag).
    pub ciphertext: Vec<u8>,
    /// The sender's Ed25519 signature over the chat transcript.
    pub signature: [u8; ED25519_SIGNATURE_LEN],
}

impl EncryptedEnvelope {
    /// Constructs an envelope, validating the ciphertext bounds.
    pub fn new(
        epoch: u64,
        sender_id: u64,
        sender_sequence: u64,
        nonce: [u8; XCHACHA_NONCE_LEN],
        ciphertext: Vec<u8>,
        signature: [u8; ED25519_SIGNATURE_LEN],
    ) -> Result<Self, ProtocolError> {
        if !(CHAT_MIN_CIPHERTEXT_LEN..=CHAT_MAX_CIPHERTEXT_LEN).contains(&ciphertext.len()) {
            return Err(ProtocolError::InvalidField {
                field: 5,
                detail: format!(
                    "ciphertext must be {CHAT_MIN_CIPHERTEXT_LEN}..={CHAT_MAX_CIPHERTEXT_LEN} bytes, found {}",
                    ciphertext.len()
                ),
            });
        }
        Ok(Self {
            epoch,
            sender_id,
            sender_sequence,
            nonce,
            ciphertext,
            signature,
        })
    }

    /// Strictly decodes an encrypted envelope.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut epoch = None;
        let mut sender_id = None;
        let mut sender_sequence = None;
        let mut nonce = None;
        let mut ciphertext = None;
        let mut signature = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                epoch = Some(decoder.u64()?);
                Ok(())
            }
            2 => {
                sender_id = Some(decoder.u64()?);
                Ok(())
            }
            3 => {
                sender_sequence = Some(decoder.u64()?);
                Ok(())
            }
            4 => {
                let bytes = decoder.bytes()?;
                nonce = Some(bytes.try_into().map_err(|_| ProtocolError::InvalidField {
                    field: 4,
                    detail: format!(
                        "nonce must be {XCHACHA_NONCE_LEN} bytes, found {}",
                        bytes.len()
                    ),
                })?);
                Ok(())
            }
            5 => {
                ciphertext = Some(decoder.bytes()?.to_vec());
                Ok(())
            }
            6 => {
                signature =
                    Some(
                        decoder
                            .bytes()?
                            .try_into()
                            .map_err(|_| ProtocolError::InvalidField {
                                field: 6,
                                detail: format!("signature must be {ED25519_SIGNATURE_LEN} bytes"),
                            })?,
                    );
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Self::new(
            epoch.ok_or(ProtocolError::MissingField { field: 1 })?,
            sender_id.ok_or(ProtocolError::MissingField { field: 2 })?,
            sender_sequence.ok_or(ProtocolError::MissingField { field: 3 })?,
            nonce.ok_or(ProtocolError::MissingField { field: 4 })?,
            ciphertext.ok_or(ProtocolError::MissingField { field: 5 })?,
            signature.ok_or(ProtocolError::MissingField { field: 6 })?,
        )
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(6)?.u8(1)?.u64(self.epoch)?;
        encoder.u8(2)?.u64(self.sender_id)?;
        encoder.u8(3)?.u64(self.sender_sequence)?;
        encoder.u8(4)?.bytes(&self.nonce)?;
        encoder.u8(5)?.bytes(&self.ciphertext)?;
        encoder.u8(6)?.bytes(&self.signature)?;
        Ok(())
    }
}
