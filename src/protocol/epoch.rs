//! Epoch message schemas (Stage 6, sections 14, 15 and 18).
//!
//! `EPOCH_WRAP` (0x60) carries a per-member wrapped epoch key; the member
//! unwraps it with its member wrapping key and acknowledges with
//! `EPOCH_ACK` (0x61).

use minicbor::Encoder;

use crate::constants::{EPOCH_WRAP_CIPHERTEXT_LEN, XCHACHA_NONCE_LEN};
use crate::protocol::messages::ProtocolError;
use crate::protocol::strict::StrictDecoder;

/// `EPOCH_WRAP` (0x60): the host delivers the wrapped epoch key to one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochWrap {
    /// The epoch this key belongs to.
    pub epoch: u64,
    /// The fresh per-envelope nonce.
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    /// The ciphertext: the 32-byte key plus the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl EpochWrap {
    /// Constructs an epoch wrap, validating the envelope sizes.
    pub fn new(
        epoch: u64,
        nonce: [u8; XCHACHA_NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if ciphertext.len() != EPOCH_WRAP_CIPHERTEXT_LEN {
            return Err(ProtocolError::InvalidField {
                field: 3,
                detail: format!(
                    "ciphertext must be {EPOCH_WRAP_CIPHERTEXT_LEN} bytes, found {}",
                    ciphertext.len()
                ),
            });
        }
        Ok(Self {
            epoch,
            nonce,
            ciphertext,
        })
    }

    /// Strictly decodes an epoch-wrap payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut epoch = None;
        let mut nonce = None;
        let mut ciphertext = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                epoch = Some(decoder.u64()?);
                Ok(())
            }
            2 => {
                let bytes = decoder.bytes()?;
                nonce = Some(bytes.try_into().map_err(|_| ProtocolError::InvalidField {
                    field: 2,
                    detail: format!(
                        "nonce must be {XCHACHA_NONCE_LEN} bytes, found {}",
                        bytes.len()
                    ),
                })?);
                Ok(())
            }
            3 => {
                ciphertext = Some(decoder.bytes()?.to_vec());
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Self::new(
            epoch.ok_or(ProtocolError::MissingField { field: 1 })?,
            nonce.ok_or(ProtocolError::MissingField { field: 2 })?,
            ciphertext.ok_or(ProtocolError::MissingField { field: 3 })?,
        )
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(3)?.u8(1)?.u64(self.epoch)?;
        encoder.u8(2)?.bytes(&self.nonce)?;
        encoder.u8(3)?.bytes(&self.ciphertext)?;
        Ok(())
    }
}

/// `EPOCH_ACK` (0x61): a member acknowledges a new epoch key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochAck {
    /// The acknowledged epoch.
    pub epoch: u64,
}

impl EpochAck {
    /// Constructs an epoch acknowledgement.
    pub const fn new(epoch: u64) -> Self {
        Self { epoch }
    }

    /// Strictly decodes an epoch-ack payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut epoch = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                epoch = Some(decoder.u64()?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            epoch: epoch.ok_or(ProtocolError::MissingField { field: 1 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(1)?.u8(1)?.u64(self.epoch)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::protocol::strict::StrictDecoder;

    fn decode<T>(
        payload: &[u8],
        schema: fn(&mut StrictDecoder<'_>) -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        let limits = Limits::default();
        let mut decoder = StrictDecoder::new(payload, &limits);
        let value = schema(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    fn encode<T>(
        value: &T,
        encode: fn(&T, &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut encoder = Encoder::new(&mut out);
        encode(value, &mut encoder).unwrap();
        out
    }

    #[test]
    fn epoch_wrap_roundtrips() {
        let message = EpochWrap::new(7, [0x21; 24], vec![0x33; 48]).unwrap();
        let payload = encode(&message, EpochWrap::encode);
        assert_eq!(decode(&payload, EpochWrap::strict_decode).unwrap(), message);
    }

    #[test]
    fn epoch_ack_roundtrips() {
        let message = EpochAck::new(7);
        let payload = encode(&message, EpochAck::encode);
        assert_eq!(decode(&payload, EpochAck::strict_decode).unwrap(), message);
    }

    #[test]
    fn epoch_wrap_rejects_wrong_envelope_sizes() {
        // Wrong nonce length (16 bytes).
        let mut payload = vec![0xa2, 0x01, 0x07, 0x02, 0x50];
        payload.extend([0x21; 16]);
        assert!(matches!(
            decode(&payload, EpochWrap::strict_decode),
            Err(ProtocolError::Cbor(_) | ProtocolError::InvalidField { .. })
        ));

        // Wrong ciphertext length (32 bytes instead of 48).
        let mut payload = vec![0xa3, 0x01, 0x07, 0x02, 0x58];
        payload.extend([0x21; 24]);
        payload.push(0x03);
        payload.push(0x40);
        payload.extend([0x33; 32]);
        assert!(matches!(
            decode(&payload, EpochWrap::strict_decode),
            Err(ProtocolError::Cbor(_) | ProtocolError::InvalidField { .. })
        ));

        // The constructor rejects wrong lengths directly.
        assert!(EpochWrap::new(1, [0; 24], vec![0; 47]).is_err());
        assert!(EpochWrap::new(1, [0; 24], vec![0; 49]).is_err());
    }

    //it's never too late

    #[test]
    fn epoch_messages_reject_unknown_fields_and_duplicates() {
        // EpochAck with an unknown field.
        assert!(matches!(
            decode(&[0xa1, 0x09, 0x01], EpochAck::strict_decode),
            Err(ProtocolError::UnknownField { field: 9 })
        ));
        // EpochAck with a duplicate field.
        assert!(matches!(
            decode(&[0xa2, 0x01, 0x07, 0x01, 0x08], EpochAck::strict_decode),
            Err(ProtocolError::Cbor(
                crate::protocol::strict::StrictError::DuplicateMapKey { key: 1 }
            ))
        ));
        // EpochAck without an epoch.
        assert!(matches!(
            decode(&[0xa0], EpochAck::strict_decode),
            Err(ProtocolError::MissingField { field: 1 })
        ));
    }
}
