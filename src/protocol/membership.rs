//! Membership broadcast schemas (Stage 7, sections 5, 32 and 33).
//!
//! `MEMBER_JOINED` (0x20), `MEMBER_LEFT` (0x21), `MEMBER_KICKED` (0x22),
//! and `MEMBER_SNAPSHOT` (0x24) are host-authored room events, signed with
//! the host's Ed25519 key over the canonical room-event transcript and
//! carrying the room sequence number and epoch.

use minicbor::Encoder;

use crate::constants::ED25519_PUBKEY_LEN;
use crate::protocol::messages::ProtocolError;
use crate::protocol::strict::StrictDecoder;

/// One member as carried by `MEMBER_SNAPSHOT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMember {
    /// The member id.
    pub member_id: u64,
    /// The nickname.
    pub nickname: String,
    /// The display color index.
    pub color: u8,
    /// Whether this is the host participant.
    pub is_host: bool,
    /// The member's Ed25519 public key.
    pub ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
}

impl SnapshotMember {
    fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut member_id = None;
        let mut nickname = None;
        let mut color = None;
        let mut is_host = None;
        let mut pubkey = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                member_id = Some(decoder.u64()?);
                Ok(())
            }
            2 => {
                nickname = Some(decoder.str()?.to_owned());
                Ok(())
            }
            3 => {
                color = Some(decoder.u8()?);
                Ok(())
            }
            4 => {
                is_host = Some(decoder.bool()?);
                Ok(())
            }
            5 => {
                let bytes = decoder.bytes()?;
                pubkey = Some(bytes.try_into().map_err(|_| ProtocolError::InvalidField {
                    field: 5,
                    detail: format!("ed25519 pubkey must be {ED25519_PUBKEY_LEN} bytes"),
                })?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            member_id: member_id.ok_or(ProtocolError::MissingField { field: 1 })?,
            nickname: nickname.ok_or(ProtocolError::MissingField { field: 2 })?,
            color: color.ok_or(ProtocolError::MissingField { field: 3 })?,
            is_host: is_host.ok_or(ProtocolError::MissingField { field: 4 })?,
            ed25519_pubkey: pubkey.ok_or(ProtocolError::MissingField { field: 5 })?,
        })
    }

    fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(5)?.u8(1)?.u64(self.member_id)?;
        encoder.u8(2)?.str(&self.nickname)?;
        encoder.u8(3)?.u8(self.color)?;
        encoder.u8(4)?.bool(self.is_host)?;
        encoder.u8(5)?.bytes(&self.ed25519_pubkey)?;
        Ok(())
    }
}

/// `MEMBER_JOINED` (0x20): a member was admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberJoined {
    /// The room sequence number of this event.
    pub sequence: u64,
    /// The epoch the change belongs to.
    pub epoch: u64,
    /// The new member id.
    pub member_id: u64,
    /// The new member's nickname.
    pub nickname: String,
    /// The new member's Ed25519 public key.
    pub ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// The host's signature over the room-event transcript.
    pub signature: [u8; 64],
}

/// `MEMBER_LEFT` (0x21): a member left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberLeft {
    /// The room sequence number of this event.
    pub sequence: u64,
    /// The epoch the change belongs to.
    pub epoch: u64,
    /// The departed member id.
    pub member_id: u64,
    /// The host's signature over the room-event transcript.
    pub signature: [u8; 64],
}

/// `MEMBER_KICKED` (0x22): a member was kicked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberKicked {
    /// The room sequence number of this event.
    pub sequence: u64,
    /// The epoch the change belongs to.
    pub epoch: u64,
    /// The kicked member id.
    pub member_id: u64,
    /// The host's signature over the room-event transcript.
    pub signature: [u8; 64],
}

/// `JOIN_POLICY_CHANGED` (0x23): the host opened or locked admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPolicyChanged {
    /// The room sequence number of this event.
    pub sequence: u64,
    /// The epoch in which the policy changed.
    pub epoch: u64,
    /// Whether new join flows are enabled.
    pub open: bool,
    /// The host's signature over the room-event transcript.
    pub signature: [u8; 64],
}

/// `MEMBER_SNAPSHOT` (0x24): the full member list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSnapshot {
    /// The room sequence number of this event.
    pub sequence: u64,
    /// The epoch of the snapshot.
    pub epoch: u64,
    /// Every active member.
    pub members: Vec<SnapshotMember>,
    /// The host's signature over the room-event transcript.
    pub signature: [u8; 64],
}

/// Reads a 64-byte signature field.
fn read_signature(decoder: &mut StrictDecoder<'_>, field: u64) -> Result<[u8; 64], ProtocolError> {
    decoder
        .bytes()?
        .try_into()
        .map_err(|_| ProtocolError::InvalidField {
            field,
            detail: "signature must be 64 bytes".to_owned(),
        })
}

impl MemberJoined {
    /// Strictly decodes a member-joined payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut sequence = None;
        let mut epoch = None;
        let mut member_id = None;
        let mut nickname = None;
        let mut pubkey = None;
        let mut signature = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                sequence = Some(decoder.u64()?);
                Ok(())
            }
            2 => {
                epoch = Some(decoder.u64()?);
                Ok(())
            }
            3 => {
                member_id = Some(decoder.u64()?);
                Ok(())
            }
            4 => {
                nickname = Some(decoder.str()?.to_owned());
                Ok(())
            }
            5 => {
                let bytes = decoder.bytes()?;
                pubkey = Some(bytes.try_into().map_err(|_| ProtocolError::InvalidField {
                    field: 5,
                    detail: format!("ed25519 pubkey must be {ED25519_PUBKEY_LEN} bytes"),
                })?);
                Ok(())
            }
            6 => {
                signature = Some(read_signature(decoder, key)?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            sequence: sequence.ok_or(ProtocolError::MissingField { field: 1 })?,
            epoch: epoch.ok_or(ProtocolError::MissingField { field: 2 })?,
            member_id: member_id.ok_or(ProtocolError::MissingField { field: 3 })?,
            nickname: nickname.ok_or(ProtocolError::MissingField { field: 4 })?,
            ed25519_pubkey: pubkey.ok_or(ProtocolError::MissingField { field: 5 })?,
            signature: signature.ok_or(ProtocolError::MissingField { field: 6 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(6)?.u8(1)?.u64(self.sequence)?;
        encoder.u8(2)?.u64(self.epoch)?;
        encoder.u8(3)?.u64(self.member_id)?;
        encoder.u8(4)?.str(&self.nickname)?;
        encoder.u8(5)?.bytes(&self.ed25519_pubkey)?;
        encoder.u8(6)?.bytes(&self.signature)?;
        Ok(())
    }
}

/// Decodes a member-gone event (left or kicked).
fn decode_gone(
    decoder: &mut StrictDecoder<'_>,
) -> Result<(u64, u64, u64, [u8; 64]), ProtocolError> {
    let mut sequence = None;
    let mut epoch = None;
    let mut member_id = None;
    let mut signature = None;
    decoder.map_entries(|decoder, key| match key {
        1 => {
            sequence = Some(decoder.u64()?);
            Ok(())
        }
        2 => {
            epoch = Some(decoder.u64()?);
            Ok(())
        }
        3 => {
            member_id = Some(decoder.u64()?);
            Ok(())
        }
        4 => {
            signature = Some(read_signature(decoder, key)?);
            Ok(())
        }
        other => Err(ProtocolError::UnknownField { field: other }),
    })?;
    Ok((
        sequence.ok_or(ProtocolError::MissingField { field: 1 })?,
        epoch.ok_or(ProtocolError::MissingField { field: 2 })?,
        member_id.ok_or(ProtocolError::MissingField { field: 3 })?,
        signature.ok_or(ProtocolError::MissingField { field: 4 })?,
    ))
}

/// Encodes a member-gone event (left or kicked).
fn encode_gone(
    encoder: &mut Encoder<&mut Vec<u8>>,
    sequence: u64,
    epoch: u64,
    member_id: u64,
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    encoder.map(4)?.u8(1)?.u64(sequence)?;
    encoder.u8(2)?.u64(epoch)?;
    encoder.u8(3)?.u64(member_id)?;
    encoder.u8(4)?.bytes(signature)?;
    Ok(())
}

impl MemberLeft {
    /// Strictly decodes a member-left payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let (sequence, epoch, member_id, signature) = decode_gone(decoder)?;
        Ok(Self {
            sequence,
            epoch,
            member_id,
            signature,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encode_gone(
            encoder,
            self.sequence,
            self.epoch,
            self.member_id,
            &self.signature,
        )
    }
}

impl MemberKicked {
    /// Strictly decodes a member-kicked payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let (sequence, epoch, member_id, signature) = decode_gone(decoder)?;
        Ok(Self {
            sequence,
            epoch,
            member_id,
            signature,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encode_gone(
            encoder,
            self.sequence,
            self.epoch,
            self.member_id,
            &self.signature,
        )
    }
}

impl JoinPolicyChanged {
    /// Strictly decodes a join-policy change.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut sequence = None;
        let mut epoch = None;
        let mut open = None;
        let mut signature = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                sequence = Some(decoder.u64()?);
                Ok(())
            }
            2 => {
                epoch = Some(decoder.u64()?);
                Ok(())
            }
            3 => {
                open = Some(decoder.bool()?);
                Ok(())
            }
            4 => {
                signature = Some(read_signature(decoder, key)?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            sequence: sequence.ok_or(ProtocolError::MissingField { field: 1 })?,
            epoch: epoch.ok_or(ProtocolError::MissingField { field: 2 })?,
            open: open.ok_or(ProtocolError::MissingField { field: 3 })?,
            signature: signature.ok_or(ProtocolError::MissingField { field: 4 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(4)?.u8(1)?.u64(self.sequence)?;
        encoder.u8(2)?.u64(self.epoch)?;
        encoder.u8(3)?.bool(self.open)?;
        encoder.u8(4)?.bytes(&self.signature)?;
        Ok(())
    }
}

impl MemberSnapshot {
    /// Strictly decodes a member-snapshot payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut sequence = None;
        let mut epoch = None;
        let mut members = None;
        let mut signature = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                sequence = Some(decoder.u64()?);
                Ok(())
            }
            2 => {
                epoch = Some(decoder.u64()?);
                Ok(())
            }
            3 => {
                let mut decoded = Vec::new();
                decoder.array_entries::<ProtocolError, _>(|decoder| {
                    decoded.push(SnapshotMember::strict_decode(decoder)?);
                    Ok(())
                })?;
                members = Some(decoded);
                Ok(())
            }
            4 => {
                signature = Some(read_signature(decoder, key)?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            sequence: sequence.ok_or(ProtocolError::MissingField { field: 1 })?,
            epoch: epoch.ok_or(ProtocolError::MissingField { field: 2 })?,
            members: members.ok_or(ProtocolError::MissingField { field: 3 })?,
            signature: signature.ok_or(ProtocolError::MissingField { field: 4 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(4)?.u8(1)?.u64(self.sequence)?;
        encoder.u8(2)?.u64(self.epoch)?;
        encoder.u8(3)?.array(self.members.len() as u64)?;
        for member in &self.members {
            member.encode(encoder)?;
        }
        encoder.u8(4)?.bytes(&self.signature)?;
        Ok(())
    }
}
