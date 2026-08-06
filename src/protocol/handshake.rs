//! Handshake and admission message schemas (Stage 4, sections 8-12 and 36-37).
//!
//! These are the typed payloads of message types `0x01..=0x08`. Like the
//! Stage 2 control messages, they are encoded deterministically and decoded
//! strictly (unknown fields, duplicate keys, wrong lengths and malformed
//! input are rejected). Signature *verification* over the transcripts in
//! `crate::crypto::transcript` arrives in Stage 6; this module validates
//! the structure and sizes of the signature fields.

use minicbor::Encoder;

use crate::constants::{
    ED25519_PUBKEY_LEN, ED25519_SIGNATURE_LEN, HMAC_LEN, NONCE_LEN, ROOM_SESSION_ID_LEN, SALT_LEN,
    X25519_PUBKEY_LEN,
};
use crate::protocol::messages::ProtocolError;
use crate::protocol::session::RoomSessionId;
use crate::protocol::strict::StrictDecoder;
use crate::validation::{validate_intro, validate_nickname};

/// Maximum length of a rejection reason in bytes.
pub const MAX_REJECT_REASON_BYTES: usize = 256;

/// Reads a fixed-size byte field.
fn fixed_bytes<const N: usize>(
    decoder: &mut StrictDecoder<'_>,
    field: u64,
) -> Result<[u8; N], ProtocolError> {
    let bytes = decoder.bytes()?;
    let array: [u8; N] = bytes.try_into().map_err(|_| ProtocolError::InvalidField {
        field,
        detail: format!("expected {N} bytes, found {}", bytes.len()),
    })?;
    Ok(array)
}

/// Appends a fixed-size byte field to the encoder.
fn encode_fixed<const N: usize>(
    encoder: &mut Encoder<&mut Vec<u8>>,
    field: u64,
    bytes: &[u8; N],
) -> Result<(), ProtocolError> {
    encoder.u8(field as u8)?.bytes(bytes)?;
    Ok(())
}

/// `CLIENT_HELLO` (0x02): the participant offers a version and features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// The protocol version offered by the client.
    pub version: u8,
    /// A fresh client nonce.
    pub client_nonce: [u8; NONCE_LEN],
    /// Feature bits; V1 defines no optional features and requires zero.
    pub features: u32,
}

impl ClientHello {
    /// Constructs a client hello.
    pub fn new(version: u8, client_nonce: [u8; NONCE_LEN], features: u32) -> Self {
        Self {
            version,
            client_nonce,
            features,
        }
    }

    /// Strictly decodes a client-hello payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut version = None;
        let mut client_nonce = None;
        let mut features = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                version = Some(decoder.u8()?);
                Ok(())
            }
            2 => {
                client_nonce = Some(fixed_bytes::<NONCE_LEN>(decoder, key)?);
                Ok(())
            }
            3 => {
                features = Some(decoder.u32()?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            version: version.ok_or(ProtocolError::MissingField { field: 1 })?,
            client_nonce: client_nonce.ok_or(ProtocolError::MissingField { field: 2 })?,
            features: features.ok_or(ProtocolError::MissingField { field: 3 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(3)?.u8(1)?.u8(self.version)?;
        encode_fixed(encoder, 2, &self.client_nonce)?;
        encoder.u8(3)?.u32(self.features)?;
        Ok(())
    }
}

/// `HOST_HELLO` (0x01): the host answers with its trust-chain material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHello {
    /// The protocol version selected by the host.
    pub version: u8,
    /// The room session id.
    pub room_session_id: RoomSessionId,
    /// The host's ephemeral Ed25519 public key.
    pub host_ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// The host's ephemeral X25519 public key (for the per-member key
    /// channel, section 15).
    pub host_x25519_pubkey: [u8; X25519_PUBKEY_LEN],
    /// A fresh server nonce.
    pub server_nonce: [u8; NONCE_LEN],
    /// The host's signature over the host-hello transcript.
    pub host_signature: [u8; ED25519_SIGNATURE_LEN],
}

impl HostHello {
    /// Constructs a host hello.
    pub fn new(
        version: u8,
        room_session_id: RoomSessionId,
        host_ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
        host_x25519_pubkey: [u8; X25519_PUBKEY_LEN],
        server_nonce: [u8; NONCE_LEN],
        host_signature: [u8; ED25519_SIGNATURE_LEN],
    ) -> Self {
        Self {
            version,
            room_session_id,
            host_ed25519_pubkey,
            host_x25519_pubkey,
            server_nonce,
            host_signature,
        }
    }

    /// Strictly decodes a host-hello payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut version = None;
        let mut room_session_id = None;
        let mut host_pubkey = None;
        let mut host_x25519_pubkey = None;
        let mut server_nonce = None;
        let mut signature = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                version = Some(decoder.u8()?);
                Ok(())
            }
            2 => {
                room_session_id = Some(RoomSessionId::from(fixed_bytes::<ROOM_SESSION_ID_LEN>(
                    decoder, key,
                )?));
                Ok(())
            }
            3 => {
                host_pubkey = Some(fixed_bytes::<ED25519_PUBKEY_LEN>(decoder, key)?);
                Ok(())
            }
            4 => {
                host_x25519_pubkey = Some(fixed_bytes::<X25519_PUBKEY_LEN>(decoder, key)?);
                Ok(())
            }
            5 => {
                server_nonce = Some(fixed_bytes::<NONCE_LEN>(decoder, key)?);
                Ok(())
            }
            6 => {
                signature = Some(fixed_bytes::<ED25519_SIGNATURE_LEN>(decoder, key)?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            version: version.ok_or(ProtocolError::MissingField { field: 1 })?,
            room_session_id: room_session_id.ok_or(ProtocolError::MissingField { field: 2 })?,
            host_ed25519_pubkey: host_pubkey.ok_or(ProtocolError::MissingField { field: 3 })?,
            host_x25519_pubkey: host_x25519_pubkey
                .ok_or(ProtocolError::MissingField { field: 4 })?,
            server_nonce: server_nonce.ok_or(ProtocolError::MissingField { field: 5 })?,
            host_signature: signature.ok_or(ProtocolError::MissingField { field: 6 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(6)?.u8(1)?.u8(self.version)?;
        encode_fixed(encoder, 2, self.room_session_id.as_bytes())?;
        encode_fixed(encoder, 3, &self.host_ed25519_pubkey)?;
        encode_fixed(encoder, 4, &self.host_x25519_pubkey)?;
        encode_fixed(encoder, 5, &self.server_nonce)?;
        encode_fixed(encoder, 6, &self.host_signature)?;
        Ok(())
    }
}

/// `TOKEN_VERIFY` (0x03): the participant presents the invitation token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenVerify {
    /// The invitation token bytes (16..=32 bytes).
    pub token: Vec<u8>,
}

impl TokenVerify {
    /// Constructs a token-verify message, validating the token length.
    pub fn new(token: Vec<u8>) -> Result<Self, ProtocolError> {
        if !(16..=32).contains(&token.len()) {
            return Err(ProtocolError::InvalidField {
                field: 1,
                detail: format!("token must be 16..=32 bytes, found {}", token.len()),
            });
        }
        Ok(Self { token })
    }

    /// Strictly decodes a token-verify payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut token = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                token = Some(decoder.bytes()?.to_vec());
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        let token = token.ok_or(ProtocolError::MissingField { field: 1 })?;
        Self::new(token)
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(1)?.u8(1)?.bytes(&self.token)?;
        Ok(())
    }
}

/// `PASSWORD_CHALLENGE` (0x04): the host challenges the participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordChallenge {
    /// Argon2id memory cost in KiB.
    pub m_cost: u32,
    /// Argon2id time cost.
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u8,
    /// The verifier salt.
    pub salt: [u8; SALT_LEN],
    /// A fresh per-connection challenge nonce.
    pub challenge_nonce: [u8; NONCE_LEN],
}

impl PasswordChallenge {
    /// Constructs a password challenge.
    pub fn new(
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
        salt: [u8; SALT_LEN],
        challenge_nonce: [u8; NONCE_LEN],
    ) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
            salt,
            challenge_nonce,
        }
    }

    /// Strictly decodes a password-challenge payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut m_cost = None;
        let mut t_cost = None;
        let mut p_cost = None;
        let mut salt = None;
        let mut challenge_nonce = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                m_cost = Some(decoder.u32()?);
                Ok(())
            }
            2 => {
                t_cost = Some(decoder.u32()?);
                Ok(())
            }
            3 => {
                p_cost = Some(decoder.u8()?);
                Ok(())
            }
            4 => {
                salt = Some(fixed_bytes::<SALT_LEN>(decoder, key)?);
                Ok(())
            }
            5 => {
                challenge_nonce = Some(fixed_bytes::<NONCE_LEN>(decoder, key)?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            m_cost: m_cost.ok_or(ProtocolError::MissingField { field: 1 })?,
            t_cost: t_cost.ok_or(ProtocolError::MissingField { field: 2 })?,
            p_cost: p_cost.ok_or(ProtocolError::MissingField { field: 3 })?,
            salt: salt.ok_or(ProtocolError::MissingField { field: 4 })?,
            challenge_nonce: challenge_nonce.ok_or(ProtocolError::MissingField { field: 5 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(5)?.u8(1)?.u32(self.m_cost)?;
        encoder.u8(2)?.u32(self.t_cost)?;
        encoder.u8(3)?.u8(self.p_cost)?;
        encode_fixed(encoder, 4, &self.salt)?;
        encode_fixed(encoder, 5, &self.challenge_nonce)?;
        Ok(())
    }
}

/// `CHALLENGE_PROOF` (0x05): the participant answers the password challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeProof {
    /// The HMAC-SHA-256 proof.
    pub proof: [u8; HMAC_LEN],
}

impl ChallengeProof {
    /// Constructs a challenge proof.
    pub fn new(proof: [u8; HMAC_LEN]) -> Self {
        Self { proof }
    }

    /// Strictly decodes a challenge-proof payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut proof = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                proof = Some(fixed_bytes::<HMAC_LEN>(decoder, key)?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            proof: proof.ok_or(ProtocolError::MissingField { field: 1 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(1)?;
        encode_fixed(encoder, 1, &self.proof)?;
        Ok(())
    }
}

/// `JOIN_REQUEST` (0x06): the participant applies for membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// The requested nickname (NFC-normalized).
    pub nickname: String,
    /// The optional introduction message (host-visible only).
    pub introduction: Option<String>,
    /// The participant's ephemeral Ed25519 public key.
    pub ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// The participant's ephemeral X25519 public key.
    pub x25519_pubkey: [u8; X25519_PUBKEY_LEN],
    /// The participant's signature over the join-request transcript
    /// (verified in Stage 6).
    pub signature: [u8; ED25519_SIGNATURE_LEN],
}

impl JoinRequest {
    /// Constructs a join request, validating nickname and introduction.
    pub fn new(
        nickname: String,
        introduction: Option<String>,
        ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
        x25519_pubkey: [u8; X25519_PUBKEY_LEN],
        signature: [u8; ED25519_SIGNATURE_LEN],
    ) -> Result<Self, ProtocolError> {
        let limits = crate::limits::Limits::default();
        let nickname = validate_nickname(&nickname, &limits).map_err(ProtocolError::Validation)?;
        if let Some(introduction) = &introduction {
            validate_intro(introduction, &limits).map_err(ProtocolError::Validation)?;
        }
        Ok(Self {
            nickname,
            introduction,
            ed25519_pubkey,
            x25519_pubkey,
            signature,
        })
    }

    /// Strictly decodes a join-request payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut nickname = None;
        let mut introduction = None;
        let mut ed25519_pubkey = None;
        let mut x25519_pubkey = None;
        let mut signature = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                nickname = Some(decoder.str()?.to_owned());
                Ok(())
            }
            2 => {
                introduction = Some(decoder.str()?.to_owned());
                Ok(())
            }
            3 => {
                ed25519_pubkey = Some(fixed_bytes::<ED25519_PUBKEY_LEN>(decoder, key)?);
                Ok(())
            }
            4 => {
                x25519_pubkey = Some(fixed_bytes::<X25519_PUBKEY_LEN>(decoder, key)?);
                Ok(())
            }
            5 => {
                signature = Some(fixed_bytes::<ED25519_SIGNATURE_LEN>(decoder, key)?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Self::new(
            nickname.ok_or(ProtocolError::MissingField { field: 1 })?,
            introduction,
            ed25519_pubkey.ok_or(ProtocolError::MissingField { field: 3 })?,
            x25519_pubkey.ok_or(ProtocolError::MissingField { field: 4 })?,
            signature.ok_or(ProtocolError::MissingField { field: 5 })?,
        )
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        let entries = if self.introduction.is_some() { 5 } else { 4 };
        encoder.map(entries)?.u8(1)?.str(&self.nickname)?;
        if let Some(introduction) = &self.introduction {
            encoder.u8(2)?.str(introduction)?;
        }
        encode_fixed(encoder, 3, &self.ed25519_pubkey)?;
        encode_fixed(encoder, 4, &self.x25519_pubkey)?;
        encode_fixed(encoder, 5, &self.signature)?;
        Ok(())
    }
}

/// `JOIN_ACCEPTED` (0x07): the host admits the participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinAccepted {
    /// The room-lifetime member id assigned to the participant.
    pub member_id: u64,
}

impl JoinAccepted {
    /// Constructs a join-accepted message.
    pub const fn new(member_id: u64) -> Self {
        Self { member_id }
    }

    /// Strictly decodes a join-accepted payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut member_id = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                member_id = Some(decoder.u64()?);
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Ok(Self {
            member_id: member_id.ok_or(ProtocolError::MissingField { field: 1 })?,
        })
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        encoder.map(1)?.u8(1)?.u64(self.member_id)?;
        Ok(())
    }
}

/// `JOIN_REJECTED` (0x08): the host denies the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRejected {
    /// An optional rejection reason.
    pub reason: Option<String>,
}

impl JoinRejected {
    /// Constructs a join-rejected message, validating the reason.
    pub fn new(reason: Option<String>) -> Result<Self, ProtocolError> {
        let reason = match reason {
            Some(reason) if reason.is_empty() => None,
            Some(reason) => {
                if reason.len() > MAX_REJECT_REASON_BYTES {
                    return Err(ProtocolError::InvalidField {
                        field: 1,
                        detail: format!(
                            "reason must be at most {MAX_REJECT_REASON_BYTES} bytes, found {}",
                            reason.len()
                        ),
                    });
                }
                if crate::validation::contains_control_char(&reason) {
                    return Err(ProtocolError::InvalidField {
                        field: 1,
                        detail: "reason contains control characters".to_owned(),
                    });
                }
                Some(reason)
            }
            None => None,
        };
        Ok(Self { reason })
    }

    /// Strictly decodes a join-rejected payload.
    pub fn strict_decode(decoder: &mut StrictDecoder<'_>) -> Result<Self, ProtocolError> {
        let mut reason = None;
        decoder.map_entries(|decoder, key| match key {
            1 => {
                reason = Some(decoder.str()?.to_owned());
                Ok(())
            }
            other => Err(ProtocolError::UnknownField { field: other }),
        })?;
        Self::new(reason)
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError> {
        if let Some(reason) = &self.reason {
            encoder.map(1)?.u8(1)?.str(reason)?;
        } else {
            encoder.map(0)?;
        }
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

    fn roundtrip<T: PartialEq + std::fmt::Debug>(
        value: &T,
        encode: fn(&T, &mut Encoder<&mut Vec<u8>>) -> Result<(), ProtocolError>,
        schema: fn(&mut StrictDecoder<'_>) -> Result<T, ProtocolError>,
    ) -> T {
        let mut out = Vec::new();
        let mut encoder = Encoder::new(&mut out);
        encode(value, &mut encoder).unwrap();
        decode(&out, schema).unwrap()
    }

    #[test]
    fn client_hello_roundtrips() {
        let message = ClientHello::new(1, [0x21; 16], 0);
        roundtrip(&message, ClientHello::encode, ClientHello::strict_decode);
    }

    #[test]
    fn host_hello_roundtrips() {
        let message = HostHello::new(
            1,
            RoomSessionId::from([0x31; 32]),
            [0x32; 32],
            [0x35; 32],
            [0x33; 16],
            [0x34; 64],
        );
        roundtrip(&message, HostHello::encode, HostHello::strict_decode);
    }

    #[test]
    fn token_verify_roundtrips_and_validates_length() {
        let message = TokenVerify::new(vec![0x41; 16]).unwrap();
        roundtrip(&message, TokenVerify::encode, TokenVerify::strict_decode);

        assert!(TokenVerify::new(vec![0x41; 15]).is_err());
        assert!(TokenVerify::new(vec![0x41; 33]).is_err());
        assert!(TokenVerify::new(Vec::new()).is_err());
    }

    #[test]
    fn password_challenge_roundtrips() {
        let message = PasswordChallenge::new(19456, 2, 1, [0x51; 16], [0x52; 16]);
        roundtrip(
            &message,
            PasswordChallenge::encode,
            PasswordChallenge::strict_decode,
        );
    }

    #[test]
    fn challenge_proof_roundtrips() {
        let message = ChallengeProof::new([0x61; 32]);
        roundtrip(
            &message,
            ChallengeProof::encode,
            ChallengeProof::strict_decode,
        );
    }

    #[test]
    fn join_request_roundtrips_with_and_without_introduction() {
        let with = JoinRequest::new(
            "deniz".to_owned(),
            Some("hello".to_owned()),
            [0x71; 32],
            [0x72; 32],
            [0x73; 64],
        )
        .unwrap();
        let decoded = roundtrip(&with, JoinRequest::encode, JoinRequest::strict_decode);
        assert_eq!(decoded, with);

        let without =
            JoinRequest::new("deniz".to_owned(), None, [0x71; 32], [0x72; 32], [0x73; 64]).unwrap();
        let decoded = roundtrip(&without, JoinRequest::encode, JoinRequest::strict_decode);
        assert_eq!(decoded, without);
    }

    #[test]
    fn join_accepted_and_rejected_roundtrip() {
        let accepted = JoinAccepted::new(42);
        let decoded = roundtrip(&accepted, JoinAccepted::encode, JoinAccepted::strict_decode);
        assert_eq!(decoded, accepted);

        let rejected = JoinRejected::new(Some("full".to_owned())).unwrap();
        let decoded = roundtrip(&rejected, JoinRejected::encode, JoinRejected::strict_decode);
        assert_eq!(decoded, rejected);

        let bare = JoinRejected::new(None).unwrap();
        let decoded = roundtrip(&bare, JoinRejected::encode, JoinRejected::strict_decode);
        assert_eq!(decoded, bare);
    }

    #[test]
    fn wrong_fixed_lengths_are_rejected() {
        // ClientHello with a 15-byte nonce.
        let mut payload = vec![0xa2, 0x01, 0x01, 0x02, 0x4f];
        payload.extend([0x21; 15]);
        assert!(matches!(
            decode(&payload, ClientHello::strict_decode),
            Err(ProtocolError::Cbor(_) | ProtocolError::InvalidField { .. })
        ));
        // HostHello with a 31-byte session id.
        let mut payload = vec![0xa2, 0x01, 0x01, 0x02, 0x5f];
        payload.extend([0x31; 31]);
        assert!(matches!(
            decode(&payload, HostHello::strict_decode),
            Err(ProtocolError::Cbor(_) | ProtocolError::InvalidField { .. })
        ));
    }

    #[test]
    fn join_request_validates_nickname_and_introduction() {
        // Nickname with a control character.
        assert!(
            JoinRequest::new(
                "bad\u{1b}name".to_owned(),
                None,
                [0u8; 32],
                [0u8; 32],
                [0u8; 64],
            )
            .is_err()
        );
        // Nickname too long (33 scalars).
        assert!(JoinRequest::new("a".repeat(33), None, [0u8; 32], [0u8; 32], [0u8; 64],).is_err());
        // Multi-line introduction.
        assert!(
            JoinRequest::new(
                "ok".to_owned(),
                Some("line one\nline two".to_owned()),
                [0u8; 32],
                [0u8; 32],
                [0u8; 64],
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // ClientHello with an unknown field 9.
        assert!(matches!(
            decode(&[0xa1, 0x09, 0x01], ClientHello::strict_decode),
            Err(ProtocolError::UnknownField { field: 9 })
        ));
    }

    #[test]
    fn duplicate_fields_are_rejected() {
        // JoinAccepted with field 1 twice.
        assert!(matches!(
            decode(&[0xa2, 0x01, 0x07, 0x01, 0x08], JoinAccepted::strict_decode),
            Err(ProtocolError::Cbor(
                crate::protocol::strict::StrictError::DuplicateMapKey { key: 1 }
            ))
        ));
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        // ChallengeProof without a proof.
        assert!(matches!(
            decode(&[0xa0], ChallengeProof::strict_decode),
            Err(ProtocolError::MissingField { field: 1 })
        ));
    }

    #[test]
    fn reject_reason_rules_are_enforced() {
        assert!(JoinRejected::new(Some("x".repeat(257))).is_err());
        assert!(JoinRejected::new(Some("bad\u{1b}".to_owned())).is_err());
        assert_eq!(JoinRejected::new(Some(String::new())).unwrap().reason, None);
    }
}
