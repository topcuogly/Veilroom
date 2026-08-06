//! Canonical signature transcripts (section 38).
//!
//! Every signature input is a deterministic byte string with explicit field
//! ordering and length encoding; transcripts are never delegated blindly to
//! a generic serializer, and a transcript of one message type cannot be
//! reused for another because each starts with a fixed domain label.
//!
//! Encoding of a field: labels and variable-length byte strings are
//! prefixed with a big-endian `u32` length; fixed-size fields (keys,
//! nonces, hashes) are appended raw; integers are appended in big-endian
//! order.

use crate::constants::{ED25519_PUBKEY_LEN, HMAC_LEN, NONCE_LEN, ROOM_SESSION_ID_LEN};
use sha2::{Digest, Sha256};

/// Domain label of the host-hello signature transcript.
pub const HOST_HELLO_LABEL: &str = "VEILROOM-HOST-HELLO-V1";

/// Domain label of the join-request signature transcript.
pub const JOIN_REQUEST_LABEL: &str = "VEILROOM-JOIN-REQUEST-V1";

/// Domain label of signed room-event transcripts.
pub const ROOM_EVENT_LABEL: &str = "VEILROOM-ROOM-EVENT-V1";

/// Domain label of chat-message signature transcripts (Stage 7).
pub const CHAT_MESSAGE_LABEL: &str = "VEILROOM-CHAT-MESSAGE-V1";

/// Domain label bound into epoch-key envelopes as additional data.
pub const EPOCH_WRAP_LABEL: &str = "VEILROOM-EPOCH-WRAP-V1";

/// HKDF info label of the per-member wrapping key.
pub const MEMBER_WRAP_KEY_LABEL: &str = "VEILROOM-MEMBER-WRAP-KEY-V1";

/// One member of a snapshot body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBodyMember {
    /// The member id.
    pub member_id: u64,
    /// The nickname.
    pub nickname: String,
    /// The color index.
    pub color_index: u8,
    /// Whether this is the host participant.
    pub is_host: bool,
    /// The member's Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
}

/// Builds a signed room-event transcript (section 5).
///
/// Field order:
/// `label | u8 version | fixed room_session_id | u64 sequence | u64 epoch |
/// u8 event_type | bytes body`.
pub fn room_event_transcript(
    version: u8,
    room_session_id: &[u8; 32],
    sequence: u64,
    epoch: u64,
    event_type: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut builder = TranscriptBuilder::new();
    builder
        .label(ROOM_EVENT_LABEL)
        .u8(version)
        .fixed(room_session_id)
        .u64(sequence)
        .u64(epoch)
        .u8(event_type)
        .bytes(body);
    builder.finish()
}

/// Body of a `MEMBER_JOINED` event.
pub fn member_joined_body(member_id: u64, nickname: &str, ed25519_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut builder = TranscriptBuilder::new();
    builder
        .u64(member_id)
        .bytes(nickname.as_bytes())
        .fixed(ed25519_pubkey);
    builder.finish()
}

/// Body of a `MEMBER_LEFT` or `MEMBER_KICKED` event.
pub fn member_gone_body(member_id: u64) -> Vec<u8> {
    let mut builder = TranscriptBuilder::new();
    builder.u64(member_id);
    builder.finish()
}

/// Canonical body of a signed join-policy change (`1` open, `0` locked).
pub fn join_policy_body(open: bool) -> Vec<u8> {
    vec![u8::from(open)]
}

/// Body of a `MEMBER_SNAPSHOT` event.
pub fn member_snapshot_body(members: &[SnapshotBodyMember]) -> Vec<u8> {
    let mut builder = TranscriptBuilder::new();
    builder.u64(members.len() as u64);
    for member in members {
        builder
            .u64(member.member_id)
            .bytes(member.nickname.as_bytes())
            .u8(member.color_index)
            .u8(u8::from(member.is_host))
            .fixed(&member.ed25519_pubkey);
    }
    builder.finish()
}

/// SHA-256 digest of the input.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Builds a canonical transcript from explicitly ordered fields.
#[derive(Debug, Default)]
pub struct TranscriptBuilder {
    buf: Vec<u8>,
}

impl TranscriptBuilder {
    /// Creates an empty transcript.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends the domain label: `u32` big-endian length, then the bytes.
    pub fn label(&mut self, label: &str) -> &mut Self {
        self.bytes(label.as_bytes())
    }

    /// Appends an 8-bit unsigned integer.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Appends a 16-bit unsigned integer, big-endian.
    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a 32-bit unsigned integer, big-endian.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a 64-bit unsigned integer, big-endian.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a length-prefixed byte string: `u32` big-endian length, then
    /// the bytes.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Appends fixed-size bytes without a length prefix (keys, nonces,
    /// hashes). The caller must ensure the size is protocol-fixed.
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Completes the transcript.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Inputs of the host-hello transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHelloTranscriptInput {
    /// The selected protocol version.
    pub version: u8,
    /// The onion address from the invitation.
    pub onion_address: String,
    /// The virtual port of the onion service.
    pub virtual_port: u16,
    /// The room session id.
    pub room_session_id: [u8; ROOM_SESSION_ID_LEN],
    /// The host's Ed25519 public key.
    pub host_ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// The host's X25519 public key.
    pub host_x25519_pubkey: [u8; 32],
    /// The client nonce.
    pub client_nonce: [u8; NONCE_LEN],
    /// The server nonce.
    pub server_nonce: [u8; NONCE_LEN],
    /// The SHA-256 hash of the invitation token.
    pub token_hash: [u8; HMAC_LEN],
    /// The version offered by the client.
    pub offered_version: u8,
    /// The feature bits offered by the client.
    pub client_features: u32,
}

/// Builds the host-hello transcript (section 36).
///
/// Field order:
/// `label | u8 version | bytes onion_address | u16 virtual_port |
/// fixed room_session_id | fixed host_ed25519_pubkey | fixed host_x25519_pubkey | fixed client_nonce |
/// fixed server_nonce | fixed token_hash | u8 offered_version |
/// u32 client_features`.
pub fn host_hello_transcript(input: &HostHelloTranscriptInput) -> Vec<u8> {
    let mut builder = TranscriptBuilder::new();
    builder
        .label(HOST_HELLO_LABEL)
        .u8(input.version)
        .bytes(input.onion_address.as_bytes())
        .u16(input.virtual_port)
        .fixed(&input.room_session_id)
        .fixed(&input.host_ed25519_pubkey)
        .fixed(&input.host_x25519_pubkey)
        .fixed(&input.client_nonce)
        .fixed(&input.server_nonce)
        .fixed(&input.token_hash)
        .u8(input.offered_version)
        .u32(input.client_features);
    builder.finish()
}

/// Inputs of the join-request transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequestTranscriptInput {
    /// The selected protocol version.
    pub version: u8,
    /// The room session id.
    pub room_session_id: [u8; ROOM_SESSION_ID_LEN],
    /// The client nonce.
    pub client_nonce: [u8; NONCE_LEN],
    /// The server nonce.
    pub server_nonce: [u8; NONCE_LEN],
    /// The requested nickname.
    pub nickname: String,
    /// The SHA-256 hash of the introduction message (empty message hashes
    /// to SHA-256 of the empty string).
    pub introduction_hash: [u8; HMAC_LEN],
    /// The participant's Ed25519 public key.
    pub participant_ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    /// The participant's X25519 public key.
    pub participant_x25519_pubkey: [u8; 32],
    /// The onion address from the invitation.
    pub onion_address: String,
    /// The SHA-256 hash of the invitation token.
    pub token_hash: [u8; HMAC_LEN],
}

/// Builds the join-request transcript (section 37).
///
/// Field order:
/// `label | u8 version | fixed room_session_id | fixed client_nonce |
/// fixed server_nonce | bytes nickname | fixed introduction_hash |
/// fixed participant_ed25519_pubkey | fixed participant_x25519_pubkey |
/// bytes onion_address | fixed token_hash`.
pub fn join_request_transcript(input: &JoinRequestTranscriptInput) -> Vec<u8> {
    let mut builder = TranscriptBuilder::new();
    builder
        .label(JOIN_REQUEST_LABEL)
        .u8(input.version)
        .fixed(&input.room_session_id)
        .fixed(&input.client_nonce)
        .fixed(&input.server_nonce)
        .bytes(input.nickname.as_bytes())
        .fixed(&input.introduction_hash)
        .fixed(&input.participant_ed25519_pubkey)
        .fixed(&input.participant_x25519_pubkey)
        .bytes(input.onion_address.as_bytes())
        .fixed(&input.token_hash);
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_known_vector() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn sha256_of_empty_input_matches_the_known_vector() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn host_hello_transcript_matches_the_test_vector() {
        // Fixed inputs; test keys are NOT production secrets.
        let input = HostHelloTranscriptInput {
            version: 1,
            onion_address: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
                .to_owned(),
            virtual_port: 80,
            room_session_id: [0x01u8; ROOM_SESSION_ID_LEN],
            host_ed25519_pubkey: [0x02u8; ED25519_PUBKEY_LEN],
            host_x25519_pubkey: [0x06u8; 32],
            client_nonce: [0x03u8; NONCE_LEN],
            server_nonce: [0x04u8; NONCE_LEN],
            token_hash: [0x05u8; HMAC_LEN],
            offered_version: 1,
            client_features: 0,
        };

        let transcript = host_hello_transcript(&input);

        let mut expected = Vec::new();
        // label "VEILROOM-HOST-HELLO-V1" (22 bytes)
        expected.extend_from_slice(&22u32.to_be_bytes());
        expected.extend_from_slice(b"VEILROOM-HOST-HELLO-V1");
        expected.push(1);
        // onion address (len-prefixed)
        expected.extend_from_slice(&(input.onion_address.len() as u32).to_be_bytes());
        expected.extend_from_slice(input.onion_address.as_bytes());
        expected.extend_from_slice(&80u16.to_be_bytes());
        expected.extend_from_slice(&input.room_session_id);
        expected.extend_from_slice(&input.host_ed25519_pubkey);
        expected.extend_from_slice(&input.host_x25519_pubkey);
        expected.extend_from_slice(&input.client_nonce);
        expected.extend_from_slice(&input.server_nonce);
        expected.extend_from_slice(&input.token_hash);
        expected.push(1);
        expected.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(transcript, expected);
    }

    #[test]
    fn join_request_transcript_matches_the_test_vector() {
        let input = JoinRequestTranscriptInput {
            version: 1,
            room_session_id: [0x11u8; ROOM_SESSION_ID_LEN],
            client_nonce: [0x12u8; NONCE_LEN],
            server_nonce: [0x13u8; NONCE_LEN],
            nickname: "deniz".to_owned(),
            introduction_hash: [0x14u8; HMAC_LEN],
            participant_ed25519_pubkey: [0x15u8; ED25519_PUBKEY_LEN],
            participant_x25519_pubkey: [0x16u8; 32],
            onion_address: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
                .to_owned(),
            token_hash: [0x17u8; HMAC_LEN],
        };

        let transcript = join_request_transcript(&input);

        let mut expected = Vec::new();
        // label "VEILROOM-JOIN-REQUEST-V1" (24 bytes)
        expected.extend_from_slice(&24u32.to_be_bytes());
        expected.extend_from_slice(b"VEILROOM-JOIN-REQUEST-V1");
        expected.push(1);
        expected.extend_from_slice(&input.room_session_id);
        expected.extend_from_slice(&input.client_nonce);
        expected.extend_from_slice(&input.server_nonce);
        // nickname "deniz" (5 bytes)
        expected.extend_from_slice(&5u32.to_be_bytes());
        expected.extend_from_slice(b"deniz");
        expected.extend_from_slice(&input.introduction_hash);
        expected.extend_from_slice(&input.participant_ed25519_pubkey);
        expected.extend_from_slice(&input.participant_x25519_pubkey);
        // onion address (len-prefixed)
        expected.extend_from_slice(&(input.onion_address.len() as u32).to_be_bytes());
        expected.extend_from_slice(input.onion_address.as_bytes());
        expected.extend_from_slice(&input.token_hash);
        assert_eq!(transcript, expected);
    }

    #[test]
    fn transcripts_are_deterministic() {
        let a = host_hello_transcript(&HostHelloTranscriptInput {
            version: 1,
            onion_address: "onion.onion".to_owned(),
            virtual_port: 80,
            room_session_id: [0u8; 32],
            host_ed25519_pubkey: [1u8; 32],
            host_x25519_pubkey: [5u8; 32],
            client_nonce: [2u8; 16],
            server_nonce: [3u8; 16],
            token_hash: [4u8; 32],
            offered_version: 1,
            client_features: 0,
        });
        let b = host_hello_transcript(&HostHelloTranscriptInput {
            version: 1,
            onion_address: "onion.onion".to_owned(),
            virtual_port: 80,
            room_session_id: [0u8; 32],
            host_ed25519_pubkey: [1u8; 32],
            host_x25519_pubkey: [5u8; 32],
            client_nonce: [2u8; 16],
            server_nonce: [3u8; 16],
            token_hash: [4u8; 32],
            offered_version: 1,
            client_features: 0,
        });
        assert_eq!(a, b);
    }

    #[test]
    fn labels_cannot_be_cross_reused() {
        // The two transcripts start with different domain labels.
        let host = host_hello_transcript(&HostHelloTranscriptInput {
            version: 1,
            onion_address: "x.onion".to_owned(),
            virtual_port: 80,
            room_session_id: [0u8; 32],
            host_ed25519_pubkey: [0u8; 32],
            host_x25519_pubkey: [0u8; 32],
            client_nonce: [0u8; 16],
            server_nonce: [0u8; 16],
            token_hash: [0u8; 32],
            offered_version: 1,
            client_features: 0,
        });
        let join = join_request_transcript(&JoinRequestTranscriptInput {
            version: 1,
            room_session_id: [0u8; 32],
            client_nonce: [0u8; 16],
            server_nonce: [0u8; 16],
            nickname: String::new(),
            introduction_hash: [0u8; 32],
            participant_ed25519_pubkey: [0u8; 32],
            participant_x25519_pubkey: [0u8; 32],
            onion_address: "x.onion".to_owned(),
            token_hash: [0u8; 32],
        });
        assert_ne!(host, join);
    }
}
