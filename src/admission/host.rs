//! Host-side admission flow (sections 8-12, 36 and 37).
//!
//! One `HostAdmission` instance tracks one connection through the admission
//! gate: token verification, password challenge-response, and the join
//! application. The flow is driven by typed messages; the room-level queue
//! and join policy live in the admission gate.
//!
//! Stage 6 completes the trust chain: the flow signs the host-hello
//! transcript with the host's Ed25519 key and verifies the participant's
//! join-request signature.

use crate::admission::queue::JoinApplication;
use crate::admission::{AdmissionError, JoinPolicy};
use crate::constants::NONCE_LEN;
use crate::crypto::identity::{HostIdentity, verify_ed25519};
use crate::crypto::password::PasswordVerifier;
use crate::crypto::transcript::{JoinRequestTranscriptInput, join_request_transcript, sha256};
use crate::crypto::{CryptoError, SecretBytes, random_bytes};
use crate::protocol::handshake::{
    ChallengeProof, ClientHello, HostHello, JoinAccepted, JoinRejected,
    JoinRequest as JoinRequestMessage, PasswordChallenge, TokenVerify,
};
use crate::protocol::messages::Message;
use crate::protocol::session::RoomSessionId;

/// The outcome of a host-side admission step.
#[derive(Debug)]
pub enum HostAdmissionReply {
    /// A message to send back to the connection.
    Message(Message),
    /// The connection submitted a join application; the room must queue it
    /// and notify the host.
    JoinRequested(JoinApplication),
}

/// Per-connection state of the host-side admission flow.
#[derive(Debug)]
pub struct HostAdmission<'a> {
    room_session_id: RoomSessionId,
    server_nonce: [u8; NONCE_LEN],
    token: SecretBytes,
    verifier: PasswordVerifier,
    host_identity: &'a HostIdentity,
    onion_address: String,
    client_nonce: Option<[u8; NONCE_LEN]>,
    challenge_nonce: Option<[u8; NONCE_LEN]>,
    state: HostState,
}

/// The current stage of a host-side admission flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    /// Waiting for the initial client hello.
    AwaitingHello,
    /// Waiting for the invitation token.
    AwaitingToken,
    /// Waiting for the password proof.
    AwaitingProof,
    /// Waiting for the join application.
    AwaitingJoinForm,
    /// The application has been decided.
    Decided,
}

impl<'a> HostAdmission<'a> {
    /// Creates a fresh host-side admission flow for one connection.
    ///
    /// `token` is the room's current invitation token (a bearer secret,
    /// held in a zeroizing buffer); `verifier` is the room's password
    /// verifier; `host_identity` signs the host hello.
    pub fn new(
        room_session_id: RoomSessionId,
        token: SecretBytes,
        verifier: PasswordVerifier,
        host_identity: &'a HostIdentity,
        onion_address: String,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            room_session_id,
            server_nonce: random_bytes::<NONCE_LEN>()?,
            token,
            verifier,
            host_identity,
            onion_address,
            client_nonce: None,
            challenge_nonce: None,
            state: HostState::AwaitingHello,
        })
    }

    /// The server nonce of this flow.
    pub const fn server_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.server_nonce
    }

    /// The client nonce, once a client hello has arrived.
    pub const fn client_nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        self.client_nonce.as_ref()
    }

    /// The current state of the flow.
    pub const fn state(&self) -> HostState {
        self.state
    }

    /// Answers a client hello with the signed host hello.
    ///
    /// Validates the offered version and feature bits, then signs the
    /// host-hello transcript with the host identity.
    pub fn on_client_hello(
        &mut self,
        hello: &ClientHello,
        virtual_port: u16,
    ) -> Result<Message, AdmissionError> {
        if self.state != HostState::AwaitingHello {
            return Err(AdmissionError::UnexpectedMessage);
        }
        if hello.version != 1 {
            return Err(AdmissionError::UnsupportedVersion {
                found: hello.version,
            });
        }
        if hello.features != 0 {
            return Err(AdmissionError::UnsupportedFeatures {
                features: hello.features,
            });
        }
        self.client_nonce = Some(hello.client_nonce);
        // The token hash binds the host hello to the room invitation. It is
        // an unkeyed SHA-256 disclosed before token verification, which
        // makes it an offline guessing oracle for the token; this is
        // accepted because the token is always app-generated with at least
        // 128 bits of entropy (the V1 default is 256 bits), so guessing is
        // infeasible. The hash must not be an HMAC: both sides have to
        // derive it from the token alone, and the room session id that
        // could serve as a key is itself public in the hello.
        let token_hash = sha256(&self.token[..]);
        let transcript = crate::crypto::transcript::host_hello_transcript(
            &crate::crypto::transcript::HostHelloTranscriptInput {
                version: 1,
                onion_address: self.onion_address.clone(),
                virtual_port,
                room_session_id: *self.room_session_id.as_bytes(),
                host_ed25519_pubkey: self.host_identity.ed25519_pubkey(),
                host_x25519_pubkey: self.host_identity.x25519_pubkey(),
                client_nonce: hello.client_nonce,
                server_nonce: self.server_nonce,
                token_hash,
                offered_version: hello.version,
                client_features: hello.features,
            },
        );
        let signature = self.host_identity.sign(&transcript);
        self.state = HostState::AwaitingToken;
        Ok(Message::HostHello(HostHello::new(
            1,
            self.room_session_id,
            self.host_identity.ed25519_pubkey(),
            self.host_identity.x25519_pubkey(),
            self.server_nonce,
            signature,
        )))
    }

    /// Handles one message from the connection.
    ///
    /// `policy` is the current room join policy; it is checked when a join
    /// application arrives, after the participant's join signature has been
    /// verified.
    pub fn on_message(
        &mut self,
        message: &Message,
        policy: JoinPolicy,
    ) -> Result<Option<HostAdmissionReply>, AdmissionError> {
        match (self.state, message) {
            (HostState::AwaitingToken, Message::TokenVerify(verify)) => self.handle_token(verify),
            (HostState::AwaitingProof, Message::ChallengeProof(proof)) => self.handle_proof(proof),
            (HostState::AwaitingJoinForm, Message::JoinRequest(request)) => {
                self.handle_join_request(request, policy)
            }
            _ => Err(AdmissionError::UnexpectedMessage),
        }
    }

    /// Builds the `JOIN_ACCEPTED` message for an admitted request.
    pub fn accept(&self, member_id: u64) -> Message {
        Message::JoinAccepted(JoinAccepted::new(member_id))
    }

    /// Builds the `JOIN_REJECTED` message for a denied request.
    pub fn reject(&self, reason: Option<String>) -> Result<Message, AdmissionError> {
        Ok(Message::JoinRejected(JoinRejected::new(reason)?))
    }

    fn handle_token(
        &mut self,
        verify: &TokenVerify,
    ) -> Result<Option<HostAdmissionReply>, AdmissionError> {
        if !constant_time_eq(&verify.token, &self.token[..]) {
            return Err(AdmissionError::InvalidToken);
        }
        let challenge_nonce = random_bytes::<NONCE_LEN>()?;
        self.challenge_nonce = Some(challenge_nonce);
        self.state = HostState::AwaitingProof;
        Ok(Some(HostAdmissionReply::Message(
            Message::PasswordChallenge(PasswordChallenge::new(
                self.verifier.m_cost(),
                self.verifier.t_cost(),
                self.verifier.p_cost(),
                *self.verifier.salt(),
                challenge_nonce,
            )),
        )))
    }

    fn handle_proof(
        &mut self,
        proof: &ChallengeProof,
    ) -> Result<Option<HostAdmissionReply>, AdmissionError> {
        let challenge_nonce = self
            .challenge_nonce
            .ok_or(AdmissionError::UnexpectedMessage)?;
        let client_nonce = self.client_nonce.ok_or(AdmissionError::UnexpectedMessage)?;
        if !self
            .verifier
            .verify_proof(&challenge_nonce, &client_nonce, &proof.proof)
        {
            return Err(AdmissionError::InvalidPasswordProof);
        }
        self.state = HostState::AwaitingJoinForm;
        Ok(None)
    }

    fn handle_join_request(
        &mut self,
        request: &JoinRequestMessage,
        policy: JoinPolicy,
    ) -> Result<Option<HostAdmissionReply>, AdmissionError> {
        let client_nonce = self.client_nonce.ok_or(AdmissionError::UnexpectedMessage)?;
        let introduction_hash = sha256(
            request
                .introduction
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        let token_hash = sha256(&self.token[..]);
        let transcript = join_request_transcript(&JoinRequestTranscriptInput {
            version: 1,
            room_session_id: *self.room_session_id.as_bytes(),
            client_nonce,
            server_nonce: self.server_nonce,
            nickname: request.nickname.clone(),
            introduction_hash,
            participant_ed25519_pubkey: request.ed25519_pubkey,
            participant_x25519_pubkey: request.x25519_pubkey,
            onion_address: self.onion_address.clone(),
            token_hash,
        });
        if !verify_ed25519(&request.ed25519_pubkey, &transcript, &request.signature) {
            return Err(AdmissionError::InvalidJoinSignature);
        }
        self.host_identity.try_wrap_key_for(
            &request.x25519_pubkey,
            self.room_session_id.as_bytes(),
            0,
        )?;
        if !policy.allows_join_requests() {
            return Err(AdmissionError::RoomLocked);
        }
        self.state = HostState::Decided;
        // The token is no longer needed by this connection; wipe the whole
        // allocation (not just the initialized prefix) so it does not
        // linger in memory for the rest of the membership.
        let capacity = self.token.capacity();
        self.token.resize(capacity, 0);
        self.token.clear();
        Ok(Some(HostAdmissionReply::JoinRequested(JoinApplication {
            nickname: request.nickname.clone(),
            introduction: request.introduction.clone(),
            ed25519_pubkey: request.ed25519_pubkey,
            x25519_pubkey: request.x25519_pubkey,
            signature: request.signature,
        })))
    }
}

/// Compares two byte slices in constant time.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if left.len() != right.len() {
        return false;
    }
    bool::from(left.ct_eq(right))
}
