//! Client-side admission flow (sections 8-12, 36 and 37).
//!
//! One `ClientAdmission` instance drives one connection through the
//! admission gate from the participant's side: client hello, token
//! verification, password challenge-response, join application, and the
//! host's decision.
//!
//! Stage 6 completes the trust chain: the flow verifies the host-hello
//! signature and pins the host keys, signs the join-request transcript with
//! its own ephemeral identity, and unwraps epoch keys from the host.

use crate::admission::AdmissionError;
use crate::chat::session::ChatSession;
use crate::chat::{ChatError, MemberView};
use crate::constants::NONCE_LEN;
use crate::crypto::identity::{MemberIdentity, verify_ed25519};
use crate::crypto::password::compute_password_proof;
use crate::crypto::transcript::{JoinRequestTranscriptInput, join_request_transcript, sha256};
use crate::crypto::{CryptoError, SecretBytes, random_bytes};
use crate::event::MemberId;
use crate::protocol::epoch::EpochAck;
use crate::protocol::handshake::{
    ChallengeProof, ClientHello, JoinRequest as JoinRequestMessage, TokenVerify,
};
use crate::protocol::messages::Message;
use crate::uri::Invitation;
use std::cell::Cell;

/// The host trust-chain material recorded from the host hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHelloInfo {
    /// The room session id claimed by the host.
    pub room_session_id: [u8; 32],
    /// The host's Ed25519 public key.
    pub host_ed25519_pubkey: [u8; 32],
    /// The host's X25519 public key (per-member key channel).
    pub host_x25519_pubkey: [u8; 32],
    /// The host's signature over the host-hello transcript (verified).
    pub signature: [u8; 64],
}

/// Per-connection state of the client-side admission flow.
#[derive(Debug)]
pub struct ClientAdmission {
    invitation: Invitation,
    password: SecretBytes,
    identity: MemberIdentity,
    client_nonce: [u8; NONCE_LEN],
    server_nonce: Option<[u8; NONCE_LEN]>,
    host_hello: Option<HostHelloInfo>,
    member_id: Option<MemberId>,
    chat: Option<ChatSession>,
    state: Cell<ClientState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    AwaitingHostHello,
    AwaitingChallenge,
    AwaitingJoinForm,
    AwaitingDecision,
    Admitted,
}

impl ClientAdmission {
    /// Creates a client-side admission flow with a fresh ephemeral
    /// identity.
    ///
    /// `password` is the room password entered by the participant; it is
    /// held in a zeroizing buffer and never transmitted.
    pub fn new(invitation: Invitation, password: SecretBytes) -> Result<Self, CryptoError> {
        Ok(Self {
            invitation,
            password,
            identity: MemberIdentity::generate()?,
            client_nonce: random_bytes::<NONCE_LEN>()?,
            server_nonce: None,
            host_hello: None,
            member_id: None,
            chat: None,
            state: Cell::new(ClientState::AwaitingHostHello),
        })
    }

    /// The invitation this flow is joining with.
    pub fn invitation(&self) -> &Invitation {
        &self.invitation
    }

    /// The client nonce of this flow.
    pub const fn client_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.client_nonce
    }

    /// The server nonce, once the host hello has been received.
    pub const fn server_nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        self.server_nonce.as_ref()
    }

    /// The member id, once the application has been accepted.
    pub const fn member_id(&self) -> Option<MemberId> {
        self.member_id
    }

    /// The host trust-chain material, once the host hello has arrived.
    pub const fn host_hello(&self) -> Option<&HostHelloInfo> {
        self.host_hello.as_ref()
    }

    /// The chat session, once admitted.
    pub fn chat(&self) -> Option<&ChatSession> {
        self.chat.as_ref()
    }

    /// The chat session, mutably, once admitted.
    pub fn chat_mut(&mut self) -> Option<&mut ChatSession> {
        self.chat.as_mut()
    }

    /// Whether the application has been accepted.
    pub fn is_admitted(&self) -> bool {
        matches!(self.state.get(), ClientState::Admitted)
    }

    /// The timeout that applies to the current client admission stage.
    pub fn timeout_kind(&self) -> crate::limits::TimeoutKind {
        use crate::limits::TimeoutKind;
        match self.state.get() {
            ClientState::AwaitingHostHello => TimeoutKind::ProtocolHandshake,
            ClientState::AwaitingChallenge => TimeoutKind::TokenValidation,
            ClientState::AwaitingJoinForm => TimeoutKind::JoinFormSubmission,
            ClientState::AwaitingDecision => TimeoutKind::HostDecision,
            ClientState::Admitted => TimeoutKind::Keepalive,
        }
    }

    /// The first message of the flow: the client hello.
    pub fn first_message(&self) -> Message {
        Message::ClientHello(ClientHello::new(1, self.client_nonce, 0))
    }

    /// Handles one message from the host and returns the messages to send
    /// back (at most one in V1).
    pub fn on_host_message(&mut self, message: &Message) -> Result<Vec<Message>, AdmissionError> {
        match (self.state.get(), message) {
            (ClientState::AwaitingHostHello, Message::HostHello(hello)) => {
                self.handle_host_hello(hello)
            }
            (ClientState::AwaitingChallenge, Message::PasswordChallenge(challenge)) => {
                self.handle_challenge(challenge)
            }
            (ClientState::AwaitingDecision, Message::JoinAccepted(accepted)) => {
                self.member_id = Some(MemberId::new(accepted.member_id));
                self.state.set(ClientState::Admitted);
                if let Some(host_hello) = self.host_hello.as_ref() {
                    self.chat = Some(ChatSession::new(
                        host_hello.room_session_id,
                        host_hello.host_ed25519_pubkey,
                        host_hello.host_x25519_pubkey,
                        MemberId::new(accepted.member_id),
                    ));
                }
                Ok(Vec::new())
            }
            (ClientState::AwaitingDecision, Message::JoinRejected(rejected)) => {
                Err(AdmissionError::Rejected {
                    reason: rejected.reason.clone(),
                })
            }
            (_, Message::Error(error)) => Err(AdmissionError::HostError {
                code: error.code,
                reason: error.reason.clone(),
            }),
            _ => Err(AdmissionError::UnexpectedMessage),
        }
    }

    /// Handles an `EPOCH_WRAP` from the host: unwraps the epoch key with
    /// the member wrapping key and acknowledges.
    pub fn on_epoch_wrap(
        &mut self,
        wrap: &crate::protocol::epoch::EpochWrap,
    ) -> Result<Message, AdmissionError> {
        let session = self
            .chat
            .as_mut()
            .ok_or(AdmissionError::UnexpectedMessage)?;
        let epoch = session
            .set_epoch_from_wrap(&self.identity, wrap)
            .map_err(|_| AdmissionError::UnexpectedMessage)?;
        Ok(Message::EpochAck(EpochAck::new(epoch)))
    }

    /// Handles an encrypted chat or color message from another member.
    ///
    /// Returns the received chat text, or `None` for a color change (the
    /// color is applied to the member table).
    pub fn on_member_message(
        &mut self,
        message_type: u8,
        envelope: &crate::protocol::chat::EncryptedEnvelope,
    ) -> Result<Option<String>, ChatError> {
        let session = self.chat.as_mut().ok_or(ChatError::NoEpochKey)?;
        match message_type {
            0x40 => Ok(Some(session.receive_chat(envelope)?)),
            0x41 => {
                let color = session.receive_color(envelope)?;
                let sender = MemberId::new(envelope.sender_id);
                if let Some(member) = session.member(sender).cloned() {
                    let mut updated = member;
                    updated.color = color;
                    session.install_member(updated);
                }
                Ok(None)
            }
            other => Err(ChatError::InvalidPlaintext(format!(
                "not a chat-type message: 0x{other:02x}"
            ))),
        }
    }

    /// Handles a signed membership broadcast from the host.
    pub fn on_membership_message(&mut self, message: &Message) -> Result<(), ChatError> {
        let session = self.chat.as_mut().ok_or(ChatError::NoEpochKey)?;
        match message {
            Message::MemberJoined(event) => session.handle_member_joined(event),
            Message::MemberLeft(event) => session.handle_member_gone(
                0x21,
                event.sequence,
                event.epoch,
                event.member_id,
                &event.signature,
            ),
            Message::MemberKicked(event) => session.handle_member_gone(
                0x22,
                event.sequence,
                event.epoch,
                event.member_id,
                &event.signature,
            ),
            Message::MemberSnapshot(event) => session.handle_member_snapshot(event),
            Message::JoinPolicyChanged(event) => {
                session.handle_membership_message(&Message::JoinPolicyChanged(event.clone()))
            }
            _ => Err(ChatError::InvalidPlaintext(
                "not a membership message".to_owned(),
            )),
        }
    }

    /// Sends a chat message.
    pub fn send_chat(&mut self, text: &str) -> Result<Message, ChatError> {
        let session = self.chat.as_mut().ok_or(ChatError::NoEpochKey)?;
        session.send_chat(&self.identity, text)
    }

    /// Sends a color change.
    pub fn send_color(&mut self, color: crate::command::ColorChoice) -> Result<Message, ChatError> {
        let session = self.chat.as_mut().ok_or(ChatError::NoEpochKey)?;
        session.send_color(&self.identity, color)
    }

    /// Sends a room-wide timeout request to the host.
    pub fn send_timeout_request(&mut self, seconds: u64) -> Result<Message, ChatError> {
        let session = self.chat.as_mut().ok_or(ChatError::NoEpochKey)?;
        session.send_timeout_request(&self.identity, seconds)
    }

    /// The member table entry for a member, once admitted.
    pub fn member_view(&self, member_id: MemberId) -> Option<&MemberView> {
        self.chat
            .as_ref()
            .and_then(|session| session.member(member_id))
    }

    /// Applies the local member's own color after a successful `/color`.
    ///
    /// The host relays a color change to every member except the sender, so
    /// the sender never receives its own change back and must update its
    /// own member-table entry locally; otherwise the sender's own messages
    /// would keep the default color. A no-op before the member table knows
    /// the local member.
    pub fn set_own_color(&mut self, color: crate::command::ColorChoice) {
        let Some(own_id) = self.member_id else {
            return;
        };
        let Some(session) = self.chat.as_mut() else {
            return;
        };
        if let Some(member) = session.member(own_id).cloned() {
            let mut updated = member;
            updated.color = color;
            session.install_member(updated);
        }
    }

    fn handle_host_hello(
        &mut self,
        hello: &crate::protocol::handshake::HostHello,
    ) -> Result<Vec<Message>, AdmissionError> {
        if hello.version != 1 {
            return Err(AdmissionError::UnsupportedVersion {
                found: hello.version,
            });
        }
        let token_hash = sha256(self.invitation.token());
        let transcript = crate::crypto::transcript::host_hello_transcript(
            &crate::crypto::transcript::HostHelloTranscriptInput {
                version: 1,
                onion_address: self.invitation.onion_address().to_owned(),
                virtual_port: self.invitation.port(),
                room_session_id: *hello.room_session_id.as_bytes(),
                host_ed25519_pubkey: hello.host_ed25519_pubkey,
                host_x25519_pubkey: hello.host_x25519_pubkey,
                client_nonce: self.client_nonce,
                server_nonce: hello.server_nonce,
                token_hash,
                offered_version: 1,
                client_features: 0,
            },
        );
        if !verify_ed25519(
            &hello.host_ed25519_pubkey,
            &transcript,
            &hello.host_signature,
        ) {
            return Err(AdmissionError::InvalidHostSignature);
        }
        self.identity.try_wrap_key_for(
            &hello.host_x25519_pubkey,
            hello.room_session_id.as_bytes(),
            0,
        )?;
        self.server_nonce = Some(hello.server_nonce);
        self.host_hello = Some(HostHelloInfo {
            room_session_id: *hello.room_session_id.as_bytes(),
            host_ed25519_pubkey: hello.host_ed25519_pubkey,
            host_x25519_pubkey: hello.host_x25519_pubkey,
            signature: hello.host_signature,
        });
        self.state.set(ClientState::AwaitingChallenge);
        Ok(vec![Message::TokenVerify(TokenVerify::new(
            self.invitation.token().to_vec(),
        )?)])
    }

    fn handle_challenge(
        &mut self,
        challenge: &crate::protocol::handshake::PasswordChallenge,
    ) -> Result<Vec<Message>, AdmissionError> {
        if challenge.m_cost != crate::constants::ARGON2_M_COST
            || challenge.t_cost != crate::constants::ARGON2_T_COST
            || challenge.p_cost != crate::constants::ARGON2_P_COST
        {
            return Err(AdmissionError::UnexpectedMessage);
        }
        let client_nonce = self.client_nonce;
        let proof = compute_password_proof(
            &self.password,
            &challenge.salt,
            challenge.m_cost,
            challenge.t_cost,
            challenge.p_cost,
            &challenge.challenge_nonce,
            &client_nonce,
        )?;
        self.password.clear();
        self.state.set(ClientState::AwaitingJoinForm);
        Ok(vec![Message::ChallengeProof(ChallengeProof::new(proof))])
    }

    /// Builds the signed join application message.
    pub fn join_request(
        &self,
        nickname: String,
        introduction: Option<String>,
    ) -> Result<Message, AdmissionError> {
        if !matches!(self.state.get(), ClientState::AwaitingJoinForm) {
            return Err(AdmissionError::UnexpectedMessage);
        }
        let host_hello = self
            .host_hello
            .as_ref()
            .ok_or(AdmissionError::UnexpectedMessage)?;
        let server_nonce = self.server_nonce.ok_or(AdmissionError::UnexpectedMessage)?;
        // The wire message carries the *normalized* nickname, so the
        // transcript has to be built over the same value. Signing the raw
        // form and sending the normalized one makes the host verify a
        // different transcript and reject every nickname that normalization
        // changes at all (NFD input, or a stray leading space).
        let nickname =
            crate::validation::validate_nickname(&nickname, &crate::limits::Limits::default())
                .map_err(crate::protocol::messages::ProtocolError::Validation)?;
        let introduction_hash = sha256(introduction.as_deref().unwrap_or_default().as_bytes());
        let token_hash = sha256(self.invitation.token());
        let transcript = join_request_transcript(&JoinRequestTranscriptInput {
            version: 1,
            room_session_id: host_hello.room_session_id,
            client_nonce: self.client_nonce,
            server_nonce,
            nickname: nickname.clone(),
            introduction_hash,
            participant_ed25519_pubkey: self.identity.ed25519_pubkey(),
            participant_x25519_pubkey: self.identity.x25519_pubkey(),
            onion_address: self.invitation.onion_address().to_owned(),
            token_hash,
        });
        let signature = self.identity.sign(&transcript);
        let request = Message::JoinRequest(JoinRequestMessage::new(
            nickname,
            introduction,
            self.identity.ed25519_pubkey(),
            self.identity.x25519_pubkey(),
            signature,
        )?);
        self.state.set(ClientState::AwaitingDecision);
        Ok(request)
    }
}
