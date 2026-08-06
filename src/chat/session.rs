//! Participant-side chat session (sections 16, 17, 32 and 33).
//!
//! `ChatSession` holds everything a connected member needs for encrypted
//! messaging: the current epoch key, the sender sequence, the replay
//! tracker, and the table of known members with their keys. Sending seals
//! and signs; receiving verifies the signature, authenticates the
//! ciphertext, checks the epoch and the sequence, and returns the
//! plaintext.

use crate::chat::ChatError;
use crate::chat::replay::ReplayTracker;
use crate::command::ColorChoice;
use crate::crypto::chat::{open_envelope, seal_envelope};
use crate::crypto::identity::{EpochKey, MemberIdentity, unwrap_epoch_key, verify_ed25519};
use crate::crypto::transcript::{
    SnapshotBodyMember, join_policy_body, member_gone_body, member_joined_body,
    member_snapshot_body, room_event_transcript,
};
use crate::event::MemberId;
use crate::protocol::chat::EncryptedEnvelope;
use crate::protocol::epoch::EpochWrap;
use crate::protocol::membership::{MemberJoined, MemberSnapshot, SnapshotMember};
use crate::protocol::messages::Message;
use crate::validation::validate_chat_text;

/// Message type of `CHAT_MESSAGE` (0x40).
pub const MSG_CHAT: u8 = 0x40;
/// Message type of `COLOR_CHANGE` (0x41).
pub const MSG_COLOR: u8 = 0x41;
/// Message type of `TIMEOUT_REQUEST` (0x42).
pub const MSG_TIMEOUT_REQUEST: u8 = 0x42;
/// Message type of `TIMEOUT_CHANGED` (0x43).
pub const MSG_TIMEOUT_CHANGED: u8 = 0x43;

/// The participant's view of one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    /// The member id.
    pub member_id: MemberId,
    /// The nickname.
    pub nickname: String,
    /// The display color.
    pub color: ColorChoice,
    /// Whether this is the host participant.
    pub is_host: bool,
    /// The member's Ed25519 public key (message signatures).
    pub ed25519_pubkey: [u8; 32],
}

/// The chat state of one connected member.
#[derive(Debug)]
pub struct ChatSession {
    room_session_id: [u8; 32],
    host_ed25519_pubkey: [u8; 32],
    host_x25519_pubkey: [u8; 32],
    member_id: MemberId,
    current_epoch: Option<(u64, EpochKey)>,
    sender_sequence: u64,
    members: Vec<MemberView>,
    replay: ReplayTracker,
    last_room_sequence: Option<u64>,
    join_policy_open: bool,
}

impl ChatSession {
    /// Creates a chat session for `member_id` in the room identified by
    /// `room_session_id`, trusting the host keys pinned during the
    /// handshake.
    pub fn new(
        room_session_id: [u8; 32],
        host_ed25519_pubkey: [u8; 32],
        host_x25519_pubkey: [u8; 32],
        member_id: MemberId,
    ) -> Self {
        Self {
            room_session_id,
            host_ed25519_pubkey,
            host_x25519_pubkey,
            member_id,
            current_epoch: None,
            sender_sequence: 0,
            members: Vec::new(),
            replay: ReplayTracker::new(),
            last_room_sequence: None,
            join_policy_open: true,
        }
    }

    /// This member's id.
    pub const fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// The current epoch, once a wrap has been installed.
    pub fn current_epoch(&self) -> Option<u64> {
        self.current_epoch.as_ref().map(|(epoch, _)| *epoch)
    }

    /// Installs a new epoch key from an `EPOCH_WRAP` and returns the epoch.
    pub fn set_epoch_from_wrap(
        &mut self,
        identity: &MemberIdentity,
        wrap: &EpochWrap,
    ) -> Result<u64, ChatError> {
        if let Some(current) = self.current_epoch() {
            if wrap.epoch <= current {
                return Err(ChatError::OldEpoch {
                    found: wrap.epoch,
                    current,
                });
            }
        }
        let wrap_key = identity
            .try_wrap_key_for(
                &self.host_x25519_pubkey,
                &self.room_session_id,
                self.member_id.as_u64(),
            )
            .map_err(|_| ChatError::InvalidCiphertext)?;
        let key = unwrap_epoch_key(
            &wrap_key,
            wrap.epoch,
            &self.room_session_id,
            &wrap.nonce,
            &wrap.ciphertext,
        )
        .map_err(|_| ChatError::InvalidCiphertext)?;
        self.install_epoch(wrap.epoch, key);
        Ok(wrap.epoch)
    }

    /// Installs an epoch key directly (used by the host client).
    pub fn install_epoch(&mut self, epoch: u64, key: EpochKey) {
        if self.current_epoch().is_some_and(|current| epoch <= current) {
            return;
        }
        self.current_epoch = Some((epoch, key));
        self.replay.retain_epoch(epoch);
    }

    /// The known members.
    pub fn members(&self) -> &[MemberView] {
        &self.members
    }

    /// Whether the host currently accepts new join flows.
    pub const fn join_policy_open(&self) -> bool {
        self.join_policy_open
    }

    /// The member view for an id, if known.
    pub fn member(&self, member_id: MemberId) -> Option<&MemberView> {
        self.members
            .iter()
            .find(|member| member.member_id == member_id)
    }

    /// Inserts or replaces a member view.
    pub fn install_member(&mut self, view: MemberView) {
        if let Some(existing) = self
            .members
            .iter_mut()
            .find(|m| m.member_id == view.member_id)
        {
            *existing = view;
        } else {
            self.members.push(view);
        }
    }

    /// Removes a member view.
    pub fn remove_member(&mut self, member_id: MemberId) {
        self.members.retain(|member| member.member_id != member_id);
    }

    /// Replaces the whole member table with a snapshot.
    pub fn install_snapshot(&mut self, members: Vec<SnapshotMember>) {
        self.members = members
            .into_iter()
            .map(|member| MemberView {
                member_id: MemberId::new(member.member_id),
                nickname: member.nickname,
                color: ColorChoice::from_index(member.color).unwrap_or_default(),
                is_host: member.is_host,
                ed25519_pubkey: member.ed25519_pubkey,
            })
            .collect();
    }

    /// Sends a chat message: encrypts with the epoch key, signs, sequences.
    pub fn send_chat(
        &mut self,
        identity: &MemberIdentity,
        text: &str,
    ) -> Result<Message, ChatError> {
        let limits = crate::limits::Limits::default();
        validate_chat_text(text, &limits)
            .map_err(|error| ChatError::InvalidPlaintext(error.to_string()))?;
        let envelope = self.seal(identity, MSG_CHAT, text.as_bytes())?;
        Ok(Message::ChatMessage(envelope))
    }

    /// Sends a color change.
    pub fn send_color(
        &mut self,
        identity: &MemberIdentity,
        color: ColorChoice,
    ) -> Result<Message, ChatError> {
        let envelope = self.seal(identity, MSG_COLOR, &[color.as_index()])?;
        Ok(Message::ColorChange(envelope))
    }

    /// Sends a member request for a room-wide message timeout.
    pub fn send_timeout_request(
        &mut self,
        identity: &MemberIdentity,
        seconds: u64,
    ) -> Result<Message, ChatError> {
        validate_timeout_seconds(seconds)?;
        let envelope = self.seal(identity, MSG_TIMEOUT_REQUEST, &seconds.to_be_bytes())?;
        Ok(Message::TimeoutRequest(envelope))
    }

    /// Sends a host-approved room-wide timeout setting; `None` disables it.
    pub fn send_timeout_changed(
        &mut self,
        identity: &MemberIdentity,
        interval: Option<u64>,
    ) -> Result<Message, ChatError> {
        if let Some(seconds) = interval {
            validate_timeout_seconds(seconds)?;
        }
        let mut payload = [0u8; 9];
        if let Some(seconds) = interval {
            payload[0] = 1;
            payload[1..].copy_from_slice(&seconds.to_be_bytes());
        }
        let envelope = self.seal(identity, MSG_TIMEOUT_CHANGED, &payload)?;
        Ok(Message::TimeoutChanged(envelope))
    }

    /// Receives a chat message: verifies, authenticates, replay-checks,
    /// and returns the text.
    pub fn receive_chat(&mut self, envelope: &EncryptedEnvelope) -> Result<String, ChatError> {
        let plaintext = self.open(MSG_CHAT, envelope)?;
        let text = String::from_utf8(plaintext)
            .map_err(|_| ChatError::InvalidPlaintext("not valid UTF-8".to_owned()))?;
        let limits = crate::limits::Limits::default();
        validate_chat_text(&text, &limits)
            .map_err(|error| ChatError::InvalidPlaintext(error.to_string()))?;
        Ok(text)
    }

    /// Receives a color change and returns the new color.
    pub fn receive_color(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<ColorChoice, ChatError> {
        let plaintext = self.open(MSG_COLOR, envelope)?;
        if plaintext.len() != 1 {
            return Err(ChatError::InvalidPlaintext(
                "color payload must be one byte".to_owned(),
            ));
        }
        ColorChoice::from_index(plaintext[0]).ok_or(ChatError::UnknownColor {
            index: plaintext[0],
        })
    }

    /// Opens and validates a member's timeout request.
    pub fn receive_timeout_request(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<u64, ChatError> {
        let plaintext = self.open(MSG_TIMEOUT_REQUEST, envelope)?;
        let bytes: [u8; 8] = plaintext.try_into().map_err(|_| {
            ChatError::InvalidPlaintext("timeout request must contain eight bytes".to_owned())
        })?;
        let seconds = u64::from_be_bytes(bytes);
        validate_timeout_seconds(seconds)?;
        Ok(seconds)
    }

    /// Opens and validates an accepted room-wide timeout setting.
    pub fn receive_timeout_changed(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<Option<u64>, ChatError> {
        // Room-wide settings are host-authored. The host relay already
        // refuses to forward this type from anyone else, but that makes the
        // relay the only enforcement point; the receiver checks it too.
        if envelope.sender_id != 0 {
            return Err(ChatError::InvalidPlaintext(
                "only the host can change the room timeout".to_owned(),
            ));
        }
        let plaintext = self.open(MSG_TIMEOUT_CHANGED, envelope)?;
        let bytes: [u8; 9] = plaintext.try_into().map_err(|_| {
            ChatError::InvalidPlaintext("timeout setting must contain nine bytes".to_owned())
        })?;
        match bytes[0] {
            0 if bytes[1..].iter().all(|byte| *byte == 0) => Ok(None),
            1 => {
                let seconds = u64::from_be_bytes(bytes[1..].try_into().expect("eight-byte slice"));
                validate_timeout_seconds(seconds)?;
                Ok(Some(seconds))
            }
            _ => Err(ChatError::InvalidPlaintext(
                "invalid timeout setting flag".to_owned(),
            )),
        }
    }

    /// Handles a signed `MEMBER_JOINED` broadcast.
    pub fn handle_member_joined(&mut self, event: &MemberJoined) -> Result<(), ChatError> {
        let limits = crate::limits::Limits::default();
        crate::validation::validate_nickname(&event.nickname, &limits)
            .map_err(|error| ChatError::InvalidPlaintext(error.to_string()))?;
        if event.member_id == 0
            || self.members.iter().any(|member| {
                member.member_id.as_u64() == event.member_id
                    || member.nickname == event.nickname
                    || member.ed25519_pubkey == event.ed25519_pubkey
            })
        {
            return Err(ChatError::InvalidPlaintext(
                "duplicate or invalid member identity".to_owned(),
            ));
        }
        let body = member_joined_body(event.member_id, &event.nickname, &event.ed25519_pubkey);
        self.verify_room_event(event.sequence, event.epoch, 0x20, &body, &event.signature)?;
        self.install_member(MemberView {
            member_id: MemberId::new(event.member_id),
            nickname: event.nickname.clone(),
            color: ColorChoice::default(),
            is_host: false,
            ed25519_pubkey: event.ed25519_pubkey,
        });
        Ok(())
    }

    /// Handles a signed `MEMBER_LEFT` or `MEMBER_KICKED` broadcast.
    pub fn handle_member_gone(
        &mut self,
        event_type: u8,
        sequence: u64,
        epoch: u64,
        member_id: u64,
        signature: &[u8; 64],
    ) -> Result<(), ChatError> {
        let body = member_gone_body(member_id);
        self.verify_room_event(sequence, epoch, event_type, &body, signature)?;
        self.remove_member(MemberId::new(member_id));
        Ok(())
    }

    /// Handles a signed `MEMBER_SNAPSHOT` broadcast.
    pub fn handle_member_snapshot(&mut self, event: &MemberSnapshot) -> Result<(), ChatError> {
        validate_snapshot(&event.members, self.member_id)?;
        let body = member_snapshot_body(
            &event
                .members
                .iter()
                .map(|member| SnapshotBodyMember {
                    member_id: member.member_id,
                    nickname: member.nickname.clone(),
                    color_index: member.color,
                    is_host: member.is_host,
                    ed25519_pubkey: member.ed25519_pubkey,
                })
                .collect::<Vec<_>>(),
        );
        self.verify_room_event(event.sequence, event.epoch, 0x24, &body, &event.signature)?;
        self.install_snapshot(event.members.clone());
        Ok(())
    }

    /// Handles a signed membership broadcast message.
    ///
    /// This is the session-level counterpart of
    /// `ClientAdmission::on_membership_message`, usable by any client that
    /// owns a `ChatSession` directly (e.g. the host participant).
    pub fn handle_membership_message(&mut self, message: &Message) -> Result<(), ChatError> {
        match message {
            Message::MemberJoined(event) => self.handle_member_joined(event),
            Message::MemberLeft(event) => self.handle_member_gone(
                0x21,
                event.sequence,
                event.epoch,
                event.member_id,
                &event.signature,
            ),
            Message::MemberKicked(event) => self.handle_member_gone(
                0x22,
                event.sequence,
                event.epoch,
                event.member_id,
                &event.signature,
            ),
            Message::JoinPolicyChanged(event) => {
                let body = join_policy_body(event.open);
                self.verify_room_event(event.sequence, event.epoch, 0x23, &body, &event.signature)?;
                self.join_policy_open = event.open;
                Ok(())
            }
            Message::MemberSnapshot(event) => self.handle_member_snapshot(event),
            _ => Err(ChatError::InvalidPlaintext(
                "not a membership message".to_owned(),
            )),
        }
    }

    fn seal(
        &mut self,
        identity: &MemberIdentity,
        message_type: u8,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, ChatError> {
        let (epoch, epoch_key) = self.current_epoch.as_ref().ok_or(ChatError::NoEpochKey)?;
        self.sender_sequence += 1;
        let sealed = seal_envelope(
            epoch_key,
            identity,
            1,
            &self.room_session_id,
            *epoch,
            self.member_id.as_u64(),
            self.sender_sequence,
            message_type,
            plaintext,
        )
        .map_err(|_| ChatError::InvalidCiphertext)?;
        EncryptedEnvelope::new(
            *epoch,
            self.member_id.as_u64(),
            self.sender_sequence,
            sealed.nonce,
            sealed.ciphertext,
            sealed.signature,
        )
        .map_err(|_| ChatError::InvalidCiphertext)
    }

    fn open(
        &mut self,
        message_type: u8,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, ChatError> {
        let (epoch, epoch_key) = self.current_epoch.as_ref().ok_or(ChatError::NoEpochKey)?;
        if envelope.epoch != *epoch {
            return Err(ChatError::OldEpoch {
                found: envelope.epoch,
                current: *epoch,
            });
        }
        let sender = MemberId::new(envelope.sender_id);
        let sender_pubkey = self
            .member(sender)
            .map(|member| member.ed25519_pubkey)
            .ok_or(ChatError::UnknownSender {
                sender_id: envelope.sender_id,
            })?;
        // Replay is checked before verification but only recorded after a
        // successful open, so a rejected message cannot burn its sequence.
        if let Some(last) = self.replay.last_accepted(sender, *epoch) {
            if envelope.sender_sequence <= last {
                return Err(ChatError::ReplayRejected {
                    sender_id: envelope.sender_id,
                    sequence: envelope.sender_sequence,
                });
            }
        }
        let plaintext = open_envelope(
            epoch_key,
            &sender_pubkey,
            1,
            &self.room_session_id,
            *epoch,
            envelope.sender_id,
            envelope.sender_sequence,
            message_type,
            &envelope.nonce,
            &envelope.ciphertext,
            &envelope.signature,
        )
        .map_err(|error| match error {
            crate::crypto::chat::ChatOpenError::InvalidSignature => ChatError::InvalidSignature,
            crate::crypto::chat::ChatOpenError::Decrypt(_) => ChatError::InvalidCiphertext,
        })?;
        self.replay.accept(sender, *epoch, envelope.sender_sequence);
        Ok(plaintext)
    }

    fn verify_room_event(
        &mut self,
        sequence: u64,
        epoch: u64,
        event_type: u8,
        body: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), ChatError> {
        let transcript =
            room_event_transcript(1, &self.room_session_id, sequence, epoch, event_type, body);
        if !verify_ed25519(&self.host_ed25519_pubkey, &transcript, signature) {
            return Err(ChatError::InvalidSignature);
        }
        if let Some(current) = self.current_epoch() {
            if epoch != current {
                return Err(ChatError::OldEpoch {
                    found: epoch,
                    current,
                });
            }
        }
        if self.last_room_sequence.is_some_and(|last| sequence <= last) {
            return Err(ChatError::ReplayRejected {
                sender_id: 0,
                sequence,
            });
        }
        self.last_room_sequence = Some(sequence);
        Ok(())
    }
}

fn validate_timeout_seconds(seconds: u64) -> Result<(), ChatError> {
    if (1..=crate::command::MAX_MESSAGE_TIMEOUT_SECONDS).contains(&seconds) {
        Ok(())
    } else {
        Err(ChatError::InvalidPlaintext(format!(
            "timeout must be 1..={} seconds",
            crate::command::MAX_MESSAGE_TIMEOUT_SECONDS
        )))
    }
}

/// Validates semantic invariants that CBOR shape validation cannot express.
fn validate_snapshot(members: &[SnapshotMember], own_id: MemberId) -> Result<(), ChatError> {
    let limits = crate::limits::Limits::default();
    if members.is_empty()
        || !members
            .iter()
            .any(|member| member.member_id == own_id.as_u64())
    {
        return Err(ChatError::InvalidPlaintext(
            "member snapshot omits the local member".to_owned(),
        ));
    }
    // The CBOR array limit is far looser than the room's member cap; a
    // snapshot that claims more members than the room can hold is invalid
    // regardless of who signed it.
    if members.len() > limits.max_active_members() {
        return Err(ChatError::InvalidPlaintext(format!(
            "member snapshot lists {} members, the room limit is {}",
            members.len(),
            limits.max_active_members()
        )));
    }
    let host_count = members
        .iter()
        .filter(|member| member.is_host && member.member_id == 0)
        .count();
    if host_count != 1
        || members
            .iter()
            .any(|member| member.is_host != (member.member_id == 0))
    {
        return Err(ChatError::InvalidPlaintext(
            "member snapshot has an invalid host entry".to_owned(),
        ));
    }
    for (index, member) in members.iter().enumerate() {
        crate::validation::validate_nickname(&member.nickname, &limits)
            .map_err(|error| ChatError::InvalidPlaintext(error.to_string()))?;
        if ColorChoice::from_index(member.color).is_none() {
            return Err(ChatError::UnknownColor {
                index: member.color,
            });
        }
        if members[..index].iter().any(|prior| {
            prior.member_id == member.member_id
                || prior.nickname == member.nickname
                || prior.ed25519_pubkey == member.ed25519_pubkey
        }) {
            return Err(ChatError::InvalidPlaintext(
                "member snapshot contains duplicate identities".to_owned(),
            ));
        }
    }
    Ok(())
}
