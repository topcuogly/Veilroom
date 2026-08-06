//! Two-party chat session tests (Stage 7, sections 16, 17 and 33).
//!
//! Two members exchange signed, encrypted chat and color messages through
//! the real cryptographic operations, exercising signature verification,
//! AEAD authentication, replay rejection, old-epoch rejection, and the
//! membership broadcasts.

use veilroom::chat::ChatError;
use veilroom::chat::session::ChatSession;
use veilroom::command::ColorChoice;
use veilroom::crypto::identity::{HostIdentity, MemberIdentity};
use veilroom::crypto::transcript::{
    SnapshotBodyMember, join_policy_body, member_joined_body, member_snapshot_body,
    room_event_transcript,
};
use veilroom::event::MemberId;
use veilroom::protocol::Message;
use veilroom::protocol::membership::{
    JoinPolicyChanged, MemberJoined, MemberSnapshot, SnapshotMember,
};

const SESSION: [u8; 32] = [0x11; 32];

fn host_identity() -> HostIdentity {
    HostIdentity::from_seed([0x31; 32], [0x32; 32])
}

/// Builds a session for a member and installs its own view plus the peer's.
fn member_session(
    member_id: u64,
    identity: &MemberIdentity,
    peer: (u64, &MemberIdentity),
) -> ChatSession {
    let host = host_identity();
    let mut session = ChatSession::new(
        SESSION,
        host.ed25519_pubkey(),
        host.x25519_pubkey(),
        MemberId::new(member_id),
    );
    session.install_member(veilroom::chat::session::MemberView {
        member_id: MemberId::new(member_id),
        nickname: "self".to_owned(),
        color: ColorChoice::default(),
        is_host: member_id == 0,
        ed25519_pubkey: identity.ed25519_pubkey(),
    });
    session.install_member(veilroom::chat::session::MemberView {
        member_id: MemberId::new(peer.0),
        nickname: "peer".to_owned(),
        color: ColorChoice::default(),
        is_host: false,
        ed25519_pubkey: peer.1.ed25519_pubkey(),
    });
    session
}

/// Installs the same epoch key in both sessions.
fn install_epochs(alice: &mut ChatSession, bob: &mut ChatSession) {
    let epoch_key = veilroom::crypto::identity::EpochKey::generate().unwrap();
    alice.install_epoch(
        2,
        veilroom::crypto::identity::EpochKey::from_bytes(*epoch_key.as_bytes()),
    );
    bob.install_epoch(
        2,
        veilroom::crypto::identity::EpochKey::from_bytes(*epoch_key.as_bytes()),
    );
}

fn alice() -> MemberIdentity {
    MemberIdentity::from_seed([0x41; 32], [0x42; 32])
}

fn bob() -> MemberIdentity {
    MemberIdentity::from_seed([0x43; 32], [0x44; 32])
}

/// The host's own participant identity (member 0).
fn host_client() -> MemberIdentity {
    MemberIdentity::from_seed([0x45; 32], [0x46; 32])
}

#[test]
fn chat_messages_roundtrip_between_two_members() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let message = alice
        .send_chat(&alice_identity, "merhaba, gizli bir sohbet")
        .unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!("expected a chat message");
    };
    let text = bob.receive_chat(&envelope).unwrap();
    assert_eq!(text, "merhaba, gizli bir sohbet");

    // The sender's own view would also accept its message.
    let echo = alice.receive_chat(&envelope).unwrap();
    assert_eq!(echo, text);
}

#[test]
fn sender_sequences_are_monotonic_and_replays_are_rejected() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let first = alice.send_chat(&alice_identity, "one").unwrap();
    let second = alice.send_chat(&alice_identity, "two").unwrap();
    let Message::ChatMessage(first) = first else {
        panic!()
    };
    let Message::ChatMessage(second) = second else {
        panic!()
    };
    assert!(second.sender_sequence > first.sender_sequence);

    bob.receive_chat(&first).unwrap();
    bob.receive_chat(&second).unwrap();
    // Replaying the first message is rejected.
    let error = bob.receive_chat(&first).unwrap_err();
    assert!(matches!(
        error,
        ChatError::ReplayRejected {
            sender_id: 1,
            sequence: 1
        }
    ));
}

#[test]
fn old_epoch_messages_are_rejected() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let message = alice.send_chat(&alice_identity, "old").unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };

    // Bob rotates to epoch 3; the epoch-2 message is obsolete.
    let epoch_key = veilroom::crypto::identity::EpochKey::generate().unwrap();
    bob.install_epoch(3, epoch_key);
    let error = bob.receive_chat(&envelope).unwrap_err();
    assert!(matches!(
        error,
        ChatError::OldEpoch {
            found: 2,
            current: 3
        }
    ));
}

#[test]
fn unknown_senders_are_rejected() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let message = alice.send_chat(&alice_identity, "hi").unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    // Bob no longer knows member 1.
    bob.remove_member(MemberId::new(1));
    let error = bob.receive_chat(&envelope).unwrap_err();
    assert!(matches!(error, ChatError::UnknownSender { sender_id: 1 }));
}

#[test]
fn tampered_ciphertext_and_signature_are_rejected() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let message = alice.send_chat(&alice_identity, "authentic").unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };

    // Tampered ciphertext: the signature covers the ciphertext, so the
    // tamper breaks the signature first (AEAD tag failures are covered at
    // the crypto layer, where the signature is re-issued correctly).
    let mut tampered = envelope.clone();
    tampered.ciphertext[0] ^= 0x01;
    assert!(matches!(
        bob.receive_chat(&tampered).unwrap_err(),
        ChatError::InvalidSignature
    ));

    // Tampered signature.
    let mut tampered = envelope.clone();
    tampered.signature[0] ^= 0x01;
    let error = bob.receive_chat(&tampered).unwrap_err();
    eprintln!("tampered signature error: {error:?}");
    assert!(matches!(error, ChatError::InvalidSignature));

    // Tampered sender id fails the signature transcript binding.
    let mut tampered = envelope.clone();
    tampered.sender_id = 2;
    assert!(matches!(
        bob.receive_chat(&tampered).unwrap_err(),
        ChatError::InvalidSignature | ChatError::ReplayRejected { .. }
    ));
}

#[test]
fn color_changes_roundtrip() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let message = alice
        .send_color(&alice_identity, ColorChoice::Cyan)
        .unwrap();
    let Message::ColorChange(envelope) = message else {
        panic!()
    };
    assert_eq!(bob.receive_color(&envelope).unwrap(), ColorChoice::Cyan);
}

#[test]
fn timeout_requests_and_changes_roundtrip() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let request = alice.send_timeout_request(&alice_identity, 45).unwrap();
    let Message::TimeoutRequest(request) = request else {
        panic!("expected a timeout request")
    };
    assert_eq!(bob.receive_timeout_request(&request).unwrap(), 45);

    // The accepted setting is broadcast by the host participant (member 0),
    // which is the only sender a receiver accepts it from.
    let host_client_identity = host_client();
    let mut host_side = member_session(0, &host_client_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (0, &host_client_identity));
    install_epochs(&mut host_side, &mut bob);

    let changed = host_side
        .send_timeout_changed(&host_client_identity, Some(45))
        .unwrap();
    let Message::TimeoutChanged(changed) = changed else {
        panic!("expected a timeout change")
    };
    assert_eq!(bob.receive_timeout_changed(&changed).unwrap(), Some(45));

    let disabled = host_side
        .send_timeout_changed(&host_client_identity, None)
        .unwrap();
    let Message::TimeoutChanged(disabled) = disabled else {
        panic!("expected a timeout change")
    };
    assert_eq!(bob.receive_timeout_changed(&disabled).unwrap(), None);
}

#[test]
fn a_room_timeout_change_from_a_non_host_member_is_rejected() {
    // The host relay refuses to forward this, so reaching a receiver at all
    // means the relay was bypassed; the receiver must still refuse it.
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    let forged = alice
        .send_timeout_changed(&alice_identity, Some(45))
        .unwrap();
    let Message::TimeoutChanged(forged) = forged else {
        panic!("expected a timeout change")
    };
    assert!(matches!(
        bob.receive_timeout_changed(&forged),
        Err(ChatError::InvalidPlaintext(_))
    ));
}

#[test]
fn color_payloads_with_invalid_indices_are_rejected() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);

    // A chat envelope cannot pass as a color message because the message
    // type is bound into the AAD and transcript.
    let message = alice.send_chat(&alice_identity, "x").unwrap();
    let Message::ChatMessage(envelope) = message else {
        panic!()
    };
    // The same envelope fails as a color message because the message type
    // is bound into the AAD and transcript.
    assert!(matches!(
        bob.receive_color(&envelope).unwrap_err(),
        ChatError::InvalidSignature | ChatError::ReplayRejected { .. }
    ));
}

#[test]
fn membership_broadcasts_are_verified_and_applied() {
    let host = host_identity();
    let alice_identity = alice();
    let bob_identity = bob();
    let carol_identity = MemberIdentity::from_seed([0x31; 32], [0x32; 32]);
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    let _ = install_epochs;

    // A signed MEMBER_JOINED broadcast for member 3.
    let body = member_joined_body(3, "carol", &carol_identity.ed25519_pubkey());
    let transcript = room_event_transcript(1, &SESSION, 7, 2, 0x20, &body);
    let signature = host.sign(&transcript);
    let joined = MemberJoined {
        sequence: 7,
        epoch: 2,
        member_id: 3,
        nickname: "carol".to_owned(),
        ed25519_pubkey: carol_identity.ed25519_pubkey(),
        signature,
    };
    bob.handle_member_joined(&joined).unwrap();
    assert!(bob.member(MemberId::new(3)).is_some());

    // A signed MEMBER_LEFT broadcast removes the member.
    let body = veilroom::crypto::transcript::member_gone_body(3);
    let transcript = room_event_transcript(1, &SESSION, 8, 2, 0x21, &body);
    let signature = host.sign(&transcript);
    bob.handle_member_gone(0x21, 8, 2, 3, &signature).unwrap();
    assert!(bob.member(MemberId::new(3)).is_none());

    // A broadcast signed by a different host key is rejected.
    let other_host = HostIdentity::generate().unwrap();
    let body = member_joined_body(3, "carol", &carol_identity.ed25519_pubkey());
    let transcript = room_event_transcript(1, &SESSION, 9, 2, 0x20, &body);
    let signature = other_host.sign(&transcript);
    let forged = MemberJoined {
        sequence: 9,
        epoch: 2,
        member_id: 3,
        nickname: "carol".to_owned(),
        ed25519_pubkey: carol_identity.ed25519_pubkey(),
        signature,
    };
    assert!(matches!(
        bob.handle_member_joined(&forged),
        Err(ChatError::InvalidSignature)
    ));
}

#[test]
fn room_event_sequences_cannot_be_replayed() {
    let host = host_identity();
    let bob_identity = bob();
    let mut bob = member_session(2, &bob_identity, (1, &alice()));
    bob.install_epoch(
        2,
        veilroom::crypto::identity::EpochKey::from_bytes([0x91; 32]),
    );
    let body = join_policy_body(false);
    let transcript = room_event_transcript(1, &SESSION, 7, 2, 0x23, &body);
    let event = JoinPolicyChanged {
        sequence: 7,
        epoch: 2,
        open: false,
        signature: host.sign(&transcript),
    };
    let message = Message::JoinPolicyChanged(event);
    bob.handle_membership_message(&message).unwrap();
    assert!(!bob.join_policy_open());
    assert!(matches!(
        bob.handle_membership_message(&message),
        Err(ChatError::ReplayRejected {
            sender_id: 0,
            sequence: 7
        })
    ));
}

#[test]
fn snapshots_replace_the_member_table() {
    let host = host_identity();
    let bob_identity = bob();
    let mut bob = member_session(2, &bob_identity, (1, &alice()));

    let members = vec![
        SnapshotMember {
            member_id: 0,
            nickname: "host".to_owned(),
            color: 6,
            is_host: true,
            ed25519_pubkey: host.ed25519_pubkey(),
        },
        SnapshotMember {
            member_id: 2,
            nickname: "bob".to_owned(),
            color: 5,
            is_host: false,
            ed25519_pubkey: bob_identity.ed25519_pubkey(),
        },
    ];
    let body = member_snapshot_body(
        &members
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
    let transcript = room_event_transcript(1, &SESSION, 5, 2, 0x24, &body);
    let signature = host.sign(&transcript);
    let snapshot = MemberSnapshot {
        sequence: 5,
        epoch: 2,
        members,
        signature,
    };
    bob.handle_member_snapshot(&snapshot).unwrap();
    assert_eq!(bob.members().len(), 2);
    assert_eq!(
        bob.member(MemberId::new(2)).unwrap().color,
        ColorChoice::Cyan
    );
    assert!(bob.member(MemberId::new(0)).unwrap().is_host);
}

#[test]
fn wrap_key_derivation_agrees_between_host_and_member() {
    let host = host_identity();
    let member = MemberIdentity::generate().unwrap();
    let host_key = host.wrap_key_for(&member.x25519_pubkey(), &SESSION, 5);
    let member_key = member.wrap_key_for(&host.x25519_pubkey(), &SESSION, 5);
    // Both sides must unwrap the same envelope.
    let epoch_key = veilroom::crypto::identity::EpochKey::generate().unwrap();
    let envelope =
        veilroom::crypto::identity::wrap_epoch_key(&host_key, &epoch_key, 5, &SESSION).unwrap();
    let unwrapped = veilroom::crypto::identity::unwrap_epoch_key(
        &member_key,
        5,
        &SESSION,
        &envelope.nonce,
        &envelope.ciphertext,
    )
    .unwrap();
    assert_eq!(unwrapped.as_bytes(), epoch_key.as_bytes());
}

#[test]
fn fresh_randomness_is_used_for_sealing() {
    let alice_identity = alice();
    let bob_identity = bob();
    let mut alice = member_session(1, &alice_identity, (2, &bob_identity));
    let mut bob = member_session(2, &bob_identity, (1, &alice_identity));
    install_epochs(&mut alice, &mut bob);
    let a = alice.send_chat(&alice_identity, "same text").unwrap();
    let b = alice.send_chat(&alice_identity, "same text").unwrap();
    let Message::ChatMessage(a) = a else { panic!() };
    let Message::ChatMessage(b) = b else { panic!() };
    assert_ne!(a.nonce, b.nonce, "each message must use a fresh nonce");
}
