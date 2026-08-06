//! In-memory admission-flow integration tests (instructions section 41.3).
//!
//! Drives the client-side and host-side admission flows against each other
//! through the strict frame codec with real cryptography: the host signs
//! the host hello, the client verifies it and pins the host keys, the
//! participant signs the join request, and the host verifies it. Negative
//! cases cover wrong tokens, wrong passwords, locked rooms, tampered
//! signatures, and epoch-key wrapping.

use veilroom::admission::queue::JoinRequestQueue;
use veilroom::admission::{
    AdmissionError, ClientAdmission, HostAdmission, HostAdmissionReply, JoinPolicy,
};
use veilroom::crypto::identity::HostIdentity;
use veilroom::crypto::password::PasswordVerifier;
use veilroom::crypto::{SecretBytes, random_bytes};
use veilroom::event::ConnectionId;
use veilroom::limits::Limits;
use veilroom::protocol::ids::ErrorCode;
use veilroom::protocol::session::RoomSessionId;
use veilroom::protocol::{FrameDecoder, Message, decode_message, encode_message};
use veilroom::uri::Invitation;

fn onion() -> String {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion".to_owned()
}

const ROOM_PASSWORD: &[u8] = b"correct horse battery staple";

fn limits() -> Limits {
    Limits::default()
}

fn invitation(token: &[u8]) -> Invitation {
    Invitation::new(onion(), 80, token.to_vec()).unwrap()
}

fn host_identity() -> HostIdentity {
    HostIdentity::from_seed([0x21; 32], [0x22; 32])
}

/// Transfers a message over the wire format (encode + decode round trip).
fn over_the_wire(message: &Message) -> Message {
    let bytes = encode_message(message, &limits()).unwrap();
    let mut decoder = FrameDecoder::new(limits());
    let frames = decoder.feed(&bytes).unwrap();
    assert_eq!(frames.len(), 1);
    decode_message(&frames[0], &limits()).unwrap()
}

fn hello_message(client: &ClientAdmission) -> Message {
    over_the_wire(&client.first_message())
}

/// Drives both flows through admission and returns the member id.
fn run_admission(password: &[u8], token: &[u8], policy: JoinPolicy) -> Result<u64, AdmissionError> {
    run_admission_as(password, token, policy, "deniz", "deniz")
}

/// Drives both flows through admission with an explicit nickname.
///
/// `expected` is the nickname after normalization: the client must sign the
/// same value it puts on the wire, or the host verifies a different
/// transcript and rejects the application.
fn run_admission_as(
    password: &[u8],
    token: &[u8],
    policy: JoinPolicy,
    nickname: &str,
    expected: &str,
) -> Result<u64, AdmissionError> {
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(token.to_vec()),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();
    let mut client =
        ClientAdmission::new(invitation(token), SecretBytes::from(password.to_vec())).unwrap();

    // 1. Client hello -> signed host hello.
    let hello = hello_message(&client);
    let host_hello = host.on_client_hello(
        match &hello {
            Message::ClientHello(hello) => hello,
            _ => panic!("expected a client hello"),
        },
        80,
    )?;

    // 2. The client verifies the host hello and sends the token.
    let token_verify = client.on_host_message(&over_the_wire(&host_hello))?;
    assert_eq!(token_verify.len(), 1);

    // 3. Token -> password challenge.
    let challenge = host.on_message(&over_the_wire(&token_verify[0]), policy)?;
    let challenge = match challenge {
        Some(HostAdmissionReply::Message(message)) => message,
        _ => panic!("expected a password challenge"),
    };

    // 4. Challenge -> proof.
    let proof = client.on_host_message(&over_the_wire(&challenge))?;
    assert_eq!(proof.len(), 1);

    // 5. Proof is verified silently.
    let reply = host.on_message(&over_the_wire(&proof[0]), policy)?;
    assert!(reply.is_none(), "a verified proof must not produce a reply");

    // 6. The client signs the join request; the host verifies it.
    let join_request = client.join_request(nickname.to_owned(), Some("hello".to_owned()))?;
    let reply = host.on_message(&over_the_wire(&join_request), policy)?;
    let application = match reply {
        Some(HostAdmissionReply::JoinRequested(application)) => application,
        _ => panic!("expected a join request"),
    };
    assert_eq!(application.nickname, expected);

    // 7. The room queues and accepts.
    let mut queue = JoinRequestQueue::new(&limits());
    let request_id = queue.push(ConnectionId::new(1), application).unwrap();
    let _ = queue.take(request_id).unwrap();
    let accepted = host.accept(7);
    let outgoing = client.on_host_message(&over_the_wire(&accepted))?;
    assert!(outgoing.is_empty());
    assert!(client.is_admitted());
    Ok(client.member_id().unwrap().as_u64())
}

#[test]
fn full_admission_scenario_succeeds() {
    let token = vec![0x77; 16];
    let member_id = run_admission(ROOM_PASSWORD, &token, JoinPolicy::Open).unwrap();
    assert_eq!(member_id, 7);
}

#[test]
fn a_nickname_that_normalization_rewrites_still_verifies() {
    // The wire message carries the normalized nickname, so the signature
    // has to cover that same value. Signing the raw form would make the
    // host build a different transcript and reject every nickname that
    // normalization touches at all.
    let token = vec![0x77; 16];
    for (typed, expected) in [
        (" deniz ", "deniz"),
        ("de  niz", "de niz"),
        // Decomposed input: "i" + combining acute composes to U+00ED.
        ("den\u{69}\u{301}z", "den\u{ed}z"),
    ] {
        let member_id = run_admission_as(ROOM_PASSWORD, &token, JoinPolicy::Open, typed, expected)
            .unwrap_or_else(|error| panic!("{typed:?} must be admitted, got {error}"));
        assert_eq!(member_id, 7);
    }
}

#[test]
fn host_hello_can_only_be_processed_once() {
    let token = vec![0x77; 16];
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let identity = host_identity();
    let mut host = HostAdmission::new(
        RoomSessionId::from([0x11; 32]),
        SecretBytes::from(token.clone()),
        verifier,
        &identity,
        onion(),
    )
    .unwrap();
    let client = ClientAdmission::new(
        invitation(&token),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();
    let Message::ClientHello(hello) = client.first_message() else {
        panic!("expected a client hello");
    };
    host.on_client_hello(&hello, 80).unwrap();
    assert!(matches!(
        host.on_client_hello(&hello, 80),
        Err(AdmissionError::UnexpectedMessage)
    ));
}

#[test]
fn client_join_request_can_only_be_submitted_once() {
    let token = vec![0x77; 16];
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let identity = host_identity();
    let mut host = HostAdmission::new(
        RoomSessionId::from([0x11; 32]),
        SecretBytes::from(token.clone()),
        verifier,
        &identity,
        onion(),
    )
    .unwrap();
    let mut client = ClientAdmission::new(
        invitation(&token),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();
    let hello = hello_message(&client);
    let Message::ClientHello(hello) = hello else {
        panic!("expected a client hello");
    };
    let host_hello = host.on_client_hello(&hello, 80).unwrap();
    let token_verify = client.on_host_message(&host_hello).unwrap();
    let Some(HostAdmissionReply::Message(challenge)) =
        host.on_message(&token_verify[0], JoinPolicy::Open).unwrap()
    else {
        panic!("expected a password challenge");
    };
    let proof = client.on_host_message(&challenge).unwrap();
    host.on_message(&proof[0], JoinPolicy::Open).unwrap();
    client.join_request("deniz".to_owned(), None).unwrap();
    assert!(matches!(
        client.join_request("deniz".to_owned(), None),
        Err(AdmissionError::UnexpectedMessage)
    ));
}

#[test]
fn wrong_token_fails_host_hello_verification() {
    // The host signs its hello over its own token hash; a client holding a
    // different token cannot verify the transcript.
    let room_token = vec![0x77; 16];
    let wrong_token = vec![0x78; 16];
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(room_token),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();
    let mut client = ClientAdmission::new(
        invitation(&wrong_token),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();

    let hello = hello_message(&client);
    let host_hello = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap();
    let error = client
        .on_host_message(&over_the_wire(&host_hello))
        .unwrap_err();
    assert!(matches!(error, AdmissionError::InvalidHostSignature));
}

#[test]
fn token_verify_rejects_a_wrong_token() {
    let token = vec![0x77; 16];
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(token.clone()),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();
    let mut client = ClientAdmission::new(
        invitation(&token),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();

    let hello = hello_message(&client);
    let host_hello = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap();
    client.on_host_message(&over_the_wire(&host_hello)).unwrap();

    // The client always presents its own token; simulate a wrong token.
    let wrong = Message::TokenVerify(veilroom::protocol::TokenVerify::new(vec![0x99; 16]).unwrap());
    let error = host.on_message(&wrong, JoinPolicy::Open).unwrap_err();
    assert!(matches!(error, AdmissionError::InvalidToken));
    assert_eq!(error.error_code(), ErrorCode::InvalidInvitation);
}

#[test]
fn wrong_password_is_rejected() {
    let token = vec![0x77; 16];
    let error = run_admission(b"wrong password", &token, JoinPolicy::Open).unwrap_err();
    assert!(matches!(error, AdmissionError::InvalidPasswordProof));
    assert_eq!(error.error_code(), ErrorCode::InvalidPasswordProof);
}

#[test]
fn locked_room_rejects_the_join_form() {
    let token = vec![0x77; 16];
    let error = run_admission(ROOM_PASSWORD, &token, JoinPolicy::Locked).unwrap_err();
    assert!(matches!(error, AdmissionError::RoomLocked));
    assert_eq!(error.error_code(), ErrorCode::RoomLocked);
}

#[test]
fn unsupported_version_is_rejected() {
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(vec![0x77; 16]),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();

    let hello = Message::ClientHello(veilroom::protocol::ClientHello::new(2, [0x12; 16], 0));
    let error = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        AdmissionError::UnsupportedVersion { found: 2 }
    ));
    assert_eq!(error.error_code(), ErrorCode::UnsupportedVersion);
}

#[test]
fn non_zero_feature_bits_are_rejected() {
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(vec![0x77; 16]),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();

    let hello = Message::ClientHello(veilroom::protocol::ClientHello::new(1, [0x12; 16], 0x01));
    let error = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        AdmissionError::UnsupportedFeatures { features: 0x01 }
    ));
}

#[test]
fn out_of_order_messages_are_rejected() {
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(vec![0x77; 16]),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();

    // A proof before a token verify is a protocol violation.
    let proof = Message::ChallengeProof(veilroom::protocol::ChallengeProof::new([0x55; 32]));
    let error = host.on_message(&proof, JoinPolicy::Open).unwrap_err();
    assert!(matches!(error, AdmissionError::UnexpectedMessage));

    // A join form before the proof is a protocol violation.
    let client = ClientAdmission::new(
        invitation(&[0x77; 16]),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();
    let join = client.join_request("deniz".to_owned(), None);
    assert!(matches!(join, Err(AdmissionError::UnexpectedMessage)));
}

#[test]
fn tampered_join_signature_is_rejected() {
    let token = vec![0x77; 16];
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(token.clone()),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();
    let mut client = ClientAdmission::new(
        invitation(&token),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();

    let hello = hello_message(&client);
    let host_hello = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap();
    let token_verify = client.on_host_message(&over_the_wire(&host_hello)).unwrap();
    let challenge = host
        .on_message(&over_the_wire(&token_verify[0]), JoinPolicy::Open)
        .unwrap();
    let challenge = match challenge {
        Some(HostAdmissionReply::Message(message)) => message,
        _ => panic!(),
    };
    let proof = client.on_host_message(&over_the_wire(&challenge)).unwrap();
    host.on_message(&over_the_wire(&proof[0]), JoinPolicy::Open)
        .unwrap();

    // Sign a valid join request, then tamper with the signature bytes.
    let mut join_request = client.join_request("deniz".to_owned(), None).unwrap();
    let Message::JoinRequest(request) = &mut join_request else {
        panic!("expected a join request");
    };
    request.signature[0] ^= 0x01;

    let error = host
        .on_message(&join_request, JoinPolicy::Open)
        .unwrap_err();
    assert!(matches!(error, AdmissionError::InvalidJoinSignature));
}

#[test]
fn rejection_reaches_the_client() {
    let token = vec![0x77; 16];
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(token.clone()),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();
    let mut client = ClientAdmission::new(
        invitation(&token),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();
    let hello = hello_message(&client);
    let host_hello = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap();
    let token_verify = client.on_host_message(&over_the_wire(&host_hello)).unwrap();
    let challenge = host
        .on_message(&over_the_wire(&token_verify[0]), JoinPolicy::Open)
        .unwrap();
    let challenge = match challenge {
        Some(HostAdmissionReply::Message(message)) => message,
        _ => panic!(),
    };
    client.on_host_message(&over_the_wire(&challenge)).unwrap();

    let _request = client.join_request("deniz".to_owned(), None).unwrap();
    // A rejection is accepted only after a join request was submitted.
    let error = client
        .on_host_message(&Message::JoinRejected(
            veilroom::protocol::JoinRejected::new(Some("no room for you".to_owned())).unwrap(),
        ))
        .unwrap_err();
    assert!(matches!(error, AdmissionError::Rejected { .. }));
}

#[test]
fn epoch_wrap_roundtrips_to_the_client() {
    let token = vec![0x77; 16];
    let session_id = RoomSessionId::from([0x11; 32]);
    let verifier = PasswordVerifier::derive(ROOM_PASSWORD).unwrap();
    let host_identity = host_identity();
    let mut host = HostAdmission::new(
        session_id,
        SecretBytes::from(token.clone()),
        verifier,
        &host_identity,
        onion(),
    )
    .unwrap();
    let mut client = ClientAdmission::new(
        invitation(&token),
        SecretBytes::from(ROOM_PASSWORD.to_vec()),
    )
    .unwrap();

    let hello = hello_message(&client);
    let host_hello = host
        .on_client_hello(
            match &hello {
                Message::ClientHello(hello) => hello,
                _ => panic!(),
            },
            80,
        )
        .unwrap();
    client.on_host_message(&over_the_wire(&host_hello)).unwrap();
    let token_verify =
        Message::TokenVerify(veilroom::protocol::TokenVerify::new(token.clone()).unwrap());
    let challenge = host
        .on_message(&over_the_wire(&token_verify), JoinPolicy::Open)
        .unwrap();
    let challenge = match challenge {
        Some(HostAdmissionReply::Message(message)) => message,
        _ => panic!(),
    };
    let proof = client.on_host_message(&over_the_wire(&challenge)).unwrap();
    host.on_message(&over_the_wire(&proof[0]), JoinPolicy::Open)
        .unwrap();
    let join_request = client.join_request("deniz".to_owned(), None).unwrap();
    let application = match host
        .on_message(&over_the_wire(&join_request), JoinPolicy::Open)
        .unwrap()
    {
        Some(HostAdmissionReply::JoinRequested(application)) => application,
        _ => panic!(),
    };
    let accepted = host.accept(7);
    client.on_host_message(&over_the_wire(&accepted)).unwrap();

    // Wrap an epoch key for the member and deliver it.
    let wrap_key = host_identity.wrap_key_for(&application.x25519_pubkey, session_id.as_bytes(), 7);
    let epoch_key = veilroom::crypto::identity::EpochKey::generate().unwrap();
    let envelope =
        veilroom::crypto::identity::wrap_epoch_key(&wrap_key, &epoch_key, 3, session_id.as_bytes())
            .unwrap();
    let wrap = Message::EpochWrap(
        veilroom::protocol::EpochWrap::new(3, envelope.nonce, envelope.ciphertext).unwrap(),
    );

    let ack = client.on_epoch_wrap(match &wrap {
        Message::EpochWrap(wrap) => wrap,
        _ => panic!(),
    });
    let Message::EpochAck(ack) = ack.unwrap() else {
        panic!("expected an epoch acknowledgement");
    };
    assert_eq!(ack.epoch, 3);
    assert_eq!(client.chat().unwrap().current_epoch(), Some(3));

    // A wrap for a different member id cannot be unwrapped.
    let wrong_key =
        host_identity.wrap_key_for(&application.x25519_pubkey, session_id.as_bytes(), 8);
    let envelope = veilroom::crypto::identity::wrap_epoch_key(
        &wrong_key,
        &epoch_key,
        4,
        session_id.as_bytes(),
    )
    .unwrap();
    let wrap = Message::EpochWrap(
        veilroom::protocol::EpochWrap::new(4, envelope.nonce, envelope.ciphertext).unwrap(),
    );
    let Message::EpochWrap(wrap) = wrap else {
        panic!()
    };
    assert!(client.on_epoch_wrap(&wrap).is_err());
}

#[test]
fn fresh_randomness_keeps_sessions_distinct() {
    let a = random_bytes::<16>().unwrap();
    let b = random_bytes::<16>().unwrap();
    assert_ne!(a, b);
}
