//! Golden test vectors for the protocol constructions (section 17).
//!
//! Every vector uses fixed inputs (fixed test keys, fixed session id,
//! fixed epochs, fixed sequences); the expected hex values are pinned in
//! `docs/test-vectors.md`. Test keys are NOT production secrets. Changing
//! any transcript field order, AAD binding, or signature scheme breaks
//! these pins.

use veilroom::constants::{
    ED25519_PUBKEY_LEN, HMAC_LEN, NONCE_LEN, ROOM_SESSION_ID_LEN, XCHACHA_NONCE_LEN,
};
use veilroom::crypto::chat::{chat_aad, chat_transcript};
use veilroom::crypto::identity::{HostIdentity, MemberIdentity, verify_ed25519};
use veilroom::crypto::transcript::{
    HostHelloTranscriptInput, JoinRequestTranscriptInput, host_hello_transcript,
    join_request_transcript, member_joined_body, room_event_transcript, sha256,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The fixed host-hello transcript inputs (docs/test-vectors.md).
fn hello_input() -> HostHelloTranscriptInput {
    HostHelloTranscriptInput {
        version: 1,
        onion_address: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
            .to_owned(),
        virtual_port: 80,
        room_session_id: [0x01; ROOM_SESSION_ID_LEN],
        host_ed25519_pubkey: [0x02; ED25519_PUBKEY_LEN],
        host_x25519_pubkey: [0x06; 32],
        client_nonce: [0x03; NONCE_LEN],
        server_nonce: [0x04; NONCE_LEN],
        token_hash: [0x05; HMAC_LEN],
        offered_version: 1,
        client_features: 0,
    }
}

/// The fixed join-request transcript inputs (docs/test-vectors.md).
fn join_input() -> JoinRequestTranscriptInput {
    JoinRequestTranscriptInput {
        version: 1,
        room_session_id: [0x11; ROOM_SESSION_ID_LEN],
        client_nonce: [0x12; NONCE_LEN],
        server_nonce: [0x13; NONCE_LEN],
        nickname: "deniz".to_owned(),
        introduction_hash: [0x14; HMAC_LEN],
        participant_ed25519_pubkey: [0x15; ED25519_PUBKEY_LEN],
        participant_x25519_pubkey: [0x16; 32],
        onion_address: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
            .to_owned(),
        token_hash: [0x17; HMAC_LEN],
    }
}

#[test]
fn sha256_matches_the_golden_vector() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn host_hello_transcript_matches_the_golden_vector() {
    let expected = "000000165645494c524f4f4d2d484f53542d48454c4c4f2d563101000000426161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612e6f6e696f6e0050010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020606060606060606060606060606060606060606060606060606060606060606030303030303030303030303030303030404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050100000000";
    assert_eq!(hex(&host_hello_transcript(&hello_input())), expected);
}

#[test]
fn join_request_transcript_matches_the_golden_vector() {
    let expected = "000000185645494c524f4f4d2d4a4f494e2d524551554553542d563101111111111111111111111111111111111111111111111111111111111111111112121212121212121212121212121212131313131313131313131313131313130000000564656e697a141414141414141414141414141414141414141414141414141414141414141415151515151515151515151515151515151515151515151515151515151515151616161616161616161616161616161616161616161616161616161616161616000000426161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612e6f6e696f6e1717171717171717171717171717171717171717171717171717171717171717";
    assert_eq!(hex(&join_request_transcript(&join_input())), expected);
}

#[test]
fn room_event_transcript_matches_the_golden_vector() {
    let expected = "000000165645494c524f4f4d2d524f4f4d2d4556454e542d563101212121212121212121212121212121212121212121212121212121212121212100000000000000070000000000000003200000003100000000000000090000000564656e697a2222222222222222222222222222222222222222222222222222222222222222";
    let transcript = room_event_transcript(
        1,
        &[0x21; ROOM_SESSION_ID_LEN],
        7,
        3,
        0x20,
        &member_joined_body(9, "deniz", &[0x22; 32]),
    );
    assert_eq!(hex(&transcript), expected);
}

#[test]
fn chat_transcript_matches_the_golden_vector() {
    let expected = "000000185645494c524f4f4d2d434841542d4d4553534147452d563101313131313131313131313131313131313131313131313131313131313131313100000000000000040000000000000002000000000000000b404141414141414141414141414141414141414141414141410000000568656c6c6f";
    let transcript = chat_transcript(
        1,
        &[0x31; ROOM_SESSION_ID_LEN],
        4,
        2,
        11,
        0x40,
        &[0x41; XCHACHA_NONCE_LEN],
        b"hello",
    );
    assert_eq!(hex(&transcript), expected);
}

#[test]
fn chat_aad_matches_the_golden_vector() {
    let expected = "5645494c524f4f4d2d434841542d4141442d563101313131313131313131313131313131313131313131313131313131313131313100000000000000040000000000000002000000000000000b40";
    let aad = chat_aad(1, &[0x31; ROOM_SESSION_ID_LEN], 4, 2, 11, 0x40);
    assert_eq!(hex(&aad), expected);
}

#[test]
fn fixed_identities_match_the_golden_public_keys() {
    let host = HostIdentity::from_seed([0x51; 32], [0x52; 32]);
    assert_eq!(
        hex(&host.ed25519_pubkey()),
        "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a"
    );
    assert_eq!(
        hex(&host.x25519_pubkey()),
        "f68b05ba03f7185e1ba88878682f8dd0b15158f6050889c9481d79c2d7d2fa07"
    );

    let member = MemberIdentity::from_seed([0x61; 32], [0x62; 32]);
    assert_eq!(
        hex(&member.ed25519_pubkey()),
        "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d"
    );
    assert_eq!(
        hex(&member.x25519_pubkey()),
        "4a4f8ccde198d66e99b4c014418a3223ce256c98900ae4a6811fd10f7eb84c2c"
    );
}

#[test]
fn signatures_match_the_golden_vectors_and_verify() {
    let host = HostIdentity::from_seed([0x51; 32], [0x52; 32]);
    let hello = host_hello_transcript(&hello_input());
    let host_signature = unhex(
        "3370617155a387fbc5072320bcd9fbc46dedf1d58a7131a89b1e6d670f17076daf9d7a1ef07fed4f6d0e0b738317919e37ece7bfca83ca803c620236383c770a",
    );
    assert_eq!(hex(&host.sign(&hello)), hex(&host_signature));
    let signature: [u8; 64] = host_signature.try_into().unwrap();
    assert!(verify_ed25519(&host.ed25519_pubkey(), &hello, &signature));

    let member = MemberIdentity::from_seed([0x61; 32], [0x62; 32]);
    let chat = chat_transcript(
        1,
        &[0x31; ROOM_SESSION_ID_LEN],
        4,
        2,
        11,
        0x40,
        &[0x41; XCHACHA_NONCE_LEN],
        b"hello",
    );
    let member_signature = unhex(
        "e74a33824babb13dcf952caacd1dfb5e5c01f9fc6c97fd92995963de8e7c777781988c1332a7cf90b92a6937e1f0bac08995f112ec4cdddce1d276f61b1d210a",
    );
    assert_eq!(hex(&member.sign(&chat)), hex(&member_signature));
    let signature: [u8; 64] = member_signature.try_into().unwrap();
    assert!(verify_ed25519(&member.ed25519_pubkey(), &chat, &signature));
}

#[test]
fn tampering_with_any_vector_breaks_verification() {
    // A single flipped transcript byte must invalidate the signature.
    let host = HostIdentity::from_seed([0x51; 32], [0x52; 32]);
    let hello = host_hello_transcript(&hello_input());
    let signature: [u8; 64] = unhex(
        "3370617155a387fbc5072320bcd9fbc46dedf1d58a7131a89b1e6d670f17076daf9d7a1ef07fed4f6d0e0b738317919e37ece7bfca83ca803c620236383c770a",
    )
    .try_into()
    .unwrap();
    let mut tampered = hello.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(!verify_ed25519(
        &host.ed25519_pubkey(),
        &tampered,
        &signature
    ));
}
