# Veilroom V1 Test Vectors

Golden vectors for the protocol constructions of Veilroom V1. The values
here are pinned by `tests/test_vectors.rs` and the unit tests in
`src/crypto/`; the document and the tests must stay in agreement.

All inputs use fixed test keys and fixed context values. Test keys are NOT
production secrets and must never be used outside tests.

---

## 1. SHA-256

Input: `abc`

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Pinned by `tests/test_vectors.rs::sha256_matches_the_golden_vector` and
`src/crypto/transcript.rs`.

---

## 2. Host-hello transcript

Label `VEILROOM-HOST-HELLO-V1`, canonical encoding (section 17 of the
protocol document).

Fixed inputs:

```text
version            = 0x01
onion_address      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
virtual_port       = 80
room_session_id    = 0x01 * 32
host_ed25519_pubkey = 0x02 * 32
host_x25519_pubkey  = 0x06 * 32
client_nonce       = 0x03 * 16
server_nonce       = 0x04 * 16
token_hash         = 0x05 * 32
offered_version    = 0x01
client_features    = 0x00000000
```

Expected transcript (hex):

```text
000000165645494c524f4f4d2d484f53542d48454c4c4f2d563101000000426161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612e6f6e696f6e0050010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020606060606060606060606060606060606060606060606060606060606060606030303030303030303030303030303030404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050100000000
```

---

## 3. Join-request transcript

Label `VEILROOM-JOIN-REQUEST-V1`.

Fixed inputs:

```text
version             = 0x01
room_session_id     = 0x11 * 32
client_nonce        = 0x12 * 16
server_nonce        = 0x13 * 16
nickname            = "deniz"
introduction_hash   = 0x14 * 32
participant_ed25519_pubkey = 0x15 * 32
participant_x25519_pubkey = 0x16 * 32
onion_address       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
token_hash          = 0x17 * 32
```

Expected transcript (hex):

```text
000000185645494c524f4f4d2d4a4f494e2d524551554553542d563101111111111111111111111111111111111111111111111111111111111111111112121212121212121212121212121212131313131313131313131313131313130000000564656e697a141414141414141414141414141414141414141414141414141414141414141415151515151515151515151515151515151515151515151515151515151515151616161616161616161616161616161616161616161616161616161616161616000000426161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612e6f6e696f6e1717171717171717171717171717171717171717171717171717171717171717
```

---

## 4. Room-event transcript (MEMBER_JOINED)

Label `VEILROOM-ROOM-EVENT-V1`, event type `0x20`, body built from
`member_id = 9`, `nickname = "deniz"`, `ed25519_pubkey = 0x22 * 32`.

Fixed inputs:

```text
version        = 0x01
room_session_id = 0x21 * 32
sequence       = 7
epoch          = 3
event_type     = 0x20
```

Expected transcript (hex):

```text
000000165645494c524f4f4d2d524f4f4d2d4556454e542d563101212121212121212121212121212121212121212121212121212121212121212100000000000000070000000000000003200000003100000000000000090000000564656e697a2222222222222222222222222222222222222222222222222222222222222222
```

---

## 5. Chat-message transcript

Label `VEILROOM-CHAT-MESSAGE-V1`.

Fixed inputs:

```text
version          = 0x01
room_session_id  = 0x31 * 32
epoch            = 4
sender_id        = 2
sender_sequence  = 11
message_type     = 0x40
nonce            = 0x41 * 24
ciphertext       = "hello" (5 bytes)
```

Expected transcript (hex):

```text
000000185645494c524f4f4d2d434841542d4d4553534147452d563101313131313131313131313131313131313131313131313131313131313131313100000000000000040000000000000002000000000000000b404141414141414141414141414141414141414141414141410000000568656c6c6f
```

---

## 6. Chat AEAD additional data

Label `VEILROOM-CHAT-AAD-V1` (no length prefix), same context values as
section 5.

Expected AAD (hex):

```text
5645494c524f4f4d2d434841542d4141442d563101313131313131313131313131313131313131313131313131313131313131313100000000000000040000000000000002000000000000000b40
```

---

## 7. Fixed identities

Host identity seeds `ed25519 = 0x51 * 32`, `x25519 = 0x52 * 32`:

```text
host ed25519 pubkey: c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a
host x25519  pubkey: f68b05ba03f7185e1ba88878682f8dd0b15158f6050889c9481d79c2d7d2fa07
```

Member identity seeds `ed25519 = 0x61 * 32`, `x25519 = 0x62 * 32`:

```text
member ed25519 pubkey: af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d
member x25519  pubkey: 4a4f8ccde198d66e99b4c014418a3223ce256c98900ae4a6811fd10f7eb84c2c
```

---

## 8. Signatures

The host signs the section 2 transcript with the section 7 host identity:

```text
3370617155a387fbc5072320bcd9fbc46dedf1d58a7131a89b1e6d670f17076daf9d7a1ef07fed4f6d0e0b738317919e37ece7bfca83ca803c620236383c770a
```

The member signs the section 5 chat transcript with the section 7 member
identity:

```text
e74a33824babb13dcf952caacd1dfb5e5c01f9fc6c97fd92995963de8e7c777781988c1332a7cf90b92a6937e1f0bac08995f112ec4cdddce1d276f61b1d210a
```

Ed25519 signatures are deterministic; flipping any transcript byte makes
both signatures fail verification (pinned by
`tests/test_vectors.rs::tampering_with_any_vector_breaks_verification`).

---

## 9. Member wrapping key (HKDF-SHA-256)

X25519 shared secret between the section 7 host and member identities,
HKDF-SHA-256 with salt `room_session_id = 0x71 * 32` and info
`VEILROOM-MEMBER-WRAP-KEY-V1 || member_id_be64(5)`, 32-byte output:

```text
d82dd368035f9725f806d0679b06fc368f8313658cb8f2777949e70f5d90667c
```

Pinned by `src/crypto/identity.rs::wrap_key_matches_the_golden_vector`.

---

## 10. Epoch envelope

The wrapping key from section 9 wraps the fixed epoch key
`epoch_key = 0x81 * 32` for epoch `6` in the session `0x71 * 32`. The
nonce is fresh per wrap, so the ciphertext is not reproducible; the
round trip (wrap, then unwrap with the correct epoch and session) is
verified by the identity tests, and a wrong epoch, session, or wrap key
fails authentication (tamper tests in `src/crypto/identity.rs`).

The epoch envelope additional data is fixed and verifiable:
`VEILROOM-EPOCH-WRAP-V1 || room_session_id || epoch_be64`.

---

## 11. Published algorithm vectors

The primitives are additionally pinned against published vectors:

- Ed25519: RFC 8032 test vector 1 (`src/crypto/identity.rs`)
- X25519: RFC 7748 vector 1 (`src/crypto/identity.rs`)
- HKDF-SHA-256: RFC 5869 test case 1 (`src/crypto/identity.rs`)
- SHA-256: NIST `abc` vector (`src/crypto/transcript.rs`)
