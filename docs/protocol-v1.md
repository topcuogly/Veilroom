# Veilroom Protocol V1

This document is the binding description of the Veilroom network protocol,
version 1. It must stay synchronized with the implementation; a stage is
incomplete if this document and the code disagree.

Status of each section:

- `[specified]` - pinned by this document and implemented in the current
  version directory.

All sections are specified as of Stage 9; the document and the
implementation must stay in agreement.

---

## 1. Overview and versioning `[specified]`

Veilroom V1 is a single-room, host-centered, ephemeral group chat protocol
running over raw TCP connections through Tor v3 onion services.

- Only protocol major version 1 is supported (`PROTOCOL_MAJOR_VERSION = 1`).
- A V1 client communicates only with V1. There is no downgrade.
- Multiple major versions in one room are not supported.
- Cryptographic algorithms are fixed for V1 and are not negotiated:
  Ed25519, X25519, HKDF-SHA-256, HMAC-SHA-256, XChaCha20-Poly1305, Argon2id.
- Security-relevant protocol changes require a new major version.
- Version checks exist in three places, and they must agree: the invitation
  URI (`v=1`), the frame header protocol-version byte, and the handshake.

---

## 2. Invitation URI `[specified]`

Grammar:

```text
veilroom://<onion-v3-address>:<port>?v=1&token=<token>
```

Validation rules (strict; anything else is rejected):

| Component | Rule |
|---|---|
| Scheme | Exactly `veilroom` (lowercase) |
| Userinfo | Rejected |
| Path | Rejected |
| Fragment | Rejected |
| Host | Tor v3 onion address: 56 lowercase base32 characters (`a`-`z`, `2`-`7`) followed by `.onion` (62 characters total); uppercase is rejected |
| Port | Decimal number in `1..=65535` |
| `v` | Must equal `1`; non-numeric or overflowing values are rejected |
| `token` | URL-safe base64 without padding (`A`-`Z`, `a`-`z`, `0`-`9`, `-`, `_`), decoding to `16..=32` bytes (at least 128 bits of entropy) |
| Unknown query parameters | Rejected |
| Duplicate query parameters | Rejected |
| Parameters without `=` or with empty name/value | Rejected |

The URI never contains the room password, a nickname, a persistent identity,
or a message-encryption key.

The grammar accepts 16..=32 token bytes, but a room this implementation
creates always generates 32 (`RoomActor::create`, `/newid`). The floor
matters because the host hello exposes an offline verification oracle for the
token (section 8): a token below 128 bits would be guessable without ever
talking to the host again.

Reference implementation: `src/uri.rs` (`parse_invitation`, `Invitation`).

---

## 3. Frame format `[specified]`

A single long-lived TCP byte stream carries length-prefixed binary frames
(architecture decision 6). All multi-byte integers are big-endian.

```text
uint32 frame_length   // length of the body in bytes
uint8  protocol_version
uint8  message_type
uint16 flags          // reserved in V1, must be 0x0000
bytes  payload        // strict CBOR, one value per message
```

Rules:

- `frame_length` covers version, type, flags, and payload; the minimum body
  size is 4 bytes.
- The declared length is validated against `Limits.max_frame_size`
  (16 KiB) before the payload is read; oversized frames terminate the
  connection immediately.
- The version byte must equal `1` (`PROTOCOL_MAJOR_VERSION`).
- Non-zero flags are a protocol violation (`ProtocolViolation`).
- A stream that ends with an incomplete frame is an error.
- Parsers never panic and never allocate without bound; the decoder
  buffers at most one incomplete frame.

Reference implementation: `src/protocol/frame.rs`.

## 4. Message IDs `[specified]`

Numeric message IDs are fixed for V1 and never reused for another meaning.
The ID ranges are reserved as follows:

```text
0x01-0x1F  Handshake and authentication
0x20-0x3F  Membership and room events
0x40-0x5F  Chat messages
0x60-0x7F  Epoch and key management
0x80-0x8F  Keepalive and shutdown
```

| ID | Message | Class | Stage |
|---|---|---|---|
| 0x01 | `HOST_HELLO` | handshake | 4 |
| 0x02 | `CLIENT_HELLO` | handshake | 4 |
| 0x03 | `TOKEN_VERIFY` | authentication | 4 |
| 0x04 | `PASSWORD_CHALLENGE` | authentication | 4 |
| 0x05 | `CHALLENGE_PROOF` | authentication | 4 |
| 0x06 | `JOIN_REQUEST` | join | 4 |
| 0x07 | `JOIN_ACCEPTED` | join | 4 |
| 0x08 | `JOIN_REJECTED` | join | 4 |
| 0x20 | `MEMBER_JOINED` | membership | 5 |
| 0x21 | `MEMBER_LEFT` | membership | 5 |
| 0x22 | `MEMBER_KICKED` | membership | 5 |
| 0x23 | `JOIN_POLICY_CHANGED` | membership | 5 |
| 0x24 | `MEMBER_SNAPSHOT` | membership | 5 |
| 0x40 | `CHAT_MESSAGE` | chat | 7 |
| 0x41 | `COLOR_CHANGE` | chat | 7 |
| 0x42 | `TIMEOUT_REQUEST` | chat | 7 |
| 0x43 | `TIMEOUT_CHANGED` | chat | 7 |
| 0x60 | `EPOCH_WRAP` | epoch | 6 |
| 0x61 | `EPOCH_ACK` | epoch | 6 |
| 0x80 | `KEEPALIVE` | control | 2 |
| 0x81 | `ERROR` | control | 2 |
| 0x82 | `SHUTDOWN` | control | 2 |

Stable error codes carried by `ERROR` messages:

| Code | Meaning |
|---|---|
| 1 | `PROTOCOL_VIOLATION` |
| 2 | `UNSUPPORTED_VERSION` |
| 3 | `INVALID_INVITATION` |
| 4 | `ROOM_LOCKED` |
| 5 | `INVALID_PASSWORD_PROOF` |
| 6 | `CONNECTION_TIMEOUT` |
| 7 | `ROOM_CLOSED` |
| 8 | `RATE_LIMITED` |
| 9 | `INTERNAL` |

Reference implementation: `src/protocol/ids.rs`.

## 5. CBOR schemas `[specified]`

Payloads are CBOR (RFC 8949) encoded with minicbor. Encoding is
deterministic: definite-length maps with keys in ascending field-number
order, integers encoded minimally, no tags.

The strict decoder (section 30) enforces:

- Nesting depth limited by `Limits.max_cbor_nesting_depth` (8).
- Map sizes limited by `Limits.max_cbor_map_entries` (64).
- Array sizes limited by `Limits.max_cbor_array_entries` (256).
- Indefinite-length structures are rejected.
- Duplicate map keys are rejected.
- Unknown fields are rejected by each message schema.
- Text strings are limited by `Limits.max_cbor_text_bytes` (4096) and byte
  strings by `Limits.max_cbor_bytes_len` (4096).
- Tags, unexpected types, malformed input, and trailing bytes are rejected.
- Raw or generic CBOR values never reach room logic; only typed, validated
  messages do.

### Stage 2 message schemas

`KEEPALIVE` (0x80):

```text
map(0)                    // empty map, encodes as 0xA0
```

`SHUTDOWN` (0x82):

```text
map(0)                    // empty map, encodes as 0xA0
```

`ERROR` (0x81):

```text
map {
  1: code   (uint8, one of the stable error codes)
  2: reason (text, optional, at most 256 bytes, no control characters)
}
```

### Stage 4 message schemas

`HOST_HELLO` (0x01, host -> client):

```text
map {
  1: version             (uint8, must be 1)
  2: room_session_id     (bytes, exactly 32)
  3: host_ed25519_pubkey (bytes, exactly 32)
  4: host_x25519_pubkey  (bytes, exactly 32)
  5: server_nonce        (bytes, exactly 16)
  6: host_signature      (bytes, exactly 64)
}
```

`CLIENT_HELLO` (0x02, client -> host):

```text
map {
  1: version      (uint8, must be 1)
  2: client_nonce (bytes, exactly 16)
  3: features     (uint32, must be 0 in V1)
}
```

`TOKEN_VERIFY` (0x03, client -> host):

```text
map {
  1: token (bytes, 16..=32)
}
```

`PASSWORD_CHALLENGE` (0x04, host -> client):

```text
map {
  1: m_cost          (uint32, Argon2id memory cost in KiB)
  2: t_cost          (uint32, Argon2id time cost)
  3: p_cost          (uint8, Argon2id parallelism)
  4: salt            (bytes, exactly 16)
  5: challenge_nonce (bytes, exactly 16)
}
```

`CHALLENGE_PROOF` (0x05, client -> host):

```text
map {
  1: proof (bytes, exactly 32, HMAC-SHA-256)
}
```

`JOIN_REQUEST` (0x06, client -> host):

```text
map {
  1: nickname        (text, 1..=32 Unicode scalar values, normalized)
  2: introduction    (text, optional, 1..=160 Unicode scalar values, single line)
  3: ed25519_pubkey  (bytes, exactly 32)
  4: x25519_pubkey   (bytes, exactly 32)
  5: signature       (bytes, exactly 64)
}
```

`JOIN_ACCEPTED` (0x07, host -> client):

```text
map {
  1: member_id (uint64)
}
```

`JOIN_REJECTED` (0x08, host -> client):

```text
map {
  1: reason (text, optional, at most 256 bytes, no control characters)
}
```

`EPOCH_WRAP` (0x60, host -> member):

```text
map {
  1: epoch      (uint64)
  2: nonce      (bytes, exactly 24, XChaCha20-Poly1305)
  3: ciphertext (bytes, exactly 48: the 32-byte epoch key plus the 16-byte tag)
}
```

`EPOCH_ACK` (0x61, member -> host):

```text
map {
  1: epoch (uint64)
}
```

`JOIN_POLICY_CHANGED` (0x23, host -> members):

```text
map {
  1: sequence  (uint64, strictly increasing room-event sequence)
  2: epoch     (uint64, current epoch)
  3: open      (boolean)
  4: signature (bytes, exactly 64, host Ed25519 signature)
}
```

Reference implementation: `src/protocol/strict.rs`,
`src/protocol/messages.rs`, `src/protocol/handshake.rs`,
`src/protocol/epoch.rs`.

## 6. Connection state machine `[specified]`

States:

```text
DISCONNECTED -> TOR_CONNECTING -> PROTOCOL_HANDSHAKE -> PRE_AUTH
             -> PASSWORD_VERIFIED -> JOIN_PENDING -> ACTIVE
             -> CLOSING -> DISCONNECTED
```

Only messages valid for the current state are accepted (section 13.1). The
message-class acceptance table:

| State | Accepted classes |
|---|---|
| `DISCONNECTED`, `TOR_CONNECTING` | none |
| `PROTOCOL_HANDSHAKE` | handshake, control |
| `PRE_AUTH` | authentication, control |
| `PASSWORD_VERIFIED` | join, control |
| `JOIN_PENDING` | control |
| `ACTIVE` | membership, chat, epoch, control |
| `CLOSING` | control |

A chat message received during `PRE_AUTH` is a protocol violation. The
table is enforced by `ConnectionState::accepts` in `src/state.rs`.

---

## 7. Room state machine `[specified]`

States:

```text
CREATING -> OPEN <-> LOCKED -> CLOSING -> DESTROYED
```

Transient internal states: `EPOCH_TRANSITION` (entered and left
synchronously during every membership change), `INVITE_ROTATING` (token
rotation, `/newid`).

Transitions:

- `CREATING -> OPEN`: the room is started (invitation emitted).
- `OPEN -> LOCKED`: `/reqon` -> `/reqoff`; pending requests are rejected.
- `LOCKED -> OPEN`: `/reqoff` -> `/reqon`.
- `* -> CLOSING -> DESTROYED`: host `/exit` or Tor loss; members are
  notified with `SHUTDOWN` and every connection is closed.
- Membership changes (join, leave, kick, connection loss) advance the epoch
  counter and the room sequence number through the transient
  `EPOCH_TRANSITION` state; key generation and `EPOCH_ACK` handling are
  added in Stage 6.

The room actor (`src/room/`) is the sole writer of room state; every other
task communicates through typed `RoomEvent` values (section 34.1). Member
ids are room-lifetime and unique; the host is member 0 (section 32).
`/list`, `/whois`, `/color`, `/leave`, `/kick`, `/newid`, `/reqon`,
`/reqoff`, `/requests`, `/accept`, `/reject`, `/timeout`, and `/timeoutreq` semantics follow
sections 22, 23, 32, and 33; race conditions (accept/disconnect,
kick/disconnect, nickname collisions, duplicate events) are covered by
deterministic actor tests. `/timeout <seconds>` (and `/timeout off`) sets a
room-wide per-message display lifetime. Members propose a lifetime with `/timeoutreq
<seconds>`; the host applies it with the same `/accept <request-id>` flow as
join requests.

---

## 8. Handshake sequence `[specified]`

```text
client -> host:  CLIENT_HELLO   (version, client nonce, features)
host  -> client: HOST_HELLO    (version, room session id, host Ed25519 + X25519
                                 keys, server nonce, host signature)
```

- The host rejects a client hello with a version other than 1 or non-zero
  feature bits with `ERROR / UNSUPPORTED_VERSION` or
  `ERROR / PROTOCOL_VIOLATION` respectively.
- The host signs the canonical host-hello transcript (section 17) with its
  ephemeral Ed25519 key; the participant verifies the signature and pins
  the host's Ed25519 and X25519 keys for the room.
- A host-key change within the same room session is a critical protocol
  error.
- The signed host-hello transcript contains `token_hash` (SHA-256 of the
  invitation token, section 17) and the host hello is sent *before*
  `TOKEN_VERIFY`, so anyone who can reach the onion service obtains an
  **offline verification oracle for the token**: a guess can be checked by
  rebuilding the transcript and verifying the signature, with no further
  round trip. This is accepted, not overlooked. The hash cannot be an HMAC
  because both sides must derive it from the token alone, and the only
  candidate key — the room session id — is itself public in the same
  message. The oracle is harmless at the mandated entropy: guessing a
  128-bit token is infeasible, and rooms are created with 256-bit tokens.

## 9. Invitation-token flow `[specified]`

After the host hello, the client sends:

```text
client -> host: TOKEN_VERIFY   (the invitation token bytes)
```

- The host compares the presented token to the room's current token in
  constant time. A mismatch closes the connection with
  `ERROR / INVALID_INVITATION`.
- `TOKEN_VERIFY` is valid only once per connection; the room's token is
  rotated by `/newid` (Stage 5).

## 10. Password challenge-response `[specified]`

After a valid token, the host sends a fresh challenge:

```text
host  -> client: PASSWORD_CHALLENGE  (Argon2id parameters, salt, challenge nonce)
client -> host:  CHALLENGE_PROOF     (HMAC-SHA-256 proof)
```

- The host derives the Argon2id key once at room creation from the room
  password (`ARGON2_M_COST = 19 MiB`, `ARGON2_T_COST = 2`,
  `ARGON2_P_COST = 1`, 32-byte output, fresh random 16-byte salt).
- The participant derives the same key from the supplied parameters and
  computes `HMAC-SHA-256(key, VEILROOM-PASSWORD-PROOF-V1 ||
  challenge_nonce || client_nonce)`.
- The host compares proofs in constant time; a failed proof closes the
  connection with `ERROR / INVALID_PASSWORD_PROOF`, so a connection gets
  exactly one attempt.
- The host derives its Argon2id verifier once at room creation, so every
  proof check is a cheap HMAC comparison: the KDF cost is paid only by the
  party computing a proof, and reconnecting is free for anyone holding the
  invitation token. The per-connection cap is therefore not an anti-guessing
  measure on its own.
- The host keeps a room-lifetime failure count
  (`src/admission/guard.rs`, `PasswordGuard`). Every
  `PASSWORD_FAILURE_THRESHOLD = 5` failed proofs start a lockout window
  during which new admission flows are refused with `ERROR / RATE_LIMITED`;
  the window starts at `PASSWORD_LOCKOUT_BASE = 30 s`, doubles per lockout,
  and saturates at `PASSWORD_LOCKOUT_MAX = 15 min`. Connections that are
  already admitted are never affected.
- The plaintext password is never transmitted and is never used as a
  message-encryption key.

## 11. Join request and introduction `[specified]`

After a verified proof (silently acknowledged), the client submits:

```text
client -> host: JOIN_REQUEST   (nickname, introduction, keys, signature)
```

- The nickname is validated and normalized: NFC composition, no control
  characters, no whitespace other than `U+0020` (an exotic blank such as
  `U+00A0` is refused, never folded), outer spaces trimmed, inner runs of
  spaces collapsed to one, and 1..=32 Unicode scalar values after
  normalization. Uniqueness is decided on the normalized form: the member
  table compares nicknames exactly while a terminal renders whitespace
  invisibly, so without this `deniz` and `deniz ` would be two members that
  look identical on screen. The optional introduction is validated
  separately (1..=160 Unicode scalar values, single line, no control
  characters, host-visible only) and is not normalized.
- The nickname carried by the message and the nickname covered by the
  signature are the same normalized value. A client that signs the raw
  input and transmits the normalized form produces a transcript the host
  cannot reproduce, and every nickname that normalization rewrites would
  fail admission.
- The participant signs the canonical join-request transcript (section 17)
  with its ephemeral Ed25519 key; the host verifies the signature with the
  key carried in the message. A failed verification closes the connection
  with `ERROR / PROTOCOL_VIOLATION`.
- The room must be `OPEN`; otherwise the connection is closed with
  `ERROR / ROOM_LOCKED`. Knowing the password grants only the right to
  apply.
- A nickname is reserved only when the request is accepted.

## 12. Host accept/reject `[specified]`

- Pending requests receive monotonically increasing `request_id` values
  for the current room lifetime (`src/admission/queue.rs`).
- The queue is bounded by `Limits.max_pending_requests` (8).
- `/requests` lists pending requests; `/accept <request-id>` and
  `/reject <request-id>` decide them; `/reqoff` drains the queue and
  disables the join flow until `/reqon`.
- An accepted application receives `JOIN_ACCEPTED` with its `member_id`; a
  denied one receives `JOIN_REJECTED` with an optional reason.

---

## 13. Epoch transition `[specified]`

Epoch rotation on join, leave, connection loss, and kick; no rotation for
`/color`, `/reqon`, `/reqoff`, `/newid`, or plain chat.

Flow (section 18):

1. Validate the membership change.
2. Increment the epoch number.
3. Generate a fresh 256-bit epoch key.
4. Wrap the key separately for every remaining/new active member and send
   `EPOCH_WRAP` to each; the room enters `EPOCH_TRANSITION`.
5. Each member acknowledges with `EPOCH_ACK`; the epoch activates only
   after every member has acknowledged (including the host participant).
6. While a transition is pending, only acknowledgements, connection
   losses, timeouts, and shutdown are processed; other events are rejected.
   Chat from a member that has already acknowledged the pending epoch is
   still relayed (opened with the pending key, which that member holds),
   so a single stalling member cannot freeze the room. A message from a
   member that has not acknowledged is sealed under the retired key: the
   host cannot relay it and cannot re-seal it, so it is dropped without
   terminating the connection. The host answers it with `RateLimited` and a
   reason, because the sender has already echoed the line locally and would
   otherwise believe it was delivered; the sender should send it again.
7. A member who fails to acknowledge within the configured timeout is
   disconnected, and a new transition is created for the remaining members.
8. Obsolete epoch keys are zeroized when replaced.

Stale acknowledgements (wrong epoch or non-member sender) are ignored.

## 14. Epoch-key wrapping `[specified]`

Per-member key channel (section 15):

- Every participant (including the host participant) uses an ephemeral
  X25519 key pair; the host's X25519 public key is delivered in
  `HOST_HELLO`, the participant's in `JOIN_REQUEST`.
- Both sides derive the same X25519 shared secret.
- The member wrapping key is
  `HKDF-SHA-256(salt = room_session_id, ikm = shared_secret,
  info = "VEILROOM-MEMBER-WRAP-KEY-V1" || member_id_be64)`, 32 bytes.
- Each epoch key is wrapped with XChaCha20-Poly1305 under the member
  wrapping key with a fresh random 24-byte nonce. The additional data is
  `"VEILROOM-EPOCH-WRAP-V1" || room_session_id || epoch_be64`.
- No envelope is produced for a user who has left or been kicked; a kicked
  member cannot unwrap later epoch keys (verified by tests).
- Wrap keys and epoch keys are zeroized on drop.

---

## 15. Chat-message envelope `[specified]`

Four message types carry encrypted chat-layer payloads (section 4):

- `0x40 CHAT_MESSAGE` - UTF-8 chat text (max `max_chat_text_bytes` bytes)
- `0x41 COLOR_CHANGE` - a single color index from the fixed palette
- `0x42 TIMEOUT_REQUEST` - an unsigned 64-bit, big-endian message lifetime in seconds
  (1 through 3600), sent from a member to the host
- `0x43 TIMEOUT_CHANGED` - a one-byte enabled flag followed by an unsigned
  64-bit, big-endian message lifetime; authored by the host and relayed to members

Both use the same `EncryptedEnvelope`:

```text
uint64 epoch            // the epoch this message was sealed in
uint64 sender_id        // the sender's room-lifetime member id
uint64 sender_sequence  // the sender's monotonic sequence in this epoch
bytes  nonce            // 24-byte fresh XChaCha20-Poly1305 nonce
bytes  ciphertext       // plaintext + 16-byte tag (17..=4112 bytes)
bytes  signature        // 64-byte Ed25519 signature over the chat transcript
```

Processing (member side, `ChatSession`):

- The envelope must carry the receiver's current epoch; any other epoch is
  rejected as `OldEpoch` before decryption.
- The sender must be a known member of the room (verified against the
  member table installed from signed broadcasts); an unknown sender id is
  rejected.
- Replay is checked before signature verification but recorded only after
  a successful open, so a rejected message never burns its sequence.
- The sender's Ed25519 signature is verified over the chat transcript
  (section 17), then the AEAD authenticates and decrypts (section 16).
- The sender sequence is recorded per (sender, epoch) after a successful
  open.

Reference implementation: `src/protocol/chat.rs`,
`src/crypto/chat.rs`, `src/chat/session.rs`.

The host's administration pane never sends `0x40 CHAT_MESSAGE`: the host
participates as a member by joining the room from a second terminal. Chat
messages are always authored by member connections.

---

## 16. AEAD AAD `[specified]`

The AEAD additional data of a chat message binds the context exactly as
`chat_aad` builds it (`src/crypto/chat.rs`):

```text
"VEILROOM-CHAT-AAD-V1"           // fixed label, no length prefix
u8  version                      // protocol major version (1)
fixed room_session_id            // 32 bytes
u64 epoch                        // big-endian
u64 sender_id                    // big-endian
u64 sender_sequence              // big-endian
u8  message_type                 // 0x40, 0x41, 0x42, or 0x43
```

The AAD is the only binding between the ciphertext and its context: an
envelope decrypted under the wrong epoch, session, sender, sequence, or
message type fails authentication. The signature transcript (section 17)
covers the same context plus the nonce and ciphertext, so neither the
content nor the binding can be altered.

Epoch envelopes use a distinct AAD (section 14):
`"VEILROOM-EPOCH-WRAP-V1" || room_session_id || epoch_be64`.

---

## 17. Signature transcripts and domain labels `[specified]`

Fixed labels:

```text
VEILROOM-HOST-HELLO-V1
VEILROOM-JOIN-REQUEST-V1
VEILROOM-ROOM-EVENT-V1
VEILROOM-CHAT-MESSAGE-V1
VEILROOM-EPOCH-WRAP-V1
```

The password proof additionally uses the label `VEILROOM-PASSWORD-PROOF-V1`
(an HMAC context, not a signature), and the per-member wrapping key uses
the HKDF info label `VEILROOM-MEMBER-WRAP-KEY-V1` (section 14).

Canonical transcript encoding (`src/crypto/transcript.rs`): explicit field
ordering; labels and variable-length byte strings are prefixed with a
big-endian `u32` length; fixed-size fields (keys, nonces, hashes) are
appended raw; integers are big-endian. Signature inputs are verified
through test vectors and cannot be reused across message types.

Host-hello transcript field order:

```text
label | u8 version | bytes onion_address | u16 virtual_port
fixed room_session_id | fixed host_ed25519_pubkey
fixed host_x25519_pubkey
fixed client_nonce | fixed server_nonce | fixed token_hash
u8 offered_version | u32 client_features
```

Join-request transcript field order:

```text
label | u8 version | fixed room_session_id
fixed client_nonce | fixed server_nonce | bytes nickname (normalized)
fixed introduction_hash | fixed participant_ed25519_pubkey
fixed participant_x25519_pubkey | bytes onion_address | fixed token_hash
```

Chat-message transcript field order (signed by the sender):

```text
label | u8 version | fixed room_session_id
u64 epoch | u64 sender_id | u64 sender_sequence | u8 message_type
fixed nonce | bytes ciphertext
```

Room-event transcript field order (signed by the host; used for the
membership broadcasts `0x20`, `0x21`, `0x22`, and `0x24`):

```text
label | u8 version | fixed room_session_id
u64 sequence | u64 epoch | u8 event_type | bytes body
```

Membership event bodies (`src/crypto/transcript.rs`):

- `MEMBER_JOINED` body: `u64 member_id | bytes nickname | fixed ed25519_pubkey`
- `MEMBER_LEFT` / `MEMBER_KICKED` body: `u64 member_id`
- `MEMBER_SNAPSHOT` body: `u64 count`, then per member
  `u64 member_id | bytes nickname | u8 color_index | u8 is_host | fixed ed25519_pubkey`

`token_hash` is SHA-256 of the invitation token; `introduction_hash` is
SHA-256 of the introduction message (the empty string when no introduction
is given).

Cryptographic primitives are validated against published vectors
(RFC 8032 Ed25519, RFC 7748 X25519, RFC 5869 HKDF-SHA-256, and the
XChaCha20-Poly1305 IETF draft); the protocol constructions (transcripts,
wrapping-key derivation, epoch envelopes) are pinned by golden test
vectors in the test suite.

---

## 18. Replay rules `[specified]`

Each sender maintains a monotonic sequence number per epoch, starting at
1 and incremented for every sealed message. Receivers track the last
accepted sequence per `(sender, epoch)` and reject any envelope with
`sender_sequence <= last_accepted_sequence` (`ReplayRejected`). The check
runs before verification but the sequence is recorded only after a
successful open, so a tampered or replayed message cannot desynchronize
the window. Sequence state is cleared when the epoch rotates.

Replay protection is enforced at the application layer and never
delegated to TCP.

Reference implementation: `src/chat/replay.rs`, `src/chat/session.rs`.

---

## 19. Size limits `[specified]`

Default values (`src/limits.rs`, `Limits`):

| Limit | Value |
|---|---|
| `max_active_members` | 16 |
| `max_pending_requests` | 8 |
| `max_pre_auth_connections` | 16 |
| `max_frame_size` | 16 KiB (16384 bytes) |
| `max_chat_text_bytes` | 4096 bytes |
| `max_nickname_scalars` | 32 Unicode scalar values |
| `max_intro_scalars` | 160 Unicode scalar values |
| `max_cbor_nesting_depth` | 8 levels |
| `max_cbor_map_entries` | 64 entries |
| `max_cbor_array_entries` | 256 elements |
| `max_cbor_text_bytes` | 4096 bytes |
| `max_cbor_bytes_len` | 4096 bytes |

All values belong to a single `Limits` structure; `Limits::validate()`
rejects inconsistent configurations.

---

## 20. Timeout semantics `[specified]`

Initial default durations (`src/limits.rs`, `Timeouts`). Values are tuned
through testing; Tor latency must be considered.

| Timeout | Default |
|---|---|
| `protocol_handshake` | 30 s |
| `token_validation` | 30 s |
| `password_verification` | 60 s |
| `join_form_submission` | 120 s |
| `host_decision` | 300 s |
| `epoch_acknowledgement` | 30 s |
| `keepalive_interval` | 30 s |
| `graceful_shutdown` | 10 s |

Enforcement (Stage 8): the host supervisor closes any connection that
has not completed the admission handshake within `protocol_handshake`;
the transport sends a keepalive frame every `keepalive_interval`; the
room closes on `graceful_shutdown` when the host exits. The remaining
per-state timeouts are configuration defaults for the network layer.

---

## 21. Rate limiting `[defaults specified, enforcement stage 7]`

Token-bucket policy for active members (`src/limits.rs`, `RateLimit`):
burst 5 messages, sustained 1 message per second. Enforcement (Stage 8):
the room actor applies the bucket per member on every chat message and on
every color change (they share one bucket, so color spam is throttled like
chat); an initial violation rejects the message with `RateLimited` and a
notice; persistent abuse terminates the connection. A `RateLimited` error
refuses one message and never the connection, so a member that receives it
keeps its session; only the codes that accompany a connection the host is
closing end the session. Every connection has a
bounded outbound queue (64 frames); when the queue is full the slow
connection is closed (`QueueFull`) and the member is removed. Messages
are never silently dropped.

Reference implementation: `src/chat/ratelimit.rs`, `src/net/conn.rs`,
`src/room/actor.rs`.

---

## 22. Slash commands `[specified]`

Parsed only by the local TUI (`src/command.rs`); raw command text is never
sent over the network. Unknown commands are never sent as chat text;
`//text` sends `/text` as a normal chat message. Command names are
case-sensitive.

| Command | Arguments | Class |
|---|---|---|
| `/help` | none | local |
| `/exit` | none | local |
| `/leave` | none | member |
| `/color <color>` | one of `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white` | member |
| `/color list` | none | local (all participants; prints names in their colors) |
| `/list` | none | member |
| `/whois <member>` | member id, short id, or nickname | member |
| `/kick <member>` | numeric member id, or nickname when unambiguous | host |
| `/newid` | none | host |
| `/reqon` | none | host |
| `/reqoff` | none | host |
| `/requests` | none | host |
| `/accept <request-id>` | numeric request id | host |
| `/reject <request-id>` | numeric request id | host |
| `/copy` | none | local (host: copy the full invitation URI) |
| `/clear` | none | local (all participants; clears only the local message pane) |
| `/timeout <seconds>` | positive seconds, or `off` | host (sets or disables timestamp-based expiry for each message) |
| `/timeoutreq <seconds>` | positive seconds | member (requests a host-approved per-message lifetime) |

Join requests and timeout requests share one room-lifetime request-id
namespace. `/requests`, `/accept <request-id>`, and `/reject <request-id>`
operate on either kind. An accepted timeout request causes the host to emit
`TIMEOUT_CHANGED`; a rejected request is not relayed.

---

## 23. Error and shutdown behavior `[specified]`

Stable error codes (`src/protocol/ids.rs`, `ErrorMessage`):

| Code | Name | Meaning |
|---|---|---|
| 1 | `ProtocolViolation` | A message invalid for the current state, an undecodable frame, or non-zero flags |
| 2 | `UnsupportedVersion` | The peer speaks an unsupported protocol version |
| 3 | `InvalidInvitation` | The invitation URI or token is invalid |
| 4 | `RoomLocked` | The room is not accepting join requests |
| 5 | `InvalidPasswordProof` | The password proof did not verify |
| 6 | `ConnectionTimeout` | The connection timed out |
| 7 | `RoomClosed` | The room is closing or has closed |
| 8 | `RateLimited` | One message was refused; the sender should send it again. Covers the chat rate limit and a transient room state (an epoch transition in flight). Recoverable: the connection stays open |
| 9 | `Internal` | An internal error occurred |

Admission failures (invalid token, wrong password, rejected join, bad
signatures) close the connection after an `ErrorMessage`; the host never
reveals secret material in the reason text.

Graceful shutdown sequence (host `/exit`, Ctrl-C, or Tor failure):

1. The room actor moves to `Closing` and emits `Shutdown` frames plus
   `CloseConnection` actions for every member.
2. The host supervisor writes the `Shutdown` frame, then tears down each
   connection.
3. The room task terminates; the network listener and accept loop stop.
4. The Tor subprocess receives `DEL_ONION` and `SIGNAL SHUTDOWN`; the
   session directory is removed.
5. The terminal is restored (alternate screen left, raw mode disabled,
   cursor shown) on every path, including errors and panics.

A member leaving closes its connection; the host treats the EOF as a
member left and rotates the epoch.

---

## 24. Deferred and out-of-scope behavior

Per the architecture document, V1 does not implement: file transfer,
private messages, multiple rooms, host migration, automatic reconnect,
room recovery, persistent accounts, bans, message history, message
editing/deletion, rich text, link previews, voice/video, mobile clients,
MLS, onion-address rotation, automatic clipboard writes, or a bundled Tor
binary. Explicit `/copy` and Ctrl-Y actions use an installed clipboard
helper; bracketed paste is accepted in input forms.

---

## 25. Tor runtime `[specified]`

Every Veilroom process launches and manages its own Tor subprocess
(architecture decision 9); it never connects to a system-wide daemon.

Runtime layout (architecture decision 20, section 20):

```text
$XDG_RUNTIME_DIR/veilroom/session-<random>/
├── tor-data/          # Tor data directory (control_auth_cookie, cache, state)
├── control.sock       # Tor control socket (Unix)
├── socks.sock         # Tor SOCKS socket (Unix)
├── chat.sock          # onion-service local target (app listener)
├── lock               # session lock sentinel
```

- The session directory name includes 16 random bytes from the OS CSPRNG.
- All directories are created with mode `0700`.
- Nothing is written to `$HOME`, `$XDG_CONFIG_HOME`, `$XDG_DATA_HOME`, or
  persistent `/var` locations.
- If `$XDG_RUNTIME_DIR` is unavailable the application refuses to run; it
  never falls back to `/tmp`.
- Runtime paths containing characters unsafe in an `ADD_ONION Port=` token
  are rejected before a session directory is created.
- The application refuses to run as root.
- Controlled shutdown removes the session directory; cleanup cannot be
  guaranteed after `SIGKILL` or power loss.

Tor binary discovery (section 19): an explicit `--tor-binary <path>`
override, then `tor` on `PATH`. If neither is available the application
reports a clear error.

Tor control subset used by V1 (section 21):

- `AUTHENTICATE` with the control cookie (hex-encoded)
- `GETINFO status/bootstrap-phase` (bootstrap status)
- `ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=<port>,unix:<chat.sock>`
  (ephemeral v3 onion, no `Detach`, Unix-socket local target)
- `DEL_ONION <service-id>` during shutdown
- `SIGNAL SHUTDOWN` (controlled shutdown)

The Tor subprocess runs with `CookieAuthentication 1`, `SafeLogging 1`,
and `AvoidDiskWrites 1`; its stdout and stderr are discarded and no log
file is created. The control endpoint is line-based; replies are parsed
with full multiline and data-block (`250+...` terminated by `.`)
semantics.

Reference implementation: `src/platform.rs`, `src/tor/`.
