//! Strict invitation-URI parser (architecture decision 10, section 22).
//!
//! Grammar:
//!
//! ```text
//! veilroom://<onion-v3-address>:<port>?v=1&token=<token>
//! ```
//!
//! Validation rules pinned for V1:
//! - Scheme is exactly `veilroom`; no userinfo, path, or fragment components.
//! - The host is a Tor v3 onion address: 56 lowercase base32 characters
//!   (`a`-`z`, `2`-`7`) followed by `.onion`. Uppercase is rejected.
//! - The virtual port is a decimal number in `1..=65535`.
//! - The `v` query parameter must equal the protocol major version.
//! - The `token` query parameter is URL-safe base64 without padding decoding
//!   to 16..=32 bytes (at least 128 bits of entropy).
//! - Unknown query parameters, duplicate parameters, and malformed
//!   parameters are rejected.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha3::{Digest, Sha3_256};

use crate::constants::{
    INVITATION_SCHEME, MAX_TOKEN_BYTES, MIN_TOKEN_BYTES, ONION_V3_ALPHABET, ONION_V3_BODY_LENGTH,
    ONION_V3_SUFFIX, PROTOCOL_MAJOR_VERSION, URI_PARAM_TOKEN, URI_PARAM_VERSION,
};
use crate::error::UriError;

/// Scheme/authority delimiter of the invitation URI.
const URI_DELIMITER: &str = "://";
/// Query parameter separator.
const QUERY_PARAM_SEPARATOR: char = '&';
/// Query parameter name/value separator.
const QUERY_VALUE_SEPARATOR: char = '=';

/// A strictly validated invitation (section 22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    onion_address: String,
    port: u16,
    token: Vec<u8>,
}

impl Invitation {
    /// Constructs an invitation from validated components.
    ///
    /// The onion address is validated against the V1 grammar, the port must
    /// be non-zero, and the token must decode to `MIN_TOKEN_BYTES..=
    /// MAX_TOKEN_BYTES` bytes.
    pub fn new(onion_address: String, port: u16, token: Vec<u8>) -> Result<Self, UriError> {
        validate_onion_address(&onion_address)?;
        if port == 0 {
            return Err(UriError::InvalidPort);
        }
        if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len()) {
            return Err(UriError::InvalidTokenLength { found: token.len() });
        }
        Ok(Self {
            onion_address,
            port,
            token,
        })
    }

    /// The validated onion v3 address, including the `.onion` suffix.
    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }

    /// The virtual port of the onion service.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The decoded invitation token bytes.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Renders the invitation as a canonical V1 URI.
    ///
    /// The output is guaranteed to parse back to an equal invitation.
    pub fn to_uri_string(&self) -> String {
        format!(
            "{INVITATION_SCHEME}://{}:{}?{URI_PARAM_VERSION}={PROTOCOL_MAJOR_VERSION}&{URI_PARAM_TOKEN}={}",
            self.onion_address,
            self.port,
            URL_SAFE_NO_PAD.encode(&self.token),
        )
    }
}

/// Parses and strictly validates an invitation URI.
///
/// Checks run in a fixed order: scheme, userinfo, fragment, path, onion
/// address, port, query parameters (unknown, duplicate, malformed), version,
/// token.
pub fn parse_invitation(input: &str) -> Result<Invitation, UriError> {
    if input.contains('#') {
        return Err(UriError::FragmentNotAllowed);
    }
    let Some(scheme_end) = input.find(URI_DELIMITER) else {
        return Err(UriError::InvalidScheme);
    };
    let scheme = &input[..scheme_end];
    if scheme.contains('@') || scheme.contains(':') {
        return Err(UriError::UserInfoNotAllowed);
    }
    if scheme != INVITATION_SCHEME {
        return Err(UriError::InvalidScheme);
    }
    let rest = &input[scheme_end + URI_DELIMITER.len()..];
    let (authority, query) = match rest.find('?') {
        Some(idx) => (&rest[..idx], &rest[idx + 1..]),
        None => (rest, ""),
    };
    if authority.contains('/') {
        return Err(UriError::PathNotAllowed);
    }
    let (host, port_text) = authority.rsplit_once(':').ok_or(UriError::MissingPort)?;
    validate_onion_address(host)?;
    let port = parse_port(port_text)?;
    if query.is_empty() {
        return Err(UriError::MissingVersion);
    }

    let mut version: Option<u8> = None;
    let mut token: Option<Vec<u8>> = None;
    let mut seen_names: Vec<&str> = Vec::new();
    for parameter in query.split(QUERY_PARAM_SEPARATOR) {
        let (name, value) = match parameter.split_once(QUERY_VALUE_SEPARATOR) {
            Some(pair) => pair,
            None => {
                return Err(UriError::InvalidQueryParameter {
                    name: parameter.to_owned(),
                });
            }
        };
        if name.is_empty() || value.is_empty() {
            return Err(UriError::InvalidQueryParameter {
                name: name.to_owned(),
            });
        }
        if seen_names.contains(&name) {
            return Err(UriError::DuplicateQueryParameter {
                name: name.to_owned(),
            });
        }
        seen_names.push(name);
        match name {
            URI_PARAM_VERSION => {
                if !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(UriError::InvalidVersion);
                }
                version = Some(value.parse().map_err(|_| UriError::InvalidVersion)?);
            }
            URI_PARAM_TOKEN => {
                let decoded = URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|_| UriError::InvalidToken)?;
                if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&decoded.len()) {
                    return Err(UriError::InvalidTokenLength {
                        found: decoded.len(),
                    });
                }
                token = Some(decoded);
            }
            other => {
                return Err(UriError::UnknownQueryParameter {
                    name: other.to_owned(),
                });
            }
        }
    }
    let version = version.ok_or(UriError::MissingVersion)?;
    if version != PROTOCOL_MAJOR_VERSION {
        return Err(UriError::UnsupportedVersion { found: version });
    }
    let token = token.ok_or(UriError::MissingToken)?;
    Ok(Invitation {
        onion_address: host.to_owned(),
        port,
        token,
    })
}

/// Validates a Tor v3 onion address: 56 base32 characters followed by `.onion`.
fn validate_onion_address(address: &str) -> Result<(), UriError> {
    let Some(body) = address.strip_suffix(ONION_V3_SUFFIX) else {
        return Err(UriError::MalformedOnionAddress);
    };
    if body.len() != ONION_V3_BODY_LENGTH {
        return Err(UriError::MalformedOnionAddress);
    }
    if !body
        .bytes()
        .all(|b| ONION_V3_ALPHABET.as_bytes().contains(&b))
    {
        return Err(UriError::InvalidOnionAlphabet);
    }
    if !is_valid_onion_v3_body(body) {
        return Err(UriError::MalformedOnionAddress);
    }
    Ok(())
}

/// Validates the decoded v3 address version and checksum.
pub(crate) fn is_valid_onion_v3_body(body: &str) -> bool {
    let Some(decoded) = decode_base32(body) else {
        return false;
    };
    if decoded.len() != 35 || decoded[34] != 3 {
        return false;
    }
    let mut checksum_input = Vec::with_capacity(15 + 32 + 1);
    checksum_input.extend_from_slice(b".onion checksum");
    checksum_input.extend_from_slice(&decoded[..32]);
    checksum_input.push(3);
    let digest = sha3_256(&checksum_input);
    decoded[32..34] == digest[..2]
}

fn decode_base32(text: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(text.len() * 5 / 8);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in text.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 && accumulator != 0 {
        return None;
    }
    Some(output)
}

/// SHA3-256 of the input, used only for the onion v3 address checksum.
fn sha3_256(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
}

/// Parses the virtual port: a decimal number in `1..=65535`.
fn parse_port(text: &str) -> Result<u16, UriError> {
    if text.is_empty() {
        return Err(UriError::MissingPort);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UriError::InvalidPort);
    }
    let port: u16 = text.parse().map_err(|_| UriError::InvalidPort)?;
    if port == 0 {
        return Err(UriError::InvalidPort);
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onion_body(repeat: char) -> String {
        std::iter::repeat_n(repeat, ONION_V3_BODY_LENGTH).collect()
    }

    fn valid_onion() -> String {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion".to_owned()
    }

    fn token_text(n_bytes: usize) -> String {
        URL_SAFE_NO_PAD.encode(vec![b'x'; n_bytes])
    }

    fn valid_uri(token_bytes: usize) -> String {
        format!(
            "{INVITATION_SCHEME}://{}:443?v={PROTOCOL_MAJOR_VERSION}&{URI_PARAM_TOKEN}={}",
            valid_onion(),
            token_text(token_bytes)
        )
    }

    #[test]
    fn parse_valid_uri() {
        let invitation = parse_invitation(&valid_uri(16)).unwrap();
        assert_eq!(invitation.onion_address(), valid_onion());
        assert_eq!(
            invitation.onion_address().len(),
            ONION_V3_BODY_LENGTH + ONION_V3_SUFFIX.len(),
            "a v3 onion hostname is 56 base32 body characters plus `.onion`"
        );
        assert_eq!(invitation.port(), 443);
        assert_eq!(invitation.token(), &vec![b'x'; 16]);
    }

    #[test]
    fn parse_valid_uri_with_32_byte_token() {
        let invitation = parse_invitation(&valid_uri(32)).unwrap();
        assert_eq!(
            invitation.token().len(),
            32,
            "the 32-byte token must survive generation, formatting, and parsing un-truncated"
        );
        assert_eq!(invitation.token(), &vec![b'x'; 32]);
    }

    #[test]
    fn roundtrip_via_to_uri_string() {
        let invitation = parse_invitation(&valid_uri(24)).unwrap();
        let rendered = invitation.to_uri_string();
        assert_eq!(parse_invitation(&rendered), Ok(invitation));
        // The rendered URI must not truncate the onion or the token.
        let reparsed = parse_invitation(&rendered).unwrap();
        assert_eq!(reparsed.onion_address().len(), 62);
        assert_eq!(reparsed.token().len(), 24);
    }

    #[test]
    fn constructor_validates_components() {
        assert!(Invitation::new(valid_onion(), 443, vec![b'x'; 16]).is_ok());
        assert_eq!(
            Invitation::new("bad.onion".to_owned(), 443, vec![b'x'; 16]),
            Err(UriError::MalformedOnionAddress)
        );
        assert_eq!(
            Invitation::new(valid_onion(), 0, vec![b'x'; 16]),
            Err(UriError::InvalidPort)
        );
        assert_eq!(
            Invitation::new(valid_onion(), 443, vec![b'x'; 15]),
            Err(UriError::InvalidTokenLength { found: 15 })
        );
        assert_eq!(
            Invitation::new(valid_onion(), 443, vec![b'x'; 33]),
            Err(UriError::InvalidTokenLength { found: 33 })
        );
    }

    #[test]
    fn rejects_missing_or_wrong_scheme() {
        assert_eq!(parse_invitation(""), Err(UriError::InvalidScheme));
        assert_eq!(
            parse_invitation("veilroomer://x.onion:80"),
            Err(UriError::InvalidScheme)
        );
        assert_eq!(
            parse_invitation("http://x.onion:80"),
            Err(UriError::InvalidScheme)
        );
        assert_eq!(
            parse_invitation("veilroom:/x.onion:80"),
            Err(UriError::InvalidScheme)
        );
    }

    #[test]
    fn rejects_userinfo_fragment_and_path() {
        let suffix = format!(":443?v=1&{URI_PARAM_TOKEN}={}", token_text(16));
        assert_eq!(
            parse_invitation(&format!("user:pass@veilroom://a{ONION_V3_SUFFIX}{suffix}")),
            Err(UriError::UserInfoNotAllowed)
        );
        assert_eq!(
            parse_invitation(&format!("user@veilroom://a{ONION_V3_SUFFIX}{suffix}")),
            Err(UriError::UserInfoNotAllowed)
        );
        assert_eq!(
            parse_invitation(&format!("veilroom://a{ONION_V3_SUFFIX}{suffix}#frag")),
            Err(UriError::FragmentNotAllowed)
        );
        assert_eq!(
            parse_invitation(&format!("veilroom://a{ONION_V3_SUFFIX}/room{suffix}")),
            Err(UriError::PathNotAllowed)
        );
    }

    #[test]
    fn rejects_malformed_onion_addresses() {
        let suffix = format!(":443?v=1&{URI_PARAM_TOKEN}={}", token_text(16));
        // Too short.
        assert_eq!(
            parse_invitation(&format!("veilroom://abc{ONION_V3_SUFFIX}{suffix}")),
            Err(UriError::MalformedOnionAddress)
        );
        // Missing suffix.
        assert_eq!(
            parse_invitation(&format!("veilroom://{}{suffix}", onion_body('a'))),
            Err(UriError::MalformedOnionAddress)
        );
        // Uppercase body.
        assert_eq!(
            parse_invitation(&format!("veilroom://{}.onion{suffix}", onion_body('A'))),
            Err(UriError::InvalidOnionAlphabet)
        );
        // Character outside the base32 alphabet ('1' is not valid in v3).
        let mut bad = onion_body('a');
        bad.replace_range(0..1, "1");
        assert_eq!(
            parse_invitation(&format!("veilroom://{bad}.onion{suffix}")),
            Err(UriError::InvalidOnionAlphabet)
        );
        // Double suffix.
        let mut doubled = onion_body('a');
        doubled.push_str(".onion.onion");
        assert_eq!(
            parse_invitation(&format!("veilroom://{doubled}{suffix}")),
            Err(UriError::MalformedOnionAddress)
        );
    }

    #[test]
    fn rejects_invalid_ports() {
        let host = format!("veilroom://{}", valid_onion());
        let query = format!("?v=1&{URI_PARAM_TOKEN}={}", token_text(16));
        // Missing port.
        assert_eq!(
            parse_invitation(&format!("{host}{query}")),
            Err(UriError::MissingPort)
        );
        // Empty port.
        assert_eq!(
            parse_invitation(&format!("{host}:{query}")),
            Err(UriError::MissingPort)
        );
        // Non-numeric port.
        assert_eq!(
            parse_invitation(&format!("{host}:abc{query}")),
            Err(UriError::InvalidPort)
        );
        // Zero port.
        assert_eq!(
            parse_invitation(&format!("{host}:0{query}")),
            Err(UriError::InvalidPort)
        );
        // Overflowing port.
        assert_eq!(
            parse_invitation(&format!("{host}:65536{query}")),
            Err(UriError::InvalidPort)
        );
        // Maximum port is accepted.
        assert!(parse_invitation(&format!("{host}:65535{query}")).is_ok());
    }

    #[test]
    fn rejects_invalid_versions() {
        let host = format!("veilroom://{}:443", valid_onion());
        let token = format!("{URI_PARAM_TOKEN}={}", token_text(16));
        // Missing version.
        assert_eq!(
            parse_invitation(&format!("{host}?{token}")),
            Err(UriError::MissingVersion)
        );
        // Unsupported version.
        assert_eq!(
            parse_invitation(&format!("{host}?v=2&{token}")),
            Err(UriError::UnsupportedVersion { found: 2 })
        );
        // Non-numeric version.
        assert_eq!(
            parse_invitation(&format!("{host}?v=abc&{token}")),
            Err(UriError::InvalidVersion)
        );
        // Version overflowing u8.
        assert_eq!(
            parse_invitation(&format!("{host}?v=300&{token}")),
            Err(UriError::InvalidVersion)
        );
    }

    #[test]
    fn rejects_invalid_tokens() {
        let host = format!("veilroom://{}:443?v=1", valid_onion());
        // Missing token.
        assert_eq!(parse_invitation(&host), Err(UriError::MissingToken));
        // Empty token.
        assert_eq!(
            parse_invitation(&format!("{host}&{URI_PARAM_TOKEN}=")),
            Err(UriError::InvalidQueryParameter {
                name: URI_PARAM_TOKEN.to_owned()
            })
        );
        // Not valid base64.
        assert_eq!(
            parse_invitation(&format!("{host}&{URI_PARAM_TOKEN}=!!!!")),
            Err(UriError::InvalidToken)
        );
        // Base64 with padding.
        assert_eq!(
            parse_invitation(&format!("{host}&{URI_PARAM_TOKEN}=eHh4eHh4eHh4eHh4eA==")),
            Err(UriError::InvalidToken)
        );
        // Decodes to fewer than 16 bytes.
        assert_eq!(
            parse_invitation(&format!("{host}&{URI_PARAM_TOKEN}={}", token_text(15))),
            Err(UriError::InvalidTokenLength { found: 15 })
        );
        // Decodes to more than 32 bytes.
        assert_eq!(
            parse_invitation(&format!("{host}&{URI_PARAM_TOKEN}={}", token_text(33))),
            Err(UriError::InvalidTokenLength { found: 33 })
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_malformed_query_parameters() {
        let host = format!("veilroom://{}:443", valid_onion());
        let token = format!("{URI_PARAM_TOKEN}={}", token_text(16));
        assert_eq!(
            parse_invitation(&format!("{host}?v=1&{token}&foo=bar")),
            Err(UriError::UnknownQueryParameter {
                name: "foo".to_owned()
            })
        );
        assert_eq!(
            parse_invitation(&format!("{host}?v=1&v=1&{token}")),
            Err(UriError::DuplicateQueryParameter {
                name: "v".to_owned()
            })
        );
        assert_eq!(
            parse_invitation(&format!(
                "{host}?v=1&{token}&{URI_PARAM_TOKEN}={}",
                token_text(16)
            )),
            Err(UriError::DuplicateQueryParameter {
                name: URI_PARAM_TOKEN.to_owned()
            })
        );
        // Parameter without `=`.
        assert_eq!(
            parse_invitation(&format!("{host}?v=1&{token}&token")),
            Err(UriError::InvalidQueryParameter {
                name: "token".to_owned()
            })
        );
        // Empty parameter segment.
        assert_eq!(
            parse_invitation(&format!("{host}?v=1&&{token}")),
            Err(UriError::InvalidQueryParameter {
                name: String::new()
            })
        );
    }

    #[test]
    fn validate_onion_address_unit() {
        assert!(validate_onion_address(&valid_onion()).is_ok());
        // Correct length and base32 alphabet are insufficient: Tor v3 also
        // binds a checksum and the address-format version.
        assert!(validate_onion_address(&format!("{}.onion", onion_body('7'))).is_err());
        assert!(validate_onion_address(&format!("{}.onion", onion_body('z'))).is_err());
        assert!(validate_onion_address("").is_err());
        assert!(validate_onion_address("a.onion").is_err());
        assert!(validate_onion_address("x.onion.onion").is_err());
        assert!(validate_onion_address("onion").is_err());
    }

    #[test]
    fn parse_port_unit() {
        assert_eq!(parse_port("80"), Ok(80));
        assert_eq!(parse_port("65535"), Ok(65535));
        assert_eq!(parse_port(""), Err(UriError::MissingPort));
        assert_eq!(parse_port("0"), Err(UriError::InvalidPort));
        assert_eq!(parse_port("65536"), Err(UriError::InvalidPort));
        assert_eq!(parse_port("abc"), Err(UriError::InvalidPort));
        assert_eq!(parse_port("1.5"), Err(UriError::InvalidPort));
        assert_eq!(parse_port("-1"), Err(UriError::InvalidPort));
    }
}
