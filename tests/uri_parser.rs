//! Public-API integration tests for the invitation-URI parser.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use veilroom::error::UriError;
use veilroom::uri::{Invitation, parse_invitation};

const ONION_BODY_LEN: usize = 56;
// Tor v3 address for an all-zero 32-byte identity key. The trailing bytes
// contain the valid checksum and version; 56 arbitrary base32 characters
// are not a valid v3 address.
const VALID_ONION_BODY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd";

fn onion_body(repeat: char) -> String {
    std::iter::repeat_n(repeat, ONION_BODY_LEN).collect()
}

fn valid_onion() -> String {
    format!("{VALID_ONION_BODY}.onion")
}

fn token_text(n_bytes: usize) -> String {
    URL_SAFE_NO_PAD.encode(vec![b'x'; n_bytes])
}

fn valid_uri(token_bytes: usize) -> String {
    format!(
        "veilroom://{}:80?v=1&token={}",
        valid_onion(),
        token_text(token_bytes)
    )
}

#[test]
fn parses_a_valid_invitation() {
    let invitation = parse_invitation(&valid_uri(16)).unwrap();
    assert_eq!(invitation.onion_address(), valid_onion());
    assert_eq!(invitation.port(), 80);
    assert_eq!(invitation.token(), &vec![b'x'; 16]);
}

#[test]
fn parses_minimum_and_maximum_token_sizes() {
    let min = parse_invitation(&valid_uri(16)).unwrap();
    assert_eq!(min.token().len(), 16);

    let max = parse_invitation(&valid_uri(32)).unwrap();
    assert_eq!(max.token().len(), 32);
}

#[test]
fn parses_any_valid_port() {
    for port in [1u16, 80, 443, 65535] {
        let uri = format!(
            "veilroom://{}:{port}?v=1&token={}",
            valid_onion(),
            token_text(16)
        );
        assert_eq!(parse_invitation(&uri).unwrap().port(), port);
    }
}

#[test]
fn roundtrip_produces_an_identical_invitation() {
    let invitation = parse_invitation(&valid_uri(24)).unwrap();
    assert_eq!(
        parse_invitation(&invitation.to_uri_string()),
        Ok(invitation)
    );
}

#[test]
fn constructed_invitation_renders_and_reparses() {
    let invitation = Invitation::new(valid_onion(), 443, vec![0x42; 32]).unwrap();
    let parsed = parse_invitation(&invitation.to_uri_string()).unwrap();
    assert_eq!(parsed, invitation);
}

#[test]
fn rejects_wrong_schemes() {
    assert_eq!(
        parse_invitation("veilroom:onion:80?v=1&token=x"),
        Err(UriError::InvalidScheme)
    );
    assert_eq!(
        parse_invitation("http://a.onion:80?v=1&token=x"),
        Err(UriError::InvalidScheme)
    );
    assert_eq!(
        parse_invitation("veilrooms://a.onion:80?v=1&token=x"),
        Err(UriError::InvalidScheme)
    );
}

#[test]
fn rejects_userinfo() {
    let uri = format!(
        "bob:secret@veilroom://{}:80?v=1&token={}",
        valid_onion(),
        token_text(16)
    );
    assert_eq!(parse_invitation(&uri), Err(UriError::UserInfoNotAllowed));
}

#[test]
fn rejects_fragments() {
    let uri = format!("{}#section", valid_uri(16));
    assert_eq!(parse_invitation(&uri), Err(UriError::FragmentNotAllowed));
}

#[test]
fn rejects_paths() {
    let uri = format!(
        "veilroom://{}/join?v=1&token={}",
        valid_onion(),
        token_text(16)
    );
    assert_eq!(parse_invitation(&uri), Err(UriError::PathNotAllowed));
}

#[test]
fn rejects_malformed_onions() {
    let cases = [
        format!("veilroom://a.onion:80?v=1&token={}", token_text(16)),
        format!(
            "veilroom://{}.onion:80?v=1&token={}",
            onion_body('a').repeat(2),
            token_text(16)
        ),
        format!(
            "veilroom://{}.com:80?v=1&token={}",
            onion_body('a'),
            token_text(16)
        ),
        format!(
            "veilroom://{}.onion:80?v=1&token={}",
            onion_body('A'),
            token_text(16)
        ),
        format!(
            "veilroom://{}.onion:80?v=1&token={}",
            onion_body('0'),
            token_text(16)
        ),
        format!(
            "veilroom://{}.onion:80?v=1&token={}",
            onion_body('8'),
            token_text(16)
        ),
        format!(
            "veilroom://{}.onion.onion:80?v=1&token={}",
            onion_body('a'),
            token_text(16)
        ),
    ];
    for case in cases {
        let error = parse_invitation(&case).unwrap_err();
        assert!(
            matches!(
                error,
                UriError::MalformedOnionAddress | UriError::InvalidOnionAlphabet
            ),
            "uri `{case}` produced {error:?}"
        );
    }
}

#[test]
fn rejects_invalid_ports() {
    let token = token_text(16);
    let onion = valid_onion();
    let cases = [
        format!("veilroom://{onion}?v=1&token={token}"),
        format!("veilroom://{onion}:?v=1&token={token}"),
        format!("veilroom://{onion}:80x?v=1&token={token}"),
        format!("veilroom://{onion}:-1?v=1&token={token}"),
        format!("veilroom://{onion}:0?v=1&token={token}"),
        format!("veilroom://{onion}:65536?v=1&token={token}"),
    ];
    for case in cases {
        let error = parse_invitation(&case).unwrap_err();
        assert!(
            matches!(error, UriError::MissingPort | UriError::InvalidPort),
            "uri `{case}` produced {error:?}"
        );
    }
}

#[test]
fn rejects_unsupported_versions() {
    let token = token_text(16);
    let base = format!("veilroom://{}:80", valid_onion());
    assert_eq!(
        parse_invitation(&format!("{base}?v=2&token={token}")),
        Err(UriError::UnsupportedVersion { found: 2 })
    );
    assert_eq!(
        parse_invitation(&format!("{base}?v=0&token={token}")),
        Err(UriError::UnsupportedVersion { found: 0 })
    );
    assert_eq!(
        parse_invitation(&format!("{base}?v=one&token={token}")),
        Err(UriError::InvalidVersion)
    );
    assert_eq!(
        parse_invitation(&format!("{base}?token={token}")),
        Err(UriError::MissingVersion)
    );
}

#[test]
fn rejects_invalid_tokens() {
    let base = format!("veilroom://{}:80?v=1", valid_onion());
    assert_eq!(parse_invitation(&base), Err(UriError::MissingToken));
    assert_eq!(
        parse_invitation(&format!("{base}&token=")),
        Err(UriError::InvalidQueryParameter {
            name: "token".to_owned()
        })
    );
    assert_eq!(
        parse_invitation(&format!("{base}&token=!!!not-base64!!!")),
        Err(UriError::InvalidToken)
    );
    assert_eq!(
        parse_invitation(&format!("{base}&token=QUJDREVGRw==")),
        Err(UriError::InvalidToken)
    );
    assert_eq!(
        parse_invitation(&format!("{base}&token={}", token_text(15))),
        Err(UriError::InvalidTokenLength { found: 15 })
    );
    assert_eq!(
        parse_invitation(&format!("{base}&token={}", token_text(33))),
        Err(UriError::InvalidTokenLength { found: 33 })
    );
}

#[test]
fn rejects_unknown_duplicate_and_malformed_parameters() {
    let base = format!(
        "veilroom://{}:80?v=1&token={}",
        valid_onion(),
        token_text(16)
    );
    assert_eq!(
        parse_invitation(&format!("{base}&expires=1")),
        Err(UriError::UnknownQueryParameter {
            name: "expires".to_owned()
        })
    );
    assert_eq!(
        parse_invitation(&format!("{base}&v=1")),
        Err(UriError::DuplicateQueryParameter {
            name: "v".to_owned()
        })
    );
    let malformed = [
        format!("veilroom://{}:80?v=1&token", valid_onion()),
        format!("veilroom://{}:80?v=1&=abc", valid_onion()),
        format!(
            "veilroom://{}:80?v=1&&token={}",
            valid_onion(),
            token_text(16)
        ),
        format!(
            "veilroom://{}:80?v=1&token={}&",
            valid_onion(),
            token_text(16)
        ),
    ];
    for uri in malformed {
        assert!(
            matches!(
                parse_invitation(&uri),
                Err(UriError::InvalidQueryParameter { .. })
            ),
            "uri `{uri}` was not rejected as a malformed parameter"
        );
    }
}
