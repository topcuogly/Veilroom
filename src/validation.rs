//! Validation and sanitization of nicknames, introduction messages, and
//! chat text (sections 25, 28, and 32).
//!
//! Rules:
//! - Control characters, DEL, and C1 controls are rejected everywhere
//!   (this also rejects every ANSI escape sequence, because all ANSI escape
//!   sequences start with ESC or a C1 control).
//! - Nicknames are NFC-normalized and limited to a number of Unicode scalar
//!   values.
//! - Introduction messages are optional, single-line, and limited to a
//!   number of Unicode scalar values.
//! - Chat text is limited to a number of UTF-8 bytes.

use unicode_normalization::UnicodeNormalization;

use crate::error::ValidationError;
use crate::limits::Limits;

/// Whether the input contains any control character or display-spoofing
/// format character.
///
/// Covers C0 (`U+0000..=U+001F`), DEL (`U+007F`), and C1 (`U+0080..=U+009F`).
/// Because every ANSI escape sequence starts with ESC (`U+001B`) or a C1
/// control, this also rejects all ANSI escape sequences. Additionally,
/// Unicode `Cf` format characters that enable display spoofing (bidi
/// overrides and isolates, zero-width and directional marks) are rejected.
pub fn contains_control_char(input: &str) -> bool {
    input.chars().any(is_unsafe_display_char)
}

/// Whether a single `char` must never reach the terminal or the wire.
///
/// Control characters (`char::is_control`: C0, DEL, C1) are rejected, as are
/// the Unicode `Cf` format characters that can be used to spoof on-screen
/// text: bidi overrides/embeddings (`U+202A..=U+202E`), bidi isolates
/// (`U+2066..=U+2069`), directional marks (`U+200E`, `U+200F`), zero-width
/// characters (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`), and the invisible
/// mathematical format characters (`U+2060..=U+2064`). Variation selectors
/// (`U+FE0E`, `U+FE0F`) are intentionally kept so that emoji still render.
pub fn is_unsafe_display_char(ch: char) -> bool {
    ch.is_control() || is_dangerous_format_char(ch)
}

fn is_dangerous_format_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}'..='\u{200F}' // ZWSP, ZWNJ, ZWJ, LRM, RLM
            | '\u{202A}'..='\u{202E}' // bidi overrides and embeddings
            | '\u{2060}'..='\u{2064}' // word joiner and invisible format chars
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}' // zero-width no-break space / BOM
    )
}

/// Validates and normalizes a nickname.
///
/// Returns the normalized nickname on success. The nickname must be
/// non-empty, free of control characters, and no longer than
/// `limits.max_nickname_scalars()` Unicode scalar values.
///
/// Whitespace is normalized because the member table enforces uniqueness by
/// exact comparison while the terminal renders whitespace invisibly: without
/// this, `"deniz"`, `"deniz "`, and `"deniz\u{a0}"` are three distinct
/// members that look identical on screen, which is an impersonation vector
/// in a room whose whole notion of identity is the nickname. Whitespace
/// other than a plain space is rejected outright rather than folded, so the
/// requester sees why the nickname was refused; plain spaces are trimmed at
/// the ends and collapsed in the middle.
pub fn validate_nickname(input: &str, limits: &Limits) -> Result<String, ValidationError> {
    if input.is_empty() {
        return Err(ValidationError::EmptyNickname);
    }
    let composed: String = input.nfc().collect();
    if contains_control_char(&composed) {
        return Err(ValidationError::ControlCharacterNotAllowed);
    }
    if composed.chars().any(|ch| ch.is_whitespace() && ch != ' ') {
        return Err(ValidationError::ExoticWhitespaceNotAllowed);
    }
    let normalized = collapse_spaces(&composed);
    if normalized.is_empty() {
        return Err(ValidationError::EmptyNickname);
    }
    if normalized.chars().count() > limits.max_nickname_scalars() {
        return Err(ValidationError::NicknameTooLong {
            max: limits.max_nickname_scalars(),
        });
    }
    Ok(normalized)
}

/// Trims outer spaces and collapses inner runs of spaces to a single space.
fn collapse_spaces(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for word in input.split(' ').filter(|word| !word.is_empty()) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// Validates an optional introduction message (section 9).
///
/// An empty string is accepted and means "no introduction". Otherwise the
/// message must be a single line, free of control characters, and no longer
/// than `limits.max_intro_scalars()` Unicode scalar values.
pub fn validate_intro(input: &str, limits: &Limits) -> Result<(), ValidationError> {
    if input.is_empty() {
        return Ok(());
    }
    if input.contains(['\n', '\r']) {
        return Err(ValidationError::NotSingleLine);
    }
    if contains_control_char(input) {
        return Err(ValidationError::ControlCharacterNotAllowed);
    }
    if input.chars().count() > limits.max_intro_scalars() {
        return Err(ValidationError::IntroTooLong {
            max: limits.max_intro_scalars(),
        });
    }
    Ok(())
}

/// Validates chat text (sections 25 and 28).
///
/// The message must be free of control characters and no longer than
/// `limits.max_chat_text_bytes()` UTF-8 bytes.
pub fn validate_chat_text(input: &str, limits: &Limits) -> Result<(), ValidationError> {
    if contains_control_char(input) {
        return Err(ValidationError::ControlCharacterNotAllowed);
    }
    if input.len() > limits.max_chat_text_bytes() {
        return Err(ValidationError::ChatTextTooLong {
            max_bytes: limits.max_chat_text_bytes(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn contains_control_char_detects_all_control_classes() {
        assert!(!contains_control_char("plain text"));
        assert!(contains_control_char("\u{0000}"));
        assert!(contains_control_char("\u{001b}[31m"));
        assert!(contains_control_char("\u{007f}"));
        assert!(contains_control_char("\u{009b}31m"));
        assert!(contains_control_char("a\nb"));
    }

    #[test]
    fn display_spoofing_format_chars_are_rejected() {
        assert!(contains_control_char("evil\u{202e}"));
        assert!(contains_control_char("\u{202a}text\u{202c}"));
        assert!(contains_control_char("a\u{2066}b\u{2069}"));
        assert!(contains_control_char("a\u{200b}b"));
        assert!(contains_control_char("a\u{200d}b"));
        assert!(contains_control_char("\u{feff}b"));
        assert!(contains_control_char("a\u{200f}b"));
        // Emoji presentation selectors are allowed.
        assert!(!contains_control_char("\u{2764}\u{fe0f}"));
        assert!(!contains_control_char("\u{1f469}\u{1f3fd}"));
    }

    #[test]
    fn nickname_rejects_empty() {
        assert_eq!(
            validate_nickname("", &limits()),
            Err(ValidationError::EmptyNickname)
        );
    }

    #[test]
    fn nickname_normalizes_to_nfc() {
        let normalized = validate_nickname("e\u{301}", &limits()).unwrap();
        assert_eq!(normalized, "\u{e9}");
        assert_eq!(normalized.chars().count(), 1);
    }

    #[test]
    fn nickname_normalization_is_idempotent() {
        let once = validate_nickname("e\u{301}", &limits()).unwrap();
        let twice = validate_nickname(&once, &limits()).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn nickname_respects_scalar_boundary() {
        let ok: String = "a".repeat(32);
        let too_long: String = "a".repeat(33);
        assert_eq!(validate_nickname(&ok, &limits()), Ok(ok));
        assert_eq!(
            validate_nickname(&too_long, &limits()),
            Err(ValidationError::NicknameTooLong { max: 32 })
        );
    }

    #[test]
    fn nickname_whitespace_cannot_forge_a_distinct_identity() {
        // The member table enforces uniqueness by exact comparison while the
        // terminal renders these identically; without normalization each of
        // these is a separate member that looks like "deniz" on screen.
        for padded in ["deniz ", " deniz", "  deniz  "] {
            let normalized = validate_nickname(padded, &limits());
            assert_eq!(
                normalized.as_deref(),
                Ok("deniz"),
                "{padded:?} must normalize onto the same identity"
            );
        }
        assert_eq!(validate_nickname("de  niz", &limits()).unwrap(), "de niz");
        // Tab is already refused as a control character, before whitespace
        // normalization is reached.
        assert_eq!(
            validate_nickname("deniz\t", &limits()),
            Err(ValidationError::ControlCharacterNotAllowed)
        );
    }

    #[test]
    fn nickname_rejects_whitespace_other_than_a_plain_space() {
        // NBSP and the ideographic space render as blanks but are distinct
        // bytes, so they are refused rather than silently folded.
        for exotic in ["deniz\u{a0}", "deniz\u{3000}", "de\u{2003}niz", "\u{2009}"] {
            assert_eq!(
                validate_nickname(exotic, &limits()),
                Err(ValidationError::ExoticWhitespaceNotAllowed),
                "{exotic:?} must be refused"
            );
        }
    }

    #[test]
    fn whitespace_only_nicknames_are_empty() {
        assert_eq!(
            validate_nickname("   ", &limits()),
            Err(ValidationError::EmptyNickname)
        );
    }

    #[test]
    fn nickname_normalization_is_idempotent_after_trimming() {
        let once = validate_nickname("  Deniz  Topcuoglu ", &limits()).unwrap();
        let twice = validate_nickname(&once, &limits()).unwrap();
        assert_eq!(once, "Deniz Topcuoglu");
        assert_eq!(once, twice);
    }

    #[test]
    fn nickname_rejects_control_characters() {
        assert_eq!(
            validate_nickname("ali\u{1b}[31m", &limits()),
            Err(ValidationError::ControlCharacterNotAllowed)
        );
        assert_eq!(
            validate_nickname("ali\u{9b}", &limits()),
            Err(ValidationError::ControlCharacterNotAllowed)
        );
    }

    #[test]
    fn empty_intro_is_allowed() {
        assert_eq!(validate_intro("", &limits()), Ok(()));
    }

    #[test]
    fn intro_respects_scalar_boundary() {
        let ok: String = "b".repeat(160);
        let too_long: String = "b".repeat(161);
        assert_eq!(validate_intro(&ok, &limits()), Ok(()));
        assert_eq!(
            validate_intro(&too_long, &limits()),
            Err(ValidationError::IntroTooLong { max: 160 })
        );
    }

    #[test]
    fn intro_must_be_single_line() {
        assert_eq!(
            validate_intro("line one\nline two", &limits()),
            Err(ValidationError::NotSingleLine)
        );
        assert_eq!(
            validate_intro("line one\rline two", &limits()),
            Err(ValidationError::NotSingleLine)
        );
    }

    #[test]
    fn intro_rejects_other_control_characters() {
        assert_eq!(
            validate_intro("hello\u{0007}", &limits()),
            Err(ValidationError::ControlCharacterNotAllowed)
        );
    }

    #[test]
    fn chat_text_respects_byte_boundary() {
        assert_eq!(validate_chat_text("", &limits()), Ok(()));
        let ok: String = "c".repeat(4096);
        let too_long: String = "c".repeat(4097);
        assert_eq!(validate_chat_text(&ok, &limits()), Ok(()));
        assert_eq!(
            validate_chat_text(&too_long, &limits()),
            Err(ValidationError::ChatTextTooLong { max_bytes: 4096 })
        );
    }

    #[test]
    fn chat_text_boundary_counts_utf8_bytes() {
        // Two-byte characters: 2048 chars = 4096 bytes is fine...
        let ok: String = "\u{e9}".repeat(2048);
        assert_eq!(validate_chat_text(&ok, &limits()), Ok(()));
        // ...one more char (4098 bytes) is not.
        let too_long: String = "\u{e9}".repeat(2049);
        assert_eq!(
            validate_chat_text(&too_long, &limits()),
            Err(ValidationError::ChatTextTooLong { max_bytes: 4096 })
        );
    }

    #[test]
    fn chat_text_rejects_control_characters() {
        assert_eq!(
            validate_chat_text("hi\u{1b}", &limits()),
            Err(ValidationError::ControlCharacterNotAllowed)
        );
    }
}
