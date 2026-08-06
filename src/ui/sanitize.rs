//! Display sanitization of user-controlled text (terminal security, section 25).
//!
//! Nicknames, messages, introductions, and notice text are scrubbed before
//! rendering so that client-controlled ANSI escape sequences, control
//! characters, and display-spoofing format characters (bidi overrides,
//! zero-width marks) can never reach the terminal. Sanitization operates on
//! decoded `char` values, so multi-byte UTF-8 content is preserved exactly
//! while every unsafe character is removed.

use crate::validation::is_unsafe_display_char;

/// Scrubs control and display-spoofing characters from `input` for safe
/// display.
///
/// - C0 control characters (`U+0000..=U+001F`) are dropped; tab, newline, and
///   carriage return are replaced with a space.
/// - DEL (`U+007F`) and C1 controls (`U+0080..=U+009F`, including the CSI
///   introducer) are dropped.
/// - Unicode `Cf` format characters used for display spoofing (bidi
///   overrides/isolates, directional and zero-width marks) are dropped.
/// - All other Unicode scalar values pass through unchanged, so no ANSI
///   escape sequence or visual reordering can be constructed from the output.
pub fn sanitize_for_display(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if is_unsafe_display_char(ch) {
            if matches!(ch, '\t' | '\n' | '\r') {
                out.push(' ');
            }
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through_unchanged() {
        assert_eq!(sanitize_for_display("hello world"), "hello world");
        assert_eq!(sanitize_for_display("ünïcödé 私の部屋"), "ünïcödé 私の部屋");
    }

    #[test]
    fn escape_sequences_are_removed() {
        assert_eq!(
            sanitize_for_display("\u{1b}[31mred"),
            "[31mred",
            "ESC is dropped, the rest is inert text"
        );
        assert_eq!(sanitize_for_display("\u{1b}(B\u{1b}[m"), "(B[m");
    }

    #[test]
    fn control_characters_are_dropped() {
        assert_eq!(sanitize_for_display("a\u{7f}b"), "ab");
        assert_eq!(sanitize_for_display("a\u{9b}b"), "ab");
        assert_eq!(sanitize_for_display("a\u{0}b"), "ab");
        assert_eq!(sanitize_for_display("\u{1}"), "");
    }

    #[test]
    fn whitespace_controls_become_spaces() {
        assert_eq!(sanitize_for_display("a\tb\nc\rd"), "a b c d");
    }

    #[test]
    fn c1_controls_inside_utf8_do_not_corrupt_text() {
        // The C1 byte range overlaps UTF-8 continuation bytes; sanitizing on
        // decoded chars must leave valid multi-byte sequences untouched.
        assert_eq!(sanitize_for_display("caf\u{e9}"), "caf\u{e9}");
        assert_eq!(sanitize_for_display("日本語"), "日本語");
    }

    #[test]
    fn sanitized_output_never_contains_control_chars() {
        let sample = "\u{1b}[31m\thello\u{7f}\u{9b}world\n";
        let clean = sanitize_for_display(sample);
        assert!(clean.chars().all(|ch| !ch.is_control()));
    }

    #[test]
    fn bidi_and_zero_width_marks_are_removed() {
        assert_eq!(sanitize_for_display("evil\u{202e}"), "evil");
        assert_eq!(sanitize_for_display("\u{202a}hi\u{202c}"), "hi");
        assert_eq!(sanitize_for_display("a\u{2066}b\u{2069}c"), "abc");
        assert_eq!(sanitize_for_display("a\u{200b}b\u{200d}c"), "abc");
        assert_eq!(sanitize_for_display("\u{feff}x"), "x");
        // Emoji with variation selectors still pass through.
        assert_eq!(sanitize_for_display("\u{2764}\u{fe0f}"), "\u{2764}\u{fe0f}");
    }
}
