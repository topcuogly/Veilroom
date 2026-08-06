//! Tor control protocol line parsing (deepseek instructions section 9.4).
//!
//! The control protocol (Tor Control Protocol spec, version 1) is a
//! line-based text protocol. Replies use the form:
//!
//! ```text
//! <code><separator><data>
//! ```
//!
//! - `<code>` is a three-digit status code.
//! - `<separator>` is `-` for a continued multiline reply, ` ` (space) for
//!   the final line, and `+` for a data-encoded (RFC 9063-style) block that
//!   is terminated by a line containing a single `.`.
//! - `<data>` is the remainder of the line.
//!
//! Naive `split('\n')` parsing is not sufficient: multiline replies must be
//! assembled by status code, and data-encoded blocks have their own
//! terminator. This module implements both rules and is fully tested.

/// A single parsed control-protocol line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlLine {
    /// The three-digit status code.
    pub code: u16,
    /// How the line continues the reply.
    pub kind: LineKind,
    /// The data after the code and separator.
    pub data: String,
}

/// The role of a line within a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    /// `code-...`: the reply continues on the next line.
    Continuation,
    /// `code+...`: a data-encoded block that runs until a lone `.` line.
    Data,
    /// `code ...`: the final line of the reply.
    Last,
}

/// Errors produced while parsing control-protocol lines.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParserError {
    /// The line does not begin with a three-digit status code.
    #[error("control line does not start with a three-digit status code")]
    MalformedLine,

    /// A reply line uses a status code that differs from the code the reply
    /// started with.
    #[error("control reply mixes status codes: started with {expected}, found {found}")]
    CodeMismatch {
        /// The status code the reply started with.
        expected: u16,
        /// The status code of the offending line.
        found: u16,
    },

    /// A data-encoded block (`+` separator) appeared inside an existing reply.
    #[error("unexpected data-encoded line inside an existing reply")]
    UnexpectedDataBlock,

    /// A data-block terminator (a bare `.` line) arrived without an open
    /// data block.
    #[error("data-block terminator without an open data block")]
    UnexpectedDataTerminator,
    /// The complete reply exceeded the aggregate line/byte limit.
    #[error("control reply exceeds the aggregate size limit")]
    ReplyTooLarge,
}

/// A complete control-protocol reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The reply status code.
    pub code: u16,
    /// The data of every line of the reply, including the first.
    pub lines: Vec<String>,
}

impl Reply {
    /// Whether the reply carries the success code 250.
    pub const fn is_ok(&self) -> bool {
        self.code == 250
    }

    /// The data of the first line of the reply.
    pub fn first_line(&self) -> &str {
        self.lines.first().map(String::as_str).unwrap_or_default()
    }
}

impl std::fmt::Display for Reply {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "code {}: {}", self.code, self.lines.join(" | "))
    }
}

/// Parses one control-protocol line.
///
/// Returns `None` for a line that does not follow the protocol grammar
/// (for example an empty line, an event line with a code other than three
/// digits, or a line without a separator). A `650` event line parses like
/// any other line; callers decide how to treat it.
pub fn parse_control_line(line: &str) -> Option<ControlLine> {
    if line.len() < 4 {
        return None;
    }
    let code_bytes = line.as_bytes();
    if !(code_bytes[0].is_ascii_digit()
        && code_bytes[1].is_ascii_digit()
        && code_bytes[2].is_ascii_digit())
    {
        return None;
    }
    let code = line[0..3].parse::<u16>().ok()?;
    let separator = code_bytes[3] as char;
    let kind = match separator {
        '-' => LineKind::Continuation,
        '+' => LineKind::Data,
        ' ' => LineKind::Last,
        _ => return None,
    };
    let data = line[4..].to_owned();
    Some(ControlLine { code, kind, data })
}

/// Accumulates control lines into complete replies.
///
/// Multiline replies are assembled only when every line carries the same
/// status code; a `+` data block is terminated by a line containing a lone
/// `.`. A single-line reply (`code data`) completes immediately.
#[derive(Debug, Clone)]
pub struct ReplyAccumulator {
    code: Option<u16>,
    lines: Vec<String>,
    in_data_block: bool,
}

impl Default for ReplyAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyAccumulator {
    /// Creates an empty accumulator.
    pub const fn new() -> Self {
        Self {
            code: None,
            lines: Vec::new(),
            in_data_block: false,
        }
    }

    /// Whether a reply is currently being accumulated.
    pub const fn is_active(&self) -> bool {
        self.code.is_some()
    }

    /// Whether the accumulator is inside a `+` data block.
    ///
    /// While inside a data block every line is raw data; the block ends at a
    /// bare `.` line, which must be delivered through
    /// [`ReplyAccumulator::feed_data_line`].
    pub const fn in_data_block(&self) -> bool {
        self.in_data_block
    }

    /// Feeds a raw line while inside a `+` data block.
    ///
    /// A line containing exactly `.` terminates the block and completes the
    /// reply; any other line is appended as data. Lines that begin with a
    /// period inside a data block are protocol-escaped by doubling; the
    /// caller must deliver them unescaped.
    pub fn feed_data_line(&mut self, raw_line: &str) -> Result<Option<Reply>, ParserError> {
        if !self.in_data_block {
            return Err(ParserError::UnexpectedDataTerminator);
        }
        if raw_line == "." {
            // A data block is followed by the reply's final `code SP line`.
            // Completing here would leave that final line unread and poison
            // the next command.
            self.in_data_block = false;
            Ok(None)
        } else {
            // Tor dot-stuffs data lines beginning with a period.
            let line = raw_line
                .strip_prefix("..")
                .map_or(raw_line, |_| &raw_line[1..]);
            self.push_line(line.to_owned())?;
            Ok(None)
        }
    }

    /// Feeds one parsed line and returns the completed reply, if any.
    pub fn feed(&mut self, line: ControlLine) -> Result<Option<Reply>, ParserError> {
        if let Some(expected) = self.code {
            if line.code != expected {
                return Err(ParserError::CodeMismatch {
                    expected,
                    found: line.code,
                });
            }
        }
        match line.kind {
            LineKind::Last => {
                self.push_line(line.data)?;
                self.code.get_or_insert(line.code);
                Ok(Some(self.take_reply()))
            }
            LineKind::Data => {
                if self.code.is_none() {
                    self.begin(line)?;
                    Ok(None)
                } else {
                    Err(ParserError::UnexpectedDataBlock)
                }
            }
            LineKind::Continuation => {
                if self.code.is_none() {
                    self.begin(line)?;
                    Ok(None)
                } else {
                    self.push_line(line.data)?;
                    Ok(None)
                }
            }
        }
    }

    fn begin(&mut self, line: ControlLine) -> Result<(), ParserError> {
        self.code = Some(line.code);
        self.push_line(line.data)?;
        self.in_data_block = line.kind == LineKind::Data;
        Ok(())
    }

    fn push_line(&mut self, line: String) -> Result<(), ParserError> {
        const MAX_REPLY_LINES: usize = 1024;
        const MAX_REPLY_BYTES: usize = 1024 * 1024;
        let bytes = self.lines.iter().map(String::len).sum::<usize>() + line.len();
        if self.lines.len() >= MAX_REPLY_LINES || bytes > MAX_REPLY_BYTES {
            return Err(ParserError::ReplyTooLarge);
        }
        self.lines.push(line);
        Ok(())
    }

    fn take_reply(&mut self) -> Reply {
        let reply = Reply {
            code: self.code.take().unwrap_or_default(),
            lines: std::mem::take(&mut self.lines),
        };
        self.in_data_block = false;
        reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(input: &str) -> ControlLine {
        parse_control_line(input).unwrap()
    }

    #[test]
    fn parses_single_line_replies() {
        let parsed = line("250 OK");
        assert_eq!(parsed.code, 250);
        assert_eq!(parsed.kind, LineKind::Last);
        assert_eq!(parsed.data, "OK");
    }

    #[test]
    fn parses_continuation_and_data_lines() {
        let continued = line("250-ServiceID=abc");
        assert_eq!(continued.kind, LineKind::Continuation);
        assert_eq!(continued.data, "ServiceID=abc");

        let data = line("250+status/bootstrap-phase=");
        assert_eq!(data.kind, LineKind::Data);
        assert_eq!(data.data, "status/bootstrap-phase=");
    }

    #[test]
    fn parses_error_replies() {
        let parsed = line("510 Unrecognized command");
        assert_eq!(parsed.code, 510);
        assert_eq!(parsed.kind, LineKind::Last);
        assert_eq!(parsed.data, "Unrecognized command");
        assert_eq!(line("515-"), line("515-"));
        assert_eq!(line("515-").data, "");
    }

    #[test]
    fn rejects_malformed_lines() {
        for bad in [
            "", "25 OK", "2500 OK", "250", "ABC OK", "2 0 OK", "250XOK", "25-OK", "250\tOK",
        ] {
            assert!(parse_control_line(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn single_line_reply_records_its_code() {
        let mut accumulator = ReplyAccumulator::new();
        let reply = accumulator.feed(line("250 OK")).unwrap().unwrap();
        assert_eq!(reply.code, 250);
        assert!(reply.is_ok());
        assert_eq!(reply.lines, ["OK"]);
        assert!(!accumulator.is_active());

        let mut accumulator = ReplyAccumulator::new();
        let reply = accumulator
            .feed(line("510 Unrecognized command"))
            .unwrap()
            .unwrap();
        assert_eq!(reply.code, 510);
        assert!(!reply.is_ok());
    }

    #[test]
    fn a_continuation_line_starts_an_active_reply() {
        let mut accumulator = ReplyAccumulator::new();
        let reply = accumulator.feed(line("250-orphan")).unwrap();
        assert!(reply.is_none());
        assert!(accumulator.is_active());
        let reply = accumulator.feed(line("250 OK")).unwrap().unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines, ["orphan", "OK"]);
    }

    #[test]
    fn a_data_block_inside_an_existing_reply_is_rejected() {
        let mut accumulator = ReplyAccumulator::new();
        accumulator.feed(line("250-ServiceID=abc")).unwrap();
        assert_eq!(
            accumulator.feed(line("250+more data")),
            Err(ParserError::UnexpectedDataBlock)
        );
    }

    #[test]
    fn multiline_reply_assembles_by_code() {
        let mut accumulator = ReplyAccumulator::new();
        assert!(
            accumulator
                .feed(line(
                    "250-ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ))
                .unwrap()
                .is_none()
        );
        assert!(accumulator.is_active());
        let reply = accumulator.feed(line("250 OK")).unwrap().unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(
            reply.lines,
            [
                "ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "OK"
            ]
        );
    }

    #[test]
    fn multiline_error_reply_assembles() {
        let mut accumulator = ReplyAccumulator::new();
        assert!(
            accumulator
                .feed(line("515-Authentication failed"))
                .unwrap()
                .is_none()
        );
        let reply = accumulator
            .feed(line("515 Authentication failed"))
            .unwrap()
            .unwrap();
        assert_eq!(reply.code, 515);
        assert!(!reply.is_ok());
        assert_eq!(
            reply.lines,
            ["Authentication failed", "Authentication failed"]
        );
    }

    #[test]
    fn data_blocks_terminate_on_a_lone_period() {
        let mut accumulator = ReplyAccumulator::new();
        assert!(
            accumulator
                .feed(line("250+status/bootstrap-phase=NOTICE"))
                .unwrap()
                .is_none()
        );
        assert!(accumulator.in_data_block());
        assert!(
            accumulator
                .feed_data_line("CONTINUATION inside data")
                .unwrap()
                .is_none()
        );
        assert!(accumulator.feed_data_line("..hidden").unwrap().is_none());
        assert!(accumulator.feed_data_line(".").unwrap().is_none());
        let reply = accumulator.feed(line("250 OK")).unwrap().unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(
            reply.lines,
            [
                "status/bootstrap-phase=NOTICE",
                "CONTINUATION inside data",
                ".hidden",
                "OK"
            ]
        );
        assert!(!accumulator.is_active());
        assert!(!accumulator.in_data_block());
    }

    #[test]
    fn a_terminator_without_a_data_block_is_an_error() {
        let mut accumulator = ReplyAccumulator::new();
        assert_eq!(
            accumulator.feed_data_line("."),
            Err(ParserError::UnexpectedDataTerminator)
        );
    }

    #[test]
    fn mixed_status_codes_are_rejected() {
        let mut accumulator = ReplyAccumulator::new();
        accumulator.feed(line("250-ServiceID=abc")).unwrap();
        assert_eq!(
            accumulator.feed(line("510 Broken")),
            Err(ParserError::CodeMismatch {
                expected: 250,
                found: 510
            })
        );
    }

    #[test]
    fn event_lines_parse_like_any_other_line() {
        let parsed = line("650 STATUS_GENERAL NOTICE BOOTSTRAP PROGRESS=90");
        assert_eq!(parsed.code, 650);
        assert_eq!(parsed.kind, LineKind::Last);
        assert_eq!(parsed.data, "STATUS_GENERAL NOTICE BOOTSTRAP PROGRESS=90");
    }
}
