//! Tor control-protocol client (sections 20 and 21).
//!
//! Connects to the control socket of the Tor subprocess, authenticates with
//! the control cookie, and exchanges commands and replies. Line reading is
//! bounded: a control line longer than [`MAX_CONTROL_LINE_BYTES`] terminates
//! the connection, so a broken or hostile control endpoint can never drive
//! unbounded allocation.

use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::tor::parser::{Reply, ReplyAccumulator, parse_control_line};

/// Maximum accepted length of a single control-protocol line, in bytes.
pub const MAX_CONTROL_LINE_BYTES: usize = 4096;

/// Errors produced by the control client.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The control endpoint sent a line longer than the limit.
    #[error("control line exceeds the limit of {max} bytes")]
    LineTooLong {
        /// The configured maximum line length in bytes.
        max: usize,
    },

    /// The control endpoint violated the control-protocol grammar.
    #[error("malformed control-protocol reply: {0}")]
    Parser(#[from] crate::tor::parser::ParserError),

    /// The connection ended in the middle of a line or reply.
    #[error("control connection closed unexpectedly")]
    UnexpectedEof,

    /// The connection could not be established within the timeout.
    #[error("control connection timed out")]
    ConnectTimeout,
    /// A control command did not complete within its deadline.
    #[error("tor control command timed out")]
    CommandTimeout,

    /// The control connection desynchronized after a timed-out command and
    /// must not be used again.
    #[error("tor control connection is desynchronized after a timeout")]
    Desynchronized,

    /// The command contained a carriage return or line feed.
    #[error("control command must not contain line breaks")]
    InvalidCommand,

    /// The control endpoint refused the cookie authentication.
    #[error("tor control authentication failed: {0:?}")]
    AuthenticationFailed(Reply),

    /// The underlying socket failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Reads control-protocol lines from any async byte source.
///
/// Lines are delimited by `\n`; a trailing `\r` is stripped. Reading stops
/// with [`ControlError::LineTooLong`] once a line exceeds the cap, so memory
/// use is strictly bounded.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    pending: Vec<u8>,
    buf: Vec<u8>,
    max: usize,
}

impl<R> LineReader<R> {
    /// Creates a line reader over `inner` with the given cap.
    pub const fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            buf: Vec::new(),
            max,
        }
    }
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    /// Reads the next line.
    ///
    /// Returns `None` at a clean end of stream. An end of stream inside a
    /// line is an error.
    pub async fn next_line(&mut self) -> Result<Option<String>, ControlError> {
        // A complete line may already be buffered from a previous read.
        if let Some(end) = self.pending.iter().position(|&b| b == b'\n') {
            self.buf.clear();
            self.buf.extend_from_slice(&self.pending[..end]);
            self.pending.drain(..=end);
            return Ok(Some(self.finish_line()?));
        }
        // Carry any unterminated remainder into the current line.
        self.buf.clear();
        self.buf.append(&mut self.pending);
        let mut scratch = [0u8; 512];
        loop {
            let read = self.inner.read(&mut scratch).await?;
            if read == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(ControlError::UnexpectedEof);
            }
            match scratch[..read].iter().position(|&b| b == b'\n') {
                Some(end) => {
                    self.buf.extend_from_slice(&scratch[..end]);
                    if self.buf.len() > self.max {
                        return Err(ControlError::LineTooLong { max: self.max });
                    }
                    self.pending.extend_from_slice(&scratch[end + 1..read]);
                    return Ok(Some(self.finish_line()?));
                }
                None => {
                    self.buf.extend_from_slice(&scratch[..read]);
                    if self.buf.len() > self.max {
                        return Err(ControlError::LineTooLong { max: self.max });
                    }
                }
            }
        }
    }

    fn finish_line(&mut self) -> Result<String, ControlError> {
        let line = std::str::from_utf8(&self.buf)
            .map_err(|_| ControlError::Parser(crate::tor::parser::ParserError::MalformedLine))?;
        Ok(line.strip_suffix('\r').unwrap_or(line).to_owned())
    }
}

/// A client connection to the Tor control socket.
#[derive(Debug)]
pub struct ControlClient {
    reader: LineReader<tokio::io::ReadHalf<UnixStream>>,
    writer: tokio::io::WriteHalf<UnixStream>,
    /// Set once a command times out: the reply stream is then unknown and
    /// every later command would misassociate stale reply lines.
    poisoned: bool,
}

impl ControlClient {
    /// Connects to a control socket, retrying until `timeout` elapses.
    pub async fn connect(path: &Path, timeout_duration: Duration) -> Result<Self, ControlError> {
        let deadline = tokio::time::Instant::now() + timeout_duration;
        let mut delay = tokio::time::interval(Duration::from_millis(100));
        delay.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            match UnixStream::connect(path).await {
                Ok(stream) => {
                    let (read_half, write_half) = tokio::io::split(stream);
                    return Ok(Self {
                        reader: LineReader::new(read_half, MAX_CONTROL_LINE_BYTES),
                        writer: write_half,
                        poisoned: false,
                    });
                }
                Err(error) => {
                    if tokio::time::Instant::now() >= deadline {
                        // Distinguish a permission/other failure from "not
                        // ready yet".
                        if error.kind() == io::ErrorKind::NotFound
                            || error.kind() == io::ErrorKind::ConnectionRefused
                        {
                            return Err(ControlError::ConnectTimeout);
                        }
                        return Err(ControlError::Io(error));
                    }
                    delay.tick().await;
                }
            }
        }
    }

    /// Sends a control command and returns the complete reply.
    pub async fn command(&mut self, command: &str) -> Result<Reply, ControlError> {
        // A timed-out command leaves an unknown number of reply lines in
        // the socket; using the connection afterwards would misassociate
        // stale lines with the next command, so it is permanently poisoned.
        if self.poisoned {
            return Err(ControlError::Desynchronized);
        }
        match tokio::time::timeout(Duration::from_secs(10), self.command_inner(command)).await {
            Ok(result) => result,
            Err(_) => {
                self.poisoned = true;
                Err(ControlError::CommandTimeout)
            }
        }
    }

    async fn command_inner(&mut self, command: &str) -> Result<Reply, ControlError> {
        if command.contains(['\r', '\n']) {
            return Err(ControlError::InvalidCommand);
        }
        self.writer
            .write_all(format!("{command}\r\n").as_bytes())
            .await?;
        let mut accumulator = ReplyAccumulator::new();
        loop {
            let Some(line_text) = self.reader.next_line().await? else {
                return Err(ControlError::UnexpectedEof);
            };
            if accumulator.in_data_block() {
                // Inside a `+` data block every line is raw data; a bare
                // "." terminates the block.
                if let Some(reply) = accumulator.feed_data_line(&line_text)? {
                    return Ok(reply);
                }
                continue;
            }
            let Some(line) = parse_control_line(&line_text) else {
                if line_text == "." {
                    return Err(ControlError::Parser(
                        crate::tor::parser::ParserError::UnexpectedDataTerminator,
                    ));
                }
                return Err(ControlError::Parser(
                    crate::tor::parser::ParserError::MalformedLine,
                ));
            };
            if let Some(reply) = accumulator.feed(line)? {
                return Ok(reply);
            }
        }
    }

    /// Authenticates with the control cookie (hex-encoded).
    ///
    /// A `513` "already authenticated" reply is treated as success. The
    /// command buffer holding the cookie hex is zeroized after use.
    pub async fn authenticate(&mut self, cookie_hex: &str) -> Result<(), ControlError> {
        let command = zeroize::Zeroizing::new(format!("AUTHENTICATE {cookie_hex}"));
        let reply = self.command(&command).await?;
        if reply.is_ok() {
            return Ok(());
        }
        if reply.code == 513 && reply.first_line().contains("authenticated") {
            return Ok(());
        }
        Err(ControlError::AuthenticationFailed(reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn line_reader_handles_lf_and_crlf() {
        let input: &[u8] = b"250 OK\r\n250-Continued\n250 Last\r\n";
        let mut reader = LineReader::new(input, MAX_CONTROL_LINE_BYTES);
        assert_eq!(reader.next_line().await.unwrap(), Some("250 OK".to_owned()));
        assert_eq!(
            reader.next_line().await.unwrap(),
            Some("250-Continued".to_owned())
        );
        assert_eq!(
            reader.next_line().await.unwrap(),
            Some("250 Last".to_owned())
        );
        assert_eq!(reader.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn eof_inside_a_line_is_an_error() {
        let input: &[u8] = b"250-abcdefghijklm";
        let mut reader = LineReader::new(input, MAX_CONTROL_LINE_BYTES);
        let error = reader.next_line().await.unwrap_err();
        assert!(matches!(error, ControlError::UnexpectedEof));
    }

    #[tokio::test]
    async fn line_reader_enforces_the_cap() {
        let mut input = Vec::new();
        input.extend_from_slice(&[b'x'; MAX_CONTROL_LINE_BYTES + 1]);
        input.push(b'\n');
        let mut reader = LineReader::new(input.as_slice(), MAX_CONTROL_LINE_BYTES);
        assert!(matches!(
            reader.next_line().await.unwrap_err(),
            ControlError::LineTooLong {
                max: MAX_CONTROL_LINE_BYTES
            }
        ));
    }

    #[tokio::test]
    async fn line_reader_rejects_non_utf8() {
        let input: &[u8] = &[0xff, b'\n'];
        let mut reader = LineReader::new(input, MAX_CONTROL_LINE_BYTES);
        assert!(reader.next_line().await.is_err());
    }
}
