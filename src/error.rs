//! Typed error enums used by the pure Stage 1 modules (instructions section 5.2).

use thiserror::Error;

use crate::constants::{MAX_TOKEN_BYTES, MIN_TOKEN_BYTES};

/// Errors produced while parsing or constructing an invitation URI.
///
/// Every rejection class of architecture decision 10 (section 22) is covered:
/// scheme, onion v3 format, port, version, token format and length, unknown
/// fields, and unsupported URI components.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UriError {
    /// The scheme is missing or is not exactly `veilroom`.
    #[error("URI scheme is missing or invalid")]
    InvalidScheme,

    /// The URI carries a `user:pass@` component, which is not allowed.
    #[error("URI userinfo components are not allowed")]
    UserInfoNotAllowed,

    /// The URI carries a `#fragment`, which is not allowed.
    #[error("URI fragments are not allowed")]
    FragmentNotAllowed,

    /// The URI carries a path component, which is not allowed.
    #[error("URI path components are not allowed")]
    PathNotAllowed,

    /// The host is not a 56-character onion body followed by `.onion`.
    #[error("malformed onion v3 address")]
    MalformedOnionAddress,

    /// The onion body contains characters outside the base32 alphabet.
    #[error("onion v3 address contains characters outside the base32 alphabet")]
    InvalidOnionAlphabet,

    /// The virtual port component is absent.
    #[error("URI is missing the virtual port")]
    MissingPort,

    /// The virtual port is not a decimal number in `1..=65535`.
    #[error("invalid virtual port")]
    InvalidPort,

    /// The `v` query parameter is absent.
    #[error("URI is missing the protocol version parameter")]
    MissingVersion,

    /// The `v` query parameter is not a non-negative integer.
    #[error("invalid protocol version parameter")]
    InvalidVersion,

    /// The `v` query parameter selects a version this implementation does not speak.
    #[error("unsupported protocol version {found}")]
    UnsupportedVersion {
        /// The version offered by the URI.
        found: u8,
    },

    /// The `token` query parameter is absent.
    #[error("URI is missing the invitation token")]
    MissingToken,

    /// The `token` query parameter is not valid URL-safe base64 without padding.
    #[error("invitation token is not valid URL-safe base64 without padding")]
    InvalidToken,

    /// The decoded token does not decode to `{MIN_TOKEN_BYTES}..={MAX_TOKEN_BYTES}` bytes.
    #[error(
        "invitation token must decode to {MIN_TOKEN_BYTES}..={MAX_TOKEN_BYTES} bytes, found {found}"
    )]
    InvalidTokenLength {
        /// The decoded token length in bytes.
        found: usize,
    },

    /// The query contains a parameter that V1 does not define.
    #[error("unknown query parameter `{name}`")]
    UnknownQueryParameter {
        /// The unknown parameter name.
        name: String,
    },

    /// The query contains the same parameter more than once.
    #[error("duplicate query parameter `{name}`")]
    DuplicateQueryParameter {
        /// The duplicated parameter name.
        name: String,
    },

    /// A query parameter lacks `=` or has an empty name or value.
    #[error("invalid query parameter `{name}`")]
    InvalidQueryParameter {
        /// The malformed parameter name.
        name: String,
    },
}

/// Errors produced by the slash-command parser.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    /// The input line is empty.
    #[error("input line is empty")]
    EmptyLine,

    /// The input starts with `/` but the command name is not recognized.
    #[error("unknown command `/{name}`")]
    UnknownCommand {
        /// The unrecognized command name.
        name: String,
    },

    /// The command requires exactly one argument and none was given.
    #[error("command `/{command}` requires an argument")]
    MissingArgument {
        /// The command that requires an argument.
        command: String,
    },

    /// The command takes no arguments and one was given.
    #[error("command `/{command}` does not accept arguments, got `{arg}`")]
    UnexpectedArgument {
        /// The command that received an unexpected argument.
        command: String,
        /// The unexpected argument.
        arg: String,
    },

    /// The argument has the wrong shape (for example a non-numeric id).
    #[error("invalid argument for `/{command}`: {detail}")]
    InvalidArgument {
        /// The command with an invalid argument.
        command: String,
        /// A description of why the argument is invalid.
        detail: String,
    },

    /// The argument contains control characters or ANSI escape sequences.
    #[error("argument for `/{command}` contains control characters or ANSI escape sequences")]
    ControlCharacterNotAllowed {
        /// The command with a disallowed argument.
        command: String,
    },
}

/// Errors produced by nickname, introduction, and chat-text validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// The nickname must not be empty.
    #[error("nickname must not be empty")]
    EmptyNickname,

    /// The input contains control characters or ANSI escape sequences.
    #[error("input contains control characters or ANSI escape sequences")]
    ControlCharacterNotAllowed,

    /// The nickname exceeds the configured limit of Unicode scalar values.
    #[error("nickname exceeds the limit of {max} Unicode scalar values")]
    NicknameTooLong {
        /// The configured maximum number of Unicode scalar values.
        max: usize,
    },

    /// The nickname contains a whitespace character other than a plain
    /// space.
    #[error("nickname must not contain whitespace other than a plain space")]
    ExoticWhitespaceNotAllowed,

    /// The introduction spans multiple lines.
    #[error("introduction must be a single line")]
    NotSingleLine,

    /// The introduction exceeds the configured limit of Unicode scalar values.
    #[error("introduction exceeds the limit of {max} Unicode scalar values")]
    IntroTooLong {
        /// The configured maximum number of Unicode scalar values.
        max: usize,
    },

    /// The chat message exceeds the configured limit of UTF-8 bytes.
    #[error("chat message exceeds the limit of {max_bytes} UTF-8 bytes")]
    ChatTextTooLong {
        /// The configured maximum number of UTF-8 bytes.
        max_bytes: usize,
    },
}

/// A `Limits` or `Timeouts` configuration is internally inconsistent.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid limits: {0}")]
pub struct InvalidLimits(
    /// A human-readable description of the inconsistency.
    pub String,
);
