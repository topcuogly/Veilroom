//! Parsing of user-typed lines into slash commands or chat text
//! (architecture decision 13, section 31; terminal security, section 25).
//!
//! Rules:
//! - Unknown slash commands are never silently sent as chat text.
//! - `//text` sends `/text` as a normal chat message.
//! - Arguments containing control characters or ANSI escape sequences are rejected.

use crate::error::CommandError;
use crate::event::{MemberCommand, MemberId, MemberRef, RequestId};
use crate::validation::contains_control_char;

/// Result of parsing a single user-typed line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLine {
    /// A parsed slash command.
    Command(SlashCommand),
    /// Plain chat text, including text escaped with a leading `//`.
    Chat(String),
}

/// A parsed slash command (section 31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashCommand {
    /// `/help`: show command help.
    Help,
    /// `/exit`: leave and quit, or shut the room down when hosted.
    Exit,
    /// `/leave`: leave the room as a participant (not available to the host).
    Leave,
    /// `/color <color>`: set the display color from the fixed palette.
    Color(ColorChoice),
    /// `/color list`: print every available color in that color.
    ColorList,
    /// `/list`: list active members.
    List,
    /// `/whois <member>`: show information about a member.
    Whois(String),
    /// `/kick <member>`: kick a member by member id or unique nickname.
    Kick(KickTarget),
    /// `/newid`: rotate the invitation token and produce a new invitation URI.
    NewId,
    /// `/reqon`: enable join requests.
    ReqOn,
    /// `/reqoff`: disable join requests.
    ReqOff,
    /// `/requests`: list pending join and timeout requests.
    Requests,
    /// `/accept <request-id>`: accept a pending join or timeout request.
    Accept(RequestId),
    /// `/reject <request-id>`: reject a pending join or timeout request.
    Reject(RequestId),
    /// `/copy`: copy the full invitation URI to the clipboard (host).
    Copy,
    /// `/clear`: clear the local participant's message pane.
    Clear,
    /// `/timeout <seconds|off>`: set or disable the room-wide lifetime of
    /// each message line (host-only).
    Timeout(Option<u64>),
    /// `/timeoutreq <seconds>`: request a room-wide timeout change (member).
    TimeoutRequest(u64),
}

/// The maximum `/timeout` message lifetime in seconds.
pub const MAX_MESSAGE_TIMEOUT_SECONDS: u64 = 3600;

impl ColorChoice {
    /// Every selectable color, in help-display order.
    pub const ALL: [Self; 7] = [
        Self::Red,
        Self::Green,
        Self::Yellow,
        Self::Blue,
        Self::Magenta,
        Self::Cyan,
        Self::White,
    ];

    /// The lowercase command name of this color.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Red => "red",
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Blue => "blue",
            Self::Magenta => "magenta",
            Self::Cyan => "cyan",
            Self::White => "white",
        }
    }

    /// The numeric wire index of this color.
    pub const fn as_index(self) -> u8 {
        match self {
            Self::Red => 0,
            Self::Green => 1,
            Self::Yellow => 2,
            Self::Blue => 3,
            Self::Magenta => 4,
            Self::Cyan => 5,
            Self::White => 6,
        }
    }

    /// The color for a numeric wire index, if valid.
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Red),
            1 => Some(Self::Green),
            2 => Some(Self::Yellow),
            3 => Some(Self::Blue),
            4 => Some(Self::Magenta),
            5 => Some(Self::Cyan),
            6 => Some(Self::White),
            _ => None,
        }
    }
}

/// The fixed, limited color palette (section 33). Raw ANSI codes are never accepted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ColorChoice {
    /// Red
    Red,
    /// Green
    Green,
    /// Yellow
    Yellow,
    /// Blue
    Blue,
    /// Magenta
    Magenta,
    /// Cyan
    Cyan,
    /// White
    #[default]
    White,
}

/// Target of a `/kick` command (section 32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KickTarget {
    /// Numeric room-lifetime member id. Always valid.
    Id(MemberId),
    /// Nickname; resolved by the room only when there is one unambiguous match.
    Nickname(String),
}

/// Parses a single user-typed line.
///
/// Returns [`CommandError::EmptyLine`] for an empty line, an error for an
/// unknown or malformed slash command, and [`ParsedLine::Chat`] otherwise.
pub fn parse_line(line: &str) -> Result<ParsedLine, CommandError> {
    if line.is_empty() {
        return Err(CommandError::EmptyLine);
    }
    if let Some(rest) = line.strip_prefix("//") {
        return Ok(ParsedLine::Chat(format!("/{rest}")));
    }
    let Some(rest) = line.strip_prefix('/') else {
        return Ok(ParsedLine::Chat(line.to_owned()));
    };
    // A slash followed by whitespace (`/ exit`) is chat text, never a
    // command: a command name must start immediately after the slash.
    if rest.starts_with(char::is_whitespace) {
        return Ok(ParsedLine::Chat(line.to_owned()));
    }
    let trimmed = rest.trim_start_matches(char::is_whitespace);
    let (name, args) = match trimmed.find(char::is_whitespace) {
        Some(idx) => (
            &trimmed[..idx],
            trimmed[idx..].trim_start_matches(char::is_whitespace),
        ),
        None => (trimmed, ""),
    };
    let command = match name {
        "help" => no_args("help", args, SlashCommand::Help)?,
        "exit" => no_args("exit", args, SlashCommand::Exit)?,
        "leave" => no_args("leave", args, SlashCommand::Leave)?,
        "list" => no_args("list", args, SlashCommand::List)?,
        "newid" => no_args("newid", args, SlashCommand::NewId)?,
        "reqon" => no_args("reqon", args, SlashCommand::ReqOn)?,
        "reqoff" => no_args("reqoff", args, SlashCommand::ReqOff)?,
        "requests" => no_args("requests", args, SlashCommand::Requests)?,
        "copy" => no_args("copy", args, SlashCommand::Copy)?,
        "clear" => no_args("clear", args, SlashCommand::Clear)?,
        "color" if args == "list" => SlashCommand::ColorList,
        "color" => SlashCommand::Color(parse_color(args)?),
        "timeout" => SlashCommand::Timeout(parse_timeout(args)?),
        "timeoutreq" => SlashCommand::TimeoutRequest(parse_timeout_request(args)?),
        "whois" => SlashCommand::Whois(parse_simple_arg("whois", args)?.to_owned()),
        "kick" => SlashCommand::Kick(parse_kick_target(args)?),
        "accept" => SlashCommand::Accept(parse_request_id("accept", args)?),
        "reject" => SlashCommand::Reject(parse_request_id("reject", args)?),
        _ => {
            return Err(CommandError::UnknownCommand {
                name: name.to_owned(),
            });
        }
    };
    Ok(ParsedLine::Command(command))
}

impl SlashCommand {
    /// Maps a parsed command to a host administration command, if any.
    ///
    /// Host commands are delivered through the local typed channel to
    /// `RoomTask`; they are never sent over the network (section 31).
    pub fn into_host_command(self) -> Option<crate::event::HostCommand> {
        use crate::event::HostCommand;
        match self {
            Self::Kick(target) => Some(HostCommand::Kick {
                target: target.into(),
            }),
            Self::NewId => Some(HostCommand::NewId),
            Self::ReqOn => Some(HostCommand::ReqOn),
            Self::ReqOff => Some(HostCommand::ReqOff),
            Self::Requests => Some(HostCommand::Requests),
            Self::Accept(request_id) => Some(HostCommand::Accept { request_id }),
            Self::Reject(request_id) => Some(HostCommand::Reject { request_id }),
            _ => None,
        }
    }

    /// Maps a parsed command to a member command, if any.
    pub fn into_member_command(self) -> Option<MemberCommand> {
        match self {
            Self::Leave => Some(MemberCommand::Leave),
            Self::Color(color) => Some(MemberCommand::Color(color)),
            Self::List => Some(MemberCommand::List),
            Self::Whois(target) => Some(MemberCommand::Whois(target)),
            _ => None,
        }
    }
}

impl From<KickTarget> for MemberRef {
    fn from(target: KickTarget) -> Self {
        match target {
            KickTarget::Id(id) => MemberRef::Id(id),
            KickTarget::Nickname(nickname) => MemberRef::Nickname(nickname),
        }
    }
}

/// Accepts a command only when it was given no arguments.
fn no_args(name: &str, args: &str, command: SlashCommand) -> Result<SlashCommand, CommandError> {
    if args.is_empty() {
        Ok(command)
    } else {
        Err(CommandError::UnexpectedArgument {
            command: name.to_owned(),
            arg: args.to_owned(),
        })
    }
}

/// Parses a color name against the fixed palette.
fn parse_color(args: &str) -> Result<ColorChoice, CommandError> {
    if args.is_empty() {
        return Err(CommandError::MissingArgument {
            command: "color".to_owned(),
        });
    }
    if contains_control_char(args) {
        return Err(CommandError::ControlCharacterNotAllowed {
            command: "color".to_owned(),
        });
    }
    match args {
        "red" => Ok(ColorChoice::Red),
        "green" => Ok(ColorChoice::Green),
        "yellow" => Ok(ColorChoice::Yellow),
        "blue" => Ok(ColorChoice::Blue),
        "magenta" => Ok(ColorChoice::Magenta),
        "cyan" => Ok(ColorChoice::Cyan),
        "white" => Ok(ColorChoice::White),
        _ => Err(CommandError::InvalidArgument {
            command: "color".to_owned(),
            detail: format!("unknown color `{args}`"),
        }),
    }
}

/// Parses a `/timeout` argument: a positive message lifetime, or `off`.
///
/// `Some(seconds)` enables per-message expiry and `None` (`off`) disables
/// it. Zero, non-numeric, and out-of-range values are
/// rejected.
fn parse_timeout(args: &str) -> Result<Option<u64>, CommandError> {
    if args.is_empty() {
        return Err(CommandError::MissingArgument {
            command: "timeout".to_owned(),
        });
    }
    if contains_control_char(args) {
        return Err(CommandError::ControlCharacterNotAllowed {
            command: "timeout".to_owned(),
        });
    }
    if args == "off" {
        return Ok(None);
    }
    let seconds: u64 = args.parse().map_err(|_| CommandError::InvalidArgument {
        command: "timeout".to_owned(),
        detail: format!("expected a positive number of seconds or `off`, got `{args}`"),
    })?;
    if seconds == 0 {
        return Err(CommandError::InvalidArgument {
            command: "timeout".to_owned(),
            detail: "the message lifetime must be at least 1 second".to_owned(),
        });
    }
    if seconds > MAX_MESSAGE_TIMEOUT_SECONDS {
        return Err(CommandError::InvalidArgument {
            command: "timeout".to_owned(),
            detail: format!(
                "the message lifetime may not exceed {MAX_MESSAGE_TIMEOUT_SECONDS} seconds"
            ),
        });
    }
    Ok(Some(seconds))
}

/// Parses a member's requested room-wide message lifetime.
fn parse_timeout_request(args: &str) -> Result<u64, CommandError> {
    match parse_timeout(args).map_err(|error| match error {
        CommandError::MissingArgument { .. } => CommandError::MissingArgument {
            command: "timeoutreq".to_owned(),
        },
        CommandError::ControlCharacterNotAllowed { .. } => {
            CommandError::ControlCharacterNotAllowed {
                command: "timeoutreq".to_owned(),
            }
        }
        CommandError::InvalidArgument { detail, .. } => CommandError::InvalidArgument {
            command: "timeoutreq".to_owned(),
            detail,
        },
        other => other,
    })? {
        Some(seconds) => Ok(seconds),
        None => Err(CommandError::InvalidArgument {
            command: "timeoutreq".to_owned(),
            detail: "members must request a positive number of seconds".to_owned(),
        }),
    }
}

/// Parses a required, single non-empty argument without control characters.
fn parse_simple_arg<'a>(command: &'a str, args: &'a str) -> Result<&'a str, CommandError> {
    if args.is_empty() {
        return Err(CommandError::MissingArgument {
            command: command.to_owned(),
        });
    }
    if contains_control_char(args) {
        return Err(CommandError::ControlCharacterNotAllowed {
            command: command.to_owned(),
        });
    }
    Ok(args)
}

/// Parses a `/kick` target: an all-digit argument is a member id,
/// anything else is a nickname.
fn parse_kick_target(args: &str) -> Result<KickTarget, CommandError> {
    let arg = parse_simple_arg("kick", args)?;
    if arg.bytes().all(|b| b.is_ascii_digit()) {
        let id: u64 = arg.parse().map_err(|_| CommandError::InvalidArgument {
            command: "kick".to_owned(),
            detail: format!("invalid member id `{arg}`"),
        })?;
        Ok(KickTarget::Id(MemberId::new(id)))
    } else {
        Ok(KickTarget::Nickname(arg.to_owned()))
    }
}

/// Parses a numeric request id for `/accept` and `/reject`.
fn parse_request_id(command: &str, args: &str) -> Result<RequestId, CommandError> {
    let arg = parse_simple_arg(command, args)?;
    if !arg.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CommandError::InvalidArgument {
            command: command.to_owned(),
            detail: format!("expected a numeric request id, got `{arg}`"),
        });
    }
    let id: u64 = arg.parse().map_err(|_| CommandError::InvalidArgument {
        command: command.to_owned(),
        detail: format!("invalid request id `{arg}`"),
    })?;
    Ok(RequestId::new(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_chat() {
        assert_eq!(
            parse_line("hello world"),
            Ok(ParsedLine::Chat("hello world".to_owned()))
        );
        assert_eq!(parse_line("   "), Ok(ParsedLine::Chat("   ".to_owned())));
    }

    #[test]
    fn double_slash_escapes_a_slash_command() {
        assert_eq!(
            parse_line("//help"),
            Ok(ParsedLine::Chat("/help".to_owned()))
        );
        assert_eq!(
            parse_line("///help"),
            Ok(ParsedLine::Chat("//help".to_owned()))
        );
        assert_eq!(
            parse_line("//kick alice"),
            Ok(ParsedLine::Chat("/kick alice".to_owned()))
        );
    }

    #[test]
    fn slash_followed_by_whitespace_is_chat_not_a_command() {
        assert_eq!(
            parse_line("/ exit"),
            Ok(ParsedLine::Chat("/ exit".to_owned()))
        );
        assert_eq!(
            parse_line("/\tcolor red"),
            Ok(ParsedLine::Chat("/\tcolor red".to_owned()))
        );
        assert_eq!(
            parse_line("/  leave"),
            Ok(ParsedLine::Chat("/  leave".to_owned()))
        );
    }

    #[test]
    fn empty_line_is_an_error() {
        assert_eq!(parse_line(""), Err(CommandError::EmptyLine));
    }

    #[test]
    fn argumentless_commands_parse() {
        for (line, expected) in [
            ("/help", SlashCommand::Help),
            ("/exit", SlashCommand::Exit),
            ("/leave", SlashCommand::Leave),
            ("/list", SlashCommand::List),
            ("/newid", SlashCommand::NewId),
            ("/reqon", SlashCommand::ReqOn),
            ("/reqoff", SlashCommand::ReqOff),
            ("/requests", SlashCommand::Requests),
            ("/copy", SlashCommand::Copy),
        ] {
            assert_eq!(
                parse_line(line),
                Ok(ParsedLine::Command(expected)),
                "line: {line}"
            );
        }
    }

    #[test]
    fn argumentless_commands_reject_arguments() {
        assert!(matches!(
            parse_line("/help now"),
            Err(CommandError::UnexpectedArgument { .. })
        ));
        assert!(matches!(
            parse_line("/reqoff 1"),
            Err(CommandError::UnexpectedArgument { .. })
        ));
    }

    #[test]
    fn color_parses_the_full_palette() {
        for (line, expected) in [
            ("/color red", ColorChoice::Red),
            ("/color green", ColorChoice::Green),
            ("/color yellow", ColorChoice::Yellow),
            ("/color blue", ColorChoice::Blue),
            ("/color magenta", ColorChoice::Magenta),
            ("/color cyan", ColorChoice::Cyan),
            ("/color white", ColorChoice::White),
        ] {
            assert_eq!(
                parse_line(line),
                Ok(ParsedLine::Command(SlashCommand::Color(expected)))
            );
        }
    }

    #[test]
    fn color_rejects_unknown_and_missing_values() {
        assert!(matches!(
            parse_line("/color orange"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert!(matches!(
            parse_line("/color red blue"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert_eq!(
            parse_line("/color"),
            Err(CommandError::MissingArgument {
                command: "color".to_owned()
            })
        );
    }

    #[test]
    fn timeout_parses_intervals_and_off() {
        assert_eq!(
            parse_line("/timeout 30"),
            Ok(ParsedLine::Command(SlashCommand::Timeout(Some(30))))
        );
        assert_eq!(
            parse_line("/timeout 1"),
            Ok(ParsedLine::Command(SlashCommand::Timeout(Some(1))))
        );
        assert_eq!(
            parse_line("/timeout off"),
            Ok(ParsedLine::Command(SlashCommand::Timeout(None)))
        );
        assert_eq!(
            parse_line("/timeout 3600"),
            Ok(ParsedLine::Command(SlashCommand::Timeout(Some(3600))))
        );
    }

    #[test]
    fn timeout_rejects_missing_zero_and_out_of_range_values() {
        assert_eq!(
            parse_line("/timeout"),
            Err(CommandError::MissingArgument {
                command: "timeout".to_owned()
            })
        );
        assert!(matches!(
            parse_line("/timeout 0"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert!(matches!(
            parse_line("/timeout abc"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert!(matches!(
            parse_line("/timeout 3601"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert!(matches!(
            parse_line("/timeout 18446744073709551616"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert!(matches!(
            parse_line("/timeout 30 40"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert!(matches!(
            parse_line("/timeout red\u{7f}"),
            Err(CommandError::ControlCharacterNotAllowed { .. })
        ));
    }

    #[test]
    fn timeout_request_requires_an_enabled_interval() {
        assert_eq!(
            parse_line("/timeoutreq 30"),
            Ok(ParsedLine::Command(SlashCommand::TimeoutRequest(30)))
        );
        assert_eq!(
            parse_line("/timeoutreq"),
            Err(CommandError::MissingArgument {
                command: "timeoutreq".to_owned()
            })
        );
        for line in ["/timeoutreq off", "/timeoutreq 0", "/timeoutreq 3601"] {
            assert!(matches!(
                parse_line(line),
                Err(CommandError::InvalidArgument { .. })
            ));
        }
    }

    #[test]
    fn whois_requires_an_argument() {
        assert_eq!(
            parse_line("/whois"),
            Err(CommandError::MissingArgument {
                command: "whois".to_owned()
            })
        );
        assert_eq!(
            parse_line("/whois deniz"),
            Ok(ParsedLine::Command(SlashCommand::Whois("deniz".to_owned())))
        );
    }

    #[test]
    fn kick_parses_numeric_ids_and_nicknames() {
        assert_eq!(
            parse_line("/kick 42"),
            Ok(ParsedLine::Command(SlashCommand::Kick(KickTarget::Id(
                MemberId::new(42)
            ))))
        );
        assert_eq!(
            parse_line("/kick 007"),
            Ok(ParsedLine::Command(SlashCommand::Kick(KickTarget::Id(
                MemberId::new(7)
            ))))
        );
        assert_eq!(
            parse_line("/kick alice"),
            Ok(ParsedLine::Command(SlashCommand::Kick(
                KickTarget::Nickname("alice".to_owned())
            )))
        );
        assert_eq!(
            parse_line("/kick abc123"),
            Ok(ParsedLine::Command(SlashCommand::Kick(
                KickTarget::Nickname("abc123".to_owned())
            )))
        );
    }

    #[test]
    fn kick_rejects_missing_arguments_and_overflows() {
        assert_eq!(
            parse_line("/kick"),
            Err(CommandError::MissingArgument {
                command: "kick".to_owned()
            })
        );
        assert!(matches!(
            parse_line("/kick 18446744073709551616"),
            Err(CommandError::InvalidArgument { .. })
        ));
    }

    #[test]
    fn accept_and_reject_parse_request_ids() {
        assert_eq!(
            parse_line("/accept 12"),
            Ok(ParsedLine::Command(SlashCommand::Accept(RequestId::new(
                12
            ))))
        );
        assert_eq!(
            parse_line("/reject 3"),
            Ok(ParsedLine::Command(SlashCommand::Reject(RequestId::new(3))))
        );
        assert!(matches!(
            parse_line("/accept abc"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert!(matches!(
            parse_line("/reject 1 2"),
            Err(CommandError::InvalidArgument { .. })
        ));
        assert_eq!(
            parse_line("/accept"),
            Err(CommandError::MissingArgument {
                command: "accept".to_owned()
            })
        );
    }

    #[test]
    fn unknown_commands_are_errors() {
        assert_eq!(
            parse_line("/ban alice"),
            Err(CommandError::UnknownCommand {
                name: "ban".to_owned()
            })
        );
        assert_eq!(
            parse_line("/HELP"),
            Err(CommandError::UnknownCommand {
                name: "HELP".to_owned()
            })
        );
        assert_eq!(
            parse_line("/"),
            Err(CommandError::UnknownCommand {
                name: "".to_owned()
            })
        );
    }

    #[test]
    fn control_characters_are_rejected_in_arguments() {
        assert!(matches!(
            parse_line("/kick alice\u{1b}[31m"),
            Err(CommandError::ControlCharacterNotAllowed { .. })
        ));
        assert!(matches!(
            parse_line("/color blue\u{9b}"),
            Err(CommandError::ControlCharacterNotAllowed { .. })
        ));
        assert!(matches!(
            parse_line("/whois a\u{7f}b"),
            Err(CommandError::ControlCharacterNotAllowed { .. })
        ));
    }

    #[test]
    fn slash_commands_map_to_member_commands() {
        use crate::event::MemberCommand;
        let cases = [
            (parse_line("/leave").unwrap(), Some(MemberCommand::Leave)),
            (
                parse_line("/color blue").unwrap(),
                Some(MemberCommand::Color(ColorChoice::Blue)),
            ),
            (parse_line("/list").unwrap(), Some(MemberCommand::List)),
            (
                parse_line("/whois deniz").unwrap(),
                Some(MemberCommand::Whois("deniz".to_owned())),
            ),
            (parse_line("/help").unwrap(), None),
            (parse_line("/exit").unwrap(), None),
            (parse_line("/kick 5").unwrap(), None),
        ];
        for (line, expected) in cases {
            let ParsedLine::Command(command) = line else {
                panic!("expected a command");
            };
            assert_eq!(command.into_member_command(), expected);
        }
    }

    #[test]
    fn slash_commands_map_to_host_commands() {
        use crate::event::{HostCommand, MemberRef};
        let cases = [
            (
                parse_line("/kick 5").unwrap(),
                Some(HostCommand::Kick {
                    target: MemberRef::Id(MemberId::new(5)),
                }),
            ),
            (
                parse_line("/kick alice").unwrap(),
                Some(HostCommand::Kick {
                    target: MemberRef::Nickname("alice".to_owned()),
                }),
            ),
            (parse_line("/newid").unwrap(), Some(HostCommand::NewId)),
            (parse_line("/reqon").unwrap(), Some(HostCommand::ReqOn)),
            (parse_line("/reqoff").unwrap(), Some(HostCommand::ReqOff)),
            (
                parse_line("/requests").unwrap(),
                Some(HostCommand::Requests),
            ),
            (
                parse_line("/accept 3").unwrap(),
                Some(HostCommand::Accept {
                    request_id: RequestId::new(3),
                }),
            ),
            (
                parse_line("/reject 4").unwrap(),
                Some(HostCommand::Reject {
                    request_id: RequestId::new(4),
                }),
            ),
            (parse_line("/leave").unwrap(), None),
            (parse_line("/list").unwrap(), None),
        ];
        for (line, expected) in cases {
            let ParsedLine::Command(command) = line else {
                panic!("expected a command");
            };
            assert_eq!(command.into_host_command(), expected);
        }
    }

    #[test]
    fn default_color_is_white() {
        assert_eq!(ColorChoice::default(), ColorChoice::White);
    }
}
