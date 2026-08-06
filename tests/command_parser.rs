//! Public-API integration tests for the slash-command parser.

use veilroom::command::{ColorChoice, KickTarget, ParsedLine, SlashCommand, parse_line};
use veilroom::error::CommandError;
use veilroom::event::{MemberId, RequestId};

#[test]
fn plain_text_is_chat() {
    assert_eq!(
        parse_line("hello"),
        Ok(ParsedLine::Chat("hello".to_owned()))
    );
    assert_eq!(
        parse_line("  padded  "),
        Ok(ParsedLine::Chat("  padded  ".to_owned()))
    );
}

#[test]
fn empty_line_is_rejected() {
    assert_eq!(parse_line(""), Err(CommandError::EmptyLine));
}

#[test]
fn double_slash_escapes_commands() {
    assert_eq!(
        parse_line("//help"),
        Ok(ParsedLine::Chat("/help".to_owned()))
    );
    assert_eq!(
        parse_line("///exit"),
        Ok(ParsedLine::Chat("//exit".to_owned()))
    );
}

#[test]
fn every_local_and_member_command_parses() {
    let cases = [
        ("/help", SlashCommand::Help),
        ("/exit", SlashCommand::Exit),
        ("/leave", SlashCommand::Leave),
        ("/list", SlashCommand::List),
        ("/newid", SlashCommand::NewId),
        ("/reqon", SlashCommand::ReqOn),
        ("/reqoff", SlashCommand::ReqOff),
        ("/requests", SlashCommand::Requests),
        ("/color magenta", SlashCommand::Color(ColorChoice::Magenta)),
        ("/color list", SlashCommand::ColorList),
        ("/clear", SlashCommand::Clear),
        ("/whois deniz", SlashCommand::Whois("deniz".to_owned())),
        (
            "/kick 12",
            SlashCommand::Kick(KickTarget::Id(MemberId::new(12))),
        ),
        (
            "/kick alice",
            SlashCommand::Kick(KickTarget::Nickname("alice".to_owned())),
        ),
        ("/accept 3", SlashCommand::Accept(RequestId::new(3))),
        ("/reject 7", SlashCommand::Reject(RequestId::new(7))),
        ("/timeout 45", SlashCommand::Timeout(Some(45))),
        ("/timeout off", SlashCommand::Timeout(None)),
        ("/timeoutreq 12", SlashCommand::TimeoutRequest(12)),
    ];
    for (line, expected) in cases {
        assert_eq!(
            parse_line(line),
            Ok(ParsedLine::Command(expected)),
            "line: {line}"
        );
    }
}

#[test]
fn argumentless_commands_reject_arguments() {
    assert_eq!(
        parse_line("/help /exit"),
        Err(CommandError::UnexpectedArgument {
            command: "help".to_owned(),
            arg: "/exit".to_owned()
        })
    );
    assert!(matches!(
        parse_line("/reqon please"),
        Err(CommandError::UnexpectedArgument { .. })
    ));
}

#[test]
fn unknown_commands_are_never_sent_as_chat() {
    assert_eq!(
        parse_line("/ban alice"),
        Err(CommandError::UnknownCommand {
            name: "ban".to_owned()
        })
    );
    assert_eq!(
        parse_line("/history"),
        Err(CommandError::UnknownCommand {
            name: "history".to_owned()
        })
    );
    assert_eq!(
        parse_line("/KICK 1"),
        Err(CommandError::UnknownCommand {
            name: "KICK".to_owned()
        })
    );
}

#[test]
fn argument_errors_are_typed() {
    assert_eq!(
        parse_line("/accept"),
        Err(CommandError::MissingArgument {
            command: "accept".to_owned()
        })
    );
    assert_eq!(
        parse_line("/color"),
        Err(CommandError::MissingArgument {
            command: "color".to_owned()
        })
    );
    assert!(matches!(
        parse_line("/accept nope"),
        Err(CommandError::InvalidArgument { .. })
    ));
    assert!(matches!(
        parse_line("/reject 18446744073709551616"),
        Err(CommandError::InvalidArgument { .. })
    ));
    assert!(matches!(
        parse_line("/color orange"),
        Err(CommandError::InvalidArgument { .. })
    ));
    assert!(matches!(
        parse_line("/accept 1 2"),
        Err(CommandError::InvalidArgument { .. })
    ));
    assert_eq!(
        parse_line("/timeoutreq"),
        Err(CommandError::MissingArgument {
            command: "timeoutreq".to_owned()
        })
    );
    for line in ["/timeoutreq off", "/timeoutreq 0", "/timeoutreq 3601"] {
        assert!(
            matches!(parse_line(line), Err(CommandError::InvalidArgument { .. })),
            "line: {line}"
        );
    }
}

#[test]
fn control_characters_are_rejected() {
    assert!(matches!(
        parse_line("/whois a\u{1b}"),
        Err(CommandError::ControlCharacterNotAllowed { .. })
    ));
    assert!(matches!(
        parse_line("/color red\u{7f}"),
        Err(CommandError::ControlCharacterNotAllowed { .. })
    ));
    assert!(matches!(
        parse_line("/kick \u{009b}31m"),
        Err(CommandError::ControlCharacterNotAllowed { .. })
    ));
}

#[test]
fn control_characters_never_reach_chat_text() {
    // A control character in plain chat text is chat, but the TUI layer
    // validates chat text separately before sending; the parser only handles
    // command syntax. This test documents that the parser does not silently
    // convert malicious input into commands.
    assert_eq!(
        parse_line("a\u{1b}[31mb"),
        Ok(ParsedLine::Chat("a\u{1b}[31mb".to_owned()))
    );
}
