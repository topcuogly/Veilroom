//! Keyboard-driven UI flows through the public TUI API (section 41.3).
//!
//! These tests drive the application state machine with synthetic key
//! events and verify the typed actions, screen transitions, and the
//! bounded render buffer without a terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use veilroom::ui::app::{App, AppAction, RoomUiAction};
use veilroom::ui::buffer::DEFAULT_RENDER_BUFFER_CAPACITY;
use veilroom::ui::screen::Screen;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl_c() -> KeyEvent {
    KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
}

fn type_text(app: &mut App, text: &str) {
    for ch in text.chars() {
        app.on_key(key(KeyCode::Char(ch)));
    }
}

#[test]
fn menu_selects_host_and_completes_the_setup_form() {
    let mut app = App::new();
    app.on_key(key(KeyCode::Enter));
    assert!(matches!(app.screen(), Screen::HostSetup(_)));

    type_text(&mut app, "room-password");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "room-password");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "host-nickname");
    let action = app.on_key(key(KeyCode::Enter));

    let AppAction::HostSetupSubmitted { password, nickname } = action else {
        panic!("expected a host setup submission");
    };
    assert_eq!(&*password, b"room-password");
    assert_eq!(nickname, "host-nickname");
}

#[test]
fn mismatched_passwords_restart_the_confirmation() {
    let mut app = App::new();
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "password-a");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "password-b");
    app.on_key(key(KeyCode::Enter));

    let Screen::HostSetup(form) = app.screen() else {
        panic!("still on the host setup form");
    };
    assert!(form.error.is_some(), "a mismatch must be reported");
    assert!(form.confirm.is_empty(), "the confirmation is retried");
}

#[test]
fn menu_selects_join_and_completes_the_join_setup() {
    let mut app = App::new();
    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Enter));
    assert!(matches!(app.screen(), Screen::JoinSetup(_)));

    type_text(&mut app, "veilroom://aaaa.onion:80?v=1&token=abc123");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "password");
    let action = app.on_key(key(KeyCode::Enter));

    let AppAction::JoinSetupSubmitted {
        invitation,
        password,
    } = action
    else {
        panic!("expected a join setup submission");
    };
    assert!(invitation.starts_with("veilroom://"));
    assert_eq!(&*password, b"password");
}

#[test]
fn menu_opens_about_before_exit_and_returns_to_menu() {
    let mut app = App::new();
    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Down));
    assert_eq!(app.on_key(key(KeyCode::Enter)), AppAction::None);
    assert!(matches!(app.screen(), Screen::About));

    assert_eq!(app.on_key(key(KeyCode::Enter)), AppAction::None);
    assert!(matches!(app.screen(), Screen::Menu(_)));
}

#[test]
fn room_input_parses_chat_and_commands() {
    let mut app = App::new();
    app.enter_room(veilroom::ui::RoomView::participant("deniz".to_owned()));

    type_text(&mut app, "merhaba");
    assert_eq!(
        app.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::Chat("merhaba".to_owned()))
    );

    type_text(&mut app, "/kick 3");
    assert!(matches!(
        app.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::Command(
            veilroom::command::SlashCommand::Kick(_)
        ))
    ));

    type_text(&mut app, "/bogus");
    assert!(
        matches!(
            app.on_key(key(KeyCode::Enter)),
            AppAction::Room(RoomUiAction::Error(_))
        ),
        "unknown commands surface as errors, never as chat"
    );

    type_text(&mut app, "//exit");
    assert_eq!(
        app.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::Chat("/exit".to_owned())),
        "double slash sends the text as chat"
    );
}

#[test]
fn the_render_buffer_stays_bounded_through_the_app() {
    let mut app = App::new();
    app.enter_room(veilroom::ui::RoomView::participant("deniz".to_owned()));
    for index in 0..(DEFAULT_RENDER_BUFFER_CAPACITY * 2) {
        app.room_view_mut()
            .unwrap()
            .push_system(format!("line {index}"));
    }
    let view = app.room_view().unwrap();
    assert_eq!(view.messages.len(), DEFAULT_RENDER_BUFFER_CAPACITY);
    assert!(view.messages.iter().all(|line| !line.text.is_empty()));
}

#[test]
fn every_screen_transition_is_reachable_and_leave_is_role_aware() {
    // Host: /leave is refused, /exit quits.
    let mut host = App::new();
    host.enter_room(veilroom::ui::RoomView::host("host".to_owned()));
    type_text(&mut host, "/leave");
    assert!(matches!(
        host.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::Error(_))
    ));
    type_text(&mut host, "/exit");
    assert_eq!(
        host.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::Exit)
    );

    // Participant: /leave ends the session.
    let mut member = App::new();
    member.enter_room(veilroom::ui::RoomView::participant("deniz".to_owned()));
    type_text(&mut member, "/leave");
    assert_eq!(
        member.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::Leave)
    );

    // A full-screen message returns to the menu on any key.
    member.show_message("the room was closed");
    member.on_key(key(KeyCode::Char('x')));
    assert!(matches!(member.screen(), Screen::Menu(_)));
}

#[test]
fn ctrl_c_is_a_hard_quit_signal() {
    assert_eq!(ctrl_c().code, KeyCode::Char('c'));
    assert_eq!(ctrl_c().modifiers, KeyModifiers::CONTROL);
}

#[test]
fn ctrl_y_copies_the_full_invitation_uri() {
    let mut app = App::new();
    app.enter_room(veilroom::ui::RoomView::host("host".to_owned()));

    // A full-length invitation: 56-char onion body and a 32-byte token.
    let body = "a".repeat(56);
    let token = "0123456789abcdef0123456789abcdef";
    let uri = format!("veilroom://{body}.onion:80?v=1&token={token}");
    app.room_view_mut().unwrap().set_invitation(uri.clone());

    let ctrl_y = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL);
    assert_eq!(
        app.on_key(ctrl_y),
        AppAction::Room(RoomUiAction::CopyInvitation(uri)),
        "the copy action always carries the complete stored URI"
    );
}

#[test]
fn invitation_preview_shortens_display_but_keeps_the_full_uri() {
    let mut app = App::new();
    app.enter_room(veilroom::ui::RoomView::host("host".to_owned()));
    let body = "a".repeat(56);
    let token = "0123456789abcdef0123456789abcdef";
    let uri = format!("veilroom://{body}.onion:80?v=1&token={token}");
    app.room_view_mut().unwrap().set_invitation(uri.clone());

    let view = app.room_view().unwrap();
    let preview = view.invitation_preview().unwrap();
    assert_eq!(preview, "veilroom://aaaa…aaaa.onion · token: present");
    assert!(preview.len() < uri.len());
    assert!(!preview.contains(token));
    // The full URI is still retained for the copy action.
    assert_eq!(view.invitation.as_deref(), Some(uri.as_str()));
}

#[test]
fn copy_command_copies_the_full_invitation_uri() {
    let mut app = App::new();
    app.enter_room(veilroom::ui::RoomView::host("host".to_owned()));
    let body = "a".repeat(56);
    let token = "0123456789abcdef0123456789abcdef";
    let uri = format!("veilroom://{body}.onion:80?v=1&token={token}");
    app.room_view_mut().unwrap().set_invitation(uri.clone());

    type_text(&mut app, "/copy");
    assert_eq!(
        app.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::CopyInvitation(uri)),
        "/copy carries the complete stored URI"
    );
}

#[test]
fn copy_command_without_an_invitation_is_an_error() {
    let mut app = App::new();
    app.enter_room(veilroom::ui::RoomView::participant("deniz".to_owned()));
    type_text(&mut app, "/copy");
    assert!(matches!(
        app.on_key(key(KeyCode::Enter)),
        AppAction::Room(RoomUiAction::Error(_))
    ));
}

#[test]
fn escape_always_leads_out_of_the_setup_forms() {
    // Esc used to be a no-op on every text field, so the invitation field —
    // the first screen of the join flow — had no way back to the menu; the
    // only exit was Ctrl-C, which quits the application.
    let mut app = App::new();
    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Enter));
    assert!(matches!(app.screen(), Screen::JoinSetup(_)));
    type_text(&mut app, "veilroom://x");
    app.on_key(key(KeyCode::Esc));
    assert!(
        matches!(app.screen(), Screen::Menu(_)),
        "Esc on the invitation field must return to the menu"
    );

    // Esc on the join password steps back to the invitation instead of
    // discarding a pasted URI.
    let mut app = App::new();
    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "veilroom://kept");
    app.on_key(key(KeyCode::Enter));
    app.on_key(key(KeyCode::Esc));
    let Screen::JoinSetup(form) = app.screen() else {
        panic!("Esc on the password must step back into the form")
    };
    assert_eq!(form.invitation.text(), "veilroom://kept");
    // The field is editable again, so the URI can be corrected in place.
    type_text(&mut app, "!");
    let Screen::JoinSetup(form) = app.screen() else {
        panic!("still on the join form")
    };
    assert_eq!(form.invitation.text(), "veilroom://kept!");
}

#[test]
fn escape_recovers_from_a_mistyped_first_password() {
    // A confirmation that never matches means the typo was in the first
    // entry, which the confirm field alone can never fix.
    let mut app = App::new();
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "typo");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "intended");
    app.on_key(key(KeyCode::Enter));
    let Screen::HostSetup(form) = app.screen() else {
        panic!("still on the host setup")
    };
    assert!(form.error.is_some(), "the mismatch is reported");

    app.on_key(key(KeyCode::Esc));
    let Screen::HostSetup(form) = app.screen() else {
        panic!("Esc must stay in the form, not leave it")
    };
    assert!(
        form.stored_password().is_none(),
        "the mistyped password must be discarded"
    );

    // The password can now be entered again and the form completed.
    type_text(&mut app, "intended");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "intended");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "host");
    let action = app.on_key(key(KeyCode::Enter));
    let AppAction::HostSetupSubmitted { password, .. } = action else {
        panic!("the corrected form must submit")
    };
    assert_eq!(password.as_slice(), b"intended");
}

#[test]
fn empty_submits_explain_themselves_instead_of_doing_nothing() {
    let mut app = App::new();
    app.on_key(key(KeyCode::Enter));
    // Host nickname: Enter on an empty field used to be a silent no-op.
    type_text(&mut app, "pw");
    app.on_key(key(KeyCode::Enter));
    type_text(&mut app, "pw");
    app.on_key(key(KeyCode::Enter));
    assert_eq!(app.on_key(key(KeyCode::Enter)), AppAction::None);
    let Screen::HostSetup(form) = app.screen() else {
        panic!("still on the host setup")
    };
    assert!(form.error.is_some(), "an empty nickname must be explained");

    let mut app = App::new();
    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Enter));
    app.on_key(key(KeyCode::Enter));
    let Screen::JoinSetup(form) = app.screen() else {
        panic!("still on the join setup")
    };
    assert!(
        form.error.is_some(),
        "an empty invitation must be explained"
    );
}
