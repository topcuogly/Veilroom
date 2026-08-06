//! The TUI application state machine (sections 25, 31, and 34.2).
//!
//! [`App`] owns the current [`Screen`] and translates key events into typed
//! [`AppAction`]s. Slash commands are parsed here, in the TUI, never sent as
//! raw text (section 31); `//text` sends `/text` as chat; unknown commands
//! surface as errors. The supervisor executes the actions.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::command::{ParsedLine, parse_line};
use crate::crypto::SecretBytes;
use crate::event::MenuChoice;
use crate::ui::input::{SecretSubmit, Submit};
use crate::ui::room_view::RoomView;
use crate::ui::screen::{
    HostField, HostSetupModel, JoinField, JoinFormField, JoinFormModel, JoinSetupModel, MenuModel,
    Screen, TorConnectionModel,
};

/// An action produced by the TUI for the supervisor to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppAction {
    /// Nothing to do; the app state changed internally.
    None,
    /// The application should quit.
    Quit,
    /// The host setup form was completed.
    HostSetupSubmitted {
        /// The room password (zeroized on drop).
        password: SecretBytes,
        /// The host nickname.
        nickname: String,
    },
    /// The join setup form was completed; the invitation is still raw text.
    JoinSetupSubmitted {
        /// The raw invitation URI text.
        invitation: String,
        /// The room password (zeroized on drop).
        password: SecretBytes,
    },
    /// The join form was completed.
    JoinFormSubmitted {
        /// The requested nickname.
        nickname: String,
        /// The optional introduction message.
        introduction: Option<String>,
    },
    /// An action from inside the room screen.
    Room(RoomUiAction),
}

/// An action from the room screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomUiAction {
    /// Plain chat text to send.
    Chat(String),
    /// A parsed slash command to execute.
    Command(crate::command::SlashCommand),
    /// The submitted line was invalid; show the message.
    Error(String),
    /// `/leave`: end the session and return to the menu.
    Leave,
    /// `/exit`: end the session and quit the application.
    Exit,
    /// The user requested to copy the full invitation URI to the clipboard.
    ///
    /// Carries the complete URI as stored; the value is never the
    /// shortened preview.
    CopyInvitation(String),
}

/// The TUI application state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    screen: Screen,
    quit: bool,
}

impl App {
    /// Creates the application on the main menu.
    pub fn new() -> Self {
        Self {
            screen: Screen::default(),
            quit: false,
        }
    }

    /// The current screen.
    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    /// The current screen, mutably.
    pub fn screen_mut(&mut self) -> &mut Screen {
        &mut self.screen
    }

    /// Whether the application was asked to quit.
    pub const fn should_quit(&self) -> bool {
        self.quit
    }

    /// Sets the screen.
    pub fn set_screen(&mut self, screen: Screen) {
        self.screen = screen;
    }

    /// Shows a full-screen message.
    pub fn show_message(&mut self, message: impl Into<String>) {
        self.screen = Screen::Message(message.into());
    }

    /// Returns to the main menu.
    pub fn back_to_menu(&mut self) {
        self.screen = Screen::Menu(MenuModel::default());
    }

    /// Shows a dedicated Tor bootstrap bar starting at zero percent.
    pub fn begin_tor_connection(&mut self) {
        self.screen = Screen::TorConnecting(TorConnectionModel::new());
    }

    /// Updates the visible Tor bootstrap percentage, if it is active.
    pub fn set_tor_progress(&mut self, progress: u8) {
        if let Screen::TorConnecting(connection) = &mut self.screen {
            connection.set_progress(progress);
        }
    }

    /// Moves into the room screen.
    pub fn enter_room(&mut self, view: RoomView) {
        self.screen = Screen::Room(view);
    }

    /// Shows that the submitted join request is awaiting the host decision.
    pub fn show_join_pending(&mut self) {
        self.screen = Screen::JoinPending;
    }

    /// The room view, if the room screen is active.
    pub fn room_view(&self) -> Option<&RoomView> {
        match &self.screen {
            Screen::Room(view) => Some(view),
            _ => None,
        }
    }

    /// The room view, mutably, if the room screen is active.
    pub fn room_view_mut(&mut self) -> Option<&mut RoomView> {
        match &mut self.screen {
            Screen::Room(view) => Some(view),
            _ => None,
        }
    }

    /// Handles one key event.
    pub fn on_key(&mut self, key: KeyEvent) -> AppAction {
        let mut screen = std::mem::take(&mut self.screen);
        let (action, next) = match &mut screen {
            Screen::Menu(menu) => on_menu_key(menu, key),
            Screen::TorConnecting(_) => (AppAction::None, None),
            Screen::HostSetup(form) => on_host_setup_key(form, key),
            Screen::JoinSetup(form) => on_join_setup_key(form, key),
            Screen::JoinForm(form) => on_join_form_key(form, key),
            Screen::JoinPending => (AppAction::None, None),
            Screen::Room(_) => (on_room_key(&mut screen, key), None),
            Screen::About => (AppAction::None, Some(Screen::Menu(MenuModel::default()))),
            Screen::Message(_) => (AppAction::None, Some(Screen::Menu(MenuModel::default()))),
        };
        if let Some(next) = next {
            screen = next;
        }
        self.screen = screen;
        if matches!(action, AppAction::Quit) {
            self.quit = true;
        }
        action
    }

    /// Handles one bracketed-paste payload. Paste is routed only to the
    /// currently focused editable field and can never dismiss a message
    /// screen or trigger form submission.
    pub fn on_paste(&mut self, text: &str) {
        match &mut self.screen {
            Screen::HostSetup(form) => match form.focus {
                HostField::Password => form.password.push_text(text),
                HostField::Confirm => form.confirm.push_text(text),
                HostField::Nickname => form.nickname.insert_text(text),
            },
            Screen::JoinSetup(form) => match form.focus {
                JoinField::Invitation => form.invitation.insert_text(text),
                JoinField::Password => form.password.push_text(text),
            },
            Screen::JoinForm(form) => match form.focus {
                JoinFormField::Nickname => form.nickname.insert_text(text),
                JoinFormField::Introduction => form.introduction.insert_text(text),
            },
            Screen::Room(view) => view.input.insert_text(text),
            Screen::Menu(_)
            | Screen::TorConnecting(_)
            | Screen::JoinPending
            | Screen::About
            | Screen::Message(_) => {}
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// The outcome of one key event on a screen.
type KeyResult = (AppAction, Option<Screen>);

/// A key event on the main menu.
fn on_menu_key(menu: &mut MenuModel, key: KeyEvent) -> KeyResult {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            menu.move_selection(-1);
            (AppAction::None, None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            menu.move_selection(1);
            (AppAction::None, None)
        }
        KeyCode::Enter => match menu.selected_label() {
            "Host a room" => (
                AppAction::None,
                Some(Screen::HostSetup(HostSetupModel::new())),
            ),
            "Join a room" => (
                AppAction::None,
                Some(Screen::JoinSetup(JoinSetupModel::new())),
            ),
            "About Veilroom" => (AppAction::None, Some(Screen::About)),
            _ => (AppAction::Quit, None),
        },
        KeyCode::Esc | KeyCode::Char('q') => (AppAction::Quit, None),
        _ => (AppAction::None, None),
    }
}

/// A key event on the host setup form.
fn on_host_setup_key(form: &mut HostSetupModel, key: KeyEvent) -> KeyResult {
    match form.focus {
        HostField::Password => match secret_key(&mut form.password, key) {
            SecretSubmit::Value(password) => {
                form.store_password(password);
                form.focus = HostField::Confirm;
                (AppAction::None, None)
            }
            SecretSubmit::Cancel => (AppAction::None, Some(Screen::Menu(MenuModel::default()))),
            SecretSubmit::None => (AppAction::None, None),
        },
        HostField::Confirm => match secret_key(&mut form.confirm, key) {
            SecretSubmit::Value(confirm) => {
                let matches = form
                    .stored_password()
                    .is_some_and(|p| p == confirm.as_slice());
                if matches {
                    form.focus = HostField::Nickname;
                    form.error = None;
                } else {
                    // The submitted confirmation is consumed; the password
                    // entry is kept and the confirmation is retried. When
                    // the typo was in the *first* entry the confirmation can
                    // never match, so the hint names Esc as the way back.
                    form.error = Some(
                        "The passwords do not match. Confirm again, or press Esc to \
                         re-enter the password."
                            .to_owned(),
                    );
                    form.confirm.clear();
                    form.focus = HostField::Confirm;
                }
                (AppAction::None, None)
            }
            // Esc steps back to the password entry instead of leaving the
            // form: a typo in the first entry is otherwise unrecoverable.
            SecretSubmit::Cancel => {
                form.restart_password_entry();
                (AppAction::None, None)
            }
            SecretSubmit::None => (AppAction::None, None),
        },
        HostField::Nickname => match key.code {
            KeyCode::Enter => {
                if form.nickname.submit().is_value() {
                    let nickname = form.nickname.text().to_owned();
                    let password = form.take_password().unwrap_or_default();
                    (AppAction::HostSetupSubmitted { password, nickname }, None)
                } else {
                    form.error = Some("Enter a nickname before continuing.".to_owned());
                    (AppAction::None, None)
                }
            }
            KeyCode::Esc => {
                form.restart_password_entry();
                (AppAction::None, None)
            }
            KeyCode::Backspace => {
                form.nickname.backspace();
                (AppAction::None, None)
            }
            KeyCode::Char(ch) => {
                form.nickname.insert_char(ch);
                (AppAction::None, None)
            }
            _ => (AppAction::None, None),
        },
    }
}

/// A key event on the join setup form.
fn on_join_setup_key(form: &mut JoinSetupModel, key: KeyEvent) -> KeyResult {
    match form.focus {
        JoinField::Invitation => match key.code {
            KeyCode::Enter => {
                if form.invitation.submit().is_value() {
                    form.focus = JoinField::Password;
                    form.error = None;
                } else {
                    form.error = Some("Paste an invitation URI before continuing.".to_owned());
                }
                (AppAction::None, None)
            }
            // The first step of the join flow: Esc must lead back to the
            // menu, otherwise the only way out is Ctrl-C, which quits the
            // whole application.
            KeyCode::Esc => (AppAction::None, Some(Screen::Menu(MenuModel::default()))),
            KeyCode::Backspace => {
                form.invitation.backspace();
                (AppAction::None, None)
            }
            KeyCode::Char(ch) => {
                form.invitation.insert_char(ch);
                (AppAction::None, None)
            }
            _ => (AppAction::None, None),
        },
        JoinField::Password => match secret_key(&mut form.password, key) {
            SecretSubmit::Value(password) => {
                let invitation = form.invitation.text().to_owned();
                (
                    AppAction::JoinSetupSubmitted {
                        invitation,
                        password,
                    },
                    None,
                )
            }
            // Step back to the invitation rather than out of the form, so a
            // pasted URI does not have to be sourced and pasted again.
            SecretSubmit::Cancel => {
                form.password.clear();
                form.invitation.reopen();
                form.focus = JoinField::Invitation;
                form.error = None;
                (AppAction::None, None)
            }
            SecretSubmit::None => (AppAction::None, None),
        },
    }
}

/// A key event on the join form.
fn on_join_form_key(form: &mut JoinFormModel, key: KeyEvent) -> KeyResult {
    match form.focus {
        JoinFormField::Nickname => match key.code {
            KeyCode::Enter => {
                if form.nickname.submit().is_value() {
                    form.focus = JoinFormField::Introduction;
                    form.error = None;
                } else {
                    form.error = Some("Enter a nickname before continuing.".to_owned());
                }
                (AppAction::None, None)
            }
            // The first step of the form: Esc abandons the join. The
            // supervisor owns the live connection, so this has to travel
            // back as an action rather than a screen change.
            KeyCode::Esc => (AppAction::Room(RoomUiAction::Leave), None),
            KeyCode::Backspace => {
                form.nickname.backspace();
                (AppAction::None, None)
            }
            KeyCode::Char(ch) => {
                form.nickname.insert_char(ch);
                (AppAction::None, None)
            }
            _ => (AppAction::None, None),
        },
        JoinFormField::Introduction => match key.code {
            KeyCode::Enter => {
                if form.submitted {
                    return (AppAction::None, None);
                }
                let introduction = if form.introduction.text().is_empty() {
                    None
                } else {
                    let _ = form.introduction.submit();
                    Some(form.introduction.text().to_owned())
                };
                let nickname = form.nickname.text().to_owned();
                form.submitted = true;
                (
                    AppAction::JoinFormSubmitted {
                        nickname,
                        introduction,
                    },
                    Some(Screen::JoinPending),
                )
            }
            // Step back to the nickname so it can be corrected before the
            // request is signed and sent.
            KeyCode::Esc if !form.submitted => {
                form.nickname.reopen();
                form.focus = JoinFormField::Nickname;
                form.error = None;
                (AppAction::None, None)
            }
            KeyCode::Backspace => {
                form.introduction.backspace();
                (AppAction::None, None)
            }
            KeyCode::Char(ch) => {
                form.introduction.insert_char(ch);
                (AppAction::None, None)
            }
            _ => (AppAction::None, None),
        },
    }
}

/// A key event inside the room screen.
fn on_room_key(screen: &mut Screen, key: KeyEvent) -> AppAction {
    let Some(view) = (match screen {
        Screen::Room(view) => Some(view),
        _ => None,
    }) else {
        return AppAction::None;
    };
    match key.code {
        KeyCode::Enter => {
            let text = view.input.text().to_owned();
            view.submit_line();
            if text.is_empty() {
                return AppAction::None;
            }
            match parse_line(&text) {
                Ok(ParsedLine::Chat(chat)) if !view.is_host => {
                    AppAction::Room(RoomUiAction::Chat(chat))
                }
                // The host runs the room but does not chat from this pane;
                // it joins as a member from a second terminal instead.
                Ok(ParsedLine::Chat(_)) => AppAction::Room(RoomUiAction::Error(
                    "the host cannot send chat messages; join the room from a second tab to chat"
                        .to_owned(),
                )),
                Ok(ParsedLine::Command(command)) => command_action(view, command),
                Err(error) => AppAction::Room(RoomUiAction::Error(error.to_string())),
            }
        }
        KeyCode::Backspace => {
            view.input.backspace();
            AppAction::None
        }
        KeyCode::Delete => {
            view.input.delete();
            AppAction::None
        }
        KeyCode::Left => {
            view.input.move_left();
            AppAction::None
        }
        KeyCode::Right => {
            view.input.move_right();
            AppAction::None
        }
        KeyCode::Home => {
            view.input.move_home();
            AppAction::None
        }
        KeyCode::End => {
            view.input.move_end();
            AppAction::None
        }
        KeyCode::Esc => {
            view.input.clear();
            AppAction::None
        }
        KeyCode::Char('k' | 'K') if key.modifiers == KeyModifiers::CONTROL => {
            view.toggle_system_messages();
            AppAction::None
        }
        KeyCode::Char('t' | 'T') if key.modifiers == KeyModifiers::CONTROL => {
            view.toggle_host_member_view();
            AppAction::None
        }
        KeyCode::Char(ch) if key.modifiers == KeyModifiers::CONTROL && ch == 'y' => {
            match view.invitation.clone() {
                Some(uri) => AppAction::Room(RoomUiAction::CopyInvitation(uri)),
                None => AppAction::Room(RoomUiAction::Error(
                    "no invitation is available to copy yet".to_owned(),
                )),
            }
        }
        KeyCode::Char(ch) if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT => {
            view.input.insert_char(ch);
            AppAction::None
        }
        _ => AppAction::None,
    }
}

/// Resolves a parsed slash command into a room action, mutating the view
/// for local-only commands (`/help`, `/color list`, and `/clear`).
fn command_action(view: &mut RoomView, command: crate::command::SlashCommand) -> AppAction {
    use crate::command::SlashCommand;
    match command {
        SlashCommand::Help => {
            view.push_system(
                "/help, /exit, /leave, /color <color>, /list, /whois <member>, \
                 /kick <member>, /newid, /reqon, /reqoff, /requests, /accept <id>, \
                 /reject <id>, /copy, /clear, /timeout <seconds|off>, \
                 /timeoutreq <seconds>, /color list; shortcuts: Ctrl-K \
                 message filter, Ctrl-T host/member view",
            );
            AppAction::None
        }
        SlashCommand::Copy => match view.invitation.clone() {
            Some(uri) => AppAction::Room(RoomUiAction::CopyInvitation(uri)),
            None => AppAction::Room(RoomUiAction::Error(
                "no invitation is available to copy yet".to_owned(),
            )),
        },
        SlashCommand::ColorList => {
            view.push_color_list();
            AppAction::None
        }
        SlashCommand::Clear => {
            view.clear_messages();
            AppAction::None
        }
        SlashCommand::Timeout(_) if !view.is_host => AppAction::Room(RoomUiAction::Error(
            "that command is only available to the host; use /timeoutreq <seconds>".to_owned(),
        )),
        SlashCommand::TimeoutRequest(_) if view.is_host => AppAction::Room(RoomUiAction::Error(
            "that command is only available to room members".to_owned(),
        )),
        SlashCommand::Leave => {
            if view.is_host {
                AppAction::Room(RoomUiAction::Error(
                    "The host cannot /leave; use /exit to close the room.".to_owned(),
                ))
            } else {
                AppAction::Room(RoomUiAction::Leave)
            }
        }
        SlashCommand::Exit => AppAction::Room(RoomUiAction::Exit),
        other => AppAction::Room(RoomUiAction::Command(other)),
    }
}

/// Handles one key for a masked secret field; returns the submit outcome.
fn secret_key(field: &mut crate::ui::input::SecretField, key: KeyEvent) -> SecretSubmit {
    match key.code {
        KeyCode::Enter => field.submit(),
        KeyCode::Esc => SecretSubmit::Cancel,
        KeyCode::Backspace => {
            field.pop();
            SecretSubmit::None
        }
        KeyCode::Char(ch) => {
            field.push_char(ch);
            SecretSubmit::None
        }
        _ => SecretSubmit::None,
    }
}

impl App {
    /// The selected menu choice, used by the supervisor after navigation.
    pub fn selected_menu_choice(&self) -> Option<MenuChoice> {
        match &self.screen {
            Screen::Menu(_) | Screen::TorConnecting(_) => None,
            Screen::HostSetup(_) => Some(MenuChoice::Host),
            Screen::JoinSetup(_) | Screen::JoinForm(_) | Screen::JoinPending => {
                Some(MenuChoice::Join)
            }
            Screen::About => Some(MenuChoice::About),
            Screen::Room(_) | Screen::Message(_) => None,
        }
    }
}

/// A helper to check submit outcomes without moving values.
trait SubmitValue {
    fn is_value(&self) -> bool;
}

impl SubmitValue for Submit<&str> {
    fn is_value(&self) -> bool {
        matches!(self, Submit::Value(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::MemberId;
    use crossterm::event::KeyCode;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    fn type_text(app: &mut App, text: &str) {
        for ch in text.chars() {
            app.on_key(key(KeyCode::Char(ch)));
        }
    }

    fn enter(app: &mut App) -> AppAction {
        app.on_key(key(KeyCode::Enter))
    }

    #[test]
    fn menu_navigates_and_selects_host() {
        let mut app = App::new();
        assert!(matches!(app.screen(), Screen::Menu(_)));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Up));
        let action = enter(&mut app);
        assert_eq!(action, AppAction::None);
        assert!(matches!(app.screen(), Screen::HostSetup(_)));
    }

    #[test]
    fn menu_quit_and_exit() {
        let mut app = App::new();
        assert_eq!(app.on_key(key(KeyCode::Esc)), AppAction::Quit);
        assert!(app.should_quit());
    }

    #[test]
    fn about_menu_entry_opens_and_returns_on_any_key() {
        let mut app = App::new();
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        assert_eq!(enter(&mut app), AppAction::None);
        assert!(matches!(app.screen(), Screen::About));
        assert_eq!(app.selected_menu_choice(), Some(MenuChoice::About));

        assert_eq!(app.on_key(key(KeyCode::Char('x'))), AppAction::None);
        assert!(matches!(app.screen(), Screen::Menu(_)));
    }

    #[test]
    fn host_setup_requires_matching_passwords() {
        let mut app = App::new();
        enter(&mut app);
        type_text(&mut app, "s3cret");
        enter(&mut app);
        type_text(&mut app, "wrong");
        let action = enter(&mut app);
        assert_eq!(action, AppAction::None, "mismatch stays on the form");
        let Screen::HostSetup(form) = app.screen() else {
            panic!("still on host setup");
        };
        assert!(form.error.is_some());
        assert_eq!(form.focus, HostField::Confirm, "confirmation is retried");
        assert!(form.confirm.is_empty(), "the confirmation is cleared");
        assert_eq!(
            form.stored_password(),
            Some(b"s3cret".as_slice()),
            "the password entry is kept"
        );
    }

    #[test]
    fn host_setup_submits_password_and_nickname() {
        let mut app = App::new();
        enter(&mut app);
        type_text(&mut app, "s3cret");
        enter(&mut app);
        type_text(&mut app, "s3cret");
        enter(&mut app);
        type_text(&mut app, "deniz");
        let action = enter(&mut app);
        let AppAction::HostSetupSubmitted { password, nickname } = action else {
            panic!("expected host setup submission");
        };
        assert_eq!(&*password, b"s3cret");
        assert_eq!(nickname, "deniz");
    }

    #[test]
    fn join_setup_submits_invitation_and_password() {
        let mut app = App::new();
        app.on_key(key(KeyCode::Down));
        enter(&mut app);
        type_text(&mut app, "veilroom://abc.onion:80?v=1&token=xyz");
        enter(&mut app);
        type_text(&mut app, "pass");
        let action = enter(&mut app);
        let AppAction::JoinSetupSubmitted {
            invitation,
            password,
        } = action
        else {
            panic!("expected join setup submission");
        };
        assert!(invitation.starts_with("veilroom://"));
        assert_eq!(&*password, b"pass");
    }

    #[test]
    fn pasted_invitation_stays_in_the_join_form() {
        let mut app = App::new();
        app.on_key(key(KeyCode::Down));
        enter(&mut app);
        let uri = "veilroom://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion:80?v=1&token=YWJjZGVmZ2hpamtsbW5vcA";
        app.on_paste(uri);
        assert!(matches!(app.screen(), Screen::JoinSetup(_)));
        enter(&mut app);
        app.on_paste("pass");
        let AppAction::JoinSetupSubmitted {
            invitation,
            password,
        } = enter(&mut app)
        else {
            panic!("expected pasted join setup submission");
        };
        assert_eq!(invitation, uri);
        assert_eq!(&*password, b"pass");
    }

    #[test]
    fn join_form_submits_with_empty_introduction() {
        let mut app = App::new();
        app.set_screen(Screen::JoinForm(JoinFormModel::new()));
        type_text(&mut app, "deniz");
        enter(&mut app);
        let action = enter(&mut app);
        assert!(matches!(
            action,
            AppAction::JoinFormSubmitted {
                nickname,
                introduction: None
            } if nickname == "deniz"
        ));
        assert!(matches!(app.screen(), Screen::JoinPending));
    }

    #[test]
    fn join_form_introduction_is_optional() {
        let mut app = App::new();
        app.set_screen(Screen::JoinForm(JoinFormModel::new()));
        type_text(&mut app, "deniz");
        enter(&mut app);
        type_text(&mut app, "hello from the terminal");
        let AppAction::JoinFormSubmitted {
            nickname,
            introduction,
        } = enter(&mut app)
        else {
            panic!("expected join form submission");
        };
        assert_eq!(nickname, "deniz");
        assert_eq!(introduction.as_deref(), Some("hello from the terminal"));
    }

    #[test]
    fn join_form_can_only_submit_once() {
        let mut app = App::new();
        app.set_screen(Screen::JoinForm(JoinFormModel::new()));
        app.on_paste("deniz");
        enter(&mut app);
        assert!(matches!(
            enter(&mut app),
            AppAction::JoinFormSubmitted { .. }
        ));
        assert_eq!(enter(&mut app), AppAction::None);
    }

    #[test]
    fn room_line_parses_commands_locally() {
        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut app, "hello");
        assert_eq!(
            enter(&mut app),
            AppAction::Room(RoomUiAction::Chat("hello".to_owned()))
        );
        type_text(&mut app, "/kick 3");
        assert_eq!(
            enter(&mut app),
            AppAction::Room(RoomUiAction::Command(crate::command::SlashCommand::Kick(
                crate::command::KickTarget::Id(MemberId::new(3))
            )))
        );
        type_text(&mut app, "/timeout 30");
        assert!(matches!(
            enter(&mut app),
            AppAction::Room(RoomUiAction::Error(_))
        ));
    }

    #[test]
    fn host_timeout_is_routed_for_room_wide_application() {
        let mut app = App::new();
        app.enter_room(RoomView::host("host".to_owned()));

        type_text(&mut app, "/timeout 2");
        assert_eq!(
            enter(&mut app),
            AppAction::Room(RoomUiAction::Command(
                crate::command::SlashCommand::Timeout(Some(2)),
            ))
        );

        type_text(&mut app, "/timeout off");
        assert_eq!(
            enter(&mut app),
            AppAction::Room(RoomUiAction::Command(
                crate::command::SlashCommand::Timeout(None),
            ))
        );
    }

    #[test]
    fn clear_and_color_list_are_local_and_available_to_everyone() {
        let mut host = App::new();
        host.enter_room(RoomView::host("host".to_owned()));
        host.room_view_mut().unwrap().push_system("old message");
        type_text(&mut host, "/clear");
        assert_eq!(enter(&mut host), AppAction::None);
        assert!(host.room_view().unwrap().messages.is_empty());

        let mut member = App::new();
        member.enter_room(RoomView::participant("alice".to_owned()));
        member.room_view_mut().unwrap().push_system("old message");
        type_text(&mut member, "/clear");
        assert_eq!(enter(&mut member), AppAction::None);
        assert!(member.room_view().unwrap().messages.is_empty());

        type_text(&mut member, "/color list");
        assert_eq!(enter(&mut member), AppAction::None);
        let palette: Vec<_> = member
            .room_view()
            .unwrap()
            .messages
            .iter()
            .filter_map(|line| match line.style {
                crate::ui::buffer::LineStyle::Palette(color) => Some((line.text.as_str(), color)),
                _ => None,
            })
            .collect();
        assert_eq!(palette.len(), crate::command::ColorChoice::ALL.len());
        assert_eq!(palette[0], ("red", crate::command::ColorChoice::Red));
        assert_eq!(palette[6], ("white", crate::command::ColorChoice::White));
    }

    #[test]
    fn double_slash_sends_slash_text_as_chat() {
        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut app, "//help");
        assert_eq!(
            enter(&mut app),
            AppAction::Room(RoomUiAction::Chat("/help".to_owned()))
        );
    }

    #[test]
    fn unknown_commands_become_errors_not_chat() {
        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut app, "/ban alice");
        let action = enter(&mut app);
        assert!(matches!(action, AppAction::Room(RoomUiAction::Error(_))));
    }

    #[test]
    fn host_leave_is_an_error_and_participant_leave_is_an_action() {
        let mut app = App::new();
        app.enter_room(RoomView::host("host".to_owned()));
        type_text(&mut app, "/leave");
        let action = enter(&mut app);
        assert!(matches!(action, AppAction::Room(RoomUiAction::Error(_))));

        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut app, "/leave");
        let action = enter(&mut app);
        assert_eq!(action, AppAction::Room(RoomUiAction::Leave));
    }

    #[test]
    fn host_chat_is_rejected_and_participant_chat_is_sent() {
        let mut host = App::new();
        host.enter_room(RoomView::host("host".to_owned()));
        type_text(&mut host, "hello from the host");
        let action = enter(&mut host);
        assert!(
            matches!(action, AppAction::Room(RoomUiAction::Error(_))),
            "a host chat line becomes an error, never a Chat action"
        );

        let mut participant = App::new();
        participant.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut participant, "hello");
        assert_eq!(
            enter(&mut participant),
            AppAction::Room(RoomUiAction::Chat("hello".to_owned()))
        );
    }

    #[test]
    fn exit_action_and_help() {
        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut app, "/exit");
        assert_eq!(enter(&mut app), AppAction::Room(RoomUiAction::Exit));

        type_text(&mut app, "/help");
        assert_eq!(enter(&mut app), AppAction::None);
        let view = app.room_view().unwrap();
        assert!(view.messages.iter().any(|l| l.text.contains("/help")));
    }

    #[test]
    fn message_screen_returns_to_menu_on_any_key() {
        let mut app = App::new();
        app.show_message("tor could not be started");
        assert_eq!(app.on_key(key(KeyCode::Char('x'))), AppAction::None);
        assert!(matches!(app.screen(), Screen::Menu(_)));
    }

    #[test]
    fn tor_connection_progress_is_bounded_and_ignores_input() {
        let mut app = App::new();
        app.begin_tor_connection();
        app.set_tor_progress(150);

        assert_eq!(app.on_key(key(KeyCode::Enter)), AppAction::None);
        assert!(matches!(
            app.screen(),
            Screen::TorConnecting(connection) if connection.progress() == 100
        ));
    }

    #[test]
    fn backspace_edits_the_room_input() {
        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut app, "hello");
        app.on_key(key(KeyCode::Backspace));
        app.on_key(key(KeyCode::Backspace));
        type_text(&mut app, "y");
        assert_eq!(
            enter(&mut app),
            AppAction::Room(RoomUiAction::Chat("hely".to_owned()))
        );
    }

    #[test]
    fn ctrl_y_copies_the_full_invitation_uri() {
        let mut app = App::new();
        app.enter_room(RoomView::host("host".to_owned()));
        let body = "a".repeat(56);
        let token = "0123456789abcdef0123456789abcdef";
        let uri = format!("veilroom://{body}.onion:80?v=1&token={token}");
        app.room_view_mut().unwrap().set_invitation(uri.clone());

        let copy_key = KeyEvent::new(KeyCode::Char('y'), crossterm::event::KeyModifiers::CONTROL);
        assert_eq!(
            app.on_key(copy_key),
            AppAction::Room(RoomUiAction::CopyInvitation(uri)),
            "the copied value is the complete stored URI, never the preview"
        );
    }

    #[test]
    fn ctrl_y_without_an_invitation_is_an_error() {
        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        let copy_key = KeyEvent::new(KeyCode::Char('y'), crossterm::event::KeyModifiers::CONTROL);
        assert!(matches!(
            app.on_key(copy_key),
            AppAction::Room(RoomUiAction::Error(_))
        ));
    }

    #[test]
    fn ctrl_t_toggles_only_the_hosts_room_layout() {
        let toggle = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);
        let mut host = App::new();
        host.enter_room(RoomView::host("host".to_owned()));
        host.room_view_mut().unwrap().input.insert_text("draft");

        assert_eq!(host.on_key(toggle), AppAction::None);
        let view = host.room_view().unwrap();
        assert!(!view.uses_host_view());
        assert_eq!(
            view.input.text(),
            "draft",
            "Ctrl-T must not type into input"
        );

        assert_eq!(host.on_key(toggle), AppAction::None);
        assert!(host.room_view().unwrap().uses_host_view());

        let mut participant = App::new();
        participant.enter_room(RoomView::participant("alice".to_owned()));
        assert_eq!(participant.on_key(toggle), AppAction::None);
        assert!(!participant.room_view().unwrap().uses_host_view());
    }

    #[test]
    fn ctrl_k_toggles_system_messages_without_editing_the_draft() {
        let toggle = KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL);
        let mut app = App::new();
        app.enter_room(RoomView::participant("alice".to_owned()));
        app.room_view_mut().unwrap().input.insert_text("draft");

        assert_eq!(app.on_key(toggle), AppAction::None);
        let view = app.room_view().unwrap();
        assert!(!view.show_system_messages);
        assert_eq!(view.input.text(), "draft");

        assert_eq!(app.on_key(toggle), AppAction::None);
        assert!(app.room_view().unwrap().show_system_messages);
    }

    #[test]
    fn join_pending_screen_ignores_keys_and_paste() {
        let mut app = App::new();
        app.show_join_pending();
        assert_eq!(app.on_key(key(KeyCode::Enter)), AppAction::None);
        app.on_paste("ignored");
        assert!(matches!(app.screen(), Screen::JoinPending));
        assert_eq!(app.selected_menu_choice(), Some(MenuChoice::Join));
    }

    #[test]
    fn ctrl_combinations_do_not_type_into_the_input() {
        let mut app = App::new();
        app.enter_room(RoomView::participant("deniz".to_owned()));
        type_text(&mut app, "a");
        let ctrl_y = KeyEvent::new(KeyCode::Char('y'), crossterm::event::KeyModifiers::CONTROL);
        let action = app.on_key(ctrl_y);
        assert!(
            matches!(action, AppAction::Room(RoomUiAction::Error(_))),
            "without an invitation the copy surfaces as an error action"
        );
        let view = app.room_view().unwrap();
        assert_eq!(view.input.text(), "a", "control keys must not type");
    }
}
