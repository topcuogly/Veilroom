//! The screen state machine of the application (sections 1 and 34.2).
//!
//! The supervisor and the TUI share one [`Screen`]: the main menu, the host
//! setup flow (password entered twice, nickname), the join setup flow
//! (invitation URI, password), the join form (nickname, introduction), the
//! host-decision waiting screen, the live room view, an about screen, and a
//! full-screen message. Screens are plain data; key
//! handling lives in `crate::ui::app`.

use crate::ui::input::{SecretField, TextField};
use crate::ui::room_view::RoomView;

/// The main-menu entry names, in display order.
pub const MENU_ITEMS: [&str; 4] = ["Host a room", "Join a room", "About Veilroom", "Exit"];

/// Text shown by the About Veilroom menu entry.
pub const ABOUT_TEXT: &str = "Veilroom is free software created to help protect individuals’ right to communicate freely. We believe messaging should be as simple, fast, and private as possible. Yet governments have deemed even this too much for their citizens. -topcuogly";

/// The main menu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MenuModel {
    /// The currently highlighted entry.
    pub selection: usize,
}

impl MenuModel {
    /// Moves the selection by `delta` (wrapping).
    pub fn move_selection(&mut self, delta: isize) {
        let len = MENU_ITEMS.len() as isize;
        let current = self.selection as isize;
        self.selection = ((current + delta).rem_euclid(len)) as usize;
    }

    /// The label of the selected entry.
    pub fn selected_label(&self) -> &'static str {
        MENU_ITEMS[self.selection]
    }
}

/// Tor bootstrap state shown on its own while a session connects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TorConnectionModel {
    progress: u8,
}

impl TorConnectionModel {
    /// Creates a connection indicator at zero percent.
    pub const fn new() -> Self {
        Self { progress: 0 }
    }

    /// Updates the observed Tor bootstrap percentage.
    pub fn set_progress(&mut self, progress: u8) {
        self.progress = progress.min(100);
    }

    /// Returns the observed Tor bootstrap percentage.
    pub const fn progress(self) -> u8 {
        self.progress
    }
}

/// Focus within the host setup form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostField {
    /// Entering the room password.
    Password,
    /// Re-entering the room password.
    Confirm,
    /// Entering the host nickname.
    Nickname,
}

/// The host setup form: password, password confirmation, nickname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSetupModel {
    /// The masked password field.
    pub password: SecretField,
    /// The masked confirmation field.
    pub confirm: SecretField,
    /// The nickname field.
    pub nickname: TextField,
    /// The field with focus.
    pub focus: HostField,
    /// An error message shown above the form, if any.
    pub error: Option<String>,
    /// The password captured from the first entry (zeroized on drop).
    stored: Option<crate::crypto::SecretBytes>,
}

impl HostSetupModel {
    /// Creates an empty host setup form.
    pub fn new() -> Self {
        Self {
            password: SecretField::new(crate::limits::Limits::default().max_nickname_scalars() * 4),
            confirm: SecretField::new(crate::limits::Limits::default().max_nickname_scalars() * 4),
            nickname: TextField::new(crate::limits::Limits::default().max_nickname_scalars() * 4),
            focus: HostField::Password,
            error: None,
            stored: None,
        }
    }

    /// Takes the captured password out of the form.
    pub fn take_password(&mut self) -> Option<crate::crypto::SecretBytes> {
        self.stored.take()
    }

    /// The captured password, without consuming it.
    pub fn stored_password(&self) -> Option<&[u8]> {
        self.stored.as_ref().map(|value| value.as_slice())
    }

    /// Stores the password captured from the first entry.
    pub fn store_password(&mut self, password: crate::crypto::SecretBytes) {
        self.stored = Some(password);
    }

    /// Discards every captured password and returns focus to the first
    /// password entry.
    ///
    /// A confirmation that never matches means the typo was in the first
    /// entry, which the confirm field alone can never fix; this is the way
    /// back. The captured password is dropped, so it is zeroized here.
    pub fn restart_password_entry(&mut self) {
        self.stored = None;
        self.password.clear();
        self.confirm.clear();
        self.focus = HostField::Password;
        self.error = Some("Enter the room password again.".to_owned());
    }
}

impl Default for HostSetupModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Focus within the join setup form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinField {
    /// The invitation URI.
    Invitation,
    /// The room password.
    Password,
}

/// The join setup form: invitation URI and password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinSetupModel {
    /// The invitation URI field.
    pub invitation: TextField,
    /// The masked password field.
    pub password: SecretField,
    /// The field with focus.
    pub focus: JoinField,
    /// An error message shown above the form, if any.
    pub error: Option<String>,
}

impl JoinSetupModel {
    /// Creates an empty join setup form.
    pub fn new() -> Self {
        let max = crate::limits::Limits::default().max_nickname_scalars() * 4;
        Self {
            invitation: TextField::new(1024),
            password: SecretField::new(max),
            focus: JoinField::Invitation,
            error: None,
        }
    }
}

impl Default for JoinSetupModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Focus within the join form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinFormField {
    /// The nickname.
    Nickname,
    /// The optional introduction message.
    Introduction,
}

/// The join form: nickname and optional introduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinFormModel {
    /// The nickname field.
    pub nickname: TextField,
    /// The optional introduction field.
    pub introduction: TextField,
    /// The field with focus.
    pub focus: JoinFormField,
    /// Whether the request has already been emitted to the supervisor.
    pub submitted: bool,
    /// An error message shown above the form, if any.
    pub error: Option<String>,
}

impl JoinFormModel {
    /// Creates an empty join form.
    pub fn new() -> Self {
        let max = crate::limits::Limits::default().max_nickname_scalars() * 4;
        let intro_max = crate::limits::Limits::default().max_intro_scalars() * 4;
        Self {
            nickname: TextField::new(max),
            introduction: TextField::new(intro_max),
            focus: JoinFormField::Nickname,
            submitted: false,
            error: None,
        }
    }
}

impl Default for JoinFormModel {
    fn default() -> Self {
        Self::new()
    }
}

/// One screen of the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// The main menu.
    Menu(MenuModel),
    /// A dedicated Tor bootstrap progress screen.
    TorConnecting(TorConnectionModel),
    /// Host setup: password, confirmation, nickname.
    HostSetup(HostSetupModel),
    /// Join setup: invitation URI and password.
    JoinSetup(JoinSetupModel),
    /// The join form: nickname and introduction.
    JoinForm(JoinFormModel),
    /// The submitted join request is waiting for the host's decision.
    JoinPending,
    /// The live room view.
    Room(RoomView),
    /// Project purpose and authorship information.
    About,
    /// A full-screen message; any key returns to the menu.
    Message(String),
}

impl Default for Screen {
    fn default() -> Self {
        Self::Menu(MenuModel::default())
    }
}
