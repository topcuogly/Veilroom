//! The Ratatui terminal interface (Stage 8, sections 25, 31, and 34.2).
//!
//! The TUI is a thin presentation layer: it parses slash commands locally,
//! renders a strictly bounded render buffer, masks secret input, and never
//! writes raw client-controlled bytes to the terminal. All business logic
//! lives in the room actor and the supervisor; the TUI communicates through
//! typed actions.

pub mod app;
pub mod buffer;
pub mod input;
pub mod notice;
pub mod render;
pub mod room_view;
pub mod sanitize;
pub mod screen;
pub mod terminal;

pub use app::{App, AppAction, RoomUiAction};
pub use buffer::{GmtTimestamp, LineStyle, MessageLine, RenderBuffer};
pub use input::{SecretField, TextField};
pub use notice::{Notice, NoticeBuffer};
pub use room_view::{MemberLine, RequestKind, RequestLine, RoomView, RoomViewMode};
pub use sanitize::sanitize_for_display;
pub use screen::Screen;
pub use terminal::{TerminalGuard, TuiError};
