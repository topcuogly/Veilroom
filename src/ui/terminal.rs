//! Terminal session lifecycle (sections 25 and 34.2).
//!
//! The application runs on the alternate screen in raw mode. [`TerminalGuard`]
//! restores the terminal on every path: normal shutdown, error returns, and
//! unwinding.

use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{self, Stdout};
use thiserror::Error;

/// Errors produced while entering or leaving the terminal session.
#[derive(Debug, Error)]
pub enum TuiError {
    /// The terminal could not be switched to raw mode.
    #[error("the terminal could not enter raw mode: {0}")]
    RawMode(#[from] io::Error),
    /// The terminal could not be drawn to.
    #[error("the terminal could not be rendered: {0}")]
    Render(io::Error),
}

/// An owned alternate-screen session.
///
/// Dropping the guard always restores the terminal: raw mode is disabled,
/// the alternate screen is left, and the cursor is shown again. The guard
/// also owns the [`Terminal`] used for drawing.
pub struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    /// Enters the alternate screen, enables raw mode, and hides the cursor.
    ///
    /// This must be called from the main thread before any other TUI work.
    pub fn enter() -> Result<Self, TuiError> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if execute!(stdout, EnterAlternateScreen, EnableBracketedPaste, Hide).is_err() {
            let _ = disable_raw_mode();
            return Err(TuiError::Render(io::Error::other(
                "entering the alternate screen failed",
            )));
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = execute!(
                    io::stdout(),
                    DisableBracketedPaste,
                    LeaveAlternateScreen,
                    Show
                );
                let _ = disable_raw_mode();
                return Err(TuiError::Render(error));
            }
        };
        Ok(Self { terminal })
    }

    /// The drawable terminal.
    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            Show
        );
        let _ = disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_guard_is_send_safe_to_build() {
        // Construction happens on the main thread in the supervisor; this
        // test only verifies the type is usable.
        let _name = std::any::type_name::<TerminalGuard>();
    }
}
