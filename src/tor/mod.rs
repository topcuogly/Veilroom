//! Tor runtime management (architecture decisions 9 and 2, sections 19-21).
//!
//! Every Veilroom process launches its own Tor subprocess with a private
//! runtime directory under `$XDG_RUNTIME_DIR/veilroom/session-<random>/`.
//! Stage 3 implements the minimal control subset: authentication, bootstrap
//! status, `ADD_ONION`, `DEL_ONION`, and controlled shutdown.

pub mod control;
pub mod manager;
pub mod parser;

pub use control::{ControlClient, ControlError, LineReader, MAX_CONTROL_LINE_BYTES};
pub use manager::{OnionService, SessionPaths, SpawnConfig, TorConfig, TorError, TorManager};
pub use parser::{ControlLine, LineKind, ParserError, Reply, ReplyAccumulator, parse_control_line};
