//! Room state and the room task (Stage 5, sections 13, 32, 33, and 34.1).
//!
//! `RoomActor` is the sole writer of room state: lifecycle, members,
//! pending requests, invitation token, join policy, epoch, and room
//! sequence. `RoomTask` wraps it with typed event and action channels.

pub mod action;
pub mod actor;
pub mod connections;
pub mod member;
pub mod task;

pub use action::{HostNotice, RequestInfo, RoomAction};
pub use actor::{HOST_CONNECTION, RoomActor, RoomError};
pub use member::{Member, MemberError, MemberInfo, MemberTable};
pub use task::{RoomSendError, RoomTask};
