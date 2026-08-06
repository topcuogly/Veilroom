//! Member state (sections 32 and 33).
//!
//! Every active member receives a unique room-lifetime `member_id`; the host
//! is member 0. Nicknames are unique within the active room and are assigned
//! atomically when a join request is accepted. The table is bounded by
//! `Limits::max_active_members`.

use crate::command::ColorChoice;
use crate::event::{ConnectionId, MemberId};

/// An active member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The room-lifetime member id.
    pub member_id: MemberId,
    /// The connection the member is attached to.
    pub connection: ConnectionId,
    /// The display nickname (unique in the room).
    pub nickname: String,
    /// The display color from the fixed palette.
    pub color: ColorChoice,
    /// Whether this is the host participant.
    pub is_host: bool,
    /// The member's ephemeral Ed25519 public key (Stage 6).
    pub ed25519_pubkey: [u8; 32],
    /// The member's ephemeral X25519 public key (Stage 6).
    pub x25519_pubkey: [u8; 32],
    /// The epoch in which the member joined.
    pub joined_epoch: u64,
}

/// A UI-facing summary of a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    /// The room-lifetime member id.
    pub member_id: MemberId,
    /// The display nickname.
    pub nickname: String,
    /// The display color.
    pub color: ColorChoice,
    /// Whether this is the host participant.
    pub is_host: bool,
}

impl From<&Member> for MemberInfo {
    fn from(member: &Member) -> Self {
        Self {
            member_id: member.member_id,
            nickname: member.nickname.clone(),
            color: member.color,
            is_host: member.is_host,
        }
    }
}

/// Errors produced by the member table.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemberError {
    /// The room is at its member limit.
    #[error("the room is full (maximum {max} members)")]
    Full {
        /// The configured maximum.
        max: usize,
    },
    /// The nickname is already used by an active member.
    #[error("nickname `{nickname}` is already in use")]
    NicknameTaken {
        /// The taken nickname.
        nickname: String,
    },
    /// The connection is already attached to an active member.
    #[error("connection {connection} is already active")]
    ConnectionTaken {
        /// The duplicate connection.
        connection: ConnectionId,
    },
    /// An ephemeral public identity is already active in this room.
    #[error("the ephemeral member identity is already active")]
    IdentityTaken,
    /// No member carries the given id.
    #[error("no member with id {id}")]
    UnknownId {
        /// The unknown member id.
        id: MemberId,
    },
}

/// The bounded table of active members.
#[derive(Debug, Clone)]
pub struct MemberTable {
    limit: usize,
    next_id: u64,
    members: Vec<Member>,
}

impl MemberTable {
    /// Creates an empty table bound by `limits`.
    pub fn new(limits: &crate::limits::Limits) -> Self {
        Self {
            limit: limits.max_active_members(),
            next_id: 1,
            members: Vec::new(),
        }
    }

    /// The configured capacity.
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// The number of active members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Whether the table is at its capacity.
    pub fn is_full(&self) -> bool {
        self.members.len() >= self.limit
    }

    /// Adds the host participant as member 0 with its identity keys.
    pub fn add_host(
        &mut self,
        connection: ConnectionId,
        nickname: String,
        ed25519_pubkey: [u8; 32],
        x25519_pubkey: [u8; 32],
    ) -> Member {
        let member = Member {
            member_id: MemberId::new(0),
            connection,
            nickname,
            color: ColorChoice::default(),
            is_host: true,
            ed25519_pubkey,
            x25519_pubkey,
            joined_epoch: 1,
        };
        self.members.push(member.clone());
        member
    }

    /// Adds a member, atomically assigning a fresh id and checking the
    /// capacity and nickname uniqueness.
    pub fn add(
        &mut self,
        connection: ConnectionId,
        nickname: String,
        ed25519_pubkey: [u8; 32],
        x25519_pubkey: [u8; 32],
        epoch: u64,
    ) -> Result<Member, MemberError> {
        if self.is_full() {
            return Err(MemberError::Full { max: self.limit });
        }
        if self.nickname_taken(&nickname) {
            return Err(MemberError::NicknameTaken { nickname });
        }
        if self.by_connection(connection).is_some() {
            return Err(MemberError::ConnectionTaken { connection });
        }
        if self.members.iter().any(|member| {
            member.ed25519_pubkey == ed25519_pubkey || member.x25519_pubkey == x25519_pubkey
        }) {
            return Err(MemberError::IdentityTaken);
        }
        let member = Member {
            member_id: MemberId::new(self.next_id),
            connection,
            nickname,
            color: ColorChoice::default(),
            is_host: false,
            ed25519_pubkey,
            x25519_pubkey,
            joined_epoch: epoch,
        };
        self.next_id += 1;
        self.members.push(member.clone());
        Ok(member)
    }

    /// Removes and returns the member with the given id, if any.
    pub fn remove(&mut self, id: MemberId) -> Option<Member> {
        let index = self
            .members
            .iter()
            .position(|member| member.member_id == id)?;
        Some(self.members.remove(index))
    }

    /// The member with the given id, if any.
    pub fn by_id(&self, id: MemberId) -> Option<&Member> {
        self.members.iter().find(|member| member.member_id == id)
    }

    /// Mutable access to the member with the given id, if any.
    pub fn by_id_mut(&mut self, id: MemberId) -> Option<&mut Member> {
        self.members
            .iter_mut()
            .find(|member| member.member_id == id)
    }

    /// The member with the given nickname, if any (nicknames are unique).
    pub fn by_nickname(&self, nickname: &str) -> Option<&Member> {
        self.members
            .iter()
            .find(|member| member.nickname == nickname)
    }

    /// The member attached to the given connection, if any.
    pub fn by_connection(&self, connection: ConnectionId) -> Option<&Member> {
        self.members
            .iter()
            .find(|member| member.connection == connection)
    }

    /// Whether the nickname is already used by an active member.
    pub fn nickname_taken(&self, nickname: &str) -> bool {
        self.members
            .iter()
            .any(|member| member.nickname == nickname)
    }

    /// Iterates over the active members.
    pub fn iter(&self) -> impl Iterator<Item = &Member> {
        self.members.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> MemberTable {
        MemberTable::new(&crate::limits::Limits::default())
    }

    #[test]
    fn host_is_member_zero() {
        let mut table = table();
        let host = table.add_host(ConnectionId::new(0), "host".to_owned(), [0; 32], [0; 32]);
        assert_eq!(host.member_id, MemberId::new(0));
        assert!(host.is_host);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn ids_are_unique_and_monotonic() {
        let mut table = table();
        let a = table
            .add(ConnectionId::new(1), "a".to_owned(), [0; 32], [0; 32], 1)
            .unwrap();
        let b = table
            .add(ConnectionId::new(2), "b".to_owned(), [1; 32], [1; 32], 1)
            .unwrap();
        assert_eq!(a.member_id, MemberId::new(1));
        assert_eq!(b.member_id, MemberId::new(2));
        assert!(a.member_id < b.member_id);
    }

    #[test]
    fn nicknames_must_be_unique() {
        let mut table = table();
        table
            .add(
                ConnectionId::new(1),
                "deniz".to_owned(),
                [0; 32],
                [0; 32],
                1,
            )
            .unwrap();
        assert_eq!(
            table.add(
                ConnectionId::new(2),
                "deniz".to_owned(),
                [0; 32],
                [0; 32],
                1
            ),
            Err(MemberError::NicknameTaken {
                nickname: "deniz".to_owned()
            })
        );
    }

    #[test]
    fn capacity_is_enforced() {
        let limits = crate::limits::Limits::with_max_active_members(2);
        let mut table = MemberTable::new(&limits);
        table.add_host(ConnectionId::new(0), "host".to_owned(), [0; 32], [0; 32]);
        table
            .add(ConnectionId::new(1), "a".to_owned(), [1; 32], [1; 32], 1)
            .unwrap();
        assert!(table.is_full());
        assert_eq!(
            table.add(ConnectionId::new(2), "b".to_owned(), [0; 32], [0; 32], 1),
            Err(MemberError::Full { max: 2 })
        );
    }

    #[test]
    fn lookup_by_id_nickname_and_connection() {
        let mut table = table();
        table.add_host(ConnectionId::new(0), "host".to_owned(), [0; 32], [0; 32]);
        let member = table
            .add(
                ConnectionId::new(5),
                "deniz".to_owned(),
                [1; 32],
                [1; 32],
                2,
            )
            .unwrap();
        assert_eq!(table.by_id(member.member_id), Some(&member));
        assert_eq!(table.by_nickname("deniz"), Some(&member));
        assert_eq!(table.by_connection(ConnectionId::new(5)), Some(&member));
        assert!(table.by_id(MemberId::new(99)).is_none());
        assert!(table.by_nickname("nobody").is_none());
    }

    #[test]
    fn remove_returns_the_member_once() {
        let mut table = table();
        let member = table
            .add(ConnectionId::new(1), "a".to_owned(), [0; 32], [0; 32], 1)
            .unwrap();
        let member_id = member.member_id;
        assert_eq!(table.remove(member_id), Some(member));
        assert_eq!(table.remove(member_id), None);
        assert!(table.is_empty());
    }

    #[test]
    fn default_color_is_assigned() {
        let mut table = table();
        let member = table
            .add(ConnectionId::new(1), "a".to_owned(), [0; 32], [0; 32], 1)
            .unwrap();
        assert_eq!(member.color, ColorChoice::default());
    }
}
