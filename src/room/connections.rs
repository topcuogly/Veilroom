//! Per-connection registry of the room.
//!
//! Tracks every known connection and its room-level role: pre-admission,
//! pending request, or active member. The registry is the anchor for the
//! accept/disconnect and kick/disconnect races (section 41.2).

use std::collections::HashMap;

use crate::event::{ConnectionId, MemberId, RequestId};

/// The room-level role of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// Connected but not yet through admission.
    Admission,
    /// Waiting for the host's decision on a join application.
    Pending {
        /// The pending request id.
        request_id: RequestId,
    },
    /// An admitted member.
    Member {
        /// The member id.
        member_id: MemberId,
    },
}

/// One known connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEntry {
    /// The connection id.
    pub id: ConnectionId,
    /// Whether the password proof was verified.
    pub password_verified: bool,
    /// The room-level role of the connection.
    pub role: ConnectionRole,
}

/// The room's per-connection registry.
#[derive(Debug, Clone, Default)]
pub struct Connections {
    entries: HashMap<ConnectionId, ConnectionEntry>,
}

impl Connections {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a new connection in the admission role.
    ///
    /// Re-registering an existing connection is a no-op.
    pub fn register(&mut self, id: ConnectionId) {
        self.entries.entry(id).or_insert(ConnectionEntry {
            id,
            password_verified: false,
            role: ConnectionRole::Admission,
        });
    }

    /// Marks a connection's password as verified.
    pub fn mark_password_verified(&mut self, id: ConnectionId) -> Option<()> {
        self.entries.get_mut(&id)?.password_verified = true;
        Some(())
    }

    /// Attaches a pending request to a connection.
    pub fn attach_request(&mut self, id: ConnectionId, request_id: RequestId) -> Option<()> {
        let entry = self.entries.get_mut(&id)?;
        entry.role = ConnectionRole::Pending { request_id };
        Some(())
    }

    /// Promotes a connection to an active member.
    pub fn promote(&mut self, id: ConnectionId, member_id: MemberId) -> Option<()> {
        let entry = self.entries.get_mut(&id)?;
        entry.role = ConnectionRole::Member { member_id };
        Some(())
    }

    /// The entry of a connection, if known.
    pub fn get(&self, id: ConnectionId) -> Option<&ConnectionEntry> {
        self.entries.get(&id)
    }

    /// The pending request attached to a connection, if any.
    pub fn request_id(&self, id: ConnectionId) -> Option<RequestId> {
        match self.get(id)?.role {
            ConnectionRole::Pending { request_id } => Some(request_id),
            _ => None,
        }
    }

    /// The member id of a connection, if it is an active member.
    pub fn member_id(&self, id: ConnectionId) -> Option<MemberId> {
        match self.get(id)?.role {
            ConnectionRole::Member { member_id } => Some(member_id),
            _ => None,
        }
    }

    /// Removes a connection and returns its entry, if known.
    pub fn remove(&mut self, id: ConnectionId) -> Option<ConnectionEntry> {
        self.entries.remove(&id)
    }

    /// Whether a connection is known.
    pub fn contains(&self, id: ConnectionId) -> bool {
        self.entries.contains_key(&id)
    }

    /// The ids of all connections that are not active members.
    pub fn non_member_ids(&self) -> Vec<ConnectionId> {
        self.entries
            .iter()
            .filter(|(_, entry)| !matches!(entry.role, ConnectionRole::Member { .. }))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Every currently tracked connection id.
    pub fn ids(&self) -> Vec<ConnectionId> {
        self.entries.keys().copied().collect()
    }

    /// The number of known connections.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_transitions() {
        let mut connections = Connections::new();
        let id = ConnectionId::new(1);
        connections.register(id);
        assert_eq!(connections.get(id).unwrap().role, ConnectionRole::Admission);
        assert!(!connections.get(id).unwrap().password_verified);

        connections.mark_password_verified(id).unwrap();
        assert!(connections.get(id).unwrap().password_verified);

        connections.attach_request(id, RequestId::new(3)).unwrap();
        assert_eq!(connections.request_id(id), Some(RequestId::new(3)));

        connections.promote(id, MemberId::new(7)).unwrap();
        assert_eq!(connections.member_id(id), Some(MemberId::new(7)));
        assert_eq!(connections.request_id(id), None);

        assert_eq!(connections.remove(id).unwrap().id, id);
        assert!(!connections.contains(id));
    }

    #[test]
    fn non_member_ids_exclude_members() {
        let mut connections = Connections::new();
        connections.register(ConnectionId::new(1));
        connections.register(ConnectionId::new(2));
        connections
            .promote(ConnectionId::new(2), MemberId::new(5))
            .unwrap();
        let non_members = connections.non_member_ids();
        assert_eq!(non_members, vec![ConnectionId::new(1)]);
    }

    #[test]
    fn registering_twice_is_a_no_op() {
        let mut connections = Connections::new();
        connections.register(ConnectionId::new(1));
        connections
            .promote(ConnectionId::new(1), MemberId::new(2))
            .unwrap();
        connections.register(ConnectionId::new(1));
        assert_eq!(
            connections.member_id(ConnectionId::new(1)),
            Some(MemberId::new(2))
        );
    }
}
