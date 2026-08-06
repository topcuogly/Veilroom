//! Bounded join-request queue (section 13.3).
//!
//! Request ids are monotonically increasing for the current room lifetime.
//! The queue is bounded by `Limits::max_pending_requests`; a nickname is
//! reserved only when a request is accepted.

use crate::event::{ConnectionId, RequestId};
use crate::limits::Limits;

/// A join application as submitted by a verified connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinApplication {
    /// The requested nickname (NFC-normalized).
    pub nickname: String,
    /// The optional introduction message (host-visible only).
    pub introduction: Option<String>,
    /// The participant's ephemeral Ed25519 public key (verified in Stage 6).
    pub ed25519_pubkey: [u8; 32],
    /// The participant's ephemeral X25519 public key.
    pub x25519_pubkey: [u8; 32],
    /// The participant's join-request signature (verified in Stage 6).
    pub signature: [u8; 64],
}

/// A pending join application with its room-assigned identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// The monotonic request id.
    pub id: RequestId,
    /// The connection that submitted the application.
    pub connection: ConnectionId,
    /// The application itself.
    pub application: JoinApplication,
}

/// Errors produced by the request queue.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QueueError {
    /// The queue is full.
    #[error("the join-request queue is full (maximum {max})")]
    Full {
        /// The configured capacity.
        max: usize,
    },
    /// No pending request carries the given id.
    #[error("no pending join request with id {id}")]
    Unknown {
        /// The unknown request id.
        id: RequestId,
    },
}

/// The room's pending join-request queue.
#[derive(Debug, Clone)]
pub struct JoinRequestQueue {
    limit: usize,
    next_id: u64,
    requests: Vec<JoinRequest>,
}

impl JoinRequestQueue {
    /// Creates an empty queue bound by `limits`.
    pub fn new(limits: &Limits) -> Self {
        Self {
            limit: limits.max_pending_requests(),
            next_id: 0,
            requests: Vec::new(),
        }
    }

    /// Creates an empty queue with an explicit capacity.
    pub fn with_capacity(limit: usize) -> Self {
        Self {
            limit,
            next_id: 0,
            requests: Vec::new(),
        }
    }

    /// The configured capacity.
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// The number of pending requests.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Submits a join application and returns its request id.
    pub fn push(
        &mut self,
        connection: ConnectionId,
        application: JoinApplication,
    ) -> Result<RequestId, QueueError> {
        if self.requests.len() >= self.limit {
            return Err(QueueError::Full { max: self.limit });
        }
        let id = self.allocate_id();
        self.requests.push(JoinRequest {
            id,
            connection,
            application,
        });
        Ok(id)
    }

    /// Allocates an id from the room-wide request sequence.
    ///
    /// The room actor also uses this for non-admission requests so `/accept`
    /// and `/reject` share one unambiguous id namespace.
    pub(crate) fn allocate_id(&mut self) -> RequestId {
        let id = RequestId::new(self.next_id);
        self.next_id += 1;
        id
    }

    /// Removes and returns the pending request with the given id.
    pub fn take(&mut self, id: RequestId) -> Result<JoinRequest, QueueError> {
        let index = self
            .requests
            .iter()
            .position(|request| request.id == id)
            .ok_or(QueueError::Unknown { id })?;
        Ok(self.requests.remove(index))
    }

    /// Removes and returns every pending request (used by `/reqoff`).
    pub fn drain(&mut self) -> Vec<JoinRequest> {
        std::mem::take(&mut self.requests)
    }

    /// The pending requests in submission order.
    pub fn pending(&self) -> &[JoinRequest] {
        &self.requests
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application(nickname: &str) -> JoinApplication {
        JoinApplication {
            nickname: nickname.to_owned(),
            introduction: None,
            ed25519_pubkey: [0u8; 32],
            x25519_pubkey: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    #[test]
    fn ids_are_monotonic_and_unique() {
        let mut queue = JoinRequestQueue::with_capacity(8);
        let a = queue.push(ConnectionId::new(1), application("a")).unwrap();
        let b = queue.push(ConnectionId::new(2), application("b")).unwrap();
        let c = queue.push(ConnectionId::new(3), application("c")).unwrap();
        assert_eq!(a, RequestId::new(0));
        assert_eq!(b, RequestId::new(1));
        assert_eq!(c, RequestId::new(2));
        assert!(a < b && b < c);
    }

    #[test]
    fn capacity_is_enforced() {
        let mut queue = JoinRequestQueue::with_capacity(2);
        queue.push(ConnectionId::new(1), application("a")).unwrap();
        queue.push(ConnectionId::new(2), application("b")).unwrap();
        assert_eq!(
            queue.push(ConnectionId::new(3), application("c")),
            Err(QueueError::Full { max: 2 })
        );
    }

    #[test]
    fn take_removes_the_request() {
        let mut queue = JoinRequestQueue::with_capacity(4);
        let id = queue
            .push(ConnectionId::new(7), application("deniz"))
            .unwrap();
        let taken = queue.take(id).unwrap();
        assert_eq!(taken.application.nickname, "deniz");
        assert_eq!(taken.connection, ConnectionId::new(7));
        assert!(queue.is_empty());
        assert_eq!(queue.take(id), Err(QueueError::Unknown { id }));
    }

    #[test]
    fn take_of_unknown_id_is_an_error() {
        let mut queue = JoinRequestQueue::with_capacity(4);
        assert_eq!(
            queue.take(RequestId::new(99)),
            Err(QueueError::Unknown {
                id: RequestId::new(99)
            })
        );
    }

    #[test]
    fn drain_rejects_every_pending_request() {
        let mut queue = JoinRequestQueue::with_capacity(4);
        queue.push(ConnectionId::new(1), application("a")).unwrap();
        queue.push(ConnectionId::new(2), application("b")).unwrap();
        let drained = queue.drain();
        assert_eq!(drained.len(), 2);
        assert!(queue.is_empty());
    }

    #[test]
    fn pending_preserves_submission_order() {
        let mut queue = JoinRequestQueue::with_capacity(4);
        queue.push(ConnectionId::new(1), application("a")).unwrap();
        queue.push(ConnectionId::new(2), application("b")).unwrap();
        let names: Vec<&str> = queue
            .pending()
            .iter()
            .map(|r| r.application.nickname.as_str())
            .collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[test]
    fn default_queue_matches_the_limits() {
        let queue = JoinRequestQueue::new(&Limits::default());
        assert_eq!(queue.limit(), Limits::default().max_pending_requests());
    }
}
