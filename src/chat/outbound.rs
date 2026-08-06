//! Bounded per-connection outgoing queue (sections 12 and 29).
//!
//! A slow client must not block the room, and messages are never silently
//! dropped: when the queue is full, the connection is terminated instead
//! (the connection layer reacts to [`QueueFull`]).

use std::collections::VecDeque;

/// The queue is full and the connection must be terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

/// A bounded FIFO queue for outbound messages.
#[derive(Debug, Clone)]
pub struct OutboundQueue<T> {
    capacity: usize,
    items: VecDeque<T>,
}

impl<T> OutboundQueue<T> {
    /// Creates an empty queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: VecDeque::with_capacity(capacity),
        }
    }

    /// The configured capacity.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of queued items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether the queue is full.
    pub fn is_full(&self) -> bool {
        self.items.len() >= self.capacity
    }

    /// Enqueues an item; fails without enqueueing when the queue is full.
    pub fn push(&mut self, item: T) -> Result<(), QueueFull> {
        if self.is_full() {
            return Err(QueueFull);
        }
        self.items.push_back(item);
        Ok(())
    }

    /// Dequeues the oldest item, if any.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_capacity_and_order() {
        let mut queue: OutboundQueue<u32> = OutboundQueue::new(2);
        assert_eq!(queue.push(1), Ok(()));
        assert_eq!(queue.push(2), Ok(()));
        assert!(queue.is_full());
        assert_eq!(queue.push(3), Err(QueueFull));
        assert_eq!(queue.len(), 2, "a rejected item must not be enqueued");
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
        assert!(queue.is_empty());
    }

    #[test]
    fn can_push_after_draining() {
        let mut queue: OutboundQueue<u32> = OutboundQueue::new(1);
        queue.push(1).unwrap();
        queue.pop();
        assert_eq!(queue.push(2), Ok(()));
    }
}
