//! Per-sender replay tracking (section 17).
//!
//! Each sender maintains a monotonically increasing sequence per epoch;
//! receivers accept a message only when its sequence is strictly greater
//! than the last accepted value for that sender and epoch. Replay
//! protection is enforced at the application layer, never delegated to TCP.

use std::collections::HashMap;

use crate::event::MemberId;

/// Tracks the last accepted sequence per sender and epoch.
#[derive(Debug, Default, Clone)]
pub struct ReplayTracker {
    last: HashMap<(MemberId, u64), u64>,
}

impl ReplayTracker {
    /// Creates an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts a message if its sequence is new for the sender and epoch.
    ///
    /// Returns `false` for a replayed or out-of-order sequence.
    pub fn accept(&mut self, sender: MemberId, epoch: u64, sequence: u64) -> bool {
        let key = (sender, epoch);
        match self.last.get(&key) {
            Some(&last) if sequence <= last => false,
            _ => {
                self.last.insert(key, sequence);
                true
            }
        }
    }

    /// The last accepted sequence for a sender and epoch, if any.
    pub fn last_accepted(&self, sender: MemberId, epoch: u64) -> Option<u64> {
        self.last.get(&(sender, epoch)).copied()
    }

    /// Drops tracking state for epochs other than `current_epoch`.
    ///
    /// Called when an epoch activates so the table does not grow without
    /// bound over a long room lifetime.
    pub fn retain_epoch(&mut self, current_epoch: u64) {
        self.last.retain(|(_, epoch), _| *epoch == current_epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_strictly_increasing_sequences() {
        let mut tracker = ReplayTracker::new();
        let sender = MemberId::new(1);
        assert!(tracker.accept(sender, 2, 1));
        assert!(tracker.accept(sender, 2, 2));
        assert!(tracker.accept(sender, 2, 3));
        assert_eq!(tracker.last_accepted(sender, 2), Some(3));
    }

    #[test]
    fn rejects_replays_and_out_of_order_sequences() {
        let mut tracker = ReplayTracker::new();
        let sender = MemberId::new(1);
        assert!(tracker.accept(sender, 2, 5));
        assert!(!tracker.accept(sender, 2, 5), "exact replay");
        assert!(!tracker.accept(sender, 2, 4), "out of order");
        assert!(!tracker.accept(sender, 2, 1), "old replay");
        assert!(tracker.accept(sender, 2, 6));
    }

    #[test]
    fn tracks_senders_and_epochs_independently() {
        let mut tracker = ReplayTracker::new();
        assert!(tracker.accept(MemberId::new(1), 2, 1));
        assert!(tracker.accept(MemberId::new(2), 2, 1));
        assert!(tracker.accept(MemberId::new(1), 3, 1));
        assert!(
            !tracker.accept(MemberId::new(1), 2, 1),
            "same sender, older epoch"
        );
    }

    #[test]
    fn retain_epoch_prunes_old_epochs() {
        let mut tracker = ReplayTracker::new();
        tracker.accept(MemberId::new(1), 1, 3);
        tracker.accept(MemberId::new(1), 2, 1);
        tracker.retain_epoch(2);
        assert!(tracker.last_accepted(MemberId::new(1), 1).is_none());
        assert_eq!(tracker.last_accepted(MemberId::new(1), 2), Some(1));
    }
}
