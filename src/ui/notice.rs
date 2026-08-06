//! Notices shown to the user (sections 31 and 33).
//!
//! Join-request notifications, membership changes, policy changes, and
//! errors are presented as a bounded notice list. The buffer is strictly
//! bounded: old notices are evicted when it fills, matching the bounded
//! render-buffer rule.

/// The maximum number of retained notices.
pub const DEFAULT_NOTICE_CAPACITY: usize = 32;

/// One user-visible notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The sanitized notice text.
    pub text: String,
    /// The GMT time at which the notice entered the local display buffer.
    pub timestamp: crate::ui::buffer::GmtTimestamp,
}

/// A bounded, ordered list of notices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeBuffer {
    notices: std::collections::VecDeque<Notice>,
    capacity: usize,
}

impl NoticeBuffer {
    /// Creates an empty buffer with [`DEFAULT_NOTICE_CAPACITY`].
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_NOTICE_CAPACITY)
    }

    /// Creates an empty buffer with an explicit capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            notices: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// The maximum number of notices this buffer can hold.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of notices currently held.
    pub fn len(&self) -> usize {
        self.notices.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.notices.is_empty()
    }

    /// Appends a notice, evicting the oldest when full.
    pub fn push(&mut self, text: impl Into<String>) {
        if self.capacity == 0 {
            return;
        }
        if self.notices.len() == self.capacity {
            self.notices.pop_front();
        }
        self.notices.push_back(Notice {
            text: text.into(),
            timestamp: crate::ui::buffer::GmtTimestamp::now(),
        });
    }

    /// Iterates over the notices from oldest to newest.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Notice> {
        self.notices.iter()
    }
}

impl Default for NoticeBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_are_bounded_and_ordered() {
        let mut buffer = NoticeBuffer::with_capacity(3);
        buffer.push("a");
        buffer.push("b");
        buffer.push("c");
        buffer.push("d");
        let texts: Vec<&str> = buffer.iter().map(|n| n.text.as_str()).collect();
        assert_eq!(texts, ["b", "c", "d"]);
    }

    #[test]
    fn zero_capacity_accepts_nothing() {
        let mut buffer = NoticeBuffer::with_capacity(0);
        buffer.push("x");
        assert!(buffer.is_empty());
    }
}
