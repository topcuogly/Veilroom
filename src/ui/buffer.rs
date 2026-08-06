//! The strictly bounded render buffer (sections 24 and 25).
//!
//! The room view keeps only the most recent lines needed to redraw the
//! visible screen. The buffer never grows beyond its capacity: pushing
//! beyond the limit evicts the oldest line. It is a render aid, not a
//! history feature.

use std::collections::VecDeque;

use crate::command::ColorChoice;

/// A GMT time-of-day attached to one in-memory display line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GmtTimestamp {
    seconds_since_midnight: u32,
}

impl GmtTimestamp {
    /// Captures the current GMT time without retaining a calendar date.
    pub fn now() -> Self {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % 86_400;
        Self {
            seconds_since_midnight: seconds as u32,
        }
    }

    /// Creates a timestamp from validated GMT hour, minute, and second fields.
    pub const fn from_hms(hour: u8, minute: u8, second: u8) -> Option<Self> {
        if hour >= 24 || minute >= 60 || second >= 60 {
            return None;
        }
        Some(Self {
            seconds_since_midnight: hour as u32 * 3_600 + minute as u32 * 60 + second as u32,
        })
    }
}

impl std::fmt::Display for GmtTimestamp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hour = self.seconds_since_midnight / 3_600;
        let minute = (self.seconds_since_midnight % 3_600) / 60;
        let second = self.seconds_since_midnight % 60;
        write!(formatter, "{hour:02}:{minute:02}:{second:02}")
    }
}

/// The default maximum number of rendered lines retained.
pub const DEFAULT_RENDER_BUFFER_CAPACITY: usize = 256;

/// The visual style of one rendered line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStyle {
    /// A chat message from a member.
    Chat,
    /// A system notice (member joined, policy changed, and so on).
    Notice,
    /// A highlighted `!` notification (join request, security warning, etc.).
    Alert,
    /// A local palette entry drawn in the represented color.
    Palette(ColorChoice),
    /// An error message.
    Error,
    /// Dimmed auxiliary text (invitation URI, hints).
    Muted,
}

/// One line of the bounded render buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageLine {
    /// The sanitized display text.
    pub text: String,
    /// The visual style of the line.
    pub style: LineStyle,
    /// The sender nickname and its display color for chat lines.
    ///
    /// Captured when the line is pushed, so a later `/color` change never
    /// re-colors messages that were already displayed.
    pub nickname: Option<NicknameSpan>,
    /// The GMT time at which the line entered the local display buffer.
    pub timestamp: GmtTimestamp,
    /// The monotonic instant paired with `timestamp` for reliable expiry.
    ///
    /// The displayed GMT time is intentionally only a time of day; this
    /// instant preserves the full age across midnight and wall-clock changes.
    pub(crate) created_at: std::time::Instant,
    /// The independently scheduled expiry instant for this line.
    ///
    /// `None` means the line does not expire automatically.
    pub(crate) expires_at: Option<std::time::Instant>,
}

/// The sanitized sender nickname of a chat line and the color it is drawn in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicknameSpan {
    /// The sanitized nickname text, as it appears at the start of `text`.
    pub text: String,
    /// The display color of the nickname.
    pub color: ColorChoice,
}

/// A bounded, ordered collection of rendered lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderBuffer {
    lines: VecDeque<MessageLine>,
    capacity: usize,
}

impl RenderBuffer {
    /// Creates an empty buffer with [`DEFAULT_RENDER_BUFFER_CAPACITY`].
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_RENDER_BUFFER_CAPACITY)
    }

    /// Creates an empty buffer with an explicit capacity.
    ///
    /// A capacity of zero rejects every line.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            lines: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// The maximum number of lines this buffer can hold.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of lines currently held.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Appends a line, evicting the oldest line when full.
    pub fn push(&mut self, line: MessageLine) {
        if self.capacity == 0 {
            return;
        }
        if self.lines.len() == self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    /// Appends several lines in order.
    pub fn extend(&mut self, lines: impl IntoIterator<Item = MessageLine>) {
        for line in lines {
            self.push(line);
        }
    }

    /// Removes every line.
    pub fn clear(&mut self) {
        self.lines.clear();
    }

    /// Recomputes each retained line's deadline from its original timestamp.
    pub(crate) fn set_expiry(&mut self, max_age: Option<std::time::Duration>) {
        for line in &mut self.lines {
            line.expires_at = max_age.and_then(|age| line.created_at.checked_add(age));
        }
    }

    /// Removes lines whose individual deadline has been reached.
    ///
    /// Returns the number of expired lines. Relative order of the retained
    /// lines is preserved.
    pub(crate) fn expire_due(&mut self, now: std::time::Instant) -> usize {
        let previous_len = self.lines.len();
        self.lines
            .retain(|line| line.expires_at.is_none_or(|deadline| deadline > now));
        previous_len - self.lines.len()
    }

    /// Returns the nearest independently scheduled line deadline.
    pub(crate) fn next_expiry(&self) -> Option<std::time::Instant> {
        self.lines.iter().filter_map(|line| line.expires_at).min()
    }

    /// Iterates over the lines from oldest to newest.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &MessageLine> {
        self.lines.iter()
    }
}

impl Default for RenderBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<MessageLine> for RenderBuffer {
    fn from_iter<T: IntoIterator<Item = MessageLine>>(iter: T) -> Self {
        let mut buffer = Self::new();
        buffer.extend(iter);
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> MessageLine {
        MessageLine {
            text: text.to_owned(),
            style: LineStyle::Chat,
            nickname: None,
            timestamp: GmtTimestamp::from_hms(0, 0, 0).unwrap(),
            created_at: std::time::Instant::now(),
            expires_at: None,
        }
    }

    #[test]
    fn gmt_timestamp_formats_as_hours_minutes_and_seconds() {
        assert_eq!(
            GmtTimestamp::from_hms(7, 8, 9).unwrap().to_string(),
            "07:08:09"
        );
        assert!(GmtTimestamp::from_hms(24, 0, 0).is_none());
        assert!(GmtTimestamp::from_hms(0, 60, 0).is_none());
        assert!(GmtTimestamp::from_hms(0, 0, 60).is_none());
    }

    #[test]
    fn pushing_beyond_capacity_evicts_the_oldest_line() {
        let mut buffer = RenderBuffer::with_capacity(3);
        buffer.push(line("a"));
        buffer.push(line("b"));
        buffer.push(line("c"));
        assert_eq!(buffer.len(), 3);
        buffer.push(line("d"));
        assert_eq!(buffer.len(), 3);
        let texts: Vec<&str> = buffer.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["b", "c", "d"]);
    }

    #[test]
    fn capacity_is_strictly_bounded() {
        let mut buffer = RenderBuffer::with_capacity(2);
        for index in 0..10_000 {
            buffer.push(line(&format!("line {index}")));
        }
        assert_eq!(buffer.len(), 2);
    }

    #[test]
    fn zero_capacity_rejects_every_line() {
        let mut buffer = RenderBuffer::with_capacity(0);
        buffer.push(line("x"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn iter_is_oldest_first() {
        let mut buffer = RenderBuffer::with_capacity(4);
        buffer.push(line("1"));
        buffer.push(line("2"));
        assert_eq!(
            buffer.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            ["1", "2"]
        );
    }

    #[test]
    fn expiry_uses_each_lines_own_deadline_and_preserves_newer_lines() {
        let now = std::time::Instant::now();
        let mut old = line("old");
        old.created_at = now - std::time::Duration::from_secs(5);
        let mut boundary = line("boundary");
        boundary.created_at = now - std::time::Duration::from_secs(3);
        let mut fresh = line("fresh");
        fresh.created_at = now - std::time::Duration::from_secs(1);

        let mut buffer = RenderBuffer::with_capacity(4);
        buffer.extend([old, boundary, fresh]);
        buffer.set_expiry(Some(std::time::Duration::from_secs(3)));

        assert_eq!(buffer.expire_due(now), 2);
        assert_eq!(
            buffer
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            ["fresh"]
        );
    }

    #[test]
    fn clear_empties_the_buffer() {
        let mut buffer = RenderBuffer::with_capacity(4);
        buffer.push(line("1"));
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn extend_appends_in_order() {
        let mut buffer = RenderBuffer::with_capacity(4);
        buffer.extend([line("a"), line("b"), line("c")]);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.iter().next().unwrap().text, "a");
        assert_eq!(buffer.iter().last().unwrap().text, "c");
    }
}
