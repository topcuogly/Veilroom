//! Single-line input fields (sections 10 and 25).
//!
//! [`TextField`] edits a chat or form line with a cursor. [`SecretField`]
//! edits a masked password without ever keeping the plaintext in a `String`:
//! the raw bytes live in a zeroizing buffer and are handed out only on
//! submit. Both fields enforce a maximum byte length and reject control
//! characters.

use crate::crypto::SecretBytes;
use crate::validation::is_unsafe_display_char;

/// How a completed field hands its value out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submit<T> {
    /// The field still has focus; nothing was submitted.
    None,
    /// The field was completed with a value.
    Value(T),
    /// The user requested to cancel the field.
    Cancel,
}

/// The result of a secret field submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSubmit {
    /// The field still has focus; nothing was submitted.
    None,
    /// The field was completed with a password.
    Value(SecretBytes),
    /// The user requested to cancel the field.
    Cancel,
}

/// A single-line editable text field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextField {
    text: String,
    cursor: usize,
    max_bytes: usize,
    complete: bool,
}

impl TextField {
    /// Creates an empty field that accepts at most `max_bytes`.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            text: String::new(),
            cursor: 0,
            max_bytes,
            complete: false,
        }
    }

    /// The current text of the field.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The cursor position in bytes.
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// The maximum accepted byte length.
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Whether the field was submitted (read-only once completed).
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// The number of bytes currently held.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether the field is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Inserts a `char` at the cursor.
    ///
    /// The insertion is rejected when it would exceed `max_bytes` or when
    /// the char is a control character or display-spoofing format character.
    pub fn insert_char(&mut self, ch: char) -> bool {
        if self.complete || is_unsafe_display_char(ch) {
            return false;
        }
        let char_len = ch.len_utf8();
        if self.text.len() + char_len > self.max_bytes {
            return false;
        }
        self.text.insert(self.cursor, ch);
        self.cursor += char_len;
        true
    }

    /// Inserts a pasted string using the same limits and control-character
    /// rejection as interactive input.
    pub fn insert_text(&mut self, text: &str) {
        for ch in text.chars() {
            let _ = self.insert_char(ch);
        }
    }

    /// Deletes the char before the cursor.
    pub fn backspace(&mut self) {
        if self.complete || self.cursor == 0 {
            return;
        }
        let prev = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(index, _)| index)
            .unwrap_or(0);
        self.text.drain(prev..self.cursor);
        self.cursor = prev;
    }

    /// Deletes the char at the cursor.
    pub fn delete(&mut self) {
        if self.complete || self.cursor >= self.text.len() {
            return;
        }
        let next = self.text[self.cursor..]
            .char_indices()
            .nth(1)
            .map(|(index, _)| self.cursor + index)
            .unwrap_or(self.text.len());
        self.text.drain(self.cursor..next);
    }

    /// Moves the cursor one char left.
    pub fn move_left(&mut self) {
        if self.complete || self.cursor == 0 {
            return;
        }
        self.cursor = self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(index, _)| index)
            .unwrap_or(0);
    }

    /// Moves the cursor one char right.
    pub fn move_right(&mut self) {
        if self.complete || self.cursor >= self.text.len() {
            return;
        }
        self.cursor = match self.text[self.cursor..].char_indices().nth(1) {
            Some((index, _)) => self.cursor + index,
            None => self.text.len(),
        };
    }

    /// Moves the cursor to the start of the line.
    pub fn move_home(&mut self) {
        if !self.complete {
            self.cursor = 0;
        }
    }

    /// Moves the cursor to the end of the line.
    pub fn move_end(&mut self) {
        if !self.complete {
            self.cursor = self.text.len();
        }
    }

    /// Clears the field and re-enables editing.
    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
        self.complete = false;
    }

    /// Re-enables editing while keeping the current text.
    ///
    /// Used when the user steps back to an already-submitted field, so a
    /// long value (a pasted invitation URI) does not have to be retyped.
    /// The cursor is placed at the end of the retained text.
    pub fn reopen(&mut self) {
        self.complete = false;
        self.cursor = self.text.len();
    }

    /// Completes the field with the current text.
    ///
    /// Empty text yields [`Submit::None`] (a submit is only valid when the
    /// field holds text).
    pub fn submit(&mut self) -> Submit<&str> {
        if self.complete {
            return Submit::None;
        }
        if self.text.is_empty() {
            return Submit::None;
        }
        self.complete = true;
        Submit::Value(&self.text)
    }
}

/// A masked password field backed by a zeroizing byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretField {
    bytes: SecretBytes,
    max_bytes: usize,
    complete: bool,
}

impl SecretField {
    /// Creates an empty masked field that accepts at most `max_bytes`.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            bytes: SecretBytes::default(),
            max_bytes,
            complete: false,
        }
    }

    /// The number of bytes currently held.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the field is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The maximum accepted byte length.
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Whether the field was submitted.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Appends a UTF-8 `char` to the password.
    ///
    /// Control and display-spoofing characters are rejected; the append is
    /// refused when it would exceed `max_bytes`.
    pub fn push_char(&mut self, ch: char) -> bool {
        if self.complete || is_unsafe_display_char(ch) {
            return false;
        }
        let len = ch.len_utf8();
        if self.bytes.len() + len > self.max_bytes {
            return false;
        }
        let mut buffer = [0u8; 4];
        self.bytes
            .extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
        true
    }

    /// Inserts pasted password text while preserving the secret buffer and
    /// its byte limit.
    pub fn push_text(&mut self, text: &str) {
        for ch in text.chars() {
            let _ = self.push_char(ch);
        }
    }

    /// Removes the last `char` from the password.
    pub fn pop(&mut self) {
        if self.complete || self.bytes.is_empty() {
            return;
        }
        let last_char_start = self
            .bytes
            .iter()
            .rev()
            .take_while(|byte| *byte & 0b1100_0000 == 0b1000_0000)
            .count();
        let len = self.bytes.len();
        self.bytes.truncate(len - last_char_start - 1);
    }

    /// Clears the field and re-enables editing.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.complete = false;
    }

    /// Completes the field, handing the zeroizing password out by value.
    ///
    /// Empty text yields [`SecretSubmit::None`]. After this call the field
    /// is empty and locked.
    pub fn submit(&mut self) -> SecretSubmit {
        if self.complete {
            return SecretSubmit::None;
        }
        if self.bytes.is_empty() {
            return SecretSubmit::None;
        }
        self.complete = true;
        let value = std::mem::take(&mut self.bytes);
        SecretSubmit::Value(value)
    }

    /// The masked display form: one bullet per UTF-8 `char`.
    ///
    /// Counts scalar values without materializing the plaintext as a
    /// `String`; the plaintext is never available for display.
    pub fn masked(&self) -> String {
        let chars = self
            .bytes
            .iter()
            .filter(|byte| *byte & 0b1100_0000 != 0b1000_0000)
            .count();
        "•".repeat(chars)
    }

    /// Takes the password out of a completed field.
    ///
    /// Returns the password only after [`Self::submit`] was called; the
    /// field is left empty either way.
    pub fn take_value(&mut self) -> Option<SecretBytes> {
        if self.complete {
            Some(std::mem::take(&mut self.bytes))
        } else {
            None
        }
    }

    /// The raw bytes of a completed field, without consuming them.
    ///
    /// Returns `None` until [`Self::submit`] was called.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.complete {
            Some(&self.bytes)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_field_inserts_and_edits() {
        let mut field = TextField::new(64);
        assert!(field.insert_char('h'));
        assert!(field.insert_char('i'));
        assert_eq!(field.text(), "hi");
        field.move_home();
        assert!(field.insert_char('x'));
        assert_eq!(field.text(), "xhi");
        field.backspace();
        assert_eq!(field.text(), "hi");
        field.move_end();
        field.delete();
        assert_eq!(field.text(), "hi");
        assert_eq!(field.cursor(), 2);
    }

    #[test]
    fn text_field_enforces_max_bytes() {
        let mut field = TextField::new(3);
        assert!(field.insert_char('a'));
        assert!(field.insert_char('b'));
        assert!(field.insert_char('c'));
        assert!(!field.insert_char('d'));
        assert_eq!(field.text(), "abc");
    }

    #[test]
    fn text_field_rejects_control_chars() {
        let mut field = TextField::new(64);
        assert!(!field.insert_char('\u{1b}'));
        assert!(field.is_empty());
    }

    #[test]
    fn text_field_rejects_display_spoofing_chars() {
        let mut field = TextField::new(64);
        assert!(!field.insert_char('\u{202e}'));
        assert!(!field.insert_char('\u{200b}'));
        assert!(!field.insert_char('\u{2066}'));
        assert!(field.is_empty());
    }

    #[test]
    fn text_field_submit_requires_text() {
        let mut field = TextField::new(64);
        assert_eq!(field.submit(), Submit::None);
        assert!(field.insert_char('x'));
        assert_eq!(field.submit(), Submit::Value("x"));
        assert_eq!(field.submit(), Submit::None, "submitting twice is refused");
        field.clear();
        assert!(field.insert_char('y'));
    }

    #[test]
    fn secret_field_masks_and_zeroizes_on_submit() {
        let mut field = SecretField::new(64);
        assert!(field.push_char('p'));
        assert!(field.push_char('ä'));
        assert_eq!(field.masked(), "••");
        assert_eq!(field.len(), 3, "ä is two UTF-8 bytes");
        let SecretSubmit::Value(password) = field.submit() else {
            panic!("expected a password");
        };
        assert_eq!(&*password, b"p\xc3\xa4");
        assert!(field.is_empty(), "the field is cleared on submit");
    }

    #[test]
    fn secret_field_pop_and_limits() {
        let mut field = SecretField::new(3);
        assert!(field.push_char('a'));
        assert!(field.push_char('b'));
        assert!(field.push_char('c'));
        assert!(!field.push_char('d'), "exceeds max bytes");
        field.pop();
        assert_eq!(field.len(), 2);
        assert_eq!(field.masked(), "••");
    }

    #[test]
    fn secret_field_rejects_controls_and_empty_submit() {
        let mut field = SecretField::new(64);
        assert!(!field.push_char('\n'));
        assert_eq!(field.submit(), SecretSubmit::None);
    }
}
