//! Room-lifetime defense against password guessing (section 10).
//!
//! The password challenge-response is deliberately asymmetric: the host
//! derives its Argon2id verifier once when the room is created and every
//! later check is a cheap HMAC comparison, so the KDF cost is paid entirely
//! by the party computing a proof. A failed proof also closes the
//! connection, which caps a single connection at one attempt — but nothing
//! stops a peer that holds the invitation token from reconnecting, so the
//! per-connection cap alone is not an anti-guessing measure.
//!
//! [`PasswordGuard`] adds the missing room-level brake: after
//! [`PASSWORD_FAILURE_THRESHOLD`] failed proofs the gate refuses new
//! admission flows for a growing back-off window. Connections that are
//! already admitted are never affected; only fresh admission flows are held
//! off, and V1 has no automatic reconnect, so a legitimate member is never
//! locked out of a room it is already in.

use std::time::{Duration, Instant};

/// Failed password proofs tolerated before the first lockout starts.
///
/// Chosen so that ordinary typing mistakes (including several people
/// mistyping a shared room password) never trip it, while an automated
/// guesser hits it almost immediately.
pub const PASSWORD_FAILURE_THRESHOLD: u32 = 5;

/// Duration of the first lockout window.
pub const PASSWORD_LOCKOUT_BASE: Duration = Duration::from_secs(30);

/// Upper bound of the exponential lockout back-off.
pub const PASSWORD_LOCKOUT_MAX: Duration = Duration::from_secs(15 * 60);

/// Tracks failed password proofs for the lifetime of one room.
#[derive(Debug, Clone)]
pub struct PasswordGuard {
    failures: u32,
    lockouts: u32,
    locked_until: Option<Instant>,
}

impl PasswordGuard {
    /// Creates a guard with no recorded failures.
    pub const fn new() -> Self {
        Self {
            failures: 0,
            lockouts: 0,
            locked_until: None,
        }
    }

    /// The number of failed password proofs seen in this room.
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    /// The number of lockout windows that have been started.
    pub const fn lockouts(&self) -> u32 {
        self.lockouts
    }

    /// Records one failed password proof.
    ///
    /// Returns the length of the lockout window when this failure starts a
    /// new one, and `None` while the room is still below the threshold.
    pub fn record_failure(&mut self, now: Instant) -> Option<Duration> {
        self.failures += 1;
        if self.failures % PASSWORD_FAILURE_THRESHOLD != 0 {
            return None;
        }
        let window = self.next_window();
        self.lockouts += 1;
        // `checked_add` cannot overflow for the bounded windows above; a
        // saturating fallback keeps the guard total rather than panicking.
        self.locked_until = now.checked_add(window).or(self.locked_until);
        Some(window)
    }

    /// Whether new admission flows must be refused at `now`.
    pub fn is_locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }

    /// The time remaining in the current lockout window, if any.
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.locked_until
            .filter(|until| now < *until)
            .map(|until| until.duration_since(now))
    }

    /// The window length for the lockout that is about to start.
    ///
    /// Doubles per lockout and saturates at [`PASSWORD_LOCKOUT_MAX`].
    fn next_window(&self) -> Duration {
        let shift = self.lockouts.min(u32::BITS - 1);
        PASSWORD_LOCKOUT_BASE
            .checked_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
            .unwrap_or(PASSWORD_LOCKOUT_MAX)
            .min(PASSWORD_LOCKOUT_MAX)
    }
}

impl Default for PasswordGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_below_the_threshold_do_not_lock() {
        let mut guard = PasswordGuard::new();
        let now = Instant::now();
        for _ in 0..PASSWORD_FAILURE_THRESHOLD - 1 {
            assert_eq!(guard.record_failure(now), None);
            assert!(!guard.is_locked(now));
        }
        assert_eq!(guard.failures(), PASSWORD_FAILURE_THRESHOLD - 1);
    }

    #[test]
    fn the_threshold_starts_a_lockout_window() {
        let mut guard = PasswordGuard::new();
        let now = Instant::now();
        for _ in 0..PASSWORD_FAILURE_THRESHOLD - 1 {
            guard.record_failure(now);
        }
        assert_eq!(
            guard.record_failure(now),
            Some(PASSWORD_LOCKOUT_BASE),
            "the threshold failure starts the base window"
        );
        assert!(guard.is_locked(now));
        assert!(guard.is_locked(now + PASSWORD_LOCKOUT_BASE - Duration::from_millis(1)));
        assert!(
            !guard.is_locked(now + PASSWORD_LOCKOUT_BASE),
            "the window ends exactly at its deadline"
        );
    }

    #[test]
    fn windows_double_and_saturate() {
        let mut guard = PasswordGuard::new();
        let now = Instant::now();
        let mut windows = Vec::new();
        for _ in 0..(PASSWORD_FAILURE_THRESHOLD * 8) {
            if let Some(window) = guard.record_failure(now) {
                windows.push(window);
            }
        }
        assert_eq!(
            &windows[..4],
            &[
                PASSWORD_LOCKOUT_BASE,
                PASSWORD_LOCKOUT_BASE * 2,
                PASSWORD_LOCKOUT_BASE * 4,
                PASSWORD_LOCKOUT_BASE * 8,
            ]
        );
        assert!(
            windows.iter().all(|window| *window <= PASSWORD_LOCKOUT_MAX),
            "no window may exceed the cap"
        );
        assert_eq!(
            *windows.last().unwrap(),
            PASSWORD_LOCKOUT_MAX,
            "the back-off saturates instead of growing without bound"
        );
    }

    #[test]
    fn remaining_reports_the_rest_of_the_window() {
        let mut guard = PasswordGuard::new();
        let now = Instant::now();
        for _ in 0..PASSWORD_FAILURE_THRESHOLD {
            guard.record_failure(now);
        }
        assert_eq!(guard.remaining(now), Some(PASSWORD_LOCKOUT_BASE));
        assert_eq!(guard.remaining(now + PASSWORD_LOCKOUT_BASE), None);
    }

    #[test]
    fn a_fresh_guard_is_never_locked() {
        let guard = PasswordGuard::new();
        assert!(!guard.is_locked(Instant::now()));
        assert_eq!(guard.remaining(Instant::now()), None);
        assert_eq!(guard.failures(), 0);
        assert_eq!(guard.lockouts(), 0);
    }
}
