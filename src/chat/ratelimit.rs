//! Token-bucket chat rate limiting (section 29).
//!
//! Active members are rate-limited with a token-bucket policy: a burst of
//! messages followed by a sustained per-second rate. Initial violations
//! reject the message and notify the user; persistent abuse terminates the
//! connection (decided by the caller from the violation count).

use std::time::Duration;

/// Defaults from `RateLimit` (burst 5, 1 per second).
#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    tokens: f64,
    refill_per_second: f64,
    last_refill: Duration,
    consecutive_violations: u32,
}

impl RateLimiter {
    /// Creates a limiter with the given burst capacity and per-second rate.
    pub fn new(burst: u32, sustained_per_second: u32) -> Self {
        let capacity = f64::from(burst);
        Self {
            capacity,
            tokens: capacity,
            refill_per_second: f64::from(sustained_per_second),
            last_refill: Duration::ZERO,
            consecutive_violations: 0,
        }
    }

    /// Attempts to allow one message at time `now` (monotonic).
    pub fn allow(&mut self, now: Duration) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.consecutive_violations = 0;
            true
        } else {
            self.consecutive_violations += 1;
            false
        }
    }

    /// The number of consecutive rejected messages since the last success.
    pub const fn consecutive_violations(&self) -> u32 {
        self.consecutive_violations
    }

    /// Whether the caller should terminate the connection.
    pub const fn is_abusive(&self, termination_threshold: u32) -> bool {
        self.consecutive_violations >= termination_threshold
    }

    fn refill(&mut self, now: Duration) {
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        self.last_refill = now;
        let added = elapsed.as_secs_f64() * self.refill_per_second;
        self.tokens = (self.tokens + added).min(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_the_full_burst_then_denies() {
        let mut limiter = RateLimiter::new(5, 1);
        for _ in 0..5 {
            assert!(limiter.allow(Duration::ZERO));
        }
        assert!(!limiter.allow(Duration::ZERO));
        assert_eq!(limiter.consecutive_violations(), 1);
    }

    #[test]
    fn refills_at_the_sustained_rate() {
        let mut limiter = RateLimiter::new(1, 1);
        assert!(limiter.allow(Duration::ZERO));
        assert!(!limiter.allow(Duration::ZERO));
        // One second later one token is available again.
        assert!(limiter.allow(Duration::from_secs(1)));
        assert!(!limiter.allow(Duration::from_secs(1)));
    }

    #[test]
    fn refills_accumulate_up_to_capacity() {
        let mut limiter = RateLimiter::new(5, 1);
        limiter.allow(Duration::ZERO);
        // After 10 seconds the bucket is full again.
        assert!(limiter.allow(Duration::from_secs(10)));
        for _ in 0..4 {
            assert!(limiter.allow(Duration::from_secs(10)));
        }
        assert!(!limiter.allow(Duration::from_secs(10)));
    }

    #[test]
    fn violations_reset_on_success() {
        let mut limiter = RateLimiter::new(1, 1);
        limiter.allow(Duration::ZERO);
        assert!(!limiter.allow(Duration::ZERO));
        assert!(!limiter.allow(Duration::ZERO));
        assert_eq!(limiter.consecutive_violations(), 2);
        assert!(limiter.allow(Duration::from_secs(2)));
        assert_eq!(limiter.consecutive_violations(), 0);
    }

    #[test]
    fn abuse_threshold_is_detected() {
        let mut limiter = RateLimiter::new(1, 1);
        limiter.allow(Duration::ZERO);
        for _ in 0..9 {
            assert!(!limiter.allow(Duration::ZERO));
        }
        assert_eq!(limiter.consecutive_violations(), 9);
        assert!(!limiter.is_abusive(10));
        assert!(!limiter.allow(Duration::ZERO));
        assert!(limiter.is_abusive(10));
    }
}
