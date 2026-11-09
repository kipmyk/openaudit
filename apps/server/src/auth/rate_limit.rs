//! In-memory thread-safe rate limiter for authentication brute-force protection.

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
struct AttemptRecord {
    count: u32,
    first_attempt_at: i64,
    last_attempt_at: i64,
}

/// Thread-safe rate limiter tracking failed login attempts per key.
#[derive(Debug)]
pub struct LoginRateLimiter {
    max_attempts: u32,
    window_secs: i64,
    attempts: Mutex<HashMap<String, AttemptRecord>>,
}

impl LoginRateLimiter {
    /// Creates a new `LoginRateLimiter`.
    #[must_use]
    pub fn new(max_attempts: u32, window_secs: i64) -> Self {
        Self {
            max_attempts,
            window_secs,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether the given key is currently rate-limited.
    ///
    /// # Errors
    ///
    /// Returns `Err(remaining_lockout_seconds)` if the key has exceeded `max_attempts`.
    pub fn check_allowed(&self, key: &str) -> Result<(), i64> {
        let now = Utc::now().timestamp();
        let mut map = self.attempts.lock().map_err(|_| 0)?;

        if let Some(record) = map.get(key) {
            let elapsed = now - record.first_attempt_at;
            if elapsed < self.window_secs {
                if record.count >= self.max_attempts {
                    let remaining = self.window_secs - elapsed;
                    return Err(remaining.max(1));
                }
            } else {
                // Window expired, record will be reset on next failure
                map.remove(key);
            }
        }

        Ok(())
    }

    /// Records a failed authentication attempt for the key.
    pub fn record_failure(&self, key: &str) {
        let now = Utc::now().timestamp();
        if let Ok(mut map) = self.attempts.lock() {
            let entry = map.entry(key.to_string()).or_insert_with(|| AttemptRecord {
                count: 0,
                first_attempt_at: now,
                last_attempt_at: now,
            });

            if now - entry.first_attempt_at >= self.window_secs {
                // Reset window
                entry.count = 1;
                entry.first_attempt_at = now;
            } else {
                entry.count += 1;
            }
            entry.last_attempt_at = now;
        }
    }

    /// Clears any recorded failures on successful authentication.
    pub fn record_success(&self, key: &str) {
        if let Ok(mut map) = self.attempts.lock() {
            map.remove(key);
        }
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        // Default: 5 failed attempts per 15-minute window (900s)
        Self::new(5, 900)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_blocks_after_threshold() {
        let limiter = LoginRateLimiter::new(3, 60);
        let key = "192.168.1.100";

        assert!(limiter.check_allowed(key).is_ok());

        limiter.record_failure(key);
        assert!(limiter.check_allowed(key).is_ok());

        limiter.record_failure(key);
        assert!(limiter.check_allowed(key).is_ok());

        limiter.record_failure(key);
        // Exceeded 3 attempts
        let res = limiter.check_allowed(key);
        assert!(res.is_err());
        assert!(res.unwrap_err() <= 60);

        // Success resets counter
        limiter.record_success(key);
        assert!(limiter.check_allowed(key).is_ok());
    }
}
