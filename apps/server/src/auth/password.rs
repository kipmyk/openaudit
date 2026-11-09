//! Argon2id cryptographic password hashing and verification.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// Hashes a plaintext password using Argon2id with a secure random salt.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn hash_password(password: &str) -> Result<String, String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long".into());
    }
    if password.len() > 128 {
        return Err("Password cannot exceed 128 characters".into());
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Password hashing failed: {e}"))?;

    Ok(hash.to_string())
}

/// Verifies a candidate plaintext password against an Argon2id hash string.
///
/// # Errors
///
/// Returns an error if the hash string cannot be parsed. Returns Ok(false) on password mismatch.
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, String> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|e| format!("Invalid password hash: {e}"))?;
    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(format!("Password verification failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password_lifecycle() {
        let password = "SuperSecretPassword123!";
        let hash = hash_password(password).expect("Hashing must succeed");
        assert!(hash.starts_with("$argon2id$"));

        // Valid password matches
        assert!(verify_password(password, &hash).expect("Verification must succeed"));

        // Invalid password rejected
        assert!(!verify_password("WrongPassword!", &hash).expect("Verification must succeed"));
    }

    #[test]
    fn test_password_length_bounds() {
        assert!(hash_password("short").is_err());
        assert!(hash_password(&"a".repeat(150)).is_err());
    }
}
