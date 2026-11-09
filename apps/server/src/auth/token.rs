//! Cryptographically signed session tokens for API authentication.

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::store::models::Role;

type HmacSha256 = Hmac<Sha256>;

/// Claims embedded within an authenticated session token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Authenticated user unique identifier.
    pub user_id: Uuid,
    /// Tenant organization identifier.
    pub org_id: Uuid,
    /// Authorized tenant role.
    pub role: Role,
    /// User email address.
    pub email: String,
    /// Unix timestamp when token was created.
    pub issued_at: i64,
    /// Unix timestamp when token expires.
    pub expires_at: i64,
}

impl TokenClaims {
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() >= self.expires_at
    }
}

/// Encodes bytes into lowercase hex string.
pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes hex string into bytes.
///
/// # Errors
/// Returns error if length is odd or characters are invalid.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string must have an even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {i}: {e}"))
        })
        .collect()
}

/// Issues a signed authentication token with the given TTL in seconds.
///
/// # Errors
///
/// Returns an error if token serialization or HMAC signing fails.
pub fn issue_token(
    user_id: Uuid,
    org_id: Uuid,
    role: Role,
    email: &str,
    ttl_seconds: i64,
    secret_key: &str,
) -> Result<String, String> {
    let now = Utc::now().timestamp();
    let expires_at = now + ttl_seconds;

    let claims = TokenClaims {
        user_id,
        org_id,
        role,
        email: email.to_string(),
        issued_at: now,
        expires_at,
    };

    let payload_bytes =
        serde_json::to_vec(&claims).map_err(|e| format!("Serialization error: {e}"))?;
    let payload_b64 = encode_hex(&payload_bytes);

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|e| format!("HMAC key initialization failed: {e}"))?;
    mac.update(payload_b64.as_bytes());
    let signature = mac.finalize().into_bytes();
    let sig_hex = encode_hex(&signature);

    Ok(format!("{payload_b64}.{sig_hex}"))
}

/// Validates a signed authentication token and returns its decoded claims.
///
/// # Errors
///
/// Returns an error if the token is malformed, has an invalid signature, or is expired.
pub fn verify_token(token_str: &str, secret_key: &str) -> Result<TokenClaims, String> {
    let (payload_hex, sig_hex) = token_str
        .split_once('.')
        .ok_or_else(|| "Malformed token format: expected payload.signature".to_string())?;

    let expected_sig_bytes =
        decode_hex(sig_hex).map_err(|e| format!("Invalid signature encoding: {e}"))?;

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|e| format!("HMAC key initialization failed: {e}"))?;
    mac.update(payload_hex.as_bytes());

    mac.verify_slice(&expected_sig_bytes)
        .map_err(|_| "Invalid token cryptographic signature".to_string())?;

    let payload_bytes =
        decode_hex(payload_hex).map_err(|e| format!("Invalid payload encoding: {e}"))?;
    let claims: TokenClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("Invalid claims JSON: {e}"))?;

    if claims.is_expired() {
        return Err("Authentication token has expired".to_string());
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_and_verify_token_roundtrip() {
        let secret = "super-secret-key-at-least-32-characters-long!";
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let email = "operator@openaudit.dev";

        let token = issue_token(user_id, org_id, Role::Admin, email, 3600, secret)
            .expect("Must issue token");

        let claims = verify_token(&token, secret).expect("Must verify valid token");
        assert_eq!(claims.user_id, user_id);
        assert_eq!(claims.org_id, org_id);
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.email, email);
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_tampered_token_rejected() {
        let secret = "super-secret-key-at-least-32-characters-long!";
        let token = issue_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Role::Viewer,
            "user@test.com",
            3600,
            secret,
        )
        .expect("Must issue token");

        let tampered = format!("{token}tamper");
        assert!(verify_token(&tampered, secret).is_err());
    }

    #[test]
    fn test_expired_token_rejected() {
        let secret = "super-secret-key-at-least-32-characters-long!";
        // Issue with negative TTL (-10 seconds)
        let token = issue_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Role::Viewer,
            "user@test.com",
            -10,
            secret,
        )
        .expect("Must issue token");

        let err = verify_token(&token, secret).unwrap_err();
        assert!(err.contains("expired"));
    }
}
