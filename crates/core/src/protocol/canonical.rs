//! RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
//!
//! Provides deterministic UTF-8 byte serialization for JSON structures according
//! to RFC 8785, with explicit validation guards against precision loss in
//! large integers.

use serde::Serialize;
use serde_json::Value;

use crate::protocol::error::ProtocolError;

/// Maximum safe integer in IEEE 754 double precision float: 2^53 - 1 (9,007,199,254,740,991).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Minimum safe integer in IEEE 754 double precision float: -(2^53 - 1) (-9,007,199,254,740,991).
pub const MIN_SAFE_INTEGER: i64 = -9_007_199_254_740_991;

/// Serializes any Serde-serializable type into canonical JSON UTF-8 bytes (RFC 8785).
///
/// # Errors
/// Returns [`ProtocolError::CryptoError`] if serialization fails or if
/// a numeric value violates the IEEE 754 safe integer bounds.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    // First serialize to serde_json::Value to inspect numeric safety
    let json_val = serde_json::to_value(value)
        .map_err(|err| ProtocolError::CryptoError(format!("JSON serialization failed: {err}")))?;

    validate_safe_integers(&json_val)?;

    serde_json_canonicalizer::to_vec(&json_val).map_err(|err| {
        ProtocolError::CryptoError(format!("RFC 8785 canonicalization failed: {err}"))
    })
}

/// Serializes a [`Value`] directly into canonical JSON UTF-8 bytes (RFC 8785).
///
/// # Errors
/// Returns [`ProtocolError::CryptoError`] if canonicalization fails or if
/// a numeric value violates IEEE 754 safe integer bounds.
pub fn canonicalize_value(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    validate_safe_integers(value)?;

    serde_json_canonicalizer::to_vec(value).map_err(|err| {
        ProtocolError::CryptoError(format!("RFC 8785 canonicalization failed: {err}"))
    })
}

/// Recursively inspects a JSON value to guarantee that all integers reside
/// strictly within the IEEE 754 safe integer range `[-(2^53 - 1), 2^53 - 1]`.
///
/// # Rationale
/// RFC 8785 section 3.2.2.3 specifies `ECMAScript` IEEE 754 64-bit float representation.
/// Arbitrary-precision numbers or 64-bit integers exceeding 53 bits cannot be safely
/// represented in JCS without precision loss.
///
/// # Errors
/// Returns [`ProtocolError::CryptoError`] if an integer exceeds safe range.
pub fn validate_safe_integers(val: &Value) -> Result<(), ProtocolError> {
    match val {
        Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                if !(MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
                    return Err(ProtocolError::CryptoError(format!(
                        "integer {i} exceeds RFC 8785 IEEE 754 safe integer range [-(2^53-1), 2^53-1]"
                    )));
                }
            } else if let Some(u) = num.as_u64() {
                if u > MAX_SAFE_INTEGER as u64 {
                    return Err(ProtocolError::CryptoError(format!(
                        "unsigned integer {u} exceeds RFC 8785 IEEE 754 safe integer range [0, 2^53-1]"
                    )));
                }
            }
            Ok(())
        }
        Value::Array(arr) => {
            for item in arr {
                validate_safe_integers(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for v in map.values() {
                validate_safe_integers(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_rfc8785_key_sorting() {
        // Keys must be sorted lexicographically by UTF-16 code units (RFC 8785 3.2.3)
        let v = json!({
            "b": 1,
            "a": 2,
            "c": 3
        });
        let canonical = canonicalize_value(&v).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            r#"{"a":2,"b":1,"c":3}"#
        );
    }

    #[test]
    fn test_rfc8785_nested_structures_and_arrays() {
        let v = json!({
            "z": [3, 2, 1],
            "a": {
                "inner_b": true,
                "inner_a": null
            }
        });
        let canonical = canonicalize_value(&v).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            r#"{"a":{"inner_a":null,"inner_b":true},"z":[3,2,1]}"#
        );
    }

    #[test]
    fn test_rfc8785_unicode_preservation_and_escapes() {
        // Non-control UTF-8 must NOT be escaped as \uXXXX (RFC 8785 3.2.2.2)
        let v = json!({
            "text": "Hello, 🌍! €100 / slash"
        });
        let canonical = canonicalize_value(&v).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            r#"{"text":"Hello, 🌍! €100 / slash"}"#
        );

        // Control characters must be escaped
        let v_ctrl = json!({
            "ctrl": "line1\nline2\t\"quote\"\\"
        });
        let canonical_ctrl = canonicalize_value(&v_ctrl).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical_ctrl).unwrap(),
            r#"{"ctrl":"line1\nline2\t\"quote\"\\"}"#
        );
    }

    #[test]
    fn test_rfc8785_number_formatting() {
        // Numbers formatted according to ECMAScript standard
        let v = json!({
            "zero": 0,
            "float_zero": 0.0,
            "neg_zero": -0.0,
            "hundred": 100.0,
            "exp_threshold": 1_000_000.0
        });
        let canonical = canonicalize_value(&v).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert!(s.contains(r#""zero":0"#));
        assert!(s.contains(r#""float_zero":0"#));
        assert!(s.contains(r#""neg_zero":0"#));
        assert!(s.contains(r#""hundred":100"#));
    }

    #[test]
    fn test_rfc8785_safe_integers_boundary() {
        // Exactly 2^53 - 1 is valid
        let v_max = json!({ "max_safe": MAX_SAFE_INTEGER });
        assert!(canonicalize_value(&v_max).is_ok());

        // Exactly -(2^53 - 1) is valid
        let v_min = json!({ "min_safe": MIN_SAFE_INTEGER });
        assert!(canonicalize_value(&v_min).is_ok());

        // 2^53 (9007199254740992) exceeds safe integer range and MUST be rejected
        let v_overflow = json!({ "unsafe": MAX_SAFE_INTEGER + 1 });
        let err = canonicalize_value(&v_overflow).unwrap_err();
        assert!(matches!(err, ProtocolError::CryptoError(_)));

        // -2^53 exceeds safe integer range and MUST be rejected
        let v_underflow = json!({ "unsafe": MIN_SAFE_INTEGER - 1 });
        let err_under = canonicalize_value(&v_underflow).unwrap_err();
        assert!(matches!(err_under, ProtocolError::CryptoError(_)));

        // u64::MAX and i64::MIN must be rejected
        let v_u64_max = json!({ "u64_max": u64::MAX });
        assert!(canonicalize_value(&v_u64_max).is_err());

        let v_i64_min = json!({ "i64_min": i64::MIN });
        assert!(canonicalize_value(&v_i64_min).is_err());
    }

    #[test]
    fn test_rfc8785_utf16_code_unit_property_ordering() {
        // RFC 8785 § 3.2.3: Sorting is strictly by UTF-16 code units.
        // Code point U+10000 is represented in UTF-16 as surrogate pair 0xD800 0xDC00.
        // Since 0xD800 < 0xFFFF, U+10000 must sort BEFORE U+FFFF in canonical output.
        let v = json!({
            "\u{ffff}": "high BMP",
            "\u{10000}": "astral surrogate pair"
        });
        let canonical = canonicalize_value(&v).unwrap();
        let s = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(
            s,
            "{\"\u{10000}\":\"astral surrogate pair\",\"\u{ffff}\":\"high BMP\"}"
        );
    }

    #[test]
    fn test_rfc8785_floating_point_and_exponent_thresholds() {
        // ECMAScript floating-point representation rules:
        // 1e-6 -> "0.000001", 1e-7 -> "1e-7"
        let v_small = json!({
            "six": 0.000_001,
            "seven": 0.000_000_1
        });
        let s_small = std::str::from_utf8(&canonicalize_value(&v_small).unwrap())
            .unwrap()
            .to_string();
        assert!(s_small.contains(r#""seven":1e-7"#));
        assert!(s_small.contains(r#""six":0.000001"#));

        // 1e20 -> "100000000000000000000", 1e21 -> "1e+21"
        let v_large = json!({
            "exp21": 1e21,
            "exp20": 1e20
        });
        let s_large = std::str::from_utf8(&canonicalize_value(&v_large).unwrap())
            .unwrap()
            .to_string();
        assert!(s_large.contains(r#""exp21":1e+21"#));
        assert!(s_large.contains(r#""exp20":100000000000000000000"#));

        // Empty collections and whitespace escapes
        let v_empty = json!({
            "b": {},
            "a": []
        });
        assert_eq!(
            std::str::from_utf8(&canonicalize_value(&v_empty).unwrap()).unwrap(),
            r#"{"a":[],"b":{}}"#
        );
    }
}
