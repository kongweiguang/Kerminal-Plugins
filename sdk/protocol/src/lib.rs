//! Portable plugin declarations. No host state, process execution, or UI toolkit lives here.

pub mod configuration;
pub mod manifest;
pub mod native;
pub mod runtime;

pub use configuration::*;
pub use manifest::*;
pub use native::*;
pub use runtime::*;

/// Errors contain schema locations, never configuration values or secret material.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct ProtocolError(pub String);

/// Share the bounded identifier grammar across packages, runtime handles and declarations.
pub fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= 128
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_'))
}

/// Reject control characters in labels without forbidding normal international text.
pub fn valid_label(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

/// Bound recursive values before conversion or rendering so unknown keys remain safe to preserve.
pub fn validate_value_bounds(value: &serde_json::Value) -> Result<(), ProtocolError> {
    let mut remaining = 16_384usize;
    value_bounds(value, 0, &mut remaining)
}

/// Apply one shared node budget to all branches, rather than a separate budget per subtree.
fn value_bounds(
    value: &serde_json::Value,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), ProtocolError> {
    if depth > 32 || *remaining == 0 {
        return Err(ProtocolError("value exceeds nesting or node limit".into()));
    }
    *remaining -= 1;
    match value {
        serde_json::Value::String(value) if value.len() > 262_144 => {
            return Err(ProtocolError("value exceeds string limit".into()));
        }
        serde_json::Value::Array(values) => {
            for value in values {
                value_bounds(value, depth + 1, remaining)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
                    return Err(ProtocolError("invalid value key".into()));
                }
                value_bounds(value, depth + 1, remaining)?;
            }
        }
        _ => {}
    }
    Ok(())
}
