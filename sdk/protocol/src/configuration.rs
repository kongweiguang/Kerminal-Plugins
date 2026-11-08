//! A deliberately finite local schema: no scripts, remote references, or process-assisted validation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{ProtocolError, valid_identifier, valid_label, validate_value_bounds};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationSchema {
    pub version: u32,
    pub root: ValueSchema,
    #[serde(default)]
    pub defaults: Map<String, Value>,
    #[serde(default)]
    pub secret_slots: Vec<SecretSlot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSlot {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaProperty {
    pub schema: ValueSchema,
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSchema {
    String {
        #[serde(default)]
        min_length: usize,
        max_length: usize,
        #[serde(default)]
        choices: Vec<String>,
    },
    Boolean,
    Integer {
        minimum: i64,
        maximum: i64,
    },
    Number {
        minimum: f64,
        maximum: f64,
    },
    Array {
        items: Box<ValueSchema>,
        max_items: usize,
    },
    Object {
        properties: BTreeMap<String, SchemaProperty>,
    },
}

impl ConfigurationSchema {
    /// Validate defaults before any config scan; opening a page must never synthesize invalid state.
    pub fn validate_definition(&self) -> Result<(), ProtocolError> {
        self.validate_host_definition()?;
        self.validate(self.version, &Value::Object(self.defaults.clone()))
    }

    /// New host forms may start with missing mandatory input, while supplied defaults must still be typed.
    pub fn validate_host_definition(&self) -> Result<(), ProtocolError> {
        if self.version == 0 || !matches!(self.root, ValueSchema::Object { .. }) {
            return Err(ProtocolError(
                "configuration requires an object and nonzero version".into(),
            ));
        }
        let mut budget = 1024;
        self.root.validate_definition(0, &mut budget)?;
        if self.secret_slots.len() > 32 {
            return Err(ProtocolError("too many secret slots".into()));
        }
        let mut slots = BTreeSet::new();
        for slot in &self.secret_slots {
            if !valid_identifier(&slot.id)
                || !valid_label(&slot.label, 256)
                || !slots.insert(&slot.id)
            {
                return Err(ProtocolError("invalid or duplicate secret slot".into()));
            }
        }
        let defaults = Value::Object(self.defaults.clone());
        validate_value_bounds(&defaults)?;
        validate_persistable_value(&defaults)?;
        self.root.validate_partial_value(&defaults)
    }

    /// Unknown keys survive round trips, but an unknown version cannot be interpreted as current data.
    pub fn validate(&self, version: u32, value: &Value) -> Result<(), ProtocolError> {
        if version != self.version {
            return Err(ProtocolError("configuration version is unsupported".into()));
        }
        validate_value_bounds(value)?;
        validate_persistable_value(value)?;
        self.root.validate_value(value)
    }

    /// Cleanup is conservative when the known schema does not account for every persisted value.
    pub fn covers_all_values(&self, value: &Value) -> bool {
        self.root.covers_all_values(value)
    }
}

impl ValueSchema {
    /// Object drafts omit mandatory fields until the user enters them; persisted values use full validation.
    fn validate_partial_value(&self, value: &Value) -> Result<(), ProtocolError> {
        if let (Self::Object { properties }, Value::Object(values)) = (self, value) {
            for (key, property) in properties {
                if let Some(value) = values.get(key) {
                    property.schema.validate_partial_value(value)?;
                }
            }
            Ok(())
        } else {
            self.validate_value(value)
        }
    }

    /// The schema itself is bounded to keep untrusted declarations cheap to validate repeatedly.
    fn validate_definition(&self, depth: usize, budget: &mut usize) -> Result<(), ProtocolError> {
        if depth > 16 || *budget == 0 {
            return Err(ProtocolError(
                "configuration schema exceeds complexity limit".into(),
            ));
        }
        *budget -= 1;
        match self {
            Self::String {
                min_length,
                max_length,
                choices,
            } => {
                if min_length > max_length || *max_length > 262_144 || choices.len() > 256 {
                    return Err(ProtocolError("invalid string constraints".into()));
                }
                let mut unique = BTreeSet::new();
                for choice in choices {
                    if choice.len() < *min_length
                        || choice.len() > *max_length
                        || !unique.insert(choice)
                    {
                        return Err(ProtocolError("invalid or duplicate string choice".into()));
                    }
                }
            }
            Self::Integer { minimum, maximum } if minimum > maximum => {
                return Err(ProtocolError("invalid integer range".into()));
            }
            Self::Number { minimum, maximum }
                if !minimum.is_finite() || !maximum.is_finite() || minimum > maximum =>
            {
                return Err(ProtocolError("invalid number range".into()));
            }
            Self::Array { items, max_items } => {
                if *max_items > 4096 {
                    return Err(ProtocolError("array limit is too large".into()));
                }
                items.validate_definition(depth + 1, budget)?;
            }
            Self::Object { properties } => {
                for (key, property) in properties {
                    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
                        return Err(ProtocolError("invalid configuration field key".into()));
                    }
                    property.schema.validate_definition(depth + 1, budget)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Diagnose types and constraints without including a user's actual input in the error text.
    pub fn validate_value(&self, value: &Value) -> Result<(), ProtocolError> {
        let valid = match (self, value) {
            (
                Self::String {
                    min_length,
                    max_length,
                    choices,
                },
                Value::String(text),
            ) => {
                text.len() >= *min_length
                    && text.len() <= *max_length
                    && (choices.is_empty() || choices.contains(text))
            }
            (Self::Boolean, Value::Bool(_)) => true,
            (Self::Integer { minimum, maximum }, Value::Number(number)) => number
                .as_i64()
                .is_some_and(|n| n >= *minimum && n <= *maximum),
            (Self::Number { minimum, maximum }, Value::Number(number)) => number
                .as_f64()
                .is_some_and(|n| n.is_finite() && n >= *minimum && n <= *maximum),
            (Self::Array { items, max_items }, Value::Array(values)) => {
                if values.len() > *max_items {
                    return Err(ProtocolError("array exceeds declared limit".into()));
                }
                for value in values {
                    items.validate_value(value)?;
                }
                true
            }
            (Self::Object { properties }, Value::Object(values)) => {
                for (key, property) in properties {
                    match values.get(key) {
                        Some(value) => property.schema.validate_value(value)?,
                        None if property.required => {
                            return Err(ProtocolError(
                                "required configuration field is missing".into(),
                            ));
                        }
                        None => {}
                    }
                }
                true
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(ProtocolError(
                "configuration field does not match its declared type or constraints".into(),
            ))
        }
    }

    /// Array indices are deliberately excluded from editable field paths, preventing stale-row edits.
    pub fn field(&self, path: &[String]) -> Option<&ValueSchema> {
        let mut current = self;
        for key in path {
            let Self::Object { properties } = current else {
                return None;
            };
            current = &properties.get(key)?.schema;
        }
        Some(current)
    }

    /// Extra fields are preserved but mean the host cannot prove the absence of private references.
    fn covers_all_values(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Object { properties }, Value::Object(values)) => {
                values.iter().all(|(key, value)| {
                    properties
                        .get(key)
                        .is_some_and(|property| property.schema.covers_all_values(value))
                })
            }
            (Self::Array { items, .. }, Value::Array(values)) => {
                values.iter().all(|value| items.covers_all_values(value))
            }
            _ => self.validate_value(value).is_ok(),
        }
    }
}

/// TOML has no null or unsigned integers above i64; reject them before a lossy conversion is possible.
fn validate_persistable_value(value: &Value) -> Result<(), ProtocolError> {
    match value {
        Value::Null => {
            return Err(ProtocolError(
                "null is not a persistent configuration value".into(),
            ));
        }
        Value::Number(number) if number.is_u64() && number.as_i64().is_none() => {
            return Err(ProtocolError(
                "configuration integer exceeds supported range".into(),
            ));
        }
        Value::Array(values) => {
            for value in values {
                validate_persistable_value(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_persistable_value(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
