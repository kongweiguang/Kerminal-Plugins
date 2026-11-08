//! Native declarations use host components and semantic styles instead of an embedded layout language.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{ConfigurationSchema, ProtocolError, ValueSchema, valid_identifier, valid_label};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeView {
    pub root: NativeNode,
    #[serde(default)]
    pub lifecycle: Option<NativeViewLifecycle>,
}

/// Native activation reads state; resources are created only by explicit, journaled commands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeViewLifecycle {
    #[serde(default)]
    pub activate: bool,
    #[serde(default)]
    pub visibility: bool,
    #[serde(default)]
    pub close: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NativeNode {
    pub id: String,
    #[serde(flatten)]
    pub kind: NativeNodeKind,
}

impl<'de> Deserialize<'de> for NativeNode {
    /// Serde cannot combine flatten and deny_unknown_fields reliably; consume identity before the strict variant.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let id = fields
            .remove("id")
            .and_then(|value| value.as_str().map(str::to_string))
            .ok_or_else(|| serde::de::Error::custom("native node requires a string identity"))?;
        let kind = serde_json::from_value(serde_json::Value::Object(fields))
            .map_err(serde::de::Error::custom)?;
        Ok(Self { id, kind })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeNodeKind {
    Column {
        children: Vec<NativeNode>,
    },
    Row {
        children: Vec<NativeNode>,
    },
    Group {
        title: String,
        children: Vec<NativeNode>,
    },
    Text {
        text: String,
    },
    Field {
        label: String,
        path: Vec<String>,
        control: FieldControl,
    },
    Secret {
        label: String,
        slot: String,
    },
    Button {
        label: String,
        command: String,
    },
    Notice {
        text: String,
        tone: NoticeTone,
    },
    Separator,
    List {
        path: Vec<String>,
        label_path: Vec<String>,
        empty_text: String,
    },
    Table {
        path: Vec<String>,
        columns: Vec<TableColumn>,
        empty_text: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldControl {
    Text,
    Multiline,
    Toggle,
    Select,
    Number,
    Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeTone {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableColumn {
    pub label: String,
    pub path: Vec<String>,
}

impl NativeView {
    /// IDs and command references are checked without creating a window or launching a plugin process.
    pub fn validate(
        &self,
        commands: &BTreeSet<&str>,
        configuration: Option<&ConfigurationSchema>,
    ) -> Result<(), ProtocolError> {
        if self
            .lifecycle
            .is_some_and(|value| !value.activate && !value.visibility && !value.close)
        {
            return Err(ProtocolError("empty native lifecycle declaration".into()));
        }
        let mut ids = BTreeSet::new();
        let mut budget = 256;
        self.root
            .validate(0, &mut budget, &mut ids, commands, configuration)?;
        self.root.validate_unique_bindings(&mut BTreeSet::new())
    }
}

impl NativeNode {
    /// A draft field has one editor in a view; duplicate bindings would otherwise leave two divergent raw inputs.
    fn validate_unique_bindings(
        &self,
        paths: &mut BTreeSet<Vec<String>>,
    ) -> Result<(), ProtocolError> {
        match &self.kind {
            NativeNodeKind::Column { children }
            | NativeNodeKind::Row { children }
            | NativeNodeKind::Group { children, .. } => {
                for child in children {
                    child.validate_unique_bindings(paths)?;
                }
            }
            NativeNodeKind::Field { path, .. } if !paths.insert(path.clone()) => {
                return Err(ProtocolError("duplicate native field binding".into()));
            }
            _ => {}
        }
        Ok(())
    }

    /// One tree-wide limit prevents broad trees from bypassing per-container resource limits.
    fn validate<'a>(
        &'a self,
        depth: usize,
        budget: &mut usize,
        ids: &mut BTreeSet<&'a str>,
        commands: &BTreeSet<&str>,
        configuration: Option<&ConfigurationSchema>,
    ) -> Result<(), ProtocolError> {
        if depth > 16 || *budget == 0 || !valid_identifier(&self.id) || !ids.insert(&self.id) {
            return Err(ProtocolError(
                "invalid or overlarge native component tree".into(),
            ));
        }
        *budget -= 1;
        match &self.kind {
            NativeNodeKind::Column { children }
            | NativeNodeKind::Row { children }
            | NativeNodeKind::Group { children, .. } => {
                if let NativeNodeKind::Group { title, .. } = &self.kind {
                    label(title)?;
                }
                for child in children {
                    child.validate(depth + 1, budget, ids, commands, configuration)?;
                }
            }
            NativeNodeKind::Text { text } | NativeNodeKind::Notice { text, .. } => {
                if text.len() > 16_384 || text.contains('\0') {
                    return Err(ProtocolError("native text exceeds limit".into()));
                }
            }
            NativeNodeKind::Field {
                label: title,
                path,
                control,
            } => {
                label(title)?;
                validate_path(path)?;
                if let Some(schema) = configuration {
                    let field = schema.root.field(path).ok_or_else(|| {
                        ProtocolError("native field is not declared in configuration".into())
                    })?;
                    let valid = match control {
                        FieldControl::Text | FieldControl::Multiline | FieldControl::Path => {
                            matches!(field, ValueSchema::String { .. })
                        }
                        FieldControl::Toggle => matches!(field, ValueSchema::Boolean),
                        FieldControl::Select => {
                            matches!(field, ValueSchema::String { choices, .. } if !choices.is_empty())
                        }
                        FieldControl::Number => matches!(
                            field,
                            ValueSchema::Integer { .. } | ValueSchema::Number { .. }
                        ),
                    };
                    if !valid {
                        return Err(ProtocolError(
                            "native control does not match configuration type".into(),
                        ));
                    }
                }
            }
            NativeNodeKind::Secret { label: title, slot } => {
                label(title)?;
                if !valid_identifier(slot)
                    || configuration.is_none_or(|schema| {
                        !schema.secret_slots.iter().any(|entry| &entry.id == slot)
                    })
                {
                    return Err(ProtocolError("native secret slot is not declared".into()));
                }
            }
            NativeNodeKind::Button {
                label: title,
                command,
            } => {
                label(title)?;
                if !commands.contains(command.as_str()) {
                    return Err(ProtocolError(
                        "native button references an unknown command".into(),
                    ));
                }
            }
            NativeNodeKind::List {
                path,
                label_path,
                empty_text,
            } => {
                validate_path(path)?;
                validate_path(label_path)?;
                label(empty_text)?;
                validate_collection_binding(configuration, path, std::slice::from_ref(label_path))?;
            }
            NativeNodeKind::Table {
                path,
                columns,
                empty_text,
            } => {
                validate_path(path)?;
                label(empty_text)?;
                if columns.is_empty() || columns.len() > 16 {
                    return Err(ProtocolError("invalid native table column count".into()));
                }
                for column in columns {
                    label(&column.label)?;
                    validate_path(&column.path)?;
                }
                let paths = columns
                    .iter()
                    .map(|column| column.path.clone())
                    .collect::<Vec<_>>();
                validate_collection_binding(configuration, path, &paths)?;
            }
            NativeNodeKind::Separator => {}
        }
        Ok(())
    }
}

/// Lists and tables bind to bounded arrays of records; cell rendering never evaluates code.
fn validate_collection_binding(
    schema: Option<&ConfigurationSchema>,
    path: &[String],
    columns: &[Vec<String>],
) -> Result<(), ProtocolError> {
    if let Some(schema) = schema {
        let Some(ValueSchema::Array { items, .. }) = schema.root.field(path) else {
            return Err(ProtocolError("native collection is not an array".into()));
        };
        for column in columns {
            if !matches!(
                items.field(column),
                Some(
                    ValueSchema::String { .. }
                        | ValueSchema::Boolean
                        | ValueSchema::Integer { .. }
                        | ValueSchema::Number { .. }
                )
            ) {
                return Err(ProtocolError(
                    "native collection cell is not a declared scalar".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Segment paths support literal dots in keys and avoid executable selectors or array-index races.
fn validate_path(path: &[String]) -> Result<(), ProtocolError> {
    if path.is_empty()
        || path.len() > 16
        || path
            .iter()
            .any(|key| key.is_empty() || key.len() > 128 || key.chars().any(char::is_control))
    {
        return Err(ProtocolError("invalid native binding path".into()));
    }
    Ok(())
}

/// Native labels use the same bounded accessible text contract as manifest labels.
fn label(value: &str) -> Result<(), ProtocolError> {
    if valid_label(value, 256) {
        Ok(())
    } else {
        Err(ProtocolError("invalid native label".into()))
    }
}
