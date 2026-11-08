//! JSON-RPC transport shapes; authority and read/write classification stay in the host.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Permission, ProtocolError, valid_identifier, validate_value_bounds};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_RPC_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Value,
}

impl RpcRequest {
    /// Host-selected methods remain ordinary JSON-RPC so SDKs need no custom transport codec.
    pub fn new(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params,
        }
    }

    /// Validate only framing here; method permissions and captured target identity belong to the host.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.jsonrpc != "2.0"
            || self.id == 0
            || !valid_identifier(&self.method)
            || !self.params.is_object()
        {
            return Err(ProtocolError("invalid JSON-RPC request envelope".into()));
        }
        validate_value_bounds(&self.params)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: Value,
}

impl RpcNotification {
    /// Notifications never impersonate replies; the host separately checks their event allowlist.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.jsonrpc != "2.0" || !valid_identifier(&self.method) || !self.params.is_object() {
            return Err(ProtocolError(
                "invalid JSON-RPC notification envelope".into(),
            ));
        }
        validate_value_bounds(&self.params)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_json_value"
    )]
    pub result: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_rpc_error"
    )]
    pub error: Option<RpcError>,
}

/// JSON-RPC permits a null success result, which must remain distinct from a missing result member.
fn present_json_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// An explicit null error is malformed, rather than an absent error member accompanying success.
fn present_rpc_error<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RpcError>, D::Error> {
    RpcError::deserialize(deserializer).map(Some)
}

impl RpcResponse {
    /// Require exactly one outcome so malformed replies cannot be mistaken for successful writes.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.jsonrpc != "2.0" || self.id == 0 || self.result.is_some() == self.error.is_some() {
            return Err(ProtocolError("invalid JSON-RPC response envelope".into()));
        }
        if let Some(result) = &self.result {
            validate_value_bounds(result)?;
        }
        if let Some(error) = &self.error {
            if error.message.len() > 4096
                || error.message.chars().any(|c| c.is_control() && c != '\n')
            {
                return Err(ProtocolError("invalid JSON-RPC error".into()));
            }
            if let Some(data) = &error.data {
                validate_value_bounds(data)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeParams {
    pub protocol_version: u32,
    pub plugin_id: String,
    pub plugin_version: String,
    pub instance_generation: u64,
    pub granted_permissions: Vec<Permission>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeResult {
    pub protocol_version: u32,
    pub plugin_id: String,
    pub plugin_version: String,
}

impl HandshakeResult {
    /// Bind the process to the installed identity instead of trusting its self-reported capabilities.
    pub fn validate_for(&self, expected: &HandshakeParams) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.protocol_version != expected.protocol_version
            || self.plugin_id != expected.plugin_id
            || self.plugin_version != expected.plugin_version
        {
            return Err(ProtocolError("plugin handshake identity mismatch".into()));
        }
        Ok(())
    }
}

/// Opaque target handles are minted and revalidated by the host, not resolved from plugin claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationContext {
    pub generation: u64,
    pub instance: Option<String>,
    pub target: Option<String>,
}

/// The host creates this context before dispatch; payload data cannot replace captured target authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationParams {
    pub context: InvocationContext,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationQueryParams {
    pub operation_id: String,
    pub context: InvocationContext,
}

/// Unknown is a first-class result; a lost acknowledgement never implies permission to retry a write.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationStatus {
    Running,
    Succeeded { result: Value },
    Failed { error: RpcError },
    Unknown,
}

/// Host configuration is already locally validated; identity remains bound to the initiating host operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestParams {
    #[serde(rename = "type")]
    pub host_type: String,
    pub configuration_version: u32,
    pub configuration: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTestResult {
    pub success: bool,
}

/// host.open is a pure intent conversion: persistent resources start only under the resulting view owner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostOpenResult {
    pub content_type: String,
    pub title: String,
    pub state_version: u32,
    pub state: Value,
}
