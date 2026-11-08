//! A small synchronous backend SDK. Plugins own their work and data; the host owns UI and capabilities.

use std::io::{self, BufRead, Read, Write};

pub use kerminal_plugin_protocol as protocol;
use protocol::{
    HandshakeParams, HandshakeResult, InvocationParams, MAX_RPC_BYTES, PROTOCOL_VERSION, RpcError,
    RpcRequest, RpcResponse,
};
pub use serde_json::{Value, json};

/// The SDK intentionally has no event loop, application dependency or automatic mutation retries.
pub trait Plugin {
    /// Identity is compiled into the executable and checked against the installed signed manifest.
    fn identity(&self) -> (&str, &str);
    /// A handler may ask the host for declared capabilities using the captured invocation context.
    fn invoke(
        &mut self,
        method: &str,
        invocation: InvocationParams,
        host: &mut Host<'_>,
    ) -> Result<Value, RpcError>;
}

/// Only the current stdio exchange is borrowed; plugin code cannot replace the transport or another plugin.
pub struct Host<'a> {
    input: &'a mut dyn BufRead,
    output: &'a mut dyn Write,
    next_id: &'a mut u64,
}

impl Host<'_> {
    /// Host calls are explicit and never retried: callers must retain unknown write outcomes themselves.
    pub fn invoke(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        if !method.starts_with("host.") {
            return Err(error(-32601, "Expected a host capability method"));
        }
        let id = *self.next_id;
        *self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| error(-32603, "Request ID exhausted"))?;
        let request = RpcRequest::new(id, method, params);
        request
            .validate()
            .map_err(|_| error(-32602, "Invalid host request"))?;
        write_frame(
            self.output,
            &serde_json::to_value(request).map_err(|_| error(-32602, "Invalid host request"))?,
        )
        .map_err(|_| error(-32000, "Host transport unavailable"))?;
        let value = read_frame(self.input)
            .map_err(|_| error(-32000, "Host transport unavailable"))?
            .ok_or_else(|| error(-32000, "Host disconnected"))?;
        let response: RpcResponse =
            serde_json::from_value(value).map_err(|_| error(-32603, "Invalid host response"))?;
        response
            .validate()
            .map_err(|_| error(-32603, "Invalid host response"))?;
        if response.id != id {
            return Err(error(-32603, "Unexpected host response identity"));
        }
        match (response.result, response.error) {
            (Some(value), None) => Ok(value),
            (None, Some(error)) => Err(error),
            _ => Err(error(-32603, "Invalid host response")),
        }
    }

    /// Long tasks publish bounded events and return task handles instead of holding the UI request open.
    pub fn emit(&mut self, method: &str, params: Value) -> io::Result<()> {
        if !method.starts_with("plugin.") || !protocol::valid_identifier(method) {
            return Err(io::Error::other("Invalid plugin event"));
        }
        protocol::validate_value_bounds(&params).map_err(io::Error::other)?;
        write_frame(
            self.output,
            &json!({"jsonrpc":"2.0", "method":method, "params":params}),
        )
    }
}

/// Stdout is reserved exclusively for the protocol; plugin diagnostics must use stderr without secrets.
pub fn run(plugin: &mut impl Plugin) -> io::Result<()> {
    serve(plugin, &mut io::stdin().lock(), &mut io::stdout().lock())
}

/// Injectable streams permit independent SDK contract tests without launching the desktop application.
pub fn serve(
    plugin: &mut impl Plugin,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> io::Result<()> {
    let mut initialized = false;
    let mut next_host_id = 1_u64;
    while let Some(value) = read_frame(input)? {
        let request: RpcRequest =
            serde_json::from_value(value).map_err(|_| io::Error::other("Invalid RPC request"))?;
        request.validate().map_err(io::Error::other)?;
        let result = if request.method == "initialize" && !initialized {
            let params: HandshakeParams = serde_json::from_value(request.params)
                .map_err(|_| io::Error::other("Invalid handshake"))?;
            let (id, version) = plugin.identity();
            let result = HandshakeResult {
                protocol_version: PROTOCOL_VERSION,
                plugin_id: id.into(),
                plugin_version: version.into(),
            };
            result.validate_for(&params).map_err(io::Error::other)?;
            initialized = true;
            serde_json::to_value(result).map_err(|_| error(-32603, "Handshake encoding failed"))
        } else if !initialized || request.method == "initialize" {
            Err(error(-32600, "Handshake required exactly once"))
        } else {
            match serde_json::from_value::<InvocationParams>(request.params) {
                Ok(invocation) => plugin.invoke(
                    &request.method,
                    invocation,
                    &mut Host {
                        input,
                        output,
                        next_id: &mut next_host_id,
                    },
                ),
                Err(_) => Err(error(-32602, "Invalid invocation")),
            }
        };
        let response = match result {
            Ok(value) => RpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(error) => RpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id,
                result: None,
                error: Some(error),
            },
        };
        response.validate().map_err(io::Error::other)?;
        write_frame(
            output,
            &serde_json::to_value(response).map_err(io::Error::other)?,
        )?;
    }
    Ok(())
}

/// A hard cap applies before allocating the next frame, including unterminated lines.
fn read_frame(input: &mut dyn BufRead) -> io::Result<Option<Value>> {
    let mut bytes = Vec::new();
    let size = input
        .take((MAX_RPC_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if size == 0 {
        return Ok(None);
    }
    if size > MAX_RPC_BYTES || bytes.last() != Some(&b'\n') {
        return Err(io::Error::other("RPC frame limit exceeded"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(io::Error::other)
}

/// Every reply is flushed so a host waiting for a handshake or write receipt never depends on buffer capacity.
fn write_frame(output: &mut dyn Write, value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() >= MAX_RPC_BYTES {
        return Err(io::Error::other("RPC frame limit exceeded"));
    }
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.flush()
}

/// Fixed SDK diagnostics avoid reflecting malformed input or secret-bearing parameters.
pub fn error(code: i32, message: &str) -> RpcError {
    RpcError {
        code,
        message: message.into(),
        data: None,
    }
}
