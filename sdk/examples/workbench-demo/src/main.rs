use kerminal_plugin_sdk::{
    Host, Plugin, Value, error, json,
    protocol::{HostRequestParams, InvocationContext, InvocationParams, RpcError},
    run,
};
use std::collections::BTreeMap;

#[derive(Default)]
struct Demo {
    receipts: BTreeMap<String, Receipt>,
}

struct Receipt {
    context: InvocationContext,
    method: String,
    result: Value,
}

struct DemoSettings {
    welcome: String,
    compact: bool,
}

impl Demo {
    /// Only committed ordinary settings are read through the owning plugin's capability; absent settings use the manifest defaults.
    fn settings(
        host: &mut Host<'_>,
        context: &InvocationContext,
    ) -> Result<DemoSettings, RpcError> {
        let saved = host.invoke(
            "host.settings.read",
            json!({"context":context,"payload":{}}),
        )?;
        if !saved.is_null() && saved.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(error(-32602, "Unsupported demonstration settings version"));
        }
        let values = saved.get("values");
        Ok(DemoSettings {
            welcome: values
                .and_then(|values| values.get("welcome"))
                .and_then(Value::as_str)
                .filter(|value| value.chars().count() <= 128)
                .unwrap_or("欢迎使用工作台便笺。")
                .to_string(),
            compact: values
                .and_then(|values| values.get("compact"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
    }

    /// In-process receipts cannot be borrowed by a different view or operation kind, even with a copied operation ID.
    fn prior_result(
        &self,
        invocation: &InvocationParams,
        method: &str,
    ) -> Result<Option<Value>, RpcError> {
        let id = invocation
            .operation_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| error(-32602, "An operation identity is required"))?;
        match self.receipts.get(id) {
            Some(receipt) if receipt.context == invocation.context && receipt.method == method => {
                Ok(Some(receipt.result.clone()))
            }
            Some(_) => Err(error(-32602, "Operation owner does not match")),
            None => Ok(None),
        }
    }

    /// This resource-free example keeps bounded receipts in memory; after restart unknown receipts must never authorize replay.
    fn remember_result(
        &mut self,
        invocation: InvocationParams,
        method: &str,
        result: Value,
    ) -> Value {
        if let Some(id) = invocation.operation_id {
            if self.receipts.len() >= 64 {
                self.receipts.pop_first();
            }
            self.receipts.insert(
                id,
                Receipt {
                    context: invocation.context,
                    method: method.into(),
                    result: result.clone(),
                },
            );
        }
        result
    }

    /// Activation and visibility only read local state; close acknowledges after releasing this example's zero external resources.
    fn lifecycle(&mut self, method: &str, invocation: InvocationParams) -> Result<Value, RpcError> {
        let view = invocation.payload.get("view").and_then(Value::as_str);
        let state = invocation
            .payload
            .get("state")
            .filter(|state| state.is_object());
        if !matches!(
            view,
            Some("example.workbench.native-page" | "example.workbench.tool-view")
        ) || invocation
            .context
            .instance
            .as_deref()
            .is_none_or(str::is_empty)
            || invocation
                .payload
                .get("state_version")
                .and_then(Value::as_u64)
                != Some(1)
            || state.is_none()
        {
            return Err(error(-32602, "Invalid demonstration view context"));
        }
        if method == "view.close" {
            if let Some(previous) = self.prior_result(&invocation, method)? {
                return Ok(previous);
            }
            return Ok(self.remember_result(invocation, method, json!({"closed":true})));
        }
        if invocation
            .payload
            .get("visible")
            .and_then(Value::as_bool)
            .is_none()
            || invocation
                .payload
                .get("window_active")
                .and_then(Value::as_bool)
                .is_none()
        {
            return Err(error(-32602, "Invalid demonstration view visibility"));
        }
        if method == "view.activate" {
            Ok(json!({"state_version":1,"state":state}))
        } else {
            Ok(json!({"acknowledged":true}))
        }
    }
}

impl Plugin for Demo {
    /// The backend identity must match the signed manifest before any declared command can execute.
    fn identity(&self) -> (&str, &str) {
        ("example.workbench", "1.0.0")
    }

    /// Host-open reads committed settings once for new notes; activation never replaces existing per-view state with defaults.
    fn invoke(
        &mut self,
        method: &str,
        invocation: InvocationParams,
        host: &mut Host<'_>,
    ) -> Result<Value, RpcError> {
        match method {
            "host.test" | "host.open" => {
                let request: HostRequestParams = serde_request(invocation.payload)?;
                if request.host_type != "example.workbench.connection"
                    || request.configuration_version != 1
                {
                    return Err(error(
                        -32602,
                        "Unsupported demonstration host configuration",
                    ));
                }
                let label = request
                    .configuration
                    .get("label")
                    .and_then(Value::as_str)
                    .filter(|label| !label.trim().is_empty() && label.chars().count() <= 128)
                    .ok_or_else(|| error(-32602, "Enter a host label"))?;
                if method == "host.test" {
                    Ok(json!({"success":true}))
                } else {
                    let settings = Self::settings(host, &invocation.context)?;
                    Ok(
                        json!({"content_type":"example.workbench.dashboard","title":label,"state_version":1,"state":{"message":settings.welcome}}),
                    )
                }
            }
            "operation.query" => {
                let id = invocation
                    .payload
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| error(-32602, "An operation identity is required"))?;
                Ok(self
                    .receipts
                    .get(id)
                    .filter(|receipt| receipt.context == invocation.context)
                    .map_or_else(
                        || json!({"status":"unknown"}),
                        |receipt| json!({"status":"succeeded","result":receipt.result}),
                    ))
            }
            "view.activate" | "view.visibility" | "view.close" => {
                self.lifecycle(method, invocation)
            }
            "command.invoke" => {
                if invocation.payload.get("command").and_then(Value::as_str)
                    == Some("example.workbench.confirm")
                {
                    if let Some(previous) = self.prior_result(&invocation, method)? {
                        return Ok(previous);
                    }
                    let settings = Self::settings(host, &invocation.context)?;
                    let message = if settings.compact {
                        "插件已成功调用宿主弹框。是否确认？"
                    } else {
                        "此确认弹框由 Kerminal 管理，通过独立插件后端发起。确认和取消都会返回原调用，不会修改便笺或建立远程连接。是否确认？"
                    };
                    let result = host.invoke("host.ui.confirm", json!({"context":invocation.context,"payload":{"id":"demo-confirm","title":"便笺示例","message":message,"danger":false}}))?;
                    Ok(self.remember_result(invocation, method, result))
                } else {
                    Err(error(-32601, "Unknown demonstration command"))
                }
            }
            _ => Err(error(-32601, "Unknown demonstration method")),
        }
    }
}

/// Conversion errors return fixed diagnostics so configuration values never leak into stderr or dialog text.
fn serde_request(value: Value) -> Result<HostRequestParams, RpcError> {
    serde_json::from_value(value).map_err(|_| error(-32602, "Invalid host configuration"))
}

/// Stdout is reserved for framed protocol messages; process failures are reported through stderr and exit status.
fn main() {
    if run(&mut Demo::default()).is_err() {
        eprintln!("Demonstration backend transport failed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    /// Actual SDK framing checks host-open intent and unknown-operation recovery without the desktop workspace.
    fn independent_stdio_host_open_and_unknown_query() {
        let messages = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":1,"plugin_id":"example.workbench","plugin_version":"1.0.0","instance_generation":1,"granted_permissions":[{"kind":"ui_dialogs"},{"kind":"settings_read"}]}}),
            json!({"jsonrpc":"2.0","id":2,"method":"host.open","params":{"context":{"generation":1,"instance":"host-one","target":null},"payload":{"type":"example.workbench.connection","configuration_version":1,"configuration":{"label":"Local demo"}}}}),
            json!({"jsonrpc":"2.0","id":1,"result":null}),
            json!({"jsonrpc":"2.0","id":3,"method":"operation.query","params":{"context":{"generation":1,"instance":"host-one","target":null},"payload":{"operation_id":"not-recorded"}}}),
        ];
        let input = messages
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>();
        let mut output = Vec::new();
        kerminal_plugin_sdk::serve(&mut Demo::default(), &mut Cursor::new(input), &mut output)
            .unwrap();
        let replies = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            replies[2]["result"]["content_type"],
            "example.workbench.dashboard"
        );
        assert_eq!(replies[1]["method"], "host.settings.read");
        assert_eq!(replies[2]["result"]["title"], "Local demo");
        assert_eq!(
            replies[2]["result"]["state"]["message"],
            "欢迎使用工作台便笺。"
        );
        assert_eq!(replies[3]["result"]["status"], "unknown");
    }

    #[test]
    /// Real host envelopes catch accidental top-level dialog fields and preserve the original owner for a cancelled confirmation.
    fn independent_stdio_command_reads_settings_and_calls_host_dialog() {
        let context = json!({"generation":7,"instance":"tool-one","target":"host-issued-token"});
        let messages = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":1,"plugin_id":"example.workbench","plugin_version":"1.0.0","instance_generation":1,"granted_permissions":[{"kind":"ui_dialogs"},{"kind":"settings_read"}]}}),
            json!({"jsonrpc":"2.0","id":2,"method":"command.invoke","params":{"context":context,"payload":{"command":"example.workbench.confirm"},"operation_id":"confirmation-one"}}),
            json!({"jsonrpc":"2.0","id":1,"result":{"version":1,"values":{"welcome":"我的新便笺","compact":false}}}),
            json!({"jsonrpc":"2.0","id":2,"result":{"confirmed":false}}),
            json!({"jsonrpc":"2.0","id":3,"method":"operation.query","params":{"context":context,"payload":{"operation_id":"confirmation-one"}}}),
        ];
        let input = messages
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>();
        let mut output = Vec::new();
        kerminal_plugin_sdk::serve(&mut Demo::default(), &mut Cursor::new(input), &mut output)
            .unwrap();
        let replies = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        let read: InvocationParams = serde_json::from_value(replies[1]["params"].clone()).unwrap();
        assert_eq!(replies[1]["method"], "host.settings.read");
        assert_eq!(serde_json::to_value(read.context).unwrap(), context);
        let dialog: InvocationParams =
            serde_json::from_value(replies[2]["params"].clone()).unwrap();
        assert_eq!(replies[2]["method"], "host.ui.confirm");
        assert_eq!(serde_json::to_value(dialog.context).unwrap(), context);
        assert_eq!(dialog.payload["id"], "demo-confirm");
        assert!(
            dialog.payload["message"]
                .as_str()
                .unwrap()
                .contains("确认和取消都会返回原调用")
        );
        assert_eq!(replies[3]["result"], json!({"confirmed":false}));
        assert_eq!(
            replies[4]["result"],
            json!({"status":"succeeded","result":{"confirmed":false}})
        );
    }

    #[test]
    /// A committed welcome value initializes new host tabs, while non-ASCII host labels follow the manifest's character limit.
    fn independent_stdio_host_open_uses_committed_welcome() {
        let label = "便".repeat(128);
        let messages = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":1,"plugin_id":"example.workbench","plugin_version":"1.0.0","instance_generation":1,"granted_permissions":[{"kind":"settings_read"}]}}),
            json!({"jsonrpc":"2.0","id":2,"method":"host.open","params":{"context":{"generation":1,"instance":"host-one","target":null},"payload":{"type":"example.workbench.connection","configuration_version":1,"configuration":{"label":label}}}}),
            json!({"jsonrpc":"2.0","id":1,"result":{"version":1,"values":{"welcome":"已保存的新便笺内容","compact":true}}}),
        ];
        let input = messages
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>();
        let mut output = Vec::new();
        kerminal_plugin_sdk::serve(&mut Demo::default(), &mut Cursor::new(input), &mut output)
            .unwrap();
        let replies = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(replies[2]["result"]["title"], label);
        assert_eq!(
            replies[2]["result"]["state"]["message"],
            "已保存的新便笺内容"
        );
    }

    #[test]
    /// A close receipt belongs to its original view even when another view copies its operation ID.
    fn independent_stdio_lifecycle_recovery_keeps_view_owner() {
        let context = json!({"generation":0,"instance":"native-owner","target":null});
        let other = json!({"generation":0,"instance":"other-owner","target":null});
        let state = json!({"message":"Preserve my draft"});
        let payload = json!({"view":"example.workbench.native-page","state_version":1,"state":state,"visible":true,"window_active":true});
        let messages = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":1,"plugin_id":"example.workbench","plugin_version":"1.0.0","instance_generation":1,"granted_permissions":[]}}),
            json!({"jsonrpc":"2.0","id":2,"method":"view.activate","params":{"context":context,"payload":payload}}),
            json!({"jsonrpc":"2.0","id":3,"method":"view.visibility","params":{"context":context,"payload":payload}}),
            json!({"jsonrpc":"2.0","id":4,"method":"view.close","params":{"context":context,"payload":payload,"operation_id":"close-one"}}),
            json!({"jsonrpc":"2.0","id":5,"method":"operation.query","params":{"context":context,"payload":{"operation_id":"close-one"}}}),
            json!({"jsonrpc":"2.0","id":6,"method":"operation.query","params":{"context":other,"payload":{"operation_id":"close-one"}}}),
            json!({"jsonrpc":"2.0","id":7,"method":"view.close","params":{"context":other,"payload":payload,"operation_id":"close-one"}}),
        ];
        let input = messages
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>();
        let mut output = Vec::new();
        kerminal_plugin_sdk::serve(&mut Demo::default(), &mut Cursor::new(input), &mut output)
            .unwrap();
        let replies = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            replies[1]["result"],
            json!({"state_version":1,"state":state})
        );
        assert_eq!(replies[2]["result"]["acknowledged"], true);
        assert_eq!(replies[3]["result"]["closed"], true);
        assert_eq!(
            replies[4]["result"],
            json!({"status":"succeeded","result":{"closed":true}})
        );
        assert_eq!(replies[5]["result"]["status"], "unknown");
        assert!(replies[6].get("error").is_some());
    }
}
