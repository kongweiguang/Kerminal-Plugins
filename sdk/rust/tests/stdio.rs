use kerminal_plugin_sdk::{
    Host, Plugin, Value, error, json,
    protocol::{InvocationParams, RpcError},
    serve,
};
use std::io::Cursor;

struct Peer;
impl Plugin for Peer {
    /// A fixed independent identity makes a mismatched installation fail before dispatch.
    fn identity(&self) -> (&str, &str) {
        ("sample.peer", "1.0.0")
    }
    /// Null and denied calls exercise actual envelope semantics, not mirrored struct serialization.
    fn invoke(
        &mut self,
        method: &str,
        _: InvocationParams,
        host: &mut Host<'_>,
    ) -> Result<Value, RpcError> {
        match method {
            "sample.null" => Ok(Value::Null),
            "sample.host" => host.invoke("host.notification", json!({"message":"completed"})),
            _ => Err(error(-32601, "Unknown method")),
        }
    }
}

/// Real newline framing permits both a null successful reply and bidirectional host calls.
#[test]
fn handles_handshake_null_and_host_callback() {
    let lines = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":1,"plugin_id":"sample.peer","plugin_version":"1.0.0","instance_generation":1,"granted_permissions":[]}}),
        json!({"jsonrpc":"2.0","id":2,"method":"sample.null","params":{"context":{"generation":1,"instance":"one","target":null},"payload":{}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"sample.host","params":{"context":{"generation":1,"instance":"one","target":null},"payload":{}}}),
        json!({"jsonrpc":"2.0","id":1,"result":{"shown":true}}),
    ];
    let input = lines
        .iter()
        .map(|value| format!("{value}\n"))
        .collect::<String>();
    let mut output = Vec::new();
    serve(&mut Peer, &mut Cursor::new(input), &mut output).unwrap();
    let replies = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(replies.len(), 4);
    assert_eq!(replies[0]["result"]["plugin_id"], "sample.peer");
    assert!(replies[1].as_object().unwrap().contains_key("result"));
    assert_eq!(replies[1]["result"], Value::Null);
    assert_eq!(replies[2]["method"], "host.notification");
    assert_eq!(replies[3]["result"]["shown"], true);
}

/// Wrong provider identity and unterminated oversized frames fail without invoking business code.
#[test]
fn rejects_mismatched_identity_and_unbounded_input() {
    let bad = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":1,"plugin_id":"someone.else","plugin_version":"1.0.0","instance_generation":1,"granted_permissions":[]}});
    let mut output = Vec::new();
    assert!(serve(&mut Peer, &mut Cursor::new(format!("{bad}\n")), &mut output).is_err());
    assert!(output.is_empty());
    assert!(
        serve(
            &mut Peer,
            &mut Cursor::new(vec![b'x'; 1_048_577]),
            &mut output
        )
        .is_err()
    );
}
