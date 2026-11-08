//! Contract tests exercise package boundaries rather than a live host or plugin runtime.

use kerminal_plugin_protocol::*;
use serde_json::{Value, json};

/// A real native settings tree binds a control and a secret slot without a process entrypoint.
fn manifest_value() -> Value {
    json!({
        "schema_version": 1, "id": "example.demo", "name": "Demo", "version": "1.2.3",
        "api": {"major": 1, "min_minor": 0}, "platforms": ["windows_x86_64"],
        "permissions": [{"kind": "secret_read", "slot": "token"}],
        "entrypoints": {"views": {"example.demo.settings-view": {"kind": "native", "view": {"root": {
            "id": "root", "kind": "column", "children": [
                {"id": "enabled", "kind": "field", "label": "Enabled", "path": ["enabled"], "control": "toggle"},
                {"id": "token", "kind": "secret", "label": "Token", "slot": "token"}
            ]
        }}}}},
        "contributions": {"settings_pages": [{"id": "example.demo.settings", "name": "Demo settings", "view": "example.demo.settings-view"}]},
        "configuration": {"settings": {
            "version": 1,
            "root": {"type": "object", "properties": {"enabled": {"schema": {"type": "boolean"}, "required": true}}},
            "defaults": {"enabled": true}, "secret_slots": [{"id": "token", "label": "Token"}]
        }},
        "files": []
    })
}

/// Encoding through JSON follows the same path as a signed package, including strict enum decoding.
fn parse(value: Value) -> Result<ValidatedManifest, ProtocolError> {
    ExternalPluginManifest::parse(&serde_json::to_vec(&value).unwrap())
}

#[test]
/// A settings draft remains host-owned even when the package also declares a supported process.
fn transactional_forms_reject_runtime_lifecycle() {
    let mut value = manifest_value();
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["lifecycle"] =
        json!({"activate":true});
    value["entrypoints"]["process"] = json!([{"platform":"windows_x86_64","path":"backend.exe"}]);
    value["files"] = json!([{"path":"backend.exe","sha256":"a".repeat(64),"size":1}]);
    assert!(parse(value).is_err());
}

#[test]
/// Runtime view lifecycle is explicit and requires an executable on every advertised platform.
fn content_lifecycle_requires_an_available_backend_declaration() {
    let mut value = manifest_value();
    value["permissions"] = json!([]);
    let schema = json!({"version":1,"root":{"type":"object","properties":{}},"defaults":{}});
    value["configuration"] = json!({});
    value["contributions"] = json!({"content_types":[{"id":"example.demo.content","name":"Content","view":"example.demo.settings-view","kinds":["tab"],"state":schema}]});
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"] = json!({"root":{"id":"root","kind":"text","text":"Content"},"lifecycle":{"activate":true,"visibility":true,"close":true}});
    assert!(parse(value.clone()).is_err());
    value["entrypoints"]["process"] = json!([{"platform":"windows_x86_64","path":"backend.exe"}]);
    value["files"] = json!([{"path":"backend.exe","sha256":"a".repeat(64),"size":1}]);
    assert!(parse(value.clone()).is_ok());
    value["platforms"] = json!(["windows_x86_64", "linux_x86_64"]);
    assert!(parse(value).is_err());
}

#[test]
/// Executable commands cannot be advertised as usable on a platform that has no backend, while future static metadata remains readable.
fn supported_commands_require_backend_on_every_platform() {
    let mut value = manifest_value();
    value["contributions"]["commands"] =
        json!([{"id":"example.demo.run","name":"Run","scope":{"kind":"app"},"target":"window"}]);
    assert!(parse(value.clone()).is_err());
    value["entrypoints"]["process"] = json!([{"platform":"windows_x86_64","path":"backend.exe"}]);
    value["files"] = json!([{"path":"backend.exe","sha256":"a".repeat(64),"size":1}]);
    assert!(parse(value.clone()).is_ok());
    value["platforms"] = json!(["windows_x86_64", "linux_x86_64"]);
    assert!(parse(value.clone()).is_err());
    value["api"]["major"] = json!(2);
    assert!(parse(value).is_ok());
}

#[test]
/// Keeping a version number does not make changed schemas compatible, and new state owners prevent unsafe rollback.
fn replacements_preserve_data_formats_and_existing_owners() {
    let current = parse(manifest_value()).unwrap();
    assert_eq!(current.manifest().data_version, 1);
    let mut next = current.manifest().clone();
    next.version = "2.0.0".into();
    next.name = "Renamed demonstration".into();
    assert!(
        next.validate_data_compatibility_with(current.manifest())
            .is_ok()
    );
    next.data_version = 2;
    assert!(
        next.validate_data_compatibility_with(current.manifest())
            .is_err()
    );
    next = current.manifest().clone();
    next.configuration.settings.as_mut().unwrap().version = 2;
    assert!(
        next.validate_data_compatibility_with(current.manifest())
            .is_err()
    );
    next = current.manifest().clone();
    next.configuration
        .settings
        .as_mut()
        .unwrap()
        .defaults
        .insert("enabled".into(), json!(false));
    assert!(
        next.validate_data_compatibility_with(current.manifest())
            .is_err()
    );
    next = current.manifest().clone();
    next.configuration.settings = None;
    assert!(
        next.validate_data_compatibility_with(current.manifest())
            .is_err()
    );
    next = current.manifest().clone();
    next.contributions.content_types.push(ContentContribution {
        id: "example.demo.new-content".into(),
        name: "New content".into(),
        view: "example.demo.content-view".into(),
        kinds: vec![ContentKind::Tab],
        state: current
            .manifest()
            .configuration
            .settings
            .as_ref()
            .unwrap()
            .clone(),
    });
    assert!(
        next.validate_data_compatibility_with(current.manifest())
            .is_ok()
    );
    assert!(
        current
            .manifest()
            .validate_data_compatibility_with(&next)
            .is_err()
    );
    let mut invalid = manifest_value();
    invalid["data_version"] = json!(0);
    assert!(parse(invalid).is_err());
}

#[test]
/// A new optional field can collide with a preserved unknown value, so schema-only approval cannot prove existing data remains readable.
fn replacements_reject_optional_fields_without_actual_data_preflight() {
    let original = manifest_value();
    let current = parse(original.clone()).unwrap();
    let mut next = original.clone();
    next["configuration"]["settings"]["root"]["properties"]["note"] =
        json!({"schema":{"type":"string","max_length":64},"required":false});
    next["configuration"]["settings"]["defaults"]["note"] = json!("");
    let additive = parse(next.clone()).unwrap();
    let existing = json!({"enabled":true,"note":42});
    assert!(
        current
            .manifest()
            .configuration
            .settings
            .as_ref()
            .unwrap()
            .validate(1, &existing)
            .is_ok()
    );
    assert!(
        additive
            .manifest()
            .configuration
            .settings
            .as_ref()
            .unwrap()
            .validate(1, &existing)
            .is_err()
    );
    assert!(
        additive
            .manifest()
            .validate_data_compatibility_with(current.manifest())
            .is_err()
    );
    assert!(
        current
            .manifest()
            .validate_data_compatibility_with(additive.manifest())
            .is_err()
    );
    next["configuration"]["settings"]["root"]["properties"]["note"]["required"] = json!(true);
    assert!(
        parse(next)
            .unwrap()
            .manifest()
            .validate_data_compatibility_with(current.manifest())
            .is_err()
    );
    let mut changed = original;
    changed["configuration"]["settings"]["root"]["properties"]["enabled"]["required"] =
        json!(false);
    assert!(
        parse(changed)
            .unwrap()
            .manifest()
            .validate_data_compatibility_with(current.manifest())
            .is_err()
    );
}

#[test]
/// Static declarations must remain usable when no process is available or the host API is too old.
fn disabled_or_unsupported_manifests_keep_configuration_schema() {
    let mut value = manifest_value();
    value["api"]["major"] = json!(2);
    let parsed = parse(value).unwrap();
    assert!(!parsed.manifest().api.is_supported());
    let schema = parsed.manifest().configuration.settings.as_ref().unwrap();
    assert!(schema.validate(1, &json!({"enabled": false})).is_ok());
    assert!(parsed.manifest().entrypoints.process.is_empty());
}

#[test]
/// Known validation and unknown-value preservation coexist; cleanup cannot claim complete coverage.
fn schema_preserves_unknown_values_but_rejects_future_versions_and_invalid_known_values() {
    let parsed = parse(manifest_value()).unwrap();
    let schema = parsed.manifest().configuration.settings.as_ref().unwrap();
    let value = json!({"enabled": true, "future": {"name": "kept"}});
    assert!(schema.validate(1, &value).is_ok());
    assert!(!schema.covers_all_values(&value));
    assert!(schema.validate(2, &value).is_err());
    assert!(schema.validate(1, &json!({"enabled": "yes"})).is_err());
    assert!(
        schema
            .validate(1, &json!({"enabled": true, "future": null}))
            .is_err()
    );
    assert!(
        schema
            .validate(1, &json!({"enabled": true, "future": u64::MAX}))
            .is_err()
    );
}

#[test]
/// A field's component type and a secret's slot must be validated before the native renderer sees it.
fn native_bindings_reject_wrong_controls_unknown_slots_and_duplicate_instances() {
    let mut value = manifest_value();
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["root"]["children"][0]["control"] =
        json!("text");
    assert!(parse(value).is_err());
    let mut value = manifest_value();
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["root"]["children"][1]["slot"] =
        json!("other");
    assert!(parse(value).is_err());
    let mut value = manifest_value();
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["root"]["children"][1]["id"] =
        json!("enabled");
    assert!(parse(value).is_err());
}

#[test]
/// File identities are portable: package verification cannot accept aliases that collide on Windows.
fn package_paths_and_case_aliases_are_rejected() {
    for path in [
        "../a", "a/../b", "/a", "C:/a", "a\\b", "a//b", "con.txt", "x/COM1", "foo.", "a ",
        "a:stream",
    ] {
        assert!(validate_package_path(path).is_err(), "{path}");
    }
    assert!(validate_package_path("assets/index.html").is_ok());
    let mut value = manifest_value();
    value["files"] = json!([
        {"path": "assets/A.js", "sha256": "0".repeat(64), "size": 1},
        {"path": "assets/a.js", "sha256": "0".repeat(64), "size": 1}
    ]);
    assert!(parse(value).is_err());
}

#[test]
/// Neither extra enum values nor attempts to occupy the builtin namespace silently degrade to defaults.
fn manifest_rejects_unknown_permissions_namespace_takeover_and_missing_entry_files() {
    let mut value = manifest_value();
    value["permissions"] = json!([{"kind": "all_access"}]);
    assert!(parse(value).is_err());
    let mut value = manifest_value();
    value["id"] = json!("Kerminal.hijack");
    assert!(parse(value).is_err());
    let mut value = manifest_value();
    value["entrypoints"]["process"] =
        json!([{"platform": "windows_x86_64", "path": "bin/plugin.exe"}]);
    assert!(parse(value).is_err());
}

#[test]
/// JSON null is a valid success value, while absent or ambiguous outcomes are protocol errors.
fn rpc_response_preserves_null_and_requires_exactly_one_result() {
    let response: RpcResponse =
        serde_json::from_value(json!({"jsonrpc":"2.0", "id":1, "result":null})).unwrap();
    assert_eq!(response.result, Some(Value::Null));
    assert!(response.validate().is_ok());
    for value in [
        json!({"jsonrpc":"2.0", "id":1}),
        json!({"jsonrpc":"2.0", "id":1, "result":null, "error":{"code":-1,"message":"failed"}}),
        json!({"jsonrpc":"1.0", "id":1, "result":true}),
    ] {
        assert!(
            serde_json::from_value::<RpcResponse>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

#[test]
/// A restarted or substituted package must not complete another installed version's handshake.
fn handshake_identity_is_bound_to_expected_package() {
    let expected = HandshakeParams {
        protocol_version: 1,
        plugin_id: "example.demo".into(),
        plugin_version: "1.2.3".into(),
        instance_generation: 2,
        granted_permissions: vec![],
    };
    let mut actual = HandshakeResult {
        protocol_version: 1,
        plugin_id: "example.demo".into(),
        plugin_version: "1.2.3".into(),
    };
    assert!(actual.validate_for(&expected).is_ok());
    actual.plugin_version = "1.2.4".into();
    assert!(actual.validate_for(&expected).is_err());
}

#[test]
/// Lists and tables must bind to declared records and scalar cells, rather than arbitrary JSON selectors.
fn native_collections_validate_bound_columns() {
    let mut value = manifest_value();
    value["configuration"]["settings"]["root"]["properties"]["rows"] = json!({"schema":{"type":"array","max_items":100,"items":{"type":"object","properties":{"name":{"schema":{"type":"string","max_length":128},"required":true}}}},"required":true});
    value["configuration"]["settings"]["defaults"]["rows"] = json!([{"name":"first"}]);
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["root"]["children"].as_array_mut().unwrap().push(json!({"id":"table","kind":"table","path":["rows"],"columns":[{"label":"Name","path":["name"]}],"empty_text":"No records"}));
    assert!(parse(value.clone()).is_ok());
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["root"]["children"][2]["columns"]
        [0]["path"] = json!(["unknown"]);
    assert!(parse(value).is_err());
}

#[test]
/// Empty host drafts are legal definitions, but the same missing mandatory values cannot be saved.
fn required_host_fields_can_start_without_defaults() {
    let schema: ConfigurationSchema = serde_json::from_value(json!({"version":1,"root":{"type":"object","properties":{"address":{"schema":{"type":"string","min_length":1,"max_length":256},"required":true}}},"defaults":{}})).unwrap();
    assert!(schema.validate_host_definition().is_ok());
    assert!(schema.validate_definition().is_err());
    assert!(schema.validate(1, &json!({})).is_err());
    assert!(schema.validate(1, &json!({"address":"localhost"})).is_ok());
}

#[test]
/// Strict variants reject accidental configuration typos and cannot share an editable path twice.
fn native_nodes_reject_unrecognized_fields_and_duplicate_bindings() {
    let mut value = manifest_value();
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["root"]["children"][0]["script"] =
        json!("ignored?");
    assert!(parse(value).is_err());
    let mut value = manifest_value();
    value["entrypoints"]["views"]["example.demo.settings-view"]["view"]["root"]["children"][1] =
        json!({"id":"other","kind":"field","label":"Other","path":["enabled"],"control":"toggle"});
    assert!(parse(value).is_err());
}

#[test]
/// An explicit null error must not be treated as an absent error alongside a success result.
fn rpc_null_error_member_is_invalid() {
    assert!(
        serde_json::from_value::<RpcResponse>(
            json!({"jsonrpc":"2.0","id":1,"result":true,"error":null})
        )
        .is_err()
    );
}
