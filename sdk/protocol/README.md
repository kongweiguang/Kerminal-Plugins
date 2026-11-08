# Kerminal plugin protocol

`kerminal-plugin-protocol` contains portable Serde declarations. It depends on no
Kerminal product crate, UI toolkit, process runner, filesystem service, or Vault.
The protocol version is independent of the application's release version.

## Package manifest

`manifest.json` uses `schema_version: 1`. The required identity fields are `id`,
`name`, `version` (SemVer), `api: { major, min_minor }`, and `platforms`. Runtime
entrypoints, contributions, configuration schemas and the exact file inventory
remain declarative. `extensions` is the only open-ended metadata object; unknown
permissions, component kinds, and ordinary declaration fields are rejected.

Every contribution, view and host configuration type belongs to the plugin's
`id.` namespace. IDs are stable ASCII identities, not translated display names.
The `kerminal` namespace is reserved. Files use portable forward-slash relative
paths; traversal, Windows device names, case aliases, absolute paths and symbolic
links are not valid package inputs. `files` lists every payload file with its
SHA-256 and byte length, excluding `manifest.json` itself. A plugin consisting
only of native declarations may have an empty file inventory.

`ExternalPluginManifest::parse` yields an immutable `ValidatedManifest`. This
proves declaration validity only. Package signature verification and trusted
source/key selection are separate installer responsibilities. A manifest cannot
grant trust to itself.

The installer signs/verifies the original archive bytes with a detached signature.
No JSON canonicalization or self-referential manifest hash is required. The host
must then verify the exact inventory before making an installation active.

## Configuration

`ConfigurationSchema` supports strings, booleans, bounded signed integers, finite
numbers, bounded arrays and objects. It has no scripts, remote references or
process-assisted validators. Unknown data fields are preserved; unknown versions
cannot be silently reinterpreted as defaults.

Settings and saved view states require valid complete defaults. Host forms may
start with missing mandatory inputs: `validate_host_definition` checks supplied
defaults, while normal `validate` still requires mandatory fields before save.

Settings secrets use declared `secret_slots` and the host's existing Vault
transactions. Native forms never receive plaintext saved secrets or raw Vault
references. Unknown settings keys, envelope fields or secret slots prevent a
codec from claiming complete private-reference coverage. External host codecs
currently make no reference-coverage claim; per-host secret slots are rejected
until a dedicated host credential contract exists.

Installed metadata and local codecs remain available when execution is disabled
or the platform/API is unsupported. Configuration scanning, file watching,
migration and the standalone validator must use the same static declarations and
must never start a sidecar or WebView.

## Native views

Private plugin data uses manifest `data_version`, a positive integer that defaults
to `1` for older packages. The initial host does not run data migrations. Updates
and rollbacks must preserve that version and all existing host, settings, content
and tool state contracts. Matching schema version numbers alone is insufficient:
existing complete schemas, including defaults and secret slots, must remain equal.
Even a new optional property can collide with an unknown value preserved by an
older schema. Adding fields to an existing schema therefore requires future
support for preflighting actual saved data or an explicit migration; it is not
silently approved by comparing schema versions. New state owners may be added,
but an older package without those owners is not a safe rollback target. Saved
content kinds and tool scopes cannot disappear. Uninstall retains data and
the last verified contract, so reinstall is subject to the same compatibility
check. A corrupt or unverifiable current package cannot authorize replacement.

For a currently supported host API, a host or command contribution requires a
process entrypoint on every advertised platform. Future unsupported API metadata
can remain readable for static configuration recovery; it cannot be executed.

Native components are `column`, `row`, `group`, `text`, `field`, `secret`,
`button`, `notice`, `separator`, `list` and `table`. The host owns the theme,
density, scrolling, focus, input method, dialog shell and persistence.

Field paths are arrays of literal object keys, such as `["connection", "port"]`.
There are no executable selectors, CSS, arbitrary layout expressions or array
index editing. One field has at most one editor per view. Lists and tables bind
to declared arrays of records and scalar columns. Tree depth is bounded to 16 and
the complete tree to 256 nodes.

Buttons reference a declared command. They enter the same host command path as
keyboard and menu invocations. The host captures the source instance and target;
plugins cannot replace them with the currently focused tab. A `secret` node maps
to the host-owned settings secret area and never creates a second secret editor.

A command originating in a content or tool view captures its current validated
ordinary inputs. `command.invoke` carries `arguments: { state_version, state,
edit_generation }` and the same opaque `context.instance` as that view. Invalid
raw input blocks submission; it is never replaced with the last valid value or
an empty argument object. Commands without a view snapshot use empty arguments.
Settings and host forms keep their separate host-owned save transaction.

A definite successful receipt confirms only the submitted edit generation in
the original live view. It does not rewrite input text or selection. Later edits
remain dirty; failed, unknown and stale receipts never confirm a draft. Dynamic
views then read authoritative state through their declared activation lifecycle.
The operation journal stores none of these arguments.

Content and tool views may opt into `lifecycle: { activate, visibility, close }`
alongside `root`. Each flag is a boolean; omitting `lifecycle` keeps the view fully
local. A lifecycle requires a process entrypoint on every supported platform.
Host forms and settings pages cannot declare it: their drafts and commits remain
owned by the host's configuration transaction.

`view.activate` reads initial data; `view.visibility` synchronizes actual
visibility and window activity. Their payload is `{ view, state_version, state,
visible, window_active }`. Activation returns `{ state_version, state }`;
visibility returns the same snapshot or `{ acknowledged: true }`. These are
read operations: neither may create a session or other persistent resource.
Resource creation goes through an explicit command. The context's opaque
`instance` identifies the view owner; it is shared with commands originating from
that view and its later close request.

The host keeps at most one lifecycle read in flight per view and coalesces rapid
visibility changes. Replies are locally schema-checked and never overwrite an
edited draft. Invalid or unavailable data retains the existing content with a
local retry action. Rendering, registration and settings scanning issue no RPC.

Views with `lifecycle.activate: true` also receive `plugin.view.state`
notifications through the existing bounded process event channel. `params` is
`{ context: { generation: 1, instance, target: null }, payload: { state_version,
state } }`; use the opaque instance from `view.activate`, not a current-window
identifier or command target. The host additionally verifies the actual emitting
process generation. Notifications carry complete snapshots, not patches. An
event that arrives after a read request takes precedence over that read's later
response. Drafts remain untouched.

Each active view creates one weak event subscription; repeated activation does
not add another. Hidden or inactive views mark their data stale without applying
each event or starting a read. A lagged receiver marks the same stale state for
the next explicit activation or local retry. Closing the view removes its
subscription. Other event names and unrelated instance/process identities are
ignored by this adapter.

`view.close` carries `{ view, state_version, state }` and returns `{ closed: true }`
only after the view's resources are released. The host writes its operation ID to
the recovery journal before dispatch. If the response or receipt save is unknown,
the original view remains owned; another close attempts `operation.query` for
that ID, never a second `view.close`. A successful query must contain
`{ status: "succeeded", result: { closed: true } }`. Dropped or timed-out close
futures retain this recovery state. Completed journal receipts can satisfy later
queries without restarting a process.

## Process requests

The transport is bounded JSON-RPC 2.0. IDs are nonzero unsigned integers. A response
has exactly one result or error; `result: null` is valid, `error: null` is not.
Requests and responses use separate process generations and host-minted opaque
target handles. Method effects and API permissions are classified by the host,
not by plugin-supplied flags.

`initialize` takes `HandshakeParams` and returns `HandshakeResult`. Both protocol
and exact installed plugin identity/version must match. Other host requests use
`InvocationParams { context, payload, operation_id? }`. A context's target is an
opaque grant, not a host ID that the plugin may freely construct.

`host.test` takes `HostRequestParams` and returns `HostTestResult`. A missing,
malformed or false success value is not a successful connection test.

`host.open` takes the same request and returns `HostOpenResult`. It is a pure
conversion to a declared content-tab intent. It must not create persistent
resources before a content owner has been established. The host verifies the
content identity, scope, state version and schema before opening the tab.

Mutation recovery uses `OperationQueryParams` and `OperationStatus`. `unknown`
does not authorize replaying a mutation. The host retains the operation owner
until a real result or explicit recovery decision exists.

The journal persists only provider, verified package digest, operation/opaque
target identities, command identity, explicit command-or-close kind, source
generation and outcome. A declared command named like a close method cannot be
interpreted as a successful view close. Older records without a kind remain
ordinary command receipts. The journal stores no
arguments, secret, raw path or result body. On restart an unfinished record is
shown as unknown and is not replayed. A changed package digest cannot query an
older package's operation; the original record stays available for recovery.

Native sidecar permissions constrain host APIs; they are not an operating-system
sandbox. Installing and executing native code still requires the host's explicit
trust decision and package verification.
