# 工作台便笺示例（独立外部插件）

用于实际安装的原生包通过 `--native-only` 构建。安装并重启后，可以新建“工作台便笺”类型的主机，填写名称并打开便笺标签页，在“便笺示例”右栏或命令面板中测试宿主确认弹框。在设置的“扩展 → 工作台便笺示例”中修改初始内容和简短提示：保存后，下次从主机列表打开的新便笺采用初始内容；已有便笺保留自己的内容。确认弹框读取最新已保存的简短提示设置。

```powershell
node sdk/examples/workbench-demo/build.mjs --native-only --tool .local/plugin-target/debug/kerminal-plugin.exe --target-dir .local/plugin-target --out .local/workbench-demo-native.tar
node --test sdk/examples/workbench-demo/build.test.mjs sdk/examples/workbench-demo/web.test.mjs
cargo test --manifest-path sdk/examples/workbench-demo/Cargo.toml
```

`--native-only` 会从 Manifest 中移除 WebView 页面贡献及资源清单，输出独立的原生暂存目录。默认构建仍保留 WebView 开发示例；它不表示当前应用生产工厂已支持安装后的 WebView 页面。不要使用同一插件 ID/版本发布不同内容，发布前选择确定的一种包。

插件声明仅请求设置读取和宿主弹框能力。普通设置不会通过命令行或环境变量传给后端；后端显式调用 `host.settings.read` 取得本插件已提交的值。便笺是本地演示，不建立远程连接、不执行外部命令。确认与取消均返回原调用，重启后未知操作只查询、不自动重放。

This example has its own Cargo workspace and depends only on `kerminal-plugin-sdk` and `serde_json`. It demonstrates all five contribution types:

| Contribution | Example |
| --- | --- |
| Host | A native label form; testing validates local demo input, opening creates a native content tab. No remote connection is claimed. |
| Content | A native dashboard and a separate WebView page, both with per-view note state. |
| Tool | A native right-side tool with a host-owned confirmation action. |
| Settings | Initial content for new host-opened notes and the next confirmation's concise/detailed explanation. |
| Command | A command-palette/tool-header action and an editable default shortcut. |

The backend implements the SDK handshake, `host.test`, `host.open`, `command.invoke`, native view lifecycle and `operation.query`. Host-open reads committed settings to initialize a new note; native activation preserves saved per-view state. Visibility acknowledges the actual host visibility without allocating resources. Close returns `closed: true` for this resource-free example and records its operation identity. The operation query returns known in-process receipts bound to their original view owner, or `unknown`; it never replays an operation. A real resource-owning backend must persist its own recoverable receipts before acknowledging writes. Confirmation and settings requests use the captured host context in the standard `context`/`payload` envelope. Stdout carries protocol frames only.

Build the developer CLI, then build a package for the current machine. Node 22.13 or later is required to strip the frontend SDK’s TypeScript types without a bundler.

```powershell
cargo build -p kerminal-plugin-tools --bin kerminal-plugin
node sdk/examples/workbench-demo/build.mjs --tool target/debug/kerminal-plugin.exe
```

On Linux/macOS use `target/debug/kerminal-plugin` for `--tool`. The script compiles the independent backend, stages the local frontend SDK and assets, and packs only those explicit files. It selects the actual OS/architecture and does not pretend a Windows binary works on other platforms. `--out` can select a new archive path; existing archives are not overwritten.

The unsigned output is a development artifact, not an installable trusted release. Sign it with an external publisher key, verify it, explicitly trust that publisher’s public key and namespace in an isolated Kerminal configuration, then import the tar and its detached `.minisig`. Native and WebView host capability gates still apply. Building this example alone does not establish that every host platform has a working WebView adapter.

The WebView requests the host bridge directly. Opening it in an ordinary browser reports the missing bridge instead of starting a localhost service. Its colors, density and typography follow host theme events; tab state is saved through the view port. A lost save acknowledgement requires a readback before the Save action is re-enabled. Browser draft protection is supplementary: host view-close semantics must be verified in native acceptance.

Generated `target`, `staging` and `dist` directories are ignored. No private key or prebuilt backend is included in the source tree; the reviewed public catalog is maintained separately at the repository root.
