# Kerminal 插件市场

这里维护 Kerminal 插件源码、独立 SDK、完整目录源文件和签名发布工具。客户端通过静态签名目录发现插件，不依赖 GitHub 搜索 API。GitHub Releases 保留完整分发；官方小型示例另提供固定 tag 下的同字节 Raw 镜像，以便不借助 GitHub token 安装。

## 使用

Kerminal → 设置 → 插件 → 市场。安装后插件仍保留在市场；“已安装”用于管理本机状态。安装、更新、启用、禁用和卸载在正常重启后生效。

- [受信来源配置](catalog/github-source.json)：固定来源 ID、公钥、命名空间和下载来源。
- [签名目录](https://raw.githubusercontent.com/kongweiguang/Kerminal-Plugins/refs/heads/main/catalog/index.json)及[分离签名](https://raw.githubusercontent.com/kongweiguang/Kerminal-Plugins/refs/heads/main/catalog/index.json.minisig)，保留 [Release 分发](https://github.com/kongweiguang/Kerminal-Plugins/releases/tag/plugins-catalog-v1)。
- [工作台便笺 1.0.0](https://github.com/kongweiguang/Kerminal-Plugins/releases/tag/plugin-workbench-v1.0.0)：Windows x64 原生示例，包含主机类型、便笺 Tab、右栏工具、设置和命令。

来源 ID `kerminal-github` 和公钥沿用原 Kerminal 示例源。新仓库初始目录 sequence 为 2，Raw 镜像目录为 3；1.0.0 包逐字迁移，SHA-256 保持不变。原仓库的旧 release 保留；升级来源地址后继续沿用原身份，不由新来源接管已安装包。新版默认信任审核后的 `kerminal.*` 官方命名空间及历史 `example.workbench`，下载域名包含 `github.com`、`release-assets.githubusercontent.com` 和 `raw.githubusercontent.com`。已有用户保存的来源不会自动扩大信任或改 URL；需在来源管理中核对公钥、命名空间和新地址后明确更新。

官方示例 Raw 包固定到 tag `plugin-workbench-1.0.0-windows-x86_64`，不跟随 main。已发布 tag 与版本包不得改写。主分支目录和签名分两次读取；更新间隙或 CDN 缓存不一致时，客户端拒绝刷新并保留上一份完整缓存，可稍后重试。所有入口使用同一公钥、摘要和单调 sequence 校验，不因使用 Raw 而跳过签名。

## 开发

源码在 [`sdk/examples/workbench-demo`](sdk/examples/workbench-demo)，它只依赖本仓库的协议及 SDK，不依赖 Kerminal 内部 crate。Rust 1.98、Node 22.13+，无需构建桌面应用：

```powershell
cargo test --locked --workspace
npm --prefix sdk/frontend test
node --test sdk/examples/workbench-demo/build.test.mjs sdk/examples/workbench-demo/web.test.mjs
cargo test --manifest-path sdk/examples/workbench-demo/Cargo.toml
cargo build --locked -p kerminal-plugin-tools
node sdk/examples/workbench-demo/build.mjs --native-only --tool target/debug/kerminal-plugin.exe --out .local/workbench-demo.tar
```

Linux 的工具路径为 `target/debug/kerminal-plugin`。每个平台独立构建，不能把 Windows 包标为 Linux。默认包含 WebView 的开发示例与生产原生包分开；当前不把 WebView 开发示例当作已交付的宿主能力。不要以相同 ID/版本发布不同字节。

## 目录与发布

[`catalog/plugins.json`](catalog/plugins.json) 是完整插件列表源文件。每个条目固定真实包地址、签名地址、SHA-256、字节数和密钥身份。新增或更新插件通过 PR 同时提交源码及该列表；目录只展示已审核、实际发布且可验签的包。没有评分、安装量或付费数据。

[`marketplace/prepare-catalog.ps1`](marketplace/prepare-catalog.ps1) 根据完整列表下载并验证所有包，生成完整目录并签名。它不需要桌面应用，也不会执行插件代码。签名私钥和密码始终保存在仓库之外：

```powershell
$password = Read-Host 'Signing password' -AsSecureString
./marketplace/prepare-catalog.ps1 -PluginToolPath target/debug/kerminal-plugin.exe `
  -SecretKeyPath C:/private/publisher.key -SigningPassword $password `
  -Sequence 4 -OutputDirectory .local/catalog-4
```

准备阶段默认不发布。核对生成的 `index.json`、签名及 `catalog-receipt.json` 后，在单一发布者控制下，将新包先作为独立不可变 release 发布，最后更新 `plugins-catalog-v1` 的目录和签名。目录有效期最多 31 天，过期前递增 sequence 并重新签名；离线或过期目录不会影响已安装插件使用。目录与分离签名不能经 GitHub API 原子替换，客户端在替换间隙验签失败时保留上次完整缓存并可重试。

已经下载的完整 Release 资产可用 `-ArtifactsDirectory <目录>` 离线准备。文件名必须对应列表中的实际 URL；仍逐项检查完整包签名、身份、SHA-256 和大小，不因为来自本地就跳过验证。联网失败会保留失败现场并退出，换新输出目录重试，不覆盖旧候选。

初始单示例发布可使用经过恢复测试的 [`publish-github.ps1`](marketplace/publish-github.ps1)。它会拒绝丢弃其他插件的旧目录；有多个插件后应使用完整列表生成结果并审核发布，不得用单示例发布器覆盖完整列表。后续发布前，核对旧目录序列及每个已发布 ID/版本的摘要，不覆写已有版本。

本仓库 CI 只验证和构建无签名候选，不持有签名密钥，也不会自动更新市场。首次正式目录及包已由本地受控发布链路发布。发布状态以实际 Release 为准。

## 来源与授权

SDK 和示例来自 [Kerminal](https://github.com/kongweiguang/Kerminal)，按 GPL-3.0-or-later 分发，保留原许可证。源码快照及首包迁移记录见 [`catalog/provenance.json`](catalog/provenance.json)。首次迁移沿用原已签名包，独立 CI 的后续构建不宣称可逐字复现该历史包。`packages/` 仅保存已审核的小型官方示例镜像，不作为任意插件二进制上传入口。

签名用于验证来源与完整性；原生后端以当前用户权限运行，不是 OS 安全沙箱。请只安装你信任的插件。
