// 单独模块使ready回执同时证明模块导入和宿主注入成功；不以DOM存在冒充引擎工作。
export function send(value) {
  window.kerminalHost.postMessage(value);
}
