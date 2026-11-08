import { send } from './bridge.js';

const boot = Math.random().toString(36).slice(2);

// DOM仅提供几何诊断；真正的显示和遮挡仍由候选窗口的系统像素验收。
function inspect(request_id) {
  const input = document.getElementById('draft');
  const bounds = input.getBoundingClientRect();
  send({ request_id, boot, draft: input.value, width: innerWidth, height: innerHeight,
    dpr: devicePixelRatio, focused: document.activeElement.id,
    inputX: bounds.x + bounds.width / 2, inputY: bounds.y + bounds.height / 2,
    visibility: document.visibilityState, background: getComputedStyle(document.body).backgroundColor,
    paint: performance.getEntriesByType('paint').map(p => ({ name: p.name, start: p.startTime })) });
}

// native-input由系统输入单独判定，宿主脚本更新草稿不伪造可信输入事件。
function onInput(event) {
  send({ request_id: 'native-input', draft: event.target.value, trusted: event.isTrusted });
}

// 两帧后读回确保本次状态更新已进入布局，避免旧帧尺寸造成虚假通过或失败。
function onHostMessage(event) {
  const message = event.detail;
  if (message.operation === 'draft') document.getElementById('draft').value = message.value;
  document.getElementById('status').textContent = '宿主回执已收到';
  requestAnimationFrame(() => requestAnimationFrame(() => inspect(message.request_id)));
}

document.getElementById('draft').addEventListener('input', onInput);
window.addEventListener('kerminal:message', onHostMessage);
inspect('ready');

// 只发送很小的探针；必须由浏览器CSP拒绝，不能用宿主接收POST后返回404冒充提前拦截。
async function verifyBridgeOnlyTransport() {
  let onViolation;
  const violation = new Promise(resolve => {
    const timeout = setTimeout(() => {
      window.removeEventListener('securitypolicyviolation', onViolation);
      resolve(false);
    }, 1500);
    onViolation = event => {
      if (event.effectiveDirective !== 'connect-src') return;
      clearTimeout(timeout);
      window.removeEventListener('securitypolicyviolation', onViolation);
      resolve(true);
    };
    window.addEventListener('securitypolicyviolation', onViolation);
  });
  const rejected = await fetch(location.href, { method: 'POST', body: 'bounded-policy-probe' })
    .then(() => false, () => true);
  send({ request_id: 'connect-policy', blocked: rejected && await violation });
}

verifyBridgeOnlyTransport();
