"""Langflow 流程诊断控制台的产品仿真皮肤。

该界面以 Flow Builder 的画布、组件检查器和运行面板复现 AWDP04 的教学链：
访客在 preview 模式选择未隔离的 ``code_runner``，读取
``WORKFLOW_VERIFIER`` 诊断字段。后端漏洞判定与 Flag 仍完全由
``target_server._dispatch`` 的 ``workflow.run_tool`` 操作负责。
"""

from __future__ import annotations

from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 4


def _run_payload(_params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 Langflow 风格的运行请求转换为教学目标的诊断操作。"""
    return {
        "mode": body.get("mode", body.get("run_mode", "preview")),
        "tool": body.get("tool", body.get("component", "diagnostics")),
        "field": body.get("field", body.get("diagnostic_field", "node_status")),
    }


ALIASES = [
    {
        "method": "POST",
        "segments": ("api", "v1", "run"),
        "action": "workflow.run_tool",
        "map": _run_payload,
    },
]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _node_rows(nodes: Mapping[str, Any]) -> str:
    rows = []
    for name, status in nodes.items():
        rows.append(
            "<tr><td><span class=\"node-dot\"></span>"
            + esc(name)
            + "</td><td><span class=\"health\">"
            + esc(status)
            + "</span></td><td>刚刚</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan=\"3\" class=\"empty\">暂无流程节点</td></tr>"


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染只读状态驱动的 Langflow Flow Builder 页面。"""
    records = _mapping(state.get("records"))
    actor = _mapping(records.get("actor"))
    nodes = _mapping(records.get("nodes"))
    actor_id = esc(actor.get("id", "guest"))
    actor_role = esc(actor.get("role", "guest"))
    initial_rows = _node_rows(nodes)
    deployment = "已启用隔离策略" if state.get("patched") else "历史部署：存在越权风险"
    deployment_class = "patched" if state.get("patched") else "vulnerable"

    page = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>订单退款诊断 Flow · Langflow</title>
<style>
:root{color-scheme:dark;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#111019;color:#efedf8}*{box-sizing:border-box}body{margin:0;min-width:1040px;background:#111019}.app{min-height:100vh;display:grid;grid-template-columns:238px 1fr}.sidebar{padding:18px 12px;border-right:1px solid #2b2939;background:#191821}.brand{display:flex;align-items:center;gap:10px;padding:7px 10px 24px;font-weight:750;letter-spacing:-.3px}.brand-mark{width:29px;height:29px;border-radius:8px;background:linear-gradient(135deg,#ae63ff,#7667ff);position:relative}.brand-mark:before,.brand-mark:after{content:"";position:absolute;border-radius:50%;background:#f4eaff}.brand-mark:before{width:8px;height:8px;left:6px;top:6px}.brand-mark:after{width:8px;height:8px;right:6px;bottom:6px}.workspace{margin:0 4px 19px;padding:10px;border:1px solid #373447;border-radius:7px;background:#24222f;color:#e2deed;font-size:12px}.workspace small{display:block;margin-top:4px;color:#9993a9}.nav-label{padding:12px 10px 7px;color:#797388;font-size:10px;font-weight:800;letter-spacing:.1em}.nav-item{display:flex;align-items:center;gap:10px;padding:9px 10px;margin:2px 0;border-radius:6px;color:#aaa5b9;font-size:13px}.nav-item.active{background:#31274a;color:#d9b8ff}.nav-icon{width:15px;text-align:center;color:#a86bff}.side-bottom{position:fixed;bottom:18px;left:14px;width:210px;padding:12px;border-top:1px solid #302e3d;color:#8e889d;font-size:11px;line-height:1.55}.side-bottom strong{display:block;color:#d6d1df;font-size:12px}.main{min-width:0}.topbar{height:61px;display:flex;align-items:center;justify-content:space-between;padding:0 25px;border-bottom:1px solid #2b2938;background:#191820}.crumb{font-size:12px;color:#a49eb2}.crumb strong{color:#efedf8;font-weight:600}.profile{display:flex;align-items:center;gap:10px;font-size:12px;color:#d9d4e3}.avatar{display:grid;place-items:center;width:28px;height:28px;border-radius:50%;background:#5e3b82;color:#f2eaff;font-size:11px;font-weight:800}.content{padding:22px 26px 28px}.flow-heading{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:14px}.flow-heading h1{margin:0;font-size:20px;font-weight:680;letter-spacing:-.3px}.flow-heading p{margin:6px 0 0;color:#9891a7;font-size:12px}.flow-actions{display:flex;gap:9px}.button{border:1px solid #454052;border-radius:6px;padding:8px 12px;background:#272431;color:#ded9e8;font-size:12px;font-weight:650;cursor:pointer}.button.primary{border-color:#9157df;background:#8d50d9;color:white}.button:hover{filter:brightness(1.12)}.risk-banner{display:flex;align-items:center;gap:11px;margin-bottom:16px;padding:11px 13px;border:1px solid #7a4a23;border-radius:7px;background:#2e211c;color:#e9c7a3;font-size:12px}.risk-banner.patched{border-color:#346452;background:#192c29;color:#a7d5bd}.risk-pill{padding:3px 6px;border-radius:4px;background:#55321f;color:#ffca8c;font-size:10px;font-weight:800}.risk-banner.patched .risk-pill{background:#244b3d;color:#bce4cb}.layout{display:grid;grid-template-columns:minmax(570px,1fr) 318px;gap:16px}.panel{border:1px solid #302e3d;border-radius:8px;background:#1c1b25;overflow:hidden}.panel-head{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:1px solid #302e3d}.panel-head h2{margin:0;font-size:13px;font-weight:700}.panel-head small{color:#8d879c;font-size:11px}.canvas{position:relative;height:392px;overflow:hidden;background-color:#17161f;background-image:linear-gradient(#252333 1px,transparent 1px),linear-gradient(90deg,#252333 1px,transparent 1px);background-size:24px 24px}.canvas:before,.canvas:after{content:"";position:absolute;height:2px;background:#8760bb;transform-origin:left center}.canvas:before{left:202px;top:135px;width:146px;transform:rotate(0deg)}.canvas:after{left:470px;top:135px;width:136px;transform:rotate(0deg)}.node{position:absolute;width:156px;border:1px solid #50476a;border-radius:8px;background:#252230;box-shadow:0 10px 28px #06050d44}.node header{display:flex;align-items:center;gap:7px;padding:9px 10px;border-bottom:1px solid #3a3549;font-size:11px;font-weight:750}.node .body{padding:10px;color:#aaa4b6;font-size:10px;line-height:1.45}.node .port{position:absolute;top:39px;width:9px;height:9px;border:2px solid #a566f6;border-radius:50%;background:#1d1b27}.node .in{left:-5px}.node .out{right:-5px}.node-start{left:45px;top:96px}.node-check{left:347px;top:96px}.node-tool{right:44px;top:96px;border-color:#8750c8}.node-type{display:grid;place-items:center;width:17px;height:17px;border-radius:4px;background:#3e3158;color:#d9bdff;font-size:10px}.tool-tag{display:inline-block;margin-top:4px;padding:2px 4px;border-radius:3px;background:#412b51;color:#d7a2ff;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9px}.canvas-note{position:absolute;bottom:17px;left:18px;padding:7px 9px;border:1px solid #393646;border-radius:5px;background:#201e2a;color:#858095;font-size:10px}.inspector{padding:14px}.tabs{display:flex;gap:5px;margin-bottom:14px;padding:3px;border-radius:6px;background:#252330}.tab{flex:1;border:0;border-radius:4px;padding:7px;background:transparent;color:#9790a4;font-size:11px;cursor:pointer}.tab.active{background:#3a3548;color:#f0eaf9}.field-label{display:block;margin:13px 0 6px;color:#aaa3b6;font-size:11px;font-weight:700}.select{width:100%;padding:9px 10px;border:1px solid #454052;border-radius:6px;background:#252330;color:#edeaf5;font-size:12px}.hint{margin:13px 0;padding:9px 10px;border-left:2px solid #a35df3;background:#271f34;color:#afa5bd;font-size:11px;line-height:1.55}.run-button{width:100%;margin-top:14px;border:0;border-radius:6px;padding:10px;background:#9456df;color:white;font-size:12px;font-weight:750;cursor:pointer}.run-button:disabled{opacity:.55;cursor:wait}.result-section{margin-top:16px}.response{min-height:176px;max-height:290px;margin:0;padding:13px;background:#13121a;color:#d8d1e3;overflow:auto;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.response.empty{color:#817a8d}.toast{display:none;margin:0 0 10px;padding:9px 11px;border-radius:6px;background:#263c34;color:#b4e3c4;font-size:11px}.toast.error{background:#482c30;color:#f0b8bd}.node-table{width:100%;border-collapse:collapse;font-size:11px}.node-table th{text-align:left;padding:9px 14px;color:#878194;font-size:10px;font-weight:700}.node-table td{padding:10px 14px;border-top:1px solid #302e3d;color:#c8c2d3}.health{padding:3px 6px;border-radius:4px;background:#203d33;color:#a9dab9;font-size:10px}.node-dot{display:inline-block;width:6px;height:6px;margin-right:7px;border-radius:50%;background:#9f62ef}.empty{text-align:center;color:#817b8d}.footer-note{margin-top:13px;color:#787286;font-size:10px}.footer-note code{color:#bba1de} @media(max-width:1100px){.layout{grid-template-columns:minmax(510px,1fr) 290px}.node-tool{right:19px}}
</style>
</head>
<body>
<div class="app" id="skin" data-base-path="__BASE_PATH__">
  <aside class="sidebar">
    <div class="brand"><span class="brand-mark"></span><span>Langflow</span></div>
    <div class="workspace">订单智能体实验室<small>个人工作区 · 训练环境</small></div>
    <div class="nav-label">构建</div>
    <div class="nav-item active"><span class="nav-icon">F</span>流程</div>
    <div class="nav-item"><span class="nav-icon">C</span>组件</div>
    <div class="nav-item"><span class="nav-icon">R</span>运行记录</div>
    <div class="nav-label">工作区</div>
    <div class="nav-item"><span class="nav-icon">V</span>变量</div>
    <div class="nav-item"><span class="nav-icon">S</span>设置</div>
    <div class="side-bottom"><strong>诊断环境</strong>Langflow 1.0-lab<br>当前角色：__ACTOR_ROLE__</div>
  </aside>
  <main class="main">
    <header class="topbar"><div class="crumb">Flows / 订单智能体实验室 / <strong>订单退款诊断 Flow</strong></div><div class="profile"><span>__ACTOR_ID__</span><span class="avatar">G</span></div></header>
    <section class="content">
      <div class="flow-heading"><div><h1>订单退款诊断 Flow</h1><p>检查订单节点与退款网关的运行状态。</p></div><div class="flow-actions"><button class="button" type="button" id="safeDiagnostics">安全诊断</button><button class="button primary" type="button" id="runTop">运行 Flow</button></div></div>
      <div class="risk-banner __DEPLOYMENT_CLASS__"><span class="risk-pill">CVE-2024-48061</span><span>Langflow 1.0-lab · __DEPLOYMENT__ · preview 运行边界与工具权限需由服务端校验。</span></div>
      <div class="layout">
        <section class="panel"><div class="panel-head"><h2>Flow 画布</h2><small>3 个组件 · 已保存</small></div>
          <div class="canvas">
            <article class="node node-start"><header><span class="node-type">I</span>诊断输入</header><div class="body">订单号与节点名称<br><span class="tool-tag">flow_input</span></div><span class="port out"></span></article>
            <article class="node node-check"><header><span class="node-type">OK</span>节点状态</header><div class="body">读取健康状态摘要<br><span class="tool-tag">diagnostics</span></div><span class="port in"></span><span class="port out"></span></article>
            <article class="node node-tool"><header><span class="node-type">&gt;_</span>工具路由</header><div class="body">预览模式诊断组件<br><span class="tool-tag">code_runner</span></div><span class="port in"></span></article>
            <div class="canvas-note">访客会话：只读 · 画布不可编辑</div>
          </div>
          <div class="panel-head"><h2>节点运行状态</h2><small id="nodeRefresh">来自当前工作区记录</small></div>
          <table class="node-table"><thead><tr><th>组件</th><th>状态</th><th>更新时间</th></tr></thead><tbody id="nodeRows">__NODE_ROWS__</tbody></table>
        </section>
        <aside class="panel"><div class="panel-head"><h2>运行检查器</h2><small>Tool diagnostics</small></div><div class="inspector">
          <div class="tabs"><button class="tab active" type="button" data-mode="preview">Preview</button><button class="tab" type="button" data-mode="production">Production</button></div>
          <label class="field-label" for="mode">运行模式</label><select class="select" id="mode"><option value="preview" selected>preview</option><option value="production">production</option></select>
          <label class="field-label" for="tool">诊断组件</label><select class="select" id="tool"><option value="diagnostics">diagnostics · 节点健康摘要</option><option value="code_runner" selected>code_runner · 内置只读诊断</option></select>
          <label class="field-label" for="field">请求字段</label><select class="select" id="field"><option value="node_status">node_status</option><option value="WORKFLOW_VERIFIER" selected>WORKFLOW_VERIFIER</option></select>
          <div class="hint">组件面板只描述能力；实际访问控制由运行端的角色与参数校验决定。当前默认值用于复现 preview 工具边界问题。</div>
          <button class="run-button" id="runTool" type="button">运行诊断工具</button>
        </div></aside>
      </div>
      <section class="panel result-section"><div class="panel-head"><h2>运行输出</h2><small id="httpStatus">尚未发起运行</small></div><div class="inspector"><div id="toast" class="toast"></div><pre id="response" class="response empty">在右侧选择运行模式、组件和诊断字段，然后运行 Flow。</pre></div></section>
      <div class="footer-note">本地训练目标：<code>__BASE_PATH__</code> · 所有操作仅调用此训练服务的 action API。</div>
    </section>
  </main>
</div>
<script>
__ACTION_JS__
const skin = document.getElementById('skin');
const basePath = skin.dataset.basePath;
const responseBox = document.getElementById('response');
const toast = document.getElementById('toast');
const statusLine = document.getElementById('httpStatus');
const runButton = document.getElementById('runTool');
const nodeRows = document.getElementById('nodeRows');

function showToast(message, failed) {
  toast.textContent = message;
  toast.className = 'toast' + (failed ? ' error' : '');
  toast.style.display = 'block';
}
function renderNodes(nodes) {
  nodeRows.replaceChildren();
  const entries = Object.entries(nodes || {});
  if (!entries.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 3; cell.className = 'empty'; cell.textContent = '暂无流程节点';
    row.appendChild(cell); nodeRows.appendChild(row); return;
  }
  entries.forEach(([name, value]) => {
    const row = document.createElement('tr');
    const nameCell = document.createElement('td');
    const dot = document.createElement('span'); dot.className = 'node-dot';
    nameCell.append(dot, document.createTextNode(String(name)));
    const statusCell = document.createElement('td');
    const health = document.createElement('span'); health.className = 'health'; health.textContent = String(value);
    statusCell.appendChild(health);
    const timeCell = document.createElement('td'); timeCell.textContent = '刚刚';
    row.append(nameCell, statusCell, timeCell); nodeRows.appendChild(row);
  });
}
async function refreshRecords() {
  const recordResponse = await fetch(basePath + '/api/records');
  if (!recordResponse.ok) return;
  const current = await recordResponse.json();
  renderNodes(current.records && current.records.nodes);
  document.getElementById('nodeRefresh').textContent = '刚刚刷新';
}
async function runDiagnostic() {
  const body = {
    mode: document.getElementById('mode').value,
    tool: document.getElementById('tool').value,
    field: document.getElementById('field').value
  };
  runButton.disabled = true;
  showToast('正在通过 Flow runtime 调用诊断组件…', false);
  try {
    const out = await callAction('workflow.run_tool', body);
    const complete = {result: out.result, target: out.target};
    responseBox.textContent = JSON.stringify(complete, null, 2);
    responseBox.classList.remove('empty');
    statusLine.textContent = 'HTTP ' + out.status + ' · ' + (out.result.message || '响应已返回');
    showToast(out.result.message || '运行完成', !out.result.ok);
    if (out.target) {
      const banner = document.querySelector('.risk-banner');
      const patched = Boolean(out.target.patched);
      banner.classList.toggle('patched', patched);
    }
    if (out.status >= 200 && out.status < 300) await refreshRecords();
  } catch (error) {
    responseBox.textContent = String(error);
    responseBox.classList.remove('empty');
    statusLine.textContent = '请求失败';
    showToast('无法连接训练目标。', true);
  } finally {
    runButton.disabled = false;
  }
}
function setSafeDiagnostics() {
  document.getElementById('mode').value = 'preview';
  document.getElementById('tool').value = 'diagnostics';
  document.getElementById('field').value = 'node_status';
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.mode === 'preview'));
}
document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => {
  document.getElementById('mode').value = tab.dataset.mode;
  document.querySelectorAll('.tab').forEach(item => item.classList.toggle('active', item === tab));
}));
document.getElementById('mode').addEventListener('change', event => {
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.mode === event.target.value));
});
runButton.addEventListener('click', runDiagnostic);
document.getElementById('runTop').addEventListener('click', runDiagnostic);
document.getElementById('safeDiagnostics').addEventListener('click', () => { setSafeDiagnostics(); runDiagnostic(); });
</script>
</body>
</html>"""
    return (
        page.replace("__BASE_PATH__", esc(base_path))
        .replace("__ACTOR_ID__", actor_id)
        .replace("__ACTOR_ROLE__", actor_role)
        .replace("__NODE_ROWS__", initial_rows)
        .replace("__DEPLOYMENT__", deployment)
        .replace("__DEPLOYMENT_CLASS__", deployment_class)
        .replace("__ACTION_JS__", action_js(base_path))
    )


SKIN = render
