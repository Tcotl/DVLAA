"""AWDP10 的 n8n 执行记录产品仿真皮肤。

该页面模拟 n8n 的 Executions 工作台：team-blue 的普通运营人员可查看
运行中的工作流，并通过行内 Stop 控制停止执行。CVE-2025-52554 的漏洞链
由既有 ``executions.stop`` 后端实现：旧版停止路由仅信任 executionId，
从而错误地允许停止 team-red 的 ``exec-red-9007`` 并在响应中泄露回滚校验。
皮肤只负责产品化展示和调用，不复制任何漏洞判定逻辑。
"""

from __future__ import annotations

from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 10


def _mapping(value: Any) -> Mapping[str, Any]:
    """将可能缺失的运行时记录安全收窄为映射。"""
    return value if isinstance(value, Mapping) else {}


def _status_label(status: str) -> str:
    labels = {"running": "运行中", "stopped": "已停止", "success": "成功", "error": "失败"}
    return labels.get(status, status or "未知")


def _stop_execution_alias(params: Mapping[str, Any], body: Mapping[str, Any]) -> dict[str, str]:
    """把 n8n 执行停止路径中的 ID 转为内部动作参数。"""
    del body
    return {"executionId": str(params.get("executionId", ""))}


ALIASES = [
    {
        "method": "POST",
        "segments": ("rest", "executions", "<executionId>", "stop"),
        "action": "executions.stop",
        "map": _stop_execution_alias,
    },
]


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染只读的 n8n Executions 工作台与停止操作入口。"""
    del challenge_id
    records = _mapping(state.get("records"))
    session = _mapping(records.get("session"))
    executions = _mapping(records.get("executions"))
    user_id = str(session.get("userId", "operator-blue"))
    team = str(session.get("team", "team-blue"))
    role = str(session.get("role", "operator"))
    patched = bool(state.get("patched"))

    rows: list[str] = []
    running_count = 0
    for execution_id, raw_execution in executions.items():
        execution = _mapping(raw_execution)
        item_id = str(execution_id)
        status = str(execution.get("status", "unknown"))
        workflow = str(execution.get("workflow", "未命名工作流"))
        execution_team = str(execution.get("team", "unknown"))
        owner = str(execution.get("owner", "unknown"))
        is_own_team = execution_team == team
        if status == "running":
            running_count += 1
        status_class = "running" if status == "running" else "stopped" if status == "stopped" else "other"
        scope_class = "own" if is_own_team else "external"
        scope_label = "当前项目" if is_own_team else "其他项目"
        stop_disabled = " disabled" if status != "running" else ""
        stop_label = "已停止" if status != "running" else "Stop"
        risk_note = "<span class=\"legacy-tag\">旧版路由受影响</span>" if not is_own_team else ""
        rows.append(
            "<tr class=\"execution-row " + scope_class + "\">"
            "<td><span class=\"status-dot " + status_class + "\"></span>"
            "<span data-status-for=\"" + esc(item_id) + "\">" + esc(_status_label(status)) + "</span></td>"
            "<td><code>" + esc(item_id) + "</code></td>"
            "<td><strong>" + esc(workflow) + "</strong><small>手动运行 · 运营自动化</small></td>"
            "<td><span class=\"team-label " + scope_class + "\">" + esc(execution_team) + "</span>"
            "<small>所有者：" + esc(owner) + "</small></td>"
            "<td><span class=\"scope-badge " + scope_class + "\">" + scope_label + "</span>" + risk_note + "</td>"
            "<td class=\"actions\"><button class=\"stop-button\" type=\"button\" data-execution-id=\""
            + esc(item_id) + "\"" + stop_disabled + ">" + stop_label + "</button></td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan=\"6\" class=\"empty\">当前项目没有可显示的执行记录。</td></tr>")

    deployment_class = "patched" if patched else "vulnerable"
    deployment_title = "已应用授权修复" if patched else "检测到旧版执行授权路径"
    deployment_message = (
        "服务端已验证执行归属；跨项目 Stop 会被拒绝，本项目执行仍可停止。"
        if patched
        else "CVE-2025-52554：旧版 /rest/executions/:id/stop 只按执行 ID 停止记录，未校验项目归属。"
    )

    return """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Executions · n8n</title>
<style>
:root{color-scheme:dark;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#191c22;color:#f2f4f7}
*{box-sizing:border-box}body{margin:0;min-width:980px;background:#191c22}.app{display:flex;min-height:100vh}.sidebar{width:240px;padding:20px 12px;background:#202329;border-right:1px solid #30343c}.brand{display:flex;align-items:center;gap:10px;padding:3px 12px 26px;font-size:21px;font-weight:750;letter-spacing:-.5px}.brand-mark{position:relative;width:29px;height:29px;border:3px solid #ff6d5a;border-radius:50%}.brand-mark:before,.brand-mark:after{position:absolute;content:"";width:5px;height:5px;background:#ff6d5a;border-radius:50%;top:-7px}.brand-mark:before{left:2px}.brand-mark:after{right:2px}.project{margin:0 7px 18px;padding:12px;border:1px solid #3a3f49;border-radius:8px;background:#282c33}.project small{display:block;margin-bottom:4px;color:#a7adb8;font-size:11px}.project strong{font-size:13px}.project span{display:block;margin-top:5px;color:#8d94a0;font-size:11px}.nav-label{padding:10px 12px 6px;color:#7f8794;font-size:10px;font-weight:700;letter-spacing:.09em}.nav{display:block;padding:10px 12px;margin:3px 0;border-radius:7px;color:#b8bec9;font-size:13px;text-decoration:none}.nav:hover{background:#2a2e36}.nav.active{background:#3a3031;color:#fff;font-weight:700;box-shadow:inset 3px 0 #ff6d5a}.nav i{display:inline-block;width:17px;color:#aeb4bf;font-style:normal}.sidebar-foot{position:fixed;bottom:22px;width:210px;padding:12px;color:#858c98;font-size:11px;border-top:1px solid #353941}.main{flex:1;min-width:0}.topbar{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 32px;border-bottom:1px solid #30343c;background:#202329}.crumb{color:#aeb4bf;font-size:13px}.crumb strong{margin-left:8px;color:#f3f4f6}.instance{display:flex;align-items:center;gap:10px;color:#c8cdd5;font-size:12px}.avatar{display:grid;place-items:center;width:28px;height:28px;border-radius:50%;background:#425266;color:#f4f7fb;font-size:10px;font-weight:800}.content{max-width:1280px;padding:32px;margin:0 auto}.page-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:22px}.page-heading h1{margin:0 0 7px;font-size:28px;letter-spacing:-.6px}.page-heading p{margin:0;color:#9fa6b2;font-size:13px}.new-execution{padding:10px 15px;border:0;border-radius:6px;background:#ff6d5a;color:#241b1b;font-weight:750;font-size:12px}.summary{display:flex;gap:12px;margin-bottom:20px}.metric{min-width:145px;padding:14px 16px;border:1px solid #363b44;border-radius:8px;background:#24272e}.metric small{display:block;color:#9da4b0;font-size:11px}.metric strong{display:block;margin-top:6px;font-size:20px}.metric .running-number{color:#77d6a6}.identity{margin-left:auto;min-width:280px;padding:13px 16px;border:1px solid #39404a;border-radius:8px;background:#252931;color:#c8cdd4;font-size:12px;line-height:1.55}.identity strong{color:#fff}.alert{display:flex;align-items:flex-start;gap:12px;padding:16px 18px;margin-bottom:20px;border:1px solid #70483f;border-radius:8px;background:#322624}.alert.patched{border-color:#355f51;background:#20322c}.alert-mark{display:grid;place-items:center;flex:0 0 26px;height:26px;border-radius:5px;background:#ff6d5a;color:#2a2020;font-size:12px;font-weight:900}.patched .alert-mark{background:#72d1a0}.alert h2{margin:0 0 4px;font-size:14px}.alert p{margin:0;color:#cbc3c0;font-size:12px;line-height:1.55}.patched p{color:#bed6ca}.alert code{padding:2px 4px;border-radius:3px;background:#191c22;color:#f1c2b8;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}.table-card,.response-card{border:1px solid #363b44;border-radius:9px;background:#24272e;overflow:hidden}.card-head{display:flex;align-items:center;justify-content:space-between;padding:17px 19px;border-bottom:1px solid #363b44}.card-head h2{margin:0;font-size:14px}.card-head span{color:#939aa6;font-size:11px}.filter{padding:7px 10px;border:1px solid #454b56;border-radius:5px;background:#292d35;color:#aeb5bf;font-size:11px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}th{padding:12px 16px;background:#21242a;color:#929aa7;font-size:10px;font-weight:750;letter-spacing:.06em;text-transform:uppercase}td{padding:15px 16px;border-top:1px solid #343941;color:#d6dae0;font-size:12px;vertical-align:middle}.execution-row.external{background:#2a2527}.execution-row:hover{background:#2c3038}td code{color:#d6d9df;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}td strong{display:block;color:#f3f4f5;font-size:13px}td small{display:block;margin-top:4px;color:#9098a5;font-size:11px}.status-dot{display:inline-block;width:8px;height:8px;margin-right:7px;border-radius:50%;background:#9fa6b1}.status-dot.running{background:#63cb94;box-shadow:0 0 0 3px #63cb941f}.status-dot.stopped{background:#8a929f}.team-label,.scope-badge,.legacy-tag{display:inline-block;padding:3px 6px;border-radius:4px;font-size:10px;font-weight:700}.team-label.own,.scope-badge.own{color:#92cef8;background:#25445c}.team-label.external,.scope-badge.external{color:#ffc0b3;background:#5a3431}.scope-badge{margin-right:5px}.legacy-tag{color:#ffb09f;background:#53302d}.stop-button{padding:7px 12px;border:1px solid #ff6d5a;border-radius:5px;background:transparent;color:#ff917f;font-size:11px;font-weight:750;cursor:pointer}.stop-button:hover{background:#4b302f}.stop-button:disabled{border-color:#464b54;color:#7f8792;background:#292d34;cursor:not-allowed}.empty{text-align:center;color:#969eaa}.response-card{margin-top:20px}.response-body{padding:16px 19px}.response-meta{display:flex;align-items:center;justify-content:space-between;min-height:22px;margin-bottom:10px;color:#9ca4b0;font-size:11px}.response-meta strong{color:#dce1e7}.response{min-height:150px;max-height:340px;margin:0;padding:14px;border:1px solid #303641;border-radius:6px;background:#17191e;color:#bdd2c3;overflow:auto;white-space:pre-wrap;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}.toast{position:fixed;right:26px;bottom:26px;z-index:3;max-width:380px;padding:12px 15px;border:1px solid #4a515d;border-radius:7px;background:#2c3038;color:#eef1f5;box-shadow:0 12px 30px #0007;opacity:0;transform:translateY(16px);pointer-events:none;transition:.2s}.toast.show{opacity:1;transform:translateY(0)}.toast.good{border-color:#3d8262}.toast.bad{border-color:#a5554a}.local-note{margin:18px 0 0;color:#818995;font-size:11px}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand"><span class="brand-mark"></span><span>n8n</span></div>
    <section class="project"><small>当前项目</small><strong>AWDP 运营自动化</strong><span>Personal · 本地训练实例</span></section>
    <div class="nav-label">工作区</div>
    <a class="nav" href="#executions"><i>□</i>概览</a>
    <a class="nav" href="#executions"><i>◇</i>工作流</a>
    <a class="nav active" href="#executions"><i>≡</i>执行记录</a>
    <div class="nav-label">管理</div>
    <a class="nav" href="#response"><i>◇</i>凭据</a>
    <a class="nav" href="#response"><i>◌</i>设置</a>
    <div class="sidebar-foot">n8n 风格产品仿真<br>仅连接本地 AWDP 训练服务</div>
  </aside>
  <div class="main">
    <header class="topbar"><div class="crumb">个人空间 <strong>/ AWDP 运营自动化</strong></div><div class="instance"><span>生产实例</span><span class="avatar">OB</span></div></header>
    <main class="content">
      <section class="page-heading"><div><h1>Executions</h1><p>查看并控制当前项目的工作流执行记录。</p></div><button class="new-execution" type="button" disabled>新建执行</button></section>
      <section class="summary"><div class="metric"><small>全部执行</small><strong>""" + str(len(executions)) + """</strong></div><div class="metric"><small>运行中</small><strong class="running-number">""" + str(running_count) + """</strong></div><div class="metric"><small>当前项目</small><strong>""" + esc(team) + """</strong></div><div class="identity">当前身份：<strong>""" + esc(user_id) + """</strong><br>角色：""" + esc(role) + """ · 项目范围：""" + esc(team) + """</div></section>
      <section class="alert """ + deployment_class + """"><span class="alert-mark">!</span><div><h2>""" + deployment_title + """</h2><p>""" + deployment_message + """ <code>CVE-2025-52554</code> · 受影响版本：n8n &lt; 1.99.1</p></div></section>
      <section class="table-card" id="executions"><div class="card-head"><h2>执行记录</h2><span class="filter">全部状态 · 最近 30 天</span></div><div class="table-wrap"><table><thead><tr><th>状态</th><th>执行 ID</th><th>工作流</th><th>项目与所有者</th><th>访问范围</th><th></th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table></div></section>
      <section class="response-card" id="response"><div class="card-head"><h2>操作响应</h2><span>服务端完整 JSON</span></div><div class="response-body"><div class="response-meta"><span id="response-status">选择一条运行中的执行记录，然后使用 Stop。</span><strong id="response-route">POST /rest/executions/:id/stop</strong></div><pre class="response" id="response-json">等待操作响应。</pre></div></section>
      <p class="local-note">本页面为 AWDP 的纯本地教学仿真；停止操作仍由目标服务的既有授权逻辑处理。</p>
    </main>
  </div>
  <div class="toast" id="toast" role="status" aria-live="polite"></div>
</div>
<script>
""" + action_js(base_path) + """
const responseStatus = document.getElementById('response-status');
const responseJson = document.getElementById('response-json');
const toast = document.getElementById('toast');
let toastTimer;

function showToast(message, kind) {
  toast.textContent = message;
  toast.className = 'toast show ' + kind;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { toast.className = 'toast'; }, 3600);
}

function updateExecutionRow(data, button) {
  if (!data || !data.executionId || !data.status) return;
  document.querySelectorAll('[data-status-for]').forEach((cell) => {
    if (cell.dataset.statusFor !== data.executionId) return;
    cell.textContent = data.status === 'stopped' ? '已停止' : data.status;
    const dot = cell.previousElementSibling;
    if (dot) dot.className = 'status-dot ' + (data.status === 'stopped' ? 'stopped' : 'other');
  });
  if (data.status === 'stopped') {
    button.textContent = '已停止';
    button.disabled = true;
  }
}

async function stopExecution(button) {
  const executionId = button.dataset.executionId;
  button.disabled = true;
  button.textContent = '正在停止…';
  responseStatus.textContent = '正在向执行控制服务发送停止请求…';
  try {
    const reply = await callAction('executions.stop', {executionId: executionId});
    responseJson.textContent = JSON.stringify({result: reply.result, target: reply.target}, null, 2);
    const message = reply.result && reply.result.message ? reply.result.message : '服务已返回响应';
    responseStatus.textContent = 'HTTP ' + reply.status + ' · ' + message;
    if (reply.result && reply.result.ok) {
      updateExecutionRow(reply.result.data, button);
      showToast('执行控制请求已完成：' + message, 'good');
    } else {
      button.disabled = false;
      button.textContent = 'Stop';
      showToast('执行控制请求被服务端拒绝：' + message, 'bad');
    }
  } catch (error) {
    responseStatus.textContent = '请求失败';
    responseJson.textContent = String(error);
    button.disabled = false;
    button.textContent = 'Stop';
    showToast('无法连接本地目标服务。', 'bad');
  }
}

document.querySelectorAll('.stop-button').forEach((button) => {
  button.addEventListener('click', () => stopExecution(button));
});
</script>
</body>
</html>"""


SKIN = render
