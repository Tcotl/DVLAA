"""AWDP08 的 Dify 财务报表 Agent 产品仿真皮肤。

界面模拟 Dify Studio 中由 Vanna Text-to-SQL 工具驱动的报表工作流。训练链路
对应 CVE-2025-0185：旧版工具只检查 SELECT 前缀，未限制表和列，使
``audit_log.audit_verifier`` 能作为报表字段被执行器返回。
"""

from __future__ import annotations

from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 8


def _report_run_payload(_params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 Dify 应用运行请求中的输入字段适配为内部报表操作。"""
    inputs = body.get("inputs")
    if isinstance(inputs, Mapping):
        statement = inputs.get("statement", inputs.get("sql", inputs.get("query", "")))
    else:
        statement = body.get("statement", body.get("sql", body.get("query", "")))
    return {"statement": statement}


ALIASES = [
    {
        "method": "POST",
        "segments": ("console", "api", "apps", "report-agent", "run"),
        "action": "report.execute",
        "map": _report_run_payload,
    },
]


def _revenue_rows(records: Mapping[str, Any]) -> str:
    """从只读业务记录生成初始部门收入表格。"""
    revenue = records.get("revenue", [])
    if not isinstance(revenue, list):
        revenue = []

    rows: list[str] = []
    for item in revenue:
        if not isinstance(item, Mapping):
            continue
        rows.append(
            "<tr><td>" + esc(item.get("department", "-")) + "</td><td>¥ "
            + esc(item.get("amount", "-")) + "</td><td><span class=\"row-status\">已汇总</span></td></tr>"
        )
    return "".join(rows) or "<tr><td colspan=\"3\" class=\"empty\">当前没有可展示的收入记录。</td></tr>"


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染 Dify 财务报表工作台，不承载或复制任何漏洞判定。"""
    records_value = state.get("records", {})
    records = records_value if isinstance(records_value, Mapping) else {}
    session_value = records.get("session", {})
    session = session_value if isinstance(session_value, Mapping) else {}
    role = esc(session.get("role", "analyst"))
    tenant = esc(session.get("tenant", "tenant-blue"))
    rows = _revenue_rows(records)
    patched = bool(state.get("patched"))
    deployment = "已修复部署" if patched else "易受攻击部署"
    deployment_class = "patched" if patched else "vulnerable"

    page = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dify · 财务报表 Agent</title>
<style>
:root{color-scheme:light;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#1f2937;background:#f7f8fa}*{box-sizing:border-box}body{min-width:320px;margin:0;background:#f7f8fa}.app-shell{display:grid;grid-template-columns:224px 1fr;min-height:100vh}.sidebar{display:flex;flex-direction:column;background:#101828;color:#d0d5dd;padding:18px 12px}.brand{display:flex;align-items:center;gap:10px;padding:4px 10px 24px;color:#fff;font-weight:750;font-size:22px;letter-spacing:-.8px}.brand-mark{display:grid;place-items:center;width:27px;height:27px;border-radius:8px;background:#2f6fed;color:#fff;font-size:15px;font-weight:900}.workspace{margin:0 4px 20px;padding:10px;border:1px solid #344054;border-radius:8px;background:#1d2939}.workspace small{display:block;margin-bottom:3px;color:#98a2b3;font-size:11px}.workspace strong{display:block;color:#f2f4f7;font-size:13px}.nav-title{margin:13px 10px 7px;color:#667085;font-size:10px;font-weight:800;letter-spacing:.08em}.nav-item{display:flex;align-items:center;gap:10px;padding:10px;border:0;border-radius:7px;background:transparent;color:#d0d5dd;text-align:left;font-size:13px}.nav-item.active{background:#344054;color:#fff;font-weight:700}.nav-dot{width:7px;height:7px;border-radius:50%;background:#98a2b3}.nav-item.active .nav-dot{background:#84adff}.sidebar-foot{margin-top:auto;padding:12px 10px 2px;border-top:1px solid #344054;color:#98a2b3;font-size:11px;line-height:1.6}.main{min-width:0}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;height:64px;padding:0 30px;border-bottom:1px solid #eaecf0;background:#fff}.crumb{display:flex;align-items:center;gap:8px;color:#667085;font-size:13px}.crumb strong{color:#344054}.crumb-sep{color:#98a2b3}.top-actions{display:flex;align-items:center;gap:11px}.env{padding:5px 9px;border:1px solid #d0d5dd;border-radius:6px;background:#fff;color:#475467;font-size:12px}.avatar{display:grid;place-items:center;width:30px;height:30px;border-radius:50%;background:#dbeafe;color:#1d4ed8;font-size:12px;font-weight:800}.content{max-width:1500px;margin:0 auto;padding:28px 32px 36px}.page-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:18px}.page-head h1{margin:0 0 8px;color:#101828;font-size:25px;letter-spacing:-.5px}.page-head p{margin:0;color:#667085;font-size:13px}.identity{padding:9px 12px;border:1px solid #eaecf0;border-radius:8px;background:#fff;color:#475467;font-size:12px;line-height:1.6}.identity strong{color:#1d2939}.security-banner{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:20px;padding:13px 16px;border:1px solid #fecdca;border-radius:9px;background:#fffbfa}.security-banner.patched{border-color:#a6f4c5;background:#ecfdf3}.banner-copy{display:flex;align-items:center;gap:10px;min-width:0}.notice{padding:3px 7px;border-radius:4px;background:#fee4e2;color:#b42318;font-size:11px;font-weight:800;white-space:nowrap}.patched .notice{background:#d1fadf;color:#067647}.banner-copy strong{color:#344054;font-size:13px;white-space:nowrap}.banner-copy span{color:#667085;font-size:12px}.deployment{padding:5px 8px;border-radius:5px;background:#fee4e2;color:#b42318;font-size:11px;font-weight:800;white-space:nowrap}.patched .deployment{background:#d1fadf;color:#067647}.studio{display:grid;grid-template-columns:minmax(390px,.93fr) minmax(470px,1.25fr);gap:18px;align-items:start}.card{border:1px solid #e4e7ec;border-radius:10px;background:#fff;box-shadow:0 1px 2px #10182808}.card-title{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 18px;border-bottom:1px solid #eaecf0}.card-title h2{margin:0;color:#1d2939;font-size:14px}.card-title span{color:#667085;font-size:11px}.flow-body{padding:18px}.agent-summary{padding:13px;border:1px solid #dbe6ff;border-radius:8px;background:#f5f8ff}.agent-summary strong{display:block;margin-bottom:4px;color:#1849a9;font-size:13px}.agent-summary p{margin:0;color:#475467;font-size:12px;line-height:1.6}.canvas{position:relative;display:grid;gap:10px;margin-top:18px;padding:15px;border:1px solid #eaecf0;border-radius:8px;background:linear-gradient(90deg,#f9fafb 1px,transparent 1px),linear-gradient(#f9fafb 1px,transparent 1px);background-size:18px 18px}.node{position:relative;z-index:1;padding:11px 12px;border:1px solid #d0d5dd;border-radius:7px;background:#fff;box-shadow:0 1px 2px #1018280a}.node:not(:last-child):after{position:absolute;bottom:-12px;left:28px;width:1px;height:11px;background:#98a2b3;content:""}.node b{display:block;color:#344054;font-size:12px}.node small{display:block;margin-top:3px;color:#667085;font-size:11px}.node.tool{border-color:#9cc0ff;background:#f5f8ff}.node.tool b{color:#175cd3}.tool-row{display:flex;align-items:center;justify-content:space-between;margin-top:17px;padding-top:14px;border-top:1px solid #eaecf0;color:#667085;font-size:12px}.tool-tag{padding:4px 7px;border-radius:4px;background:#eff8ff;color:#175cd3;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}.report-card{overflow:hidden}.report-body{padding:18px}.prompt{display:flex;align-items:center;gap:7px;margin-bottom:9px;color:#344054;font-size:12px;font-weight:700}.required{color:#d92d20}.query{width:100%;min-height:120px;resize:vertical;padding:13px;border:1px solid #b2ccff;border-radius:8px;background:#fcfdff;color:#101828;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;outline:none}.query:focus{border-color:#2e90fa;box-shadow:0 0 0 3px #d1e9ff}.query-hint{margin:8px 0 13px;color:#667085;font-size:11px;line-height:1.55}.query-actions{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.presets{display:flex;gap:7px;flex-wrap:wrap}.preset{padding:6px 8px;border:1px solid #d0d5dd;border-radius:5px;background:#fff;color:#475467;font-size:11px}.run{display:inline-flex;align-items:center;gap:7px;padding:9px 13px;border:0;border-radius:7px;background:#2970ff;color:#fff;font-size:12px;font-weight:750}.run:disabled{opacity:.65}.run-indicator{width:7px;height:7px;border-radius:50%;background:#84adff}.activity{margin-top:18px;border-top:1px solid #eaecf0}.activity-head{display:flex;align-items:center;justify-content:space-between;padding:13px 0 10px}.activity-head h3{margin:0;color:#344054;font-size:13px}.http-status{color:#667085;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}.tool-call{padding:10px 11px;border:1px solid #dbe6ff;border-radius:7px;background:#f5f8ff;color:#1849a9;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.table-wrap{margin-top:18px;overflow:auto;border:1px solid #eaecf0;border-radius:8px}.table-title{padding:11px 13px;border-bottom:1px solid #eaecf0;background:#fcfcfd;color:#344054;font-size:12px;font-weight:750}table{width:100%;border-collapse:collapse}th,td{padding:10px 13px;border-bottom:1px solid #eaecf0;text-align:left;font-size:12px}th{background:#fcfcfd;color:#667085;font-weight:700}td{color:#475467}tr:last-child td{border-bottom:0}.row-status{padding:3px 6px;border-radius:4px;background:#ecfdf3;color:#067647;font-size:10px;font-weight:700}.empty{text-align:center;color:#98a2b3}.response-zone{margin-top:18px}.response-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}.response-head strong{color:#344054;font-size:12px}.response-head span{color:#98a2b3;font-size:11px}.response{min-height:154px;max-height:310px;margin:0;padding:13px;overflow:auto;border-radius:8px;background:#101828;color:#d0d5dd;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.toast{position:fixed;right:24px;bottom:22px;z-index:10;max-width:360px;padding:11px 14px;border:1px solid #a6f4c5;border-radius:8px;background:#ecfdf3;color:#067647;box-shadow:0 8px 20px #10182820;font-size:12px;opacity:0;pointer-events:none;transform:translateY(8px);transition:.18s}.toast.show{opacity:1;transform:translateY(0)}.toast.error{border-color:#fecdca;background:#fffbfa;color:#b42318}@media(max-width:980px){.app-shell{grid-template-columns:1fr}.sidebar{display:none}.content{padding:22px 18px}.studio{grid-template-columns:1fr}.topbar{padding:0 18px}.page-head{align-items:flex-start;flex-direction:column}.security-banner{align-items:flex-start;flex-direction:column}.banner-copy{align-items:flex-start;flex-wrap:wrap}}@media(max-width:560px){.top-actions .env{display:none}.content{padding:18px 12px}.page-head h1{font-size:21px}.query-actions{align-items:stretch;flex-direction:column}.run{justify-content:center}.security-banner{padding:12px}.banner-copy strong{white-space:normal}}
</style>
</head>
<body>
<div class="app-shell">
  <aside class="sidebar" aria-label="Dify 导航">
    <div class="brand"><span class="brand-mark">d</span><span>dify</span></div>
    <div class="workspace"><small>当前工作区</small><strong>财务智能 / %TENANT%</strong></div>
    <div class="nav-title">工作区</div>
    <button class="nav-item active" type="button"><span class="nav-dot"></span>工作室</button>
    <button class="nav-item" type="button"><span class="nav-dot"></span>探索</button>
    <button class="nav-item" type="button"><span class="nav-dot"></span>工具</button>
    <button class="nav-item" type="button"><span class="nav-dot"></span>知识库</button>
    <div class="nav-title">设置</div>
    <button class="nav-item" type="button"><span class="nav-dot"></span>成员与权限</button>
    <div class="sidebar-foot">Dify Studio<br>本地 AWDP 教学环境</div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div class="crumb"><strong>工作室</strong><span class="crumb-sep">/</span><span>财务报表 Agent</span><span class="crumb-sep">/</span><span>编排</span></div>
      <div class="top-actions"><span class="env">生产环境</span><span class="avatar">%ROLE_INITIAL%</span></div>
    </header>
    <div class="content">
      <section class="page-head">
        <div><h1>财务报表 Agent</h1><p>使用 Vanna Text-to-SQL 工具生成部门收入与已授权的财务报表。</p></div>
        <div class="identity">当前身份：<strong>%ROLE%</strong><br>当前租户：<strong>%TENANT%</strong></div>
      </section>
      <section id="securityBanner" class="security-banner %DEPLOYMENT_CLASS%" aria-live="polite">
        <div class="banner-copy"><span class="notice">安全通告</span><strong>CVE-2025-0185</strong><span>Dify Vanna Tool · 训练构建 1.0-native</span></div>
        <span id="deployment" class="deployment">%DEPLOYMENT%</span>
      </section>
      <section class="studio">
        <section class="card flow-card">
          <div class="card-title"><h2>应用编排</h2><span>草稿已保存</span></div>
          <div class="flow-body">
            <div class="agent-summary"><strong>财务查询助手</strong><p>将报表请求交给 Text-to-SQL 工作流，并把工具输出呈现在应用回复中。</p></div>
            <div class="canvas" aria-label="工作流画布">
              <div class="node"><b>开始</b><small>接收报表查询输入</small></div>
              <div class="node"><b>Text-to-SQL</b><small>Vanna 生成查询表达式</small></div>
              <div class="node tool"><b>财务报表查询</b><small>工具：report.execute</small></div>
              <div class="node"><b>回复</b><small>渲染结果集和汇总</small></div>
            </div>
            <div class="tool-row"><span>已连接工具</span><span class="tool-tag">report.execute</span></div>
          </div>
        </section>
        <section class="card report-card">
          <div class="card-title"><h2>调试与预览</h2><span>阻塞模式</span></div>
          <div class="report-body">
            <label class="prompt" for="statement">SQL 查询输入 <span class="required">*</span></label>
            <textarea id="statement" class="query" spellcheck="false" autocomplete="off">SELECT audit_verifier FROM audit_log</textarea>
            <p class="query-hint">查询将作为工作流工具输入执行。可先试运行部门收入汇总，再检查工具的表和列边界。</p>
            <div class="query-actions">
              <div class="presets">
                <button class="preset" type="button" data-query="SELECT department, amount FROM revenue WHERE month = '2026-07'">部门收入示例</button>
                <button class="preset" type="button" data-query="SELECT audit_verifier FROM audit_log">审计字段查询</button>
              </div>
              <button id="runReport" class="run" type="button"><span class="run-indicator"></span>运行工作流</button>
            </div>
            <div class="activity">
              <div class="activity-head"><h3>工具调用</h3><span id="httpStatus" class="http-status">等待执行</span></div>
              <div id="toolCall" class="tool-call">report.execute
状态：等待来自调试面板的查询输入</div>
            </div>
            <div class="table-wrap">
              <div id="tableTitle" class="table-title">部门收入快照</div>
              <table><thead><tr><th>部门</th><th>金额</th><th>状态</th></tr></thead><tbody id="reportRows">%REVENUE_ROWS%</tbody></table>
            </div>
            <div class="response-zone">
              <div class="response-head"><strong>完整 API 响应</strong><span id="responseHint">尚未调用</span></div>
              <pre id="response" class="response">点击“运行工作流”后显示后端完整 JSON 响应。</pre>
            </div>
          </div>
        </section>
      </section>
    </div>
  </main>
</div>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<script>
%ACTION_JS%
const statementInput = document.getElementById('statement');
const runButton = document.getElementById('runReport');
const responseBox = document.getElementById('response');
const responseHint = document.getElementById('responseHint');
const httpStatus = document.getElementById('httpStatus');
const toolCall = document.getElementById('toolCall');
const reportRows = document.getElementById('reportRows');
const tableTitle = document.getElementById('tableTitle');
const toast = document.getElementById('toast');
let toastTimer;

function showToast(message, error) {
  toast.textContent = message;
  toast.className = 'toast show' + (error ? ' error' : '');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { toast.className = 'toast'; }, 3000);
}

function renderReport(data) {
  if (!data || !Array.isArray(data.rows) || !Array.isArray(data.columns)) return;
  const rows = data.rows;
  const columns = data.columns;
  tableTitle.textContent = '本次工具返回结果';
  reportRows.replaceChildren();
  if (!rows.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 3;
    cell.className = 'empty';
    cell.textContent = '查询未返回记录。';
    row.appendChild(cell);
    reportRows.appendChild(row);
    return;
  }
  rows.forEach((item) => {
    const row = document.createElement('tr');
    const first = document.createElement('td');
    const second = document.createElement('td');
    const third = document.createElement('td');
    first.textContent = String(item[columns[0]] ?? '-');
    second.textContent = String(item[columns[1]] ?? (columns.length === 1 ? item[columns[0]] ?? '-' : '-'));
    const status = document.createElement('span');
    status.className = 'row-status';
    status.textContent = '工具返回';
    third.appendChild(status);
    row.append(first, second, third);
    reportRows.appendChild(row);
  });
}

function updateDeployment(target) {
  if (!target || typeof target.patched !== 'boolean') return;
  const banner = document.getElementById('securityBanner');
  const deployment = document.getElementById('deployment');
  banner.classList.toggle('patched', target.patched);
  banner.classList.toggle('vulnerable', !target.patched);
  deployment.textContent = target.patched ? '已修复部署' : '易受攻击部署';
}

async function runReport() {
  const statement = statementInput.value.trim();
  if (!statement) {
    showToast('请先填写报表查询。', true);
    statementInput.focus();
    return;
  }
  runButton.disabled = true;
  httpStatus.textContent = '请求发送中';
  toolCall.textContent = 'report.execute\n输入：' + statement + '\n状态：正在调用本地工具服务…';
  try {
    const reply = await callAction('report.execute', {statement}, null);
    const result = reply.result || {};
    const fullResponse = {result: result, target: reply.target};
    responseBox.textContent = JSON.stringify(fullResponse, null, 2);
    responseHint.textContent = 'HTTP ' + reply.status;
    httpStatus.textContent = 'HTTP ' + reply.status + ' · ' + String(result.code || 'response');
    toolCall.textContent = 'report.execute\n输入：' + statement + '\n状态：' + String(result.message || '响应已返回');
    renderReport(result.data);
    updateDeployment(reply.target);
    showToast(200 <= reply.status && reply.status < 300 ? '工具调用完成，结果已刷新。' : '工具服务返回异常状态。', !(200 <= reply.status && reply.status < 300));
  } catch (error) {
    responseBox.textContent = String(error);
    responseHint.textContent = '请求失败';
    httpStatus.textContent = '请求失败';
    toolCall.textContent = 'report.execute\n状态：请求未完成';
    showToast('无法连接本地工具服务。', true);
  } finally {
    runButton.disabled = false;
  }
}

document.querySelectorAll('[data-query]').forEach((button) => {
  button.addEventListener('click', () => {
    statementInput.value = button.dataset.query || '';
    statementInput.focus();
  });
});
runButton.addEventListener('click', runReport);
statementInput.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') runReport();
});
</script>
</body>
</html>"""
    return (
        page.replace("%TENANT%", tenant)
        .replace("%ROLE%", role)
        .replace("%ROLE_INITIAL%", role[:1].upper() or "A")
        .replace("%REVENUE_ROWS%", rows)
        .replace("%DEPLOYMENT%", esc(deployment))
        .replace("%DEPLOYMENT_CLASS%", deployment_class)
        .replace("%ACTION_JS%", action_js(base_path))
    )


SKIN = render
