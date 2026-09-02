"""AWDP02 的 Dify 迁移工作流产品仿真皮肤。

本地教学界面模拟 Dify Workflow 中的外部迁移工单导入与预览。CVE-2024-10252
对应的边界失效被映射为旧版预览器将外部备注中的 ``BEGIN MIGRATION NOTE``
提升为执行上下文：导入含 ``migration_verifier`` 的备注后预览即可复现泄露链。
漏洞判定与状态变更完全由 target_server 的既有 action 后端处理。
"""

from __future__ import annotations

from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 2


DEFAULT_TICKET_ID = "TK-2048"
DEFAULT_CUSTOMER = "星辰零售"
DEFAULT_STATUS = "待预览"
DEFAULT_NOTE = "BEGIN MIGRATION NOTE\nmigration_verifier\nEND MIGRATION NOTE"


def _preview_payload(params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 Dify 风格的 preview 请求转换为内部迁移预览操作字段。"""
    del params
    return {"ticketId": str(body.get("ticketId") or body.get("ticket_id") or "").strip()}


ALIASES = [
    {
        "method": "POST",
        "segments": ("console", "api", "workflows", "migration", "preview"),
        "action": "migration.preview_ticket",
        "map": _preview_payload,
    },
]


def _ticket_rows(records: Mapping[str, Any]) -> str:
    tickets = records.get("tickets", {})
    if not isinstance(tickets, Mapping) or not tickets:
        return """<tr class=\"empty-row\"><td colspan=\"4\">迁移队列暂无工单。导入外部工单后将在此显示。</td></tr>"""

    rows: list[str] = []
    for ticket_id, item in tickets.items():
        ticket = item if isinstance(item, Mapping) else {}
        rows.append(
            "<tr>"
            f"<td><code>{esc(ticket.get('id', ticket_id))}</code></td>"
            f"<td>{esc(ticket.get('customer', '未命名客户'))}</td>"
            f"<td><span class=\"tag queued\">{esc(ticket.get('status', '待预览'))}</span></td>"
            "<td><span class=\"source\">外部工单</span></td>"
            "</tr>"
        )
    return "".join(rows)


def _identity(records: Mapping[str, Any]) -> tuple[str, str]:
    """优先使用目标状态中的会话字段；AWDP02 旧状态缺省时提供只读演示身份。"""
    session = records.get("session", {})
    actor = records.get("actor", {})
    session = session if isinstance(session, Mapping) else {}
    actor = actor if isinstance(actor, Mapping) else {}
    user = session.get("user") or session.get("userId") or actor.get("id") or "migration-operator"
    tenant = session.get("tenant") or records.get("tenant") or "tenant-blue"
    return str(user), str(tenant)


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染 Dify 风格的迁移工作流页面，不直接修改目标状态。"""
    del challenge_id
    records = state.get("records", {})
    records = records if isinstance(records, Mapping) else {}
    user, tenant = _identity(records)
    user_initials = esc(user[:2].upper())
    ticket_rows = _ticket_rows(records)
    ticket_data = records.get("tickets", {})
    ticket_count = len(ticket_data) if isinstance(ticket_data, Mapping) else 0
    patched = bool(state.get("patched"))
    deployment_state = "已部署安全边界" if patched else "旧版预览器运行中"
    deployment_class = "patched" if patched else "vulnerable"
    deployment_copy = (
        "外部工单备注以数据段处理，迁移校验字段不会进入预览响应。"
        if patched
        else "外部备注可能被提升为工作流指令，迁移校验字段存在暴露风险。"
    )
    mode_label = "已加固" if patched else "易受攻击"
    alert_border = "#bfe9d9" if patched else "#ffd0cb"
    alert_bg = "#effbf6" if patched else "#fff5f3"
    alert_icon_bg = "#d5f4e5" if patched else "#ffe0dc"
    alert_icon_color = "#187458" if patched else "#c43227"
    alert_text = "#17634f" if patched else "#a52a21"
    cve_border = "#bfe9d9" if patched else "#ffccc5"

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dify · 客服迁移工作流</title>
<style>
:root{{--bg:#f7f8fa;--panel:#fff;--line:#e6e8ec;--text:#1f2937;--muted:#667085;--green:#1c9e77;--green-deep:#15785b;--mint:#e9fbf4;--blue:#2d6cdf;--warn:#d92d20;--warn-bg:#fff3f1;--code:#162033;--shadow:0 4px 18px rgba(16,24,40,.06);--alert-border:{alert_border};--alert-bg:{alert_bg};--alert-icon-bg:{alert_icon_bg};--alert-icon-color:{alert_icon_color};--alert-text:{alert_text};--cve-border:{cve_border};font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);min-width:320px}}button,input,textarea{{font:inherit}}button{{cursor:pointer}}.app-shell{{display:grid;grid-template-columns:68px 238px minmax(0,1fr);min-height:100vh}}.rail{{background:#17202d;color:#c1cad7;display:flex;flex-direction:column;align-items:center;padding:15px 0;gap:8px}}.brand{{width:36px;height:36px;margin-bottom:17px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(135deg,#23bd8b,#18846a);color:#fff;font-weight:850;font-size:13px;letter-spacing:-1px}}.rail-btn{{width:38px;height:38px;border:0;border-radius:9px;background:transparent;color:#9eabba;font-size:17px}}.rail-btn.active{{background:#2a394b;color:#fff}}.rail-spacer{{flex:1}}.avatar{{width:31px;height:31px;border-radius:50%;display:grid;place-items:center;background:#4f46e5;color:#fff;font-size:11px;font-weight:800}}.sidebar{{border-right:1px solid var(--line);background:#fff;padding:19px 13px;overflow:auto}}.workspace{{display:flex;align-items:center;gap:9px;padding:0 7px 18px;border-bottom:1px solid var(--line)}}.workspace-mark{{width:29px;height:29px;border-radius:8px;display:grid;place-items:center;background:#edf7f3;color:var(--green-deep);font-weight:800;font-size:12px}}.workspace strong{{display:block;font-size:13px}}.workspace small{{display:block;margin-top:2px;color:var(--muted);font-size:11px}}.nav-label{{margin:21px 8px 8px;color:#98a2b3;font-size:10px;font-weight:750;letter-spacing:.08em}}.nav-item{{display:flex;align-items:center;gap:10px;padding:10px 10px;margin:2px 0;border-radius:7px;color:#475467;font-size:13px}}.nav-item.selected{{background:#eef9f5;color:var(--green-deep);font-weight:750}}.nav-icon{{width:17px;text-align:center;font-size:15px}}.sidebar-card{{margin:22px 3px 0;padding:12px;border:1px solid #dcefe8;border-radius:9px;background:#f7fcfa}}.sidebar-card strong{{display:block;font-size:12px}}.sidebar-card p{{margin:5px 0 0;color:#627669;font-size:11px;line-height:1.45}}.main{{min-width:0}}.topbar{{height:64px;padding:0 28px;border-bottom:1px solid var(--line);background:#fff;display:flex;align-items:center;justify-content:space-between;gap:15px}}.breadcrumb{{display:flex;align-items:center;gap:8px;min-width:0;color:#667085;font-size:12px}}.breadcrumb b{{overflow:hidden;color:#344054;max-width:330px;text-overflow:ellipsis;white-space:nowrap}}.crumb-arrow{{color:#aab2bd}}.top-actions{{display:flex;align-items:center;gap:9px;white-space:nowrap}}.status-dot{{width:7px;height:7px;border-radius:50%;background:#1c9e77;box-shadow:0 0 0 3px #d9f6ea}}.publish{{border:0;border-radius:6px;padding:8px 12px;background:var(--green);color:#fff;font-size:12px;font-weight:750}}.content{{max-width:1370px;padding:25px 28px 42px}}.workflow-header{{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:17px}}.workflow-title{{display:flex;gap:13px;align-items:center}}.workflow-badge{{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(145deg,#d9faf0,#dff4ff);color:#14795e;font-size:18px}}h1{{margin:0;color:#101828;font-size:22px;letter-spacing:-.02em}}.workflow-title p{{margin:5px 0 0;color:var(--muted);font-size:12px}}.identity{{display:flex;gap:8px;align-items:center;padding:8px 11px;border:1px solid var(--line);border-radius:8px;background:#fff;color:#475467;font-size:11px}}.identity b{{color:#1f2937}}.identity .divider{{width:1px;height:14px;background:var(--line)}}.alert{{display:flex;align-items:flex-start;gap:11px;padding:13px 15px;margin-bottom:18px;border:1px solid var(--alert-border);border-radius:9px;background:var(--alert-bg)}}.alert-icon{{width:23px;height:23px;flex:0 0 23px;border-radius:50%;display:grid;place-items:center;background:var(--alert-icon-bg);color:var(--alert-icon-color);font-size:13px;font-weight:900}}.alert strong{{display:block;color:var(--alert-text);font-size:13px}}.alert p{{margin:3px 0 0;color:#5a6d65;font-size:12px;line-height:1.45}}.cve{{margin-left:auto;padding:4px 7px;border:1px solid var(--cve-border);border-radius:5px;color:var(--alert-text);font:700 10px ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap}}.layout{{display:grid;grid-template-columns:minmax(0,1.13fr) minmax(330px,.87fr);gap:18px}}.card{{border:1px solid var(--line);border-radius:10px;background:var(--panel);box-shadow:var(--shadow)}}.card-header{{display:flex;align-items:center;justify-content:space-between;padding:15px 17px;border-bottom:1px solid var(--line)}}.card-header h2{{margin:0;color:#344054;font-size:14px}}.card-header span{{color:#98a2b3;font-size:11px}}.canvas{{position:relative;min-height:242px;padding:24px 18px;background:linear-gradient(#f9fafb 1px,transparent 1px),linear-gradient(90deg,#f9fafb 1px,transparent 1px);background-size:20px 20px;border-radius:0 0 10px 10px;overflow:hidden}}.flow-line{{position:absolute;top:93px;left:124px;right:127px;height:2px;background:#bfe5d7}}.flow-nodes{{position:relative;display:flex;justify-content:space-between;gap:10px}}.node{{position:relative;width:132px;min-height:107px;padding:12px;border:1px solid #dbe4e1;border-radius:9px;background:#fff;box-shadow:0 2px 7px rgba(16,24,40,.06)}}.node .node-type{{color:#8a98a7;font-size:10px}}.node b{{display:block;margin-top:8px;color:#344054;font-size:12px}}.node small{{display:block;margin-top:5px;color:#778595;font-size:10px;line-height:1.35}}.node.start{{border-color:#aee5d2}}.node.start .node-symbol{{background:#d8f7eb;color:#168262}}.node.llm{{border-color:#c7d9ff}}.node.llm .node-symbol{{background:#e8f0ff;color:#316ad4}}.node.answer{{border-color:#bde8de}}.node.answer .node-symbol{{background:#e1f7f0;color:#168262}}.node-symbol{{width:24px;height:24px;border-radius:6px;display:grid;place-items:center;font-size:12px;font-weight:800}}.canvas-caption{{position:absolute;bottom:13px;left:18px;color:#7e8a99;font-size:11px}}.steps{{padding:16px 17px}}.step{{display:flex;gap:10px;align-items:flex-start;margin:0 0 15px}}.step:last-child{{margin-bottom:0}}.step-no{{width:21px;height:21px;flex:0 0 21px;border-radius:50%;display:grid;place-items:center;background:#effaf6;color:#168262;font-size:11px;font-weight:800}}.step b{{display:block;font-size:12px;color:#344054}}.step p{{margin:3px 0 0;color:#7a8795;font-size:11px;line-height:1.35}}.queue{{grid-column:1/-1}}.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse;text-align:left}}th{{padding:10px 16px;background:#fbfcfd;border-bottom:1px solid var(--line);color:#7b8794;font-size:10px;font-weight:750;letter-spacing:.03em}}td{{padding:12px 16px;border-bottom:1px solid #eff1f3;color:#475467;font-size:12px}}tbody tr:last-child td{{border-bottom:0}}code{{color:#344054;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}}.tag{{display:inline-block;padding:3px 7px;border-radius:5px;font-size:10px;font-weight:700}}.queued{{background:#fff6df;color:#9a6700}}.source{{color:#667085;font-size:11px}}.empty-row td{{padding:24px 16px;color:#98a2b3;text-align:center}}.operation-stack{{display:grid;gap:18px}}.form-card{{padding:17px}}.form-title{{display:flex;align-items:center;gap:9px;margin-bottom:13px}}.form-index{{width:22px;height:22px;border-radius:6px;display:grid;place-items:center;background:#edf9f4;color:#15785b;font-size:11px;font-weight:800}}.form-title b{{font-size:13px;color:#344054}}.form-title span{{margin-left:auto;color:#98a2b3;font-size:10px}}.field-row{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}label{{display:block;margin-bottom:10px;color:#667085;font-size:11px;font-weight:650}}input,textarea{{display:block;width:100%;margin-top:5px;padding:8px 9px;border:1px solid #d9dfe7;border-radius:6px;outline:none;color:#344054;background:#fff;font-size:12px;transition:border .15s,box-shadow .15s}}textarea{{height:84px;resize:vertical;font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}}input:focus,textarea:focus{{border-color:#42b58e;box-shadow:0 0 0 3px #daf5ea}}.form-hint{{min-height:16px;margin:-2px 0 11px;color:#8a96a3;font-size:10px;line-height:1.4}}.button-row{{display:flex;align-items:center;gap:10px}}.run-btn{{border:0;border-radius:6px;padding:9px 12px;background:var(--green);color:#fff;font-size:12px;font-weight:750}}.run-btn:hover{{background:var(--green-deep)}}.run-btn:disabled{{cursor:wait;opacity:.65}}.ghost-btn{{border:1px solid #d8dee7;border-radius:6px;padding:8px 10px;background:#fff;color:#667085;font-size:11px}}.result-card{{grid-column:1/-1;overflow:hidden}}.response-status{{display:flex;align-items:center;gap:7px;color:#667085;font-size:11px}}.response-pill{{padding:3px 6px;border-radius:4px;background:#f2f4f7;color:#667085;font-weight:750}}.response{{min-height:156px;max-height:330px;margin:0;padding:15px 17px;background:var(--code);color:#dbe8ff;overflow:auto;white-space:pre-wrap;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}}.response.empty{{color:#93a4bc}}.toast{{position:fixed;right:22px;bottom:22px;z-index:10;max-width:360px;padding:11px 14px;border-radius:8px;background:#1f2937;color:#fff;box-shadow:0 9px 28px rgba(16,24,40,.22);font-size:12px;opacity:0;pointer-events:none;transform:translateY(12px);transition:.2s}}.toast.show{{opacity:1;transform:translateY(0)}}.toast.error{{background:#a52a21}}@media(max-width:1020px){{.app-shell{{grid-template-columns:62px 1fr}}.sidebar{{display:none}}.layout{{grid-template-columns:1fr}}.queue,.result-card{{grid-column:auto}}}}@media(max-width:650px){{.app-shell{{grid-template-columns:52px 1fr}}.content{{padding:18px 14px 30px}}.topbar{{padding:0 14px}}.workflow-header{{display:block}}.identity{{display:inline-flex;margin-top:13px}}.cve{{display:none}}.flow-nodes{{min-width:460px}}.canvas{{overflow:auto}}.field-row{{grid-template-columns:1fr}}.breadcrumb b{{max-width:145px}}.top-actions .publish{{display:none}}}}
</style>
</head>
<body>
<div class="app-shell">
  <aside class="rail" aria-label="主导航">
    <div class="brand">dify</div>
    <button class="rail-btn active" type="button" title="工作室">◇</button>
    <button class="rail-btn" type="button" title="探索">⌕</button>
    <button class="rail-btn" type="button" title="知识库">▤</button>
    <button class="rail-btn" type="button" title="工具">⌘</button>
    <div class="rail-spacer"></div>
    <div class="avatar" title="{esc(user)}">{user_initials}</div>
  </aside>
  <aside class="sidebar">
    <div class="workspace"><div class="workspace-mark">CM</div><div><strong>客户迁移工作区</strong><small>{esc(tenant)}</small></div></div>
    <div class="nav-label">构建</div>
    <div class="nav-item selected"><span class="nav-icon">◇</span>工作室</div>
    <div class="nav-item"><span class="nav-icon">▣</span>应用</div>
    <div class="nav-item"><span class="nav-icon">▤</span>知识库</div>
    <div class="nav-item"><span class="nav-icon">⌘</span>工具</div>
    <div class="nav-label">监控</div>
    <div class="nav-item"><span class="nav-icon">◷</span>运行日志</div>
    <div class="nav-item"><span class="nav-icon">◌</span>注解回复</div>
    <div class="sidebar-card"><strong>迁移工作流</strong><p>外部工单进入队列后，使用预览节点检查字段映射与下一步安排。</p></div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div class="breadcrumb"><span>工作室</span><span class="crumb-arrow">/</span><b>客服工单迁移助手</b><span class="crumb-arrow">/</span><span>工作流</span></div>
      <div class="top-actions"><span class="status-dot"></span><span style="font-size:11px;color:#667085">{esc(deployment_state)}</span><button class="publish" type="button">发布</button></div>
    </header>
    <section class="content">
      <div class="workflow-header">
        <div class="workflow-title"><div class="workflow-badge">⌘</div><div><h1>外部工单迁移预览</h1><p>将外部客服工单导入工作流，并在预览节点核对迁移字段。</p></div></div>
        <div class="identity"><span>当前身份</span><b>{esc(user)}</b><span class="divider"></span><span>租户</span><b>{esc(tenant)}</b></div>
      </div>
      <section class="alert {esc(deployment_class)}" aria-live="polite">
        <div class="alert-icon">!</div><div><strong>工作流安全状态：{esc(mode_label)}</strong><p>{esc(deployment_copy)}</p></div><span class="cve">CVE-2024-10252</span>
      </section>
      <div class="layout">
        <section class="card">
          <div class="card-header"><h2>工作流编排</h2><span>草稿 · 3 个节点</span></div>
          <div class="canvas">
            <div class="flow-line"></div>
            <div class="flow-nodes">
              <div class="node start"><div class="node-symbol">↳</div><span class="node-type">开始</span><b>接收外部工单</b><small>ticketId、客户与备注</small></div>
              <div class="node llm"><div class="node-symbol">AI</div><span class="node-type">LLM</span><b>迁移字段映射</b><small>整理工单与客户状态</small></div>
              <div class="node answer"><div class="node-symbol">✓</div><span class="node-type">结束</span><b>返回迁移预览</b><small>下一步迁移建议</small></div>
            </div>
            <div class="canvas-caption">运行模式：Preview · 预览不会写入生产迁移任务</div>
          </div>
        </section>
        <section class="card">
          <div class="card-header"><h2>运行路径</h2><span>本地教学目标</span></div>
          <div class="steps">
            <div class="step"><div class="step-no">1</div><div><b>导入外部工单</b><p>保存客户、状态和随工单传入的外部备注。</p></div></div>
            <div class="step"><div class="step-no">2</div><div><b>生成迁移预览</b><p>使用相同工单编号读取队列记录并构造预览。</p></div></div>
            <div class="step"><div class="step-no">3</div><div><b>检查响应字段</b><p>操作结果保留完整 HTTP 状态和响应内容。</p></div></div>
          </div>
        </section>
        <section class="card queue">
          <div class="card-header"><h2>迁移工单队列</h2><span id="ticketCount">当前 {ticket_count} 条</span></div>
          <div class="table-wrap"><table><thead><tr><th>工单编号</th><th>客户</th><th>迁移状态</th><th>来源</th></tr></thead><tbody id="ticketRows">{ticket_rows}</tbody></table></div>
        </section>
        <section class="operation-stack" aria-label="迁移操作">
          <form class="card form-card" id="importForm">
            <div class="form-title"><div class="form-index">1</div><b>导入迁移工单</b><span>外部 Ticket</span></div>
            <div class="field-row"><label>工单编号<input name="ticketId" required value="{DEFAULT_TICKET_ID}"></label><label>客户名称<input name="customer" required value="{DEFAULT_CUSTOMER}"></label></div>
            <label>迁移状态<input name="status" required value="{DEFAULT_STATUS}"></label>
            <label>外部工单备注<textarea name="note" spellcheck="false">{DEFAULT_NOTE}</textarea></label>
            <p class="form-hint">备注会随外部工单保存，预览节点将读取该业务数据。</p>
            <div class="button-row"><button class="run-btn" type="submit">导入到迁移队列</button><button class="ghost-btn" type="button" id="resetImport">恢复示例</button></div>
          </form>
          <form class="card form-card" id="previewForm">
            <div class="form-title"><div class="form-index">2</div><b>运行迁移预览</b><span>Preview</span></div>
            <label>已导入工单编号<input name="ticketId" required value="{DEFAULT_TICKET_ID}"></label>
            <p class="form-hint">预览仅查询迁移队列，不会提交或修改生产迁移任务。</p>
            <div class="button-row"><button class="run-btn" type="submit">生成迁移预览</button></div>
          </form>
        </section>
        <section class="card result-card" aria-live="polite">
          <div class="card-header"><h2>运行结果</h2><div class="response-status"><span class="response-pill" id="httpStatus">等待请求</span><span id="responseSummary">导入工单或生成预览后显示完整 JSON 响应。</span></div></div>
          <pre class="response empty" id="response">请选择上方业务操作。请求会发送到本地 AWDP 教学目标。</pre>
        </section>
      </div>
    </section>
  </main>
</div>
<div class="toast" id="toast" role="status"></div>
<script>
{action_js(base_path)}
const defaultTicket = {DEFAULT_TICKET_ID!r};
const defaultCustomer = {DEFAULT_CUSTOMER!r};
const defaultStatus = {DEFAULT_STATUS!r};
const defaultNote = {DEFAULT_NOTE!r};
const responseBox = document.getElementById('response');
const httpStatus = document.getElementById('httpStatus');
const responseSummary = document.getElementById('responseSummary');
const ticketRows = document.getElementById('ticketRows');
const ticketCount = document.getElementById('ticketCount');
const toast = document.getElementById('toast');
let toastTimer;

function showToast(message, isError) {{
  toast.textContent = message;
  toast.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {{ toast.className = 'toast'; }}, 3200);
}}
function showResponse(result, status) {{
  responseBox.classList.remove('empty');
  responseBox.textContent = JSON.stringify(result, null, 2);
  httpStatus.textContent = 'HTTP ' + status;
  responseSummary.textContent = result.message || result.code || '已收到响应';
}}
function appendTicket(ticket) {{
  if (!ticket || !ticket.id) return;
  const empty = ticketRows.querySelector('.empty-row');
  if (empty) empty.remove();
  const existing = Array.from(ticketRows.querySelectorAll('tr')).find(row => row.dataset.ticketId === String(ticket.id));
  if (existing) existing.remove();
  const row = document.createElement('tr');
  row.dataset.ticketId = String(ticket.id);
  const cells = [ticket.id, ticket.customer || '未命名客户', ticket.status || '待预览', '外部工单'];
  cells.forEach((value, index) => {{
    const cell = document.createElement('td');
    if (index === 0) {{ const code = document.createElement('code'); code.textContent = value; cell.appendChild(code); }}
    else if (index === 2) {{ const tag = document.createElement('span'); tag.className = 'tag queued'; tag.textContent = value; cell.appendChild(tag); }}
    else {{ cell.textContent = value; if (index === 3) cell.className = 'source'; }}
    row.appendChild(cell);
  }});
  ticketRows.prepend(row);
  ticketCount.textContent = '当前 ' + ticketRows.querySelectorAll('tr').length + ' 条';
}}
async function submitAction(form, action, successMessage, onSuccess) {{
  const button = form.querySelector('.run-btn');
  const body = Object.fromEntries(new FormData(form).entries());
  button.disabled = true;
  try {{
    const reply = await callAction(action, body);
    showResponse({{result: reply.result, target: reply.target}}, reply.status);
    const failed = !reply.result.ok;
    showToast(reply.result.message || successMessage, failed);
    if (!failed && onSuccess) onSuccess(reply.result);
  }} catch (error) {{
    const message = String(error);
    responseBox.classList.remove('empty');
    responseBox.textContent = message;
    httpStatus.textContent = '请求失败';
    responseSummary.textContent = '无法连接本地教学目标';
    showToast(message, true);
  }} finally {{ button.disabled = false; }}
}}
document.getElementById('importForm').addEventListener('submit', event => {{
  event.preventDefault();
  submitAction(event.currentTarget, 'migration.import_ticket', '工单已导入', result => {{
    appendTicket(result.data && result.data.ticket);
    document.querySelector('#previewForm [name="ticketId"]').value = event.currentTarget.ticketId.value;
  }});
}});
document.getElementById('previewForm').addEventListener('submit', event => {{
  event.preventDefault();
  submitAction(event.currentTarget, 'migration.preview_ticket', '迁移预览已生成');
}});
document.getElementById('resetImport').addEventListener('click', () => {{
  const form = document.getElementById('importForm');
  form.ticketId.value = defaultTicket;
  form.customer.value = defaultCustomer;
  form.status.value = defaultStatus;
  form.note.value = defaultNote;
}});
</script>
</body>
</html>"""


SKIN = render
