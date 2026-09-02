"""AWDP03 的 RAGFlow 知识库产品仿真皮肤。

该页面把 RAGFlow 风格的文档导入、分块索引和检索工作台映射到本地教学目标。
CVE-2024-53450 对应的漏洞链是：带有 ``kb_verification_code`` 的导入 annotation
被旧版检索器当作可信上下文，从检索结果中暴露服务端校验码。漏洞判定仍完全由
``target_server._dispatch`` 负责，本模块仅提供产品式界面和 API 形状映射。
"""

from __future__ import annotations

from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 3


def _search_payload(_params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 RAGFlow 知识库检索请求映射到本地教学 action。"""
    return {"query": str(body.get("query", "") or "")}


ALIASES = [
    {
        "method": "POST",
        "segments": ("api", "v1", "kb", "<kbId>", "search"),
        "action": "knowledge.search",
        "map": _search_payload,
    },
]


def _document_rows(documents: list[Mapping[str, Any]]) -> str:
    """生成初始文档列表；所有导入内容在服务端输出前转义。"""
    rows: list[str] = []
    for item in documents:
        document_id = esc(item.get("id", "未命名文档"))
        title = esc(item.get("title", "未命名文档"))
        body = str(item.get("body", "") or "")
        preview = esc(" ".join(body.split())[:72] or "尚未提供正文")
        chunks = max(1, (len(body) + 119) // 120)
        rows.append(
            "<tr>"
            f"<td><span class=\"doc-icon\">DOC</span><div><b>{title}</b><small>{document_id}</small></div></td>"
            f"<td>{preview}</td>"
            f"<td><span class=\"count\">{chunks}</span></td>"
            "<td><span class=\"index-ready\"><i></i> 已索引</span></td>"
            "<td><button class=\"row-action\" type=\"button\">查看</button></td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan=\"5\" class=\"empty\">当前知识库没有文档。</td></tr>"


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染 RAGFlow 风格的退货知识库与检索工作台。"""
    records = state.get("records", {})
    records = records if isinstance(records, Mapping) else {}
    raw_documents = records.get("documents", [])
    documents = [item for item in raw_documents if isinstance(item, Mapping)] if isinstance(raw_documents, list) else []
    session = records.get("session", {})
    session = session if isinstance(session, Mapping) else {}
    current_user = esc(session.get("user", records.get("actor", "知识库运营者")) or "知识库运营者")
    current_tenant = esc(session.get("tenant", records.get("tenant", "returns-lab")) or "returns-lab")
    status_text = "已加固" if state.get("patched") else "存在风险"
    status_class = "patched" if state.get("patched") else "vulnerable"
    document_count = len(documents)
    rows = _document_rows(documents)

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>退货政策知识库 · RAGFlow</title>
<style>
:root{{color-scheme:dark;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;color:#e9edff;background:#111019}}
*{{box-sizing:border-box}} body{{margin:0;min-width:1080px;background:#111019}} button,input,textarea{{font:inherit}}
.app{{display:flex;min-height:100vh}} .side{{width:238px;flex:0 0 238px;padding:18px 13px;background:#191725;border-right:1px solid #312d46}}
.brand{{display:flex;align-items:center;gap:9px;padding:5px 10px 25px;font-weight:750;font-size:20px;letter-spacing:-.45px;color:#fff}} .brand-mark{{display:grid;place-items:center;width:27px;height:27px;border-radius:8px;background:linear-gradient(135deg,#9b66ff,#6642d7);font-size:10px;letter-spacing:-1px}}
.workspace{{display:flex;align-items:center;justify-content:space-between;padding:10px;margin:0 3px 20px;border:1px solid #3d3752;border-radius:9px;background:#222033;color:#d8d2ee;font-size:12px}} .workspace b{{display:block;color:#fff;font-size:13px}} .workspace small{{display:block;margin-top:3px;color:#928ca6}}
.nav-label{{margin:20px 10px 7px;color:#746f85;font-size:10px;font-weight:800;letter-spacing:.12em}} .nav-item{{display:flex;align-items:center;gap:11px;width:100%;padding:10px;border:0;border-radius:7px;background:transparent;color:#b6b1c7;text-align:left;font-size:13px}} .nav-item.active{{background:#31294c;color:#fff}} .nav-symbol{{width:18px;color:#ad80ff;font-size:11px;text-align:center}} .nav-item:not(.active) .nav-symbol{{color:#8c869f}}
.side-bottom{{position:fixed;bottom:18px;left:14px;width:208px;padding:11px;border:1px solid #39334c;border-radius:8px;background:#201e2d;color:#a7a1b7;font-size:11px;line-height:1.55}} .side-bottom b{{color:#e5e0f2}}
.main{{flex:1;min-width:0}} .topbar{{height:66px;display:flex;align-items:center;justify-content:space-between;padding:0 30px;border-bottom:1px solid #2d2a3c;background:#161520}} .crumb{{font-size:13px;color:#aaa5bb}} .crumb b{{color:#f6f3ff;font-weight:650}} .user{{display:flex;align-items:center;gap:10px;color:#c6c1d3;font-size:12px}} .avatar{{display:grid;place-items:center;width:29px;height:29px;border-radius:50%;background:#4d3a73;color:#fff;font-size:11px;font-weight:800}}
.content{{max-width:1450px;margin:0 auto;padding:27px 34px 40px}} .page-head{{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:19px}} h1{{margin:0;color:#f7f5ff;font-size:25px;letter-spacing:-.4px}} .sub{{margin:8px 0 0;color:#9993ab;font-size:13px}} .head-actions{{display:flex;gap:9px}} .button{{border:1px solid #504969;border-radius:7px;padding:9px 13px;background:#28243a;color:#e6e1f4;font-size:12px;font-weight:650;cursor:pointer}} .button.primary{{border-color:#8e63ed;background:#8560df;color:#fff}} .button:hover{{filter:brightness(1.1)}}
.alert{{display:flex;align-items:center;gap:12px;padding:12px 14px;margin-bottom:20px;border:1px solid #68433c;border-radius:8px;background:#2c2023;color:#e4c7c0;font-size:12px}} .alert.patched{{border-color:#37624d;background:#1d2a25;color:#b9e0cc}} .alert strong{{color:#f5e3da}} .alert.patched strong{{color:#d2f0dc}} .alert .pill{{margin-left:auto;border:1px solid currentColor;border-radius:20px;padding:3px 8px;font-size:10px;font-weight:750}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:13px;margin-bottom:20px}} .stat{{padding:15px 17px;border:1px solid #343045;border-radius:9px;background:#1b1927}} .stat span{{display:block;color:#918ba2;font-size:11px}} .stat b{{display:block;margin-top:6px;color:#f3f1fb;font-size:20px}} .stat small{{color:#9993aa;font-size:11px}}
.grid{{display:grid;grid-template-columns:minmax(570px,1.25fr) minmax(390px,.88fr);gap:18px}} .panel{{border:1px solid #343044;border-radius:10px;background:#1a1826;overflow:hidden}} .panel-head{{display:flex;align-items:center;justify-content:space-between;padding:15px 17px;border-bottom:1px solid #343044}} .panel-title{{color:#f4f1fb;font-size:14px;font-weight:700}} .panel-note{{color:#8f899f;font-size:11px}} .panel-body{{padding:17px}}
.table-wrap{{overflow:auto}} table{{width:100%;border-collapse:collapse;table-layout:fixed}} th{{padding:0 9px 10px;color:#817b92;font-size:10px;font-weight:750;letter-spacing:.06em;text-align:left}} td{{padding:12px 9px;border-top:1px solid #2e2b3d;color:#cbc6d6;font-size:12px;vertical-align:middle;overflow-wrap:anywhere}} th:nth-child(1){{width:28%}} th:nth-child(2){{width:34%}} th:nth-child(3){{width:12%}} th:nth-child(4){{width:17%}} th:nth-child(5){{width:9%}} td b{{display:block;color:#f0edf8;font-weight:650}} td small{{display:block;margin-top:4px;color:#837d93;font-size:10px}} .doc-icon{{display:inline-grid;place-items:center;float:left;width:28px;height:30px;margin:0 8px 0 0;border-radius:5px;background:#30314b;color:#9caeff;font-size:8px;font-weight:800}} .count{{color:#b6a1f5}} .index-ready{{color:#87d6ae;font-size:11px;white-space:nowrap}} .index-ready i{{display:inline-block;width:6px;height:6px;margin-right:5px;border-radius:50%;background:#64ce96}} .row-action{{border:0;background:transparent;color:#b394fd;font-size:11px;cursor:pointer}} .empty{{padding:28px;text-align:center;color:#878196}}
.form-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px}} .form-grid .wide{{grid-column:1/-1}} label{{display:block;color:#aaa4b8;font-size:11px;font-weight:650}} input,textarea{{display:block;width:100%;margin-top:6px;padding:9px 10px;border:1px solid #423c55;border-radius:6px;background:#12111b;color:#ece9f5;outline:none;font-size:12px}} input:focus,textarea:focus{{border-color:#9470e9;box-shadow:0 0 0 2px #8b61e922}} textarea{{min-height:70px;resize:vertical;line-height:1.45}} .help{{margin:10px 0 0;color:#827c90;font-size:10px;line-height:1.5}} .form-actions{{display:flex;gap:8px;margin-top:14px}} .form-actions .button{{flex:1}} .search-box{{display:flex;gap:8px}} .search-box input{{margin-top:0}} .search-box .button{{white-space:nowrap}} .result-list{{min-height:170px;margin-top:14px;border-top:1px solid #343044;padding-top:11px}} .placeholder{{padding:28px 8px;color:#827c93;font-size:12px;text-align:center}} .result-card{{padding:11px;margin-bottom:8px;border:1px solid #39344b;border-radius:7px;background:#201d2c}} .result-card b{{display:block;color:#efeaff;font-size:12px}} .result-card p{{margin:6px 0 0;color:#aaa4b7;font-size:11px;line-height:1.55;white-space:pre-wrap;word-break:break-word}} .result-meta{{margin-top:8px;color:#8872be;font:10px ui-monospace,SFMono-Regular,Menlo,monospace}}
.response-panel{{margin-top:18px}} .response-meta{{padding:9px 17px;border-bottom:1px solid #343044;background:#181622;color:#9d97ac;font-size:11px}} .response-meta b{{color:#d8d1e6}} pre{{max-height:285px;min-height:125px;margin:0;padding:15px 17px;overflow:auto;background:#12111a;color:#cfd5ef;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word}} .toast{{position:fixed;right:24px;bottom:22px;z-index:4;max-width:370px;padding:11px 14px;border:1px solid #554b72;border-radius:8px;background:#29253a;color:#e6e1f3;box-shadow:0 10px 30px #0007;font-size:12px;opacity:0;transform:translateY(10px);transition:.2s;pointer-events:none}} .toast.show{{opacity:1;transform:translateY(0)}} .toast.error{{border-color:#7c4a55;color:#f0c3ca}}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand"><span class="brand-mark">RF</span> RAGFlow</div>
    <div class="workspace"><div><b>退货政策知识库</b><small>知识库工作区</small></div><span>v</span></div>
    <div class="nav-label">知识管理</div>
    <button class="nav-item active" type="button"><span class="nav-symbol">KB</span>知识库</button>
    <button class="nav-item" type="button"><span class="nav-symbol">DB</span>数据集</button>
    <button class="nav-item" type="button"><span class="nav-symbol">S</span>检索测试</button>
    <div class="nav-label">智能应用</div>
    <button class="nav-item" type="button"><span class="nav-symbol">AI</span>聊天助手</button>
    <button class="nav-item" type="button"><span class="nav-symbol">PM</span>提示词管理</button>
    <div class="side-bottom"><b>本地 AWDP 演练</b><br>产品仿真界面仅连接当前本地目标。</div>
  </aside>
  <main class="main">
    <header class="topbar"><div class="crumb"><b>知识库</b> <span> / </span> 退货政策知识库</div><div class="user"><span>{current_tenant}</span><span class="avatar">{current_user[:1] or "知"}</span><span>{current_user}</span></div></header>
    <div class="content">
      <div class="page-head"><div><h1>退货政策知识库</h1><p class="sub">管理用于检索问答的文档、分块与索引配置</p></div><div class="head-actions"><button class="button" id="refreshButton" type="button">刷新文档</button><button class="button primary" id="focusImport" type="button">导入文档</button></div></div>
      <section class="alert {status_class}" id="vulnerabilityBanner"><strong>部署状态：{status_text}</strong><span>CVE-2024-53450 · 文档 annotation 与检索上下文边界</span><span class="pill">RAGFlow 0.13.0-lab</span></section>
      <section class="stats"><div class="stat"><span>知识库文档</span><b id="documentCount">{document_count}</b><small>已接入退货政策空间</small></div><div class="stat"><span>索引引擎</span><b>Infinity</b><small>向量与关键词混合检索</small></div><div class="stat"><span>当前访问身份</span><b>{current_user}</b><small>租户：{current_tenant}</small></div></section>
      <section class="grid">
        <section class="panel"><div class="panel-head"><span class="panel-title">文档列表</span><span class="panel-note" id="documentNote">{document_count} 个文档 · 索引已就绪</span></div><div class="panel-body table-wrap"><table><thead><tr><th>文档</th><th>内容摘要</th><th>分块</th><th>索引状态</th><th></th></tr></thead><tbody id="documentRows">{rows}</tbody></table></div></section>
        <section class="panel" id="importPanel"><div class="panel-head"><span class="panel-title">导入文档</span><span class="panel-note">本地数据集</span></div><div class="panel-body"><form id="importForm"><div class="form-grid"><label>文档 ID<input name="documentId" value="RET-2026-08" required></label><label>文档标题<input name="title" value="退货申请期限" required></label><label class="wide">政策正文<textarea name="body" required>退货申请需在签收后 7 天内提交。</textarea></label><label class="wide">导入 annotation<textarea name="annotation">kb_verification_code</textarea></label></div><p class="help">导入后将进入索引队列。annotation 是迁移时附带的文档元数据。</p><div class="form-actions"><button class="button" type="submit">导入并索引</button><button class="button primary" id="reproduceButton" type="button">复现检索链</button></div></form></div></section>
        <section class="panel"><div class="panel-head"><span class="panel-title">检索测试</span><span class="panel-note">Hybrid Search</span></div><div class="panel-body"><form id="searchForm"><label>检索问题<div class="search-box"><input name="query" value="退货申请期限" required><button class="button primary" type="submit">检索</button></div></label></form><div class="result-list" id="searchResults"><div class="placeholder">输入检索词后查看命中的文档分块。</div></div></div></section>
        <section class="panel"><div class="panel-head"><span class="panel-title">检索配置</span><span class="panel-note">当前知识库</span></div><div class="panel-body"><div class="form-grid"><label>分块方法<input value="通用文本分块" disabled></label><label>相似度阈值<input value="0.20" disabled></label><label class="wide">检索字段<input value="标题 · 正文 · 元数据" disabled></label></div><p class="help">文档导入和检索请求会直接发送到本地教学服务；该页面不连接外部 RAGFlow 实例。</p></div></section>
      </section>
      <section class="panel response-panel"><div class="panel-head"><span class="panel-title">请求响应</span><span class="panel-note">Action API</span></div><div class="response-meta" id="responseStatus">准备就绪：选择导入或检索操作。</div><pre id="response">{{
  "message": "等待本地知识库操作"
}}</pre></section>
    </div>
  </main>
</div>
<div class="toast" id="toast" role="status"></div>
<script>
{action_js(base_path)}
const basePath = {base_path!r};
const documentRows = document.getElementById('documentRows');
const documentCount = document.getElementById('documentCount');
const documentNote = document.getElementById('documentNote');
const responseView = document.getElementById('response');
const responseStatus = document.getElementById('responseStatus');
const toast = document.getElementById('toast');
let toastTimer;

function tell(message, isError) {{
  toast.textContent = message;
  toast.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {{ toast.className = 'toast'; }}, 3600);
}}

function cell(text) {{
  const td = document.createElement('td');
  td.textContent = String(text ?? '');
  return td;
}}

function renderDocuments(documents) {{
  documentRows.replaceChildren();
  const list = Array.isArray(documents) ? documents : [];
  documentCount.textContent = String(list.length);
  documentNote.textContent = list.length + ' 个文档 · 索引已就绪';
  if (!list.length) {{
    const row = document.createElement('tr');
    const empty = cell('当前知识库没有文档。');
    empty.colSpan = 5;
    empty.className = 'empty';
    row.appendChild(empty);
    documentRows.appendChild(row);
    return;
  }}
  list.forEach(item => {{
    const row = document.createElement('tr');
    const document = document.createElement('td');
    const icon = document.createElement('span');
    icon.className = 'doc-icon';
    icon.textContent = 'DOC';
    const detail = document.createElement('div');
    const title = document.createElement('b');
    title.textContent = item.title || '未命名文档';
    const id = document.createElement('small');
    id.textContent = item.id || '未命名文档';
    detail.append(title, id); document.append(icon, detail);
    const body = String(item.body || '');
    const preview = cell(body.replace(/\\s+/g, ' ').slice(0, 72) || '尚未提供正文');
    const chunks = cell(Math.max(1, Math.ceil(body.length / 120)));
    chunks.firstChild.parentElement.className = 'count';
    const index = document.createElement('td');
    const status = document.createElement('span');
    status.className = 'index-ready';
    const dot = document.createElement('i'); status.append(dot, document.createTextNode(' 已索引')); index.appendChild(status);
    const action = document.createElement('td');
    const button = document.createElement('button'); button.className = 'row-action'; button.type = 'button'; button.textContent = '查看'; action.appendChild(button);
    row.append(document, preview, chunks, index, action);
    documentRows.appendChild(row);
  }});
}}

async function refreshRecords() {{
  const response = await fetch(basePath + '/api/records');
  const data = await response.json();
  renderDocuments(data.records && data.records.documents);
}}

function displayResponse(reply, label) {{
  const rawResponse = {{result: reply.result, target: reply.target}};
  responseView.textContent = JSON.stringify(rawResponse, null, 2);
  const message = reply.result && reply.result.message ? reply.result.message : '响应已返回';
  responseStatus.innerHTML = '<b>HTTP ' + reply.status + '</b> · ' + label + ' · ' + esc(message);
  tell('HTTP ' + reply.status + ' · ' + message, !(reply.result && reply.result.ok));
}}

function displaySearch(result) {{
  const root = document.getElementById('searchResults');
  root.replaceChildren();
  const results = result && result.data && Array.isArray(result.data.results) ? result.data.results : [];
  if (!results.length) {{
    const none = document.createElement('div'); none.className = 'placeholder'; none.textContent = '没有命中可用的文档分块。'; root.appendChild(none); return;
  }}
  results.forEach(item => {{
    const card = document.createElement('article'); card.className = 'result-card';
    const title = document.createElement('b'); title.textContent = item.title || item.id || '未命名结果';
    const excerpt = document.createElement('p'); excerpt.textContent = item.excerpt || '';
    const meta = document.createElement('div'); meta.className = 'result-meta'; meta.textContent = '文档 ID：' + (item.id || '—');
    card.append(title, excerpt, meta);
    if (item.kb_verification_code) {{
      const verifier = document.createElement('p'); verifier.textContent = 'kb_verification_code：' + item.kb_verification_code; card.appendChild(verifier);
    }}
    root.appendChild(card);
  }});
}}

function importPayload() {{
  const form = document.getElementById('importForm');
  return {{
    documentId: form.elements.documentId.value,
    title: form.elements.title.value,
    body: form.elements.body.value,
    annotation: form.elements.annotation.value
  }};
}}

async function importDocument() {{
  const reply = await callAction('knowledge.import_document', importPayload());
  displayResponse(reply, '导入文档');
  if (reply.result && reply.result.ok) await refreshRecords();
  return reply;
}}

async function searchKnowledge() {{
  const form = document.getElementById('searchForm');
  const reply = await callAction('knowledge.search', {{query: form.elements.query.value}});
  displayResponse(reply, '检索知识库');
  displaySearch(reply.result);
  if (reply.result && reply.result.ok) await refreshRecords();
  return reply;
}}

document.getElementById('importForm').addEventListener('submit', async event => {{
  event.preventDefault();
  try {{ await importDocument(); }} catch (error) {{ tell('导入请求失败：' + error, true); }}
}});
document.getElementById('searchForm').addEventListener('submit', async event => {{
  event.preventDefault();
  try {{ await searchKnowledge(); }} catch (error) {{ tell('检索请求失败：' + error, true); }}
}});
document.getElementById('reproduceButton').addEventListener('click', async () => {{
  const button = document.getElementById('reproduceButton');
  button.disabled = true;
  try {{
    const imported = await importDocument();
    if (imported.result && imported.result.ok) await searchKnowledge();
  }} catch (error) {{
    tell('复现链执行失败：' + error, true);
  }} finally {{
    button.disabled = false;
  }}
}});
document.getElementById('refreshButton').addEventListener('click', () => refreshRecords().then(() => tell('文档列表已刷新。')).catch(error => tell('刷新失败：' + error, true)));
document.getElementById('focusImport').addEventListener('click', () => document.getElementById('importPanel').scrollIntoView({{behavior: 'smooth', block: 'center'}}));
</script>
</body>
</html>"""


SKIN = render
