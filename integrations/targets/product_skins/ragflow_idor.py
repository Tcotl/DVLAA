"""AWDP09 的 RAGFlow 多租户合同库产品仿真皮肤。

该界面模拟 RAGFlow 知识库的文档列表与详情阅读流程。CVE-2025-25282
场景中，旧版详情接口把 URL 内 tenantId/documentId 当作授权依据，使
tenant-blue 会话能读取 tenant-red 的 contract-red-2026 和校验字段。
皮肤只调用 target_server 的 documents.view 动作，不包含漏洞判定逻辑。
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 9


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _document_alias(params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, str]:
    """将 RAGFlow 风格详情路径映射为模拟目标的内部字段。"""
    del body
    return {
        "tenantId": str(params.get("tenantId", "")),
        "documentId": str(params.get("documentId", "")),
    }


ALIASES = [
    {
        "method": "GET",
        "segments": ("api", "v1", "tenants", "<tenantId>", "documents", "<documentId>"),
        "action": "documents.view",
        "map": _document_alias,
    },
]


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染 RAGFlow 风格的租户文档详情页。"""
    records = _as_mapping(state.get("records"))
    session = _as_mapping(records.get("session"))
    documents = _as_mapping(records.get("documents"))
    user_id = str(session.get("userId", "未识别用户"))
    tenant_id = str(session.get("tenant", "tenant-blue"))
    current_documents = _as_mapping(documents.get(tenant_id))
    document_count = sum(len(_as_mapping(value)) for value in documents.values())
    patched = bool(state.get("patched"))

    rows: list[str] = []
    for document_id, document in current_documents.items():
        item = _as_mapping(document)
        title = str(item.get("title", "未命名文档"))
        summary = str(item.get("summary", "暂无摘要"))
        rows.append(
            "<tr>"
            f"<td><span class=\"file-dot\"></span>{esc(title)}</td>"
            f"<td><code>{esc(document_id)}</code></td>"
            f"<td class=\"muted\">{esc(summary)}</td>"
            "<td><button class=\"table-link document-link\" type=\"button\" "
            f"data-tenant=\"{esc(tenant_id)}\" data-document=\"{esc(document_id)}\">查看</button></td>"
            "</tr>"
        )
    document_rows = "".join(rows) or "<tr><td colspan=\"4\" class=\"empty\">当前租户尚无合同文档。</td></tr>"
    status_class = "patched" if patched else "vulnerable"
    status_text = "已部署授权边界修复" if patched else "检测到旧版文档授权处理器"
    status_note = "详情查询将绑定服务端会话租户。" if patched else "路径参数仍可能影响详情读取范围。"
    version_text = "v0.16.0-patched" if patched else "v0.16.0-legacy"
    title = "RAGFlow · 多租户合同库"

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
:root {{ color-scheme: dark; font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#101417; color:#eef1f3; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; min-width:320px; background:#101417; }}
button, input {{ font:inherit; }}
button {{ cursor:pointer; }}
.app {{ min-height:100vh; display:grid; grid-template-columns:236px minmax(0,1fr); }}
.sidebar {{ background:#171b1f; border-right:1px solid #2c3338; padding:18px 12px; }}
.brand {{ display:flex; align-items:center; gap:9px; padding:0 8px 24px; font-size:18px; font-weight:760; letter-spacing:-.4px; }}
.brand-mark {{ width:26px; height:26px; border-radius:7px; display:grid; place-items:center; background:#14b8a6; color:#072d29; font-size:12px; font-weight:900; }}
.workspace {{ color:#7e8991; font-size:11px; letter-spacing:.08em; padding:0 9px 8px; }}
.nav-item {{ width:100%; border:0; border-radius:7px; padding:10px 11px; margin:2px 0; background:transparent; color:#aeb8be; text-align:left; font-size:13px; }}
.nav-item.active {{ color:#effffc; background:#1d3735; }}
.nav-item span {{ display:inline-block; width:21px; color:#62d9ca; font-weight:700; }}
.tenant-card {{ position:fixed; bottom:18px; left:13px; width:209px; border:1px solid #323a3f; border-radius:9px; padding:11px; background:#1d2227; }}
.tenant-card strong, .tenant-card small {{ display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.tenant-card strong {{ color:#eef1f3; font-size:12px; }}
.tenant-card small {{ margin-top:4px; color:#8d9aa2; font-size:11px; }}
.main {{ min-width:0; }}
.topbar {{ height:63px; display:flex; justify-content:space-between; align-items:center; padding:0 28px; border-bottom:1px solid #2b3237; background:#15191d; }}
.crumb {{ color:#9ba6ad; font-size:13px; }}
.crumb b {{ color:#f1f5f6; font-weight:650; }}
.identity {{ display:flex; align-items:center; gap:8px; color:#a9b3ba; font-size:12px; }}
.avatar {{ width:29px; height:29px; border-radius:50%; display:grid; place-items:center; background:#254744; color:#74e3d6; font-size:11px; font-weight:800; }}
.content {{ max-width:1280px; margin:0 auto; padding:28px; }}
.heading {{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:21px; }}
h1 {{ margin:0 0 7px; font-size:24px; letter-spacing:-.5px; }}
.subtitle {{ margin:0; color:#8e9aa1; font-size:13px; }}
.metrics {{ display:flex; gap:8px; flex-wrap:wrap; }}
.metric {{ min-width:94px; border:1px solid #30383e; border-radius:7px; padding:8px 11px; background:#171c20; }}
.metric span, .metric b {{ display:block; }}
.metric span {{ color:#7d8990; font-size:10px; }}
.metric b {{ color:#e6eeee; margin-top:3px; font-size:13px; }}
.alert {{ display:flex; gap:13px; align-items:flex-start; border:1px solid #644b2c; border-radius:8px; padding:14px 16px; margin-bottom:18px; background:#2b241b; }}
.alert.patched {{ border-color:#24554e; background:#172a27; }}
.alert-indicator {{ width:9px; height:9px; flex:none; border-radius:50%; margin-top:5px; background:#f0a84d; box-shadow:0 0 0 4px #f0a84d1c; }}
.alert.patched .alert-indicator {{ background:#48c7b7; box-shadow:0 0 0 4px #48c7b71c; }}
.alert strong {{ display:block; color:#f6ede2; font-size:13px; }}
.alert.patched strong {{ color:#d9f7f1; }}
.alert p {{ margin:4px 0 0; color:#b7aa98; font-size:12px; }}
.alert.patched p {{ color:#a8c9c3; }}
.grid {{ display:grid; grid-template-columns:minmax(0,1.35fr) minmax(330px,.65fr); gap:17px; }}
.card {{ overflow:hidden; border:1px solid #30383e; border-radius:9px; background:#181d21; }}
.card-header {{ display:flex; justify-content:space-between; align-items:center; min-height:57px; padding:0 17px; border-bottom:1px solid #2c3439; }}
.card-header h2 {{ margin:0; color:#e9eff0; font-size:14px; }}
.card-header small {{ color:#849199; font-size:11px; }}
.table-wrap {{ overflow:auto; }}
table {{ width:100%; border-collapse:collapse; min-width:610px; }}
th, td {{ padding:12px 15px; border-bottom:1px solid #293136; text-align:left; font-size:12px; }}
th {{ color:#7f8c94; background:#161a1e; font-size:10px; letter-spacing:.05em; font-weight:700; }}
td {{ color:#d3dade; }}
tr:last-child td {{ border-bottom:0; }}
td.muted {{ max-width:230px; color:#8d989e; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.file-dot {{ display:inline-block; width:7px; height:7px; margin-right:7px; border-radius:2px; background:#4dcbbb; }}
code {{ color:#89dbd1; font:11px ui-monospace, SFMono-Regular, Menlo, monospace; }}
.table-link {{ border:0; padding:0; background:transparent; color:#62d9ca; font-size:12px; }}
.empty {{ color:#849199; text-align:center; }}
.form-body, .detail-body {{ padding:17px; }}
.field-label {{ display:block; margin:0 0 6px; color:#9ba7ad; font-size:11px; font-weight:650; }}
.field {{ width:100%; margin:0 0 13px; border:1px solid #3a454b; border-radius:6px; outline:0; padding:10px; background:#121619; color:#e8efef; font-size:13px; }}
.field:focus {{ border-color:#2ebaaa; box-shadow:0 0 0 3px #2ebaaa1c; }}
.hint {{ margin:-7px 0 14px; color:#75828a; font-size:11px; line-height:1.5; }}
.primary {{ width:100%; border:0; border-radius:6px; padding:10px 13px; background:#16a394; color:#062925; font-size:13px; font-weight:760; }}
.primary:hover {{ background:#2cc5b5; }}
.primary:disabled {{ cursor:wait; opacity:.7; }}
.detail-empty {{ color:#8f9ca3; font-size:12px; line-height:1.7; }}
.detail-title {{ margin:0 0 8px; color:#eef5f5; font-size:16px; }}
.detail-meta {{ margin:0 0 13px; color:#71d8ca; font-size:11px; }}
.detail-summary {{ margin:0; color:#b7c0c4; font-size:13px; line-height:1.75; white-space:pre-wrap; }}
.response {{ margin:0; max-height:280px; overflow:auto; border-top:1px solid #2c3439; padding:13px 17px; background:#111518; color:#a8d9d3; font:11px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; white-space:pre-wrap; }}
.toast {{ position:fixed; z-index:2; right:22px; bottom:22px; max-width:360px; transform:translateY(90px); opacity:0; transition:.18s ease; border:1px solid #3e8c82; border-radius:7px; padding:10px 13px; background:#183330; color:#d8f8f3; font-size:12px; box-shadow:0 12px 34px #0006; }}
.toast.show {{ transform:translateY(0); opacity:1; }}
@media (max-width:900px) {{ .app {{ grid-template-columns:1fr; }} .sidebar {{ display:none; }} .grid {{ grid-template-columns:1fr; }} .content {{ padding:20px; }} .topbar {{ padding:0 20px; }} }}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar" aria-label="RAGFlow 主导航">
    <div class="brand"><span class="brand-mark">R</span>RAGFlow</div>
    <div class="workspace">工作空间</div>
    <button class="nav-item" type="button"><span>⌘</span>概览</button>
    <button class="nav-item active" type="button"><span>▣</span>知识库</button>
    <button class="nav-item" type="button"><span>◫</span>聊天助手</button>
    <button class="nav-item" type="button"><span>⌁</span>模型配置</button>
    <div class="workspace" style="margin-top:18px">管理</div>
    <button class="nav-item" type="button"><span>◌</span>成员与租户</button>
    <div class="tenant-card"><strong>{esc(user_id)}</strong><small>当前会话 · {esc(tenant_id)}</small></div>
  </aside>
  <main class="main">
    <header class="topbar"><div class="crumb">知识库 / <b>合同文档</b></div><div class="identity"><span>已登录：{esc(user_id)}</span><span class="avatar">{esc(user_id[:2].upper())}</span></div></header>
    <div class="content">
      <section class="heading">
        <div><h1>多租户合同库</h1><p class="subtitle">从已授权的知识库索引中查看合同摘要与文档元数据。</p></div>
        <div class="metrics"><div class="metric"><span>当前租户</span><b>{esc(tenant_id)}</b></div><div class="metric"><span>已索引文档</span><b>{document_count}</b></div><div class="metric"><span>服务版本</span><b>{esc(version_text)}</b></div></div>
      </section>
      <section id="securityBanner" class="alert {status_class}"><span class="alert-indicator"></span><div><strong>CVE-2025-25282 · {esc(status_text)}</strong><p>{esc(status_note)}</p></div></section>
      <section class="grid">
        <section class="card">
          <div class="card-header"><h2>我的租户文档</h2><small>{esc(tenant_id)} · 合同知识库</small></div>
          <div class="table-wrap"><table><thead><tr><th>文档名称</th><th>文档 ID</th><th>摘要</th><th>操作</th></tr></thead><tbody>{document_rows}</tbody></table></div>
        </section>
        <section class="card">
          <div class="card-header"><h2>文档详情</h2><small>按租户与文档 ID 定位</small></div>
          <form id="documentForm" class="form-body">
            <label class="field-label" for="tenantId">租户 ID</label>
            <input id="tenantId" class="field" name="tenantId" value="tenant-red" autocomplete="off">
            <label class="field-label" for="documentId">文档 ID</label>
            <input id="documentId" class="field" name="documentId" value="contract-red-2026" autocomplete="off">
            <p class="hint">文档详情会由当前登录会话授权后返回。</p>
            <button id="viewButton" class="primary" type="submit">查看文档详情</button>
          </form>
          <div id="detail" class="detail-body"><p class="detail-empty">选择左侧文档或填写文档定位信息后查看详情。</p></div>
          <pre id="response" class="response">等待详情查询请求。</pre>
        </section>
      </section>
    </div>
  </main>
</div>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<script>
{action_js(base_path)}
const form = document.getElementById('documentForm');
const tenantInput = document.getElementById('tenantId');
const documentInput = document.getElementById('documentId');
const detail = document.getElementById('detail');
const response = document.getElementById('response');
const viewButton = document.getElementById('viewButton');
const toast = document.getElementById('toast');
let toastTimer;
function showToast(text) {{
  toast.textContent = text;
  toast.classList.add('show');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove('show'), 3600);
}}
function renderDetail(result) {{
  const data = result && result.data;
  if (!data) return;
  detail.replaceChildren();
  const heading = document.createElement('h3');
  heading.className = 'detail-title';
  heading.textContent = data.title || '未命名文档';
  const meta = document.createElement('p');
  meta.className = 'detail-meta';
  meta.textContent = `${{data.tenantId || ''}} / ${{data.documentId || ''}}`;
  const summary = document.createElement('p');
  summary.className = 'detail-summary';
  summary.textContent = data.summary || result.message || '未返回合同摘要。';
  detail.append(heading, meta, summary);
}}
async function viewDocument() {{
  const body = {{tenantId: tenantInput.value.trim(), documentId: documentInput.value.trim()}};
  viewButton.disabled = true;
  try {{
    const reply = await callAction('documents.view', body);
    response.textContent = `HTTP ${{reply.status}}\n${{JSON.stringify(reply.result, null, 2)}}`;
    renderDetail(reply.result);
    showToast(`HTTP ${{reply.status}} · ${{reply.result.message || '详情查询已完成'}}`);
  }} catch (error) {{
    response.textContent = String(error);
    showToast('详情查询失败，请检查本地目标服务。');
  }} finally {{
    viewButton.disabled = false;
  }}
}}
form.addEventListener('submit', (event) => {{ event.preventDefault(); viewDocument(); }});
document.querySelectorAll('.document-link').forEach((button) => {{
  button.addEventListener('click', () => {{
    tenantInput.value = button.dataset.tenant || '';
    documentInput.value = button.dataset.document || '';
    viewDocument();
  }});
}});
</script>
</body>
</html>"""


SKIN = render
