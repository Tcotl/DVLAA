"""AWDP06 的 Dify Studio 产品仿真皮肤。

该页面模拟 Dify 应用列表、发布审计与 DSL 导出工作流。CVE-2025-32790
对应的旧版兼容导出链错误信任请求中的 ``role=admin``：viewer 因而可以导出
tenant-red 的 ``billing-agent``，并在导出结果中得到部署校验字段。所有业务
判定仍由 target_server 的 ``dsl.list_apps`` 与 ``dsl.export`` 动作完成。
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 6


def _script_json(value: Any) -> str:
    """安全嵌入 script 标签的 JSON，避免业务字段闭合脚本。"""
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _export_alias(params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 Dify 风格的导出请求转换为训练目标的内部动作字段。"""
    return {
        "appId": str(params.get("appId", "")),
        "role": str(body.get("role", "viewer")),
    }


ALIASES = [
    {
        "method": "POST",
        "segments": ("console", "api", "apps", "<appId>", "export"),
        "action": "dsl.export",
        "map": _export_alias,
    },
]


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染只读业务记录驱动的 Dify Studio 发布审计界面。"""
    records = state.get("records", {})
    records = records if isinstance(records, Mapping) else {}
    session = records.get("session", {})
    session = session if isinstance(session, Mapping) else {}
    apps = records.get("apps", {})
    apps = apps if isinstance(apps, Mapping) else {}

    user = str(session.get("user", "viewer-blue"))
    role = str(session.get("role", "viewer"))
    tenant = str(session.get("tenant", "tenant-blue"))
    patched = bool(state.get("patched"))
    visible_apps: list[dict[str, str]] = []
    for app_id, app in apps.items():
        if not isinstance(app, Mapping):
            continue
        app_tenant = str(app.get("tenant", ""))
        visibility = str(app.get("visibility", "private"))
        if visibility == "public" or app_tenant == tenant:
            visible_apps.append(
                {
                    "appId": str(app_id),
                    "tenant": app_tenant,
                    "visibility": visibility,
                }
            )

    status_text = "已部署修复" if patched else "存在兼容导出风险"
    status_class = "patched" if patched else "risk"
    table_rows = "".join(
        "<tr>"
        f"<td><strong>{esc(app['appId'])}</strong></td>"
        f"<td>{esc(app['tenant'])}</td>"
        f"<td><span class=\"visibility {esc(app['visibility'])}\">"
        f"{'公开' if app['visibility'] == 'public' else '私有草稿'}</span></td>"
        "<td><button class=\"text-button\" type=\"button\" data-app="
        f"\"{esc(app['appId'])}\">打开</button></td>"
        "</tr>"
        for app in visible_apps
    ) or "<tr><td colspan=\"4\" class=\"empty\">当前会话没有可见应用。</td></tr>"

    initial_apps = _script_json(visible_apps)
    js = action_js(base_path)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dify Studio · 应用发布中心</title>
  <style>
    :root {{
      color-scheme: light;
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: #1f2937;
      background: #f7f8fa;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-width: 320px; background: #f7f8fa; }}
    button, input {{ font: inherit; }}
    .layout {{ min-height: 100vh; display: grid; grid-template-columns: 232px 1fr; }}
    .sidebar {{ background: #242938; color: #d9deea; padding: 18px 12px; display: flex; flex-direction: column; }}
    .brand {{ display: flex; gap: 10px; align-items: center; padding: 5px 10px 23px; color: #fff; font-weight: 700; letter-spacing: .1px; }}
    .brand-mark {{ width: 27px; height: 27px; border-radius: 8px; background: linear-gradient(135deg, #8067ff, #4ab3f4); display: grid; place-items: center; font-size: 13px; }}
    .workspace {{ color: #9da6b8; font-size: 11px; font-weight: 700; letter-spacing: .7px; padding: 0 11px 8px; text-transform: uppercase; }}
    .nav {{ display: grid; gap: 3px; }}
    .nav a {{ text-decoration: none; color: #c4cad8; padding: 9px 11px; border-radius: 7px; font-size: 14px; }}
    .nav a.active {{ background: #3c4356; color: #fff; font-weight: 650; }}
    .nav a span {{ display: inline-block; width: 23px; color: #a99bff; font-size: 12px; }}
    .side-foot {{ margin-top: auto; border-top: 1px solid #3d4353; padding: 15px 10px 4px; font-size: 12px; line-height: 1.55; color: #aeb6c6; }}
    .side-foot strong {{ color: #fff; display: block; }}
    .main {{ min-width: 0; }}
    .topbar {{ height: 64px; display: flex; align-items: center; justify-content: space-between; padding: 0 29px; border-bottom: 1px solid #e7e9ef; background: #fff; }}
    .crumb {{ font-size: 14px; color: #687386; }}
    .crumb strong {{ color: #202938; margin-left: 8px; }}
    .account {{ display: flex; align-items: center; gap: 9px; color: #596477; font-size: 13px; }}
    .avatar {{ width: 30px; height: 30px; display: grid; place-items: center; border-radius: 50%; background: #ece8ff; color: #6651dc; font-weight: 700; }}
    .page {{ max-width: 1250px; margin: 0 auto; padding: 30px 32px 42px; }}
    .title-row {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 21px; }}
    h1 {{ margin: 0 0 8px; font-size: 25px; letter-spacing: -.35px; color: #202938; }}
    .subtitle {{ margin: 0; color: #737e90; font-size: 14px; }}
    .new-app {{ border: 0; border-radius: 7px; background: #6953e8; padding: 10px 14px; color: #fff; font-size: 13px; font-weight: 650; white-space: nowrap; }}
    .security {{ display: grid; grid-template-columns: auto 1fr; align-items: center; gap: 13px; padding: 13px 16px; border: 1px solid #f0c977; border-radius: 9px; background: #fffaf0; margin-bottom: 22px; }}
    .security.patched {{ border-color: #a8dfbd; background: #f3fcf6; }}
    .security-label {{ padding: 4px 7px; border-radius: 5px; background: #fff0cc; color: #a25e00; font-size: 11px; font-weight: 750; letter-spacing: .2px; }}
    .security.patched .security-label {{ background: #dff6e7; color: #18723d; }}
    .security strong {{ font-size: 13px; color: #3c4350; }}
    .security small {{ display: block; margin-top: 3px; color: #787f8c; font-size: 12px; }}
    .content {{ display: grid; grid-template-columns: minmax(0, 1fr) 385px; gap: 20px; align-items: start; }}
    .card {{ background: #fff; border: 1px solid #e7e9ee; border-radius: 10px; box-shadow: 0 2px 5px rgba(26, 34, 50, .025); }}
    .card-head {{ display: flex; align-items: center; justify-content: space-between; padding: 18px 20px 14px; border-bottom: 1px solid #eff0f3; }}
    .card-head h2 {{ margin: 0; color: #273142; font-size: 16px; }}
    .card-head p {{ margin: 4px 0 0; color: #80899a; font-size: 12px; }}
    .refresh {{ border: 1px solid #dfe2e9; border-radius: 6px; background: #fff; color: #586477; padding: 6px 9px; font-size: 12px; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th {{ padding: 11px 20px; background: #fafbfc; color: #8a93a2; font-size: 11px; font-weight: 650; letter-spacing: .25px; }}
    td {{ padding: 15px 20px; border-top: 1px solid #f0f1f4; color: #596477; font-size: 13px; }}
    td strong {{ color: #2b3545; font-weight: 650; }}
    .visibility {{ padding: 3px 7px; border-radius: 10px; font-size: 11px; font-weight: 650; }}
    .visibility.public {{ background: #e9f7ee; color: #27814a; }}
    .visibility.private {{ background: #f1efff; color: #6953d8; }}
    .text-button {{ border: 0; background: transparent; color: #6953e8; padding: 0; font-size: 12px; cursor: pointer; }}
    .empty {{ text-align: center; color: #8a93a2; }}
    .catalog-foot {{ padding: 12px 20px 15px; border-top: 1px solid #eff0f3; color: #8992a2; font-size: 12px; }}
    .panel {{ padding: 20px; }}
    .panel h2 {{ margin: 0; font-size: 16px; color: #273142; }}
    .panel .lead {{ margin: 7px 0 18px; color: #7a8494; font-size: 12px; line-height: 1.6; }}
    .field-label {{ display: block; margin: 13px 0 6px; color: #4c5668; font-size: 12px; font-weight: 650; }}
    .field-label em {{ color: #cf4c63; font-style: normal; }}
    input {{ width: 100%; border: 1px solid #dce0e7; border-radius: 7px; padding: 10px 11px; color: #2d3748; background: #fff; outline: none; }}
    input:focus {{ border-color: #7965e9; box-shadow: 0 0 0 3px #eae6ff; }}
    .hint {{ margin: 7px 0 0; color: #929aa8; font-size: 11px; line-height: 1.5; }}
    .submit {{ width: 100%; margin-top: 18px; border: 0; border-radius: 7px; background: #6953e8; color: #fff; padding: 11px; font-size: 13px; font-weight: 700; cursor: pointer; }}
    .submit:disabled, .refresh:disabled {{ cursor: wait; opacity: .65; }}
    .request-path {{ margin-top: 14px; padding: 9px 10px; border-radius: 6px; background: #f7f7fa; color: #6b7484; font: 11px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }}
    .response-card {{ grid-column: 1 / -1; overflow: hidden; }}
    .response-meta {{ display: flex; align-items: center; gap: 9px; color: #7b8492; font-size: 12px; }}
    .http {{ padding: 3px 6px; border-radius: 4px; background: #eef0f5; color: #5b6576; font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .response {{ min-height: 210px; max-height: 420px; overflow: auto; margin: 0; padding: 17px 20px; background: #202431; color: #dce2ef; font: 12px/1.65 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; }}
    .toast {{ position: fixed; right: 24px; bottom: 22px; z-index: 5; max-width: 360px; padding: 11px 14px; border-radius: 7px; background: #293142; color: #fff; box-shadow: 0 10px 25px rgba(25, 31, 44, .2); font-size: 13px; opacity: 0; transform: translateY(12px); transition: opacity .18s, transform .18s; pointer-events: none; }}
    .toast.show {{ opacity: 1; transform: translateY(0); }}
    .toast.error {{ background: #9f3748; }}
    @media (max-width: 900px) {{ .layout {{ grid-template-columns: 1fr; }} .sidebar {{ display: none; }} .content {{ grid-template-columns: 1fr; }} }}
    @media (max-width: 560px) {{ .page {{ padding: 22px 16px; }} .topbar {{ padding: 0 16px; }} .account-text {{ display: none; }} .title-row {{ display: block; }} .new-app {{ margin-top: 13px; }} th:nth-child(2), td:nth-child(2) {{ display: none; }} }}
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar" aria-label="Dify Studio 主导航">
      <div class="brand"><span class="brand-mark">D</span><span>Dify Studio</span></div>
      <div class="workspace">工作空间</div>
      <nav class="nav">
        <a href="#apps" class="active"><span>01</span>应用</a>
        <a href="#apps"><span>02</span>工作室</a>
        <a href="#publish"><span>03</span>发布审计</a>
        <a href="#response"><span>04</span>API 访问</a>
      </nav>
      <div class="side-foot"><strong>{esc(tenant)}</strong>发布工作空间<br>本地 AWDP 训练目标</div>
    </aside>
    <main class="main">
      <header class="topbar">
        <div class="crumb">应用 <strong>发布中心</strong></div>
        <div class="account"><span class="avatar">{esc(user[:1].upper() or 'V')}</span><span class="account-text">{esc(user)} · {esc(role)}</span></div>
      </header>
      <section class="page">
        <div class="title-row">
          <div><h1>应用发布中心</h1><p class="subtitle">管理应用草稿、版本发布和 DSL 审计导出。</p></div>
          <button class="new-app" type="button" id="newApp">创建应用</button>
        </div>
        <section class="security {status_class}" aria-label="部署状态">
          <span class="security-label">{esc(status_text)}</span>
          <div><strong>CVE-2025-32790 · Dify 兼容导出服务 1.1.3-lab</strong><small>当前会话：{esc(user)}（{esc(role)}）· 租户：{esc(tenant)} · 仅在本地训练环境运行</small></div>
        </section>
        <div class="content">
          <section class="card" id="apps">
            <div class="card-head"><div><h2>我的应用</h2><p>公开应用与当前租户草稿</p></div><button class="refresh" type="button" id="refreshApps">刷新列表</button></div>
            <table aria-label="可访问应用列表"><thead><tr><th>应用名称</th><th>所属租户</th><th>可见性</th><th>操作</th></tr></thead><tbody id="appRows">{table_rows}</tbody></table>
            <div class="catalog-foot" id="catalogFoot">已加载 {len(visible_apps)} 个当前会话可访问的应用。</div>
          </section>
          <section class="card panel" id="publish">
            <h2>导出应用 DSL</h2>
            <p class="lead">将应用工作流导出为 DSL，用于发布前审计和迁移留档。</p>
            <form id="exportForm">
              <label class="field-label" for="appId">应用 ID <em>*</em></label>
              <input id="appId" name="appId" value="billing-agent" autocomplete="off" required>
              <p class="hint">输入需要导出的应用标识。发布审计将验证访问角色。</p>
              <label class="field-label" for="role">请求角色 <em>*</em></label>
              <input id="role" name="role" value="admin" autocomplete="off" required>
              <p class="hint">兼容旧版发布客户端的请求字段。</p>
              <button class="submit" id="exportButton" type="submit">导出 DSL</button>
            </form>
            <div class="request-path" id="requestPath">POST /console/api/apps/billing-agent/export</div>
          </section>
          <section class="card response-card" id="response">
            <div class="card-head"><div><h2>发布审计响应</h2><p>显示本地目标的完整 JSON 响应</p></div><div class="response-meta"><span class="http" id="httpStatus">HTTP —</span><span id="resultText">等待导出请求</span></div></div>
            <pre class="response" id="responseBody">选择应用后提交导出审计请求。</pre>
          </section>
        </div>
      </section>
    </main>
  </div>
  <div class="toast" id="toast" role="status" aria-live="polite"></div>
  <script>
{js}
    const initialApps = {initial_apps};
    const appRows = document.getElementById('appRows');
    const catalogFoot = document.getElementById('catalogFoot');
    const appIdInput = document.getElementById('appId');
    const roleInput = document.getElementById('role');
    const requestPath = document.getElementById('requestPath');
    const exportButton = document.getElementById('exportButton');
    const refreshButton = document.getElementById('refreshApps');
    const responseBody = document.getElementById('responseBody');
    const httpStatus = document.getElementById('httpStatus');
    const resultText = document.getElementById('resultText');
    const toast = document.getElementById('toast');
    let toastTimer;

    function showToast(message, isError) {{
      toast.textContent = message;
      toast.className = 'toast show' + (isError ? ' error' : '');
      window.clearTimeout(toastTimer);
      toastTimer = window.setTimeout(() => {{ toast.className = 'toast'; }}, 3500);
    }}

    function renderApps(apps) {{
      appRows.replaceChildren();
      if (!apps.length) {{
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 4;
        cell.className = 'empty';
        cell.textContent = '当前会话没有可见应用。';
        row.appendChild(cell);
        appRows.appendChild(row);
      }}
      apps.forEach((app) => {{
        const row = document.createElement('tr');
        const name = document.createElement('td');
        const strong = document.createElement('strong');
        strong.textContent = app.appId || '';
        name.appendChild(strong);
        const appTenant = document.createElement('td');
        appTenant.textContent = app.tenant || '';
        const visibility = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = 'visibility ' + (app.visibility === 'public' ? 'public' : 'private');
        badge.textContent = app.visibility === 'public' ? '公开' : '私有草稿';
        visibility.appendChild(badge);
        const operation = document.createElement('td');
        const open = document.createElement('button');
        open.type = 'button';
        open.className = 'text-button';
        open.textContent = '打开';
        open.addEventListener('click', () => {{
          appIdInput.value = app.appId || '';
          updateRequestPath();
          document.getElementById('publish').scrollIntoView({{behavior: 'smooth', block: 'center'}});
        }});
        operation.appendChild(open);
        row.append(name, appTenant, visibility, operation);
        appRows.appendChild(row);
      }});
      catalogFoot.textContent = '已加载 ' + apps.length + ' 个当前会话可访问的应用。';
    }}

    function updateRequestPath() {{
      requestPath.textContent = 'POST /console/api/apps/' + (appIdInput.value.trim() || '{esc(tenant)}') + '/export';
    }}

    function renderResponse(reply) {{
      httpStatus.textContent = 'HTTP ' + reply.status;
      const message = reply.result && reply.result.message ? reply.result.message : '已收到响应';
      resultText.textContent = message;
      responseBody.textContent = JSON.stringify({{
        http_status: reply.status,
        response: {{result: reply.result, target: reply.target}}
      }}, null, 2);
    }}

    async function refreshApps() {{
      refreshButton.disabled = true;
      try {{
        const reply = await callAction('dsl.list_apps', {{}});
        const data = reply.result && reply.result.data ? reply.result.data : {{}};
        const apps = Array.isArray(data.apps) ? data.apps : [];
        renderApps(apps);
        if (reply.status >= 200 && reply.status < 300) showToast('应用目录已刷新。', false);
      }} catch (error) {{
        showToast('应用目录刷新失败：' + String(error), true);
      }} finally {{
        refreshButton.disabled = false;
      }}
    }}

    document.getElementById('exportForm').addEventListener('submit', async (event) => {{
      event.preventDefault();
      exportButton.disabled = true;
      resultText.textContent = '正在请求导出服务…';
      try {{
        const reply = await callAction('dsl.export', {{
          appId: appIdInput.value.trim(),
          role: roleInput.value.trim()
        }});
        renderResponse(reply);
        const success = reply.status >= 200 && reply.status < 300;
        showToast(success ? '导出请求已完成，应用目录已刷新。' : '导出请求被服务端拒绝。', !success);
        if (success) await refreshApps();
      }} catch (error) {{
        httpStatus.textContent = 'HTTP —';
        resultText.textContent = '请求失败';
        responseBody.textContent = String(error);
        showToast('导出请求失败：' + String(error), true);
      }} finally {{
        exportButton.disabled = false;
      }}
    }});

    appIdInput.addEventListener('input', updateRequestPath);
    document.getElementById('newApp').addEventListener('click', () => showToast('训练目标未启用创建应用功能。', false));
    refreshButton.addEventListener('click', refreshApps);
    renderApps(initialApps);
    updateRequestPath();
  </script>
</body>
</html>"""


SKIN = render
