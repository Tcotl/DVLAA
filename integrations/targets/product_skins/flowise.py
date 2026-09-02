"""Flowise Chatflow API 控制台产品仿真皮肤。

本模块模拟 Flowise 的 Chatflow 列表与 API Playground。教学漏洞链对应
CVE-2024-8181：Flowise 1.8.2 的旧版管理员 Chatflow 路由把缺失的
``x-api-key`` 误判为公开请求；在 API Playground 中请求
``/api/v1/chatflows/admin-ops`` 即可由目标服务的既有 ``api.request``
动作复现泄露。页面不实现或复制任何漏洞判定逻辑。
"""

from __future__ import annotations

from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 5


def _map_admin_ops(_: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 Flowise 管理 Chatflow 的产品路径映射到既有教学动作。"""
    api_key = body.get("apiKey", body.get("x-api-key", body.get("x_api_key", "")))
    return {
        "path": "/api/v1/chatflows/admin-ops",
        "apiKey": "" if api_key is None else str(api_key),
    }


ALIASES = [
    {
        "method": "GET",
        "segments": ("api", "v1", "chatflows", "admin-ops"),
        "action": "api.request",
        "map": _map_admin_ops,
    },
]


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染只读的 Flowise 风格 Chatflow API 控制台。"""
    records_value = state.get("records", {})
    records = records_value if isinstance(records_value, Mapping) else {}
    health_value = records.get("health", {})
    health = health_value if isinstance(health_value, Mapping) else {}
    flow_value = records.get("admin_flow", {})
    flow = flow_value if isinstance(flow_value, Mapping) else {}
    session_value = records.get("session", {})
    session = session_value if isinstance(session_value, Mapping) else {}

    flow_id = esc(flow.get("id", "admin-ops"))
    flow_name = esc(flow.get("name", "Operations Chatflow"))
    health_status = esc(health.get("status", "unknown"))
    health_version = esc(health.get("version", "1.8.2-lab"))
    actor = esc(session.get("user", session.get("userId", "未认证调用者")))
    tenant = esc(session.get("tenant", "未绑定租户"))
    patched = bool(state.get("patched"))
    deployment = "已启用服务端路由认证" if patched else "易受攻击"
    banner_class = "patched" if patched else "vulnerable"
    banner_text = (
        "路由认证已加固：所有 Chatflow 请求均须通过服务端验证 x-api-key。"
        if patched
        else "检测到旧版路由：缺失 x-api-key 的管理员 Chatflow 请求可能被当作公开访问。"
    )
    attack_state = "已记录一次漏洞响应" if state.get("attack_solved") else "尚未触发漏洞响应"

    return """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Flowise · Chatflow API</title>
  <style>
    :root{color:#17232c;background:#f5f7fa;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    *{box-sizing:border-box} body{margin:0;min-width:320px;background:#f5f7fa}
    button,input{font:inherit} button{cursor:pointer}.app{min-height:100vh;display:grid;grid-template-columns:248px minmax(0,1fr)}
    .sidebar{background:#17212b;color:#d7e1e8;padding:18px 12px;border-right:1px solid #273542}.brand{display:flex;align-items:center;gap:10px;padding:5px 8px 21px;color:#fff;font-size:19px;font-weight:750;letter-spacing:-.5px}.brand-mark{width:29px;height:29px;border-radius:8px;background:#36c5a1;display:grid;place-items:center;color:#14242a;font-size:12px;font-weight:900}.workspace{margin:0 4px 20px;padding:10px;border:1px solid #354552;border-radius:8px;background:#202d37;font-size:12px}.workspace small{display:block;color:#8fa1ad;margin-bottom:4px}.workspace strong{font-size:13px}.nav-label{margin:18px 9px 7px;color:#80939e;font-size:10px;font-weight:800;letter-spacing:.1em}.nav-item{display:flex;align-items:center;gap:9px;margin:2px 0;padding:10px 9px;border-radius:6px;color:#b8c7cf;font-size:13px}.nav-item.active{color:#fff;background:#2d5b58}.nav-icon{width:15px;color:#6ee0c3;text-align:center;font-size:12px}.side-card{position:sticky;top:16px;margin:32px 4px 0;padding:12px;border:1px solid #354552;border-radius:8px;background:#1c2831;font-size:11px;line-height:1.55;color:#9cafb9}.side-card b{display:block;margin-bottom:4px;color:#e2edf1;font-size:12px}
    .content{min-width:0}.topbar{height:64px;display:flex;justify-content:space-between;align-items:center;padding:0 28px;background:#fff;border-bottom:1px solid #e3e8ed}.crumb{color:#6c7b86;font-size:13px}.crumb b{color:#27343e}.top-right{display:flex;align-items:center;gap:10px;font-size:12px}.avatar{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;background:#e4f8f1;color:#16745e;font-weight:800}.identity{line-height:1.25}.identity b{display:block;color:#283640;font-size:12px}.identity span{color:#7a8a95;font-size:11px}
    main{max-width:1350px;margin:0 auto;padding:27px 30px 38px}.title-row{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:22px}.title-row h1{margin:0 0 7px;color:#18262f;font-size:25px;letter-spacing:-.5px}.title-row p{margin:0;color:#71808a;font-size:13px}.tag{display:inline-flex;align-items:center;gap:6px;padding:7px 10px;border-radius:6px;background:#edf9f5;color:#16745e;font-size:11px;font-weight:750;white-space:nowrap}.tag i{width:6px;height:6px;border-radius:50%;background:#27bd92}.alert{display:flex;align-items:flex-start;gap:11px;padding:13px 15px;margin-bottom:18px;border:1px solid;border-radius:8px;font-size:13px;line-height:1.5}.alert.vulnerable{background:#fff6ed;border-color:#f3cf9e;color:#81511b}.alert.patched{background:#eefaf5;border-color:#a5dfc9;color:#17684f}.alert .cve{flex:none;padding:2px 6px;border:1px solid currentColor;border-radius:4px;font-size:10px;font-weight:850;letter-spacing:.04em}.alert strong{display:block;font-size:12px}
    .metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px;margin-bottom:18px}.metric{padding:15px 16px;border:1px solid #e2e7eb;border-radius:8px;background:#fff}.metric span{display:block;color:#82909a;font-size:11px;margin-bottom:7px}.metric b{display:block;color:#26343d;font-size:14px}.metric .ok{color:#168767}.metric .warn{color:#bb6a18}
    .layout{display:grid;grid-template-columns:minmax(280px,.85fr) minmax(440px,1.6fr);gap:18px}.card{border:1px solid #e0e6e9;border-radius:9px;background:#fff;box-shadow:0 3px 12px rgba(26,45,58,.035)}.card-title{display:flex;justify-content:space-between;align-items:center;padding:15px 17px;border-bottom:1px solid #edf0f2}.card-title h2{margin:0;color:#25323b;font-size:14px}.card-title span{color:#7a8992;font-size:11px}.flows{padding:10px}.flow{padding:13px;border:1px solid #aee7d8;border-radius:7px;background:#f3fcf9}.flow-top{display:flex;justify-content:space-between;gap:9px;align-items:center}.flow-name{display:flex;align-items:center;gap:8px;color:#1d3037;font-size:13px;font-weight:750}.flow-dot{width:8px;height:8px;border-radius:50%;background:#2ec49b}.flow-id{margin:8px 0;color:#71808a;font:11px ui-monospace,SFMono-Regular,Menlo,monospace}.flow-meta{display:flex;gap:7px}.mini{padding:3px 6px;border-radius:4px;background:#e2f7ef;color:#17775e;font-size:10px;font-weight:750}.empty-list{margin:10px 3px;color:#93a0a8;font-size:11px}.request-card{overflow:hidden}.api-head{display:flex;align-items:center;gap:9px;padding:12px 17px;background:#19262f;color:#ecf4f4}.api-head b{font-size:13px}.method{padding:3px 6px;border-radius:4px;background:#4c896f;color:#fff;font-size:10px;font-weight:850}.api-head code{color:#a9d9c8;font-size:12px}.api-body{padding:17px}.field-label{display:block;margin-bottom:6px;color:#53636d;font-size:12px;font-weight:750}.field-note{float:right;color:#87959d;font-size:10px;font-weight:500}.input-wrap{position:relative;margin-bottom:15px}.input{width:100%;height:39px;padding:9px 11px;border:1px solid #ced8dc;border-radius:6px;background:#fff;color:#1e2d35;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;outline:none}.input:focus{border-color:#2eb997;box-shadow:0 0 0 3px #d8f4ec}.key-row{display:grid;grid-template-columns:1fr auto;gap:9px;align-items:end}.button{border:0;border-radius:6px;padding:10px 13px;background:#1a9a7b;color:#fff;font-size:12px;font-weight:750}.button:hover{background:#158367}.button:disabled{opacity:.55;cursor:wait}.button.secondary{background:#edf3f5;color:#30414b}.button.secondary:hover{background:#e1ebee}.request-actions{display:flex;gap:9px;margin:2px 0 14px}.request-actions .button:first-child{flex:1}.code-line{padding:10px 11px;border-radius:6px;background:#f6f8f9;color:#54646e;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.response-head{display:flex;justify-content:space-between;align-items:center;margin-top:17px;margin-bottom:7px}.response-head b{color:#4d5d67;font-size:12px}.http-status{padding:3px 6px;border-radius:4px;background:#edf3f5;color:#61717b;font:10px ui-monospace,SFMono-Regular,Menlo,monospace}.response{min-height:218px;max-height:360px;overflow:auto;margin:0;padding:13px;border-radius:7px;background:#17232b;color:#d8e6e8;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.toast{position:fixed;right:20px;bottom:20px;z-index:3;max-width:360px;padding:11px 14px;border-radius:7px;background:#1f7c68;color:#fff;box-shadow:0 8px 26px #13242a42;font-size:12px;opacity:0;transform:translateY(12px);pointer-events:none;transition:.18s}.toast.show{opacity:1;transform:translateY(0)}.toast.error{background:#a54d3f}.footer-note{margin-top:16px;color:#81909a;font-size:11px}.footer-note code{color:#58737a}
    @media(max-width:850px){.app{grid-template-columns:1fr}.sidebar{display:none}.layout{grid-template-columns:1fr}.metrics{grid-template-columns:1fr}.topbar{padding:0 16px}main{padding:22px 16px}.title-row{display:block}.title-row .tag{margin-top:12px}}
  </style>
</head>
<body>
  <div class="app">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark">F</span>Flowise</div>
      <div class="workspace"><small>工作区</small><strong>Operations Workspace</strong></div>
      <div class="nav-label">构建</div>
      <div class="nav-item active"><span class="nav-icon">◆</span>Chatflows</div>
      <div class="nav-item"><span class="nav-icon">◇</span>Agentflows</div>
      <div class="nav-item"><span class="nav-icon">□</span>工具与凭证</div>
      <div class="nav-label">开发者</div>
      <div class="nav-item"><span class="nav-icon">›</span>API Keys</div>
      <div class="nav-item"><span class="nav-icon">›</span>变量</div>
      <div class="side-card"><b>本地教学目标</b>此控制台仅调用本地 AWDP 服务。业务记录由服务端维护，页面不会连接真实 Flowise 实例。</div>
    </aside>
    <div class="content">
      <header class="topbar">
        <div class="crumb"><b>Chatflows</b> / API Playground</div>
        <div class="top-right"><span class="avatar">A</span><div class="identity"><b>""" + actor + """</b><span>租户：""" + tenant + """</span></div></div>
      </header>
      <main>
        <div class="title-row">
          <div><h1>Chatflow API Playground</h1><p>检查 Chatflow 路由状态，并以产品 API 形状发送本地请求。</p></div>
          <div class="tag"><i></i><span id="deploymentBadge">""" + esc(deployment) + """</span></div>
        </div>
        <section id="securityBanner" class="alert """ + banner_class + """><span class="cve">CVE-2024-8181</span><div><strong>Flowise 1.8.2 路由授权状态</strong><span id="bannerText">""" + esc(banner_text) + """</span></div></section>
        <section class="metrics">
          <div class="metric"><span>公开健康检查</span><b class="ok">""" + health_status + """</b></div>
          <div class="metric"><span>服务版本</span><b>""" + health_version + """</b></div>
          <div class="metric"><span>漏洞审计</span><b id="auditState" class=""" + ("ok" if state.get("attack_solved") else "warn") + """>""" + esc(attack_state) + """</b></div>
        </section>
        <section class="layout">
          <section class="card">
            <div class="card-title"><h2>Chatflows</h2><span>1 个已登记</span></div>
            <div class="flows">
              <article class="flow">
                <div class="flow-top"><div class="flow-name"><span class="flow-dot"></span>""" + flow_name + """</div><span class="mini">运行中</span></div>
                <div class="flow-id">""" + flow_id + """</div>
                <div class="flow-meta"><span class="mini">管理员</span><span class="mini">API 可用</span></div>
              </article>
              <p class="empty-list">选择流程后，可在右侧 API Playground 检查路由响应。</p>
            </div>
          </section>
          <section class="card request-card">
            <div class="api-head"><span class="method">GET</span><b>Chatflow 详情</b><code id="endpointLabel">/api/v1/chatflows/admin-ops</code></div>
            <div class="api-body">
              <form id="apiForm">
                <label class="field-label" for="path">请求路径 <span class="field-note">API Endpoint</span></label>
                <div class="input-wrap"><input id="path" class="input" value="/api/v1/chatflows/admin-ops" spellcheck="false" autocomplete="off"></div>
                <div class="key-row">
                  <div><label class="field-label" for="apiKey">x-api-key <span class="field-note">可选请求头</span></label><input id="apiKey" class="input" value="" placeholder="留空以模拟未认证调用" spellcheck="false" autocomplete="off"></div>
                  <button id="healthButton" class="button secondary" type="button">健康检查</button>
                </div>
                <div class="request-actions"><button id="sendButton" class="button" type="submit">发送 API 请求</button></div>
              </form>
              <div id="requestPreview" class="code-line">GET /api/v1/chatflows/admin-ops\nx-api-key: （未提供）</div>
              <div class="response-head"><b>响应</b><span id="httpStatus" class="http-status">等待请求</span></div>
              <pre id="response" class="response">请选择健康检查，或保持默认管理员 Chatflow 路径并发送请求。</pre>
            </div>
          </section>
        </section>
        <p class="footer-note">当前目标：<code>""" + esc(base_path) + """</code> · 管理路由测试结果仅展示本地教学服务返回的 JSON。</p>
      </main>
    </div>
  </div>
  <div id="toast" class="toast" role="status" aria-live="polite"></div>
  <script>
""" + action_js(base_path) + """
    const form = document.getElementById('apiForm');
    const pathInput = document.getElementById('path');
    const keyInput = document.getElementById('apiKey');
    const sendButton = document.getElementById('sendButton');
    const healthButton = document.getElementById('healthButton');
    const responseBox = document.getElementById('response');
    const statusBox = document.getElementById('httpStatus');
    const preview = document.getElementById('requestPreview');
    const endpointLabel = document.getElementById('endpointLabel');
    const toast = document.getElementById('toast');

    function updatePreview() {
      const path = pathInput.value.trim() || '/api/v1/health';
      const key = keyInput.value.trim();
      endpointLabel.textContent = path;
      preview.textContent = 'GET ' + path + '\\nx-api-key: ' + (key ? key : '（未提供）');
    }

    function showToast(message, failed) {
      toast.textContent = message;
      toast.className = 'toast show' + (failed ? ' error' : '');
      window.clearTimeout(showToast.timer);
      showToast.timer = window.setTimeout(() => { toast.className = 'toast'; }, 3400);
    }

    function refreshTarget(target) {
      if (!target) return;
      const patched = Boolean(target.patched);
      const badge = document.getElementById('deploymentBadge');
      const banner = document.getElementById('securityBanner');
      badge.textContent = patched ? '已启用服务端路由认证' : '易受攻击';
      banner.className = 'alert ' + (patched ? 'patched' : 'vulnerable');
      document.getElementById('bannerText').textContent = patched
        ? '路由认证已加固：所有 Chatflow 请求均须通过服务端验证 x-api-key。'
        : '检测到旧版路由：缺失 x-api-key 的管理员 Chatflow 请求可能被当作公开访问。';
      const audit = document.getElementById('auditState');
      audit.textContent = target.attack_solved ? '已记录一次漏洞响应' : '尚未触发漏洞响应';
      audit.className = target.attack_solved ? 'ok' : 'warn';
    }

    async function requestApi() {
      const body = {path: pathInput.value.trim(), apiKey: keyInput.value.trim()};
      if (!body.path) {
        showToast('请填写 API 请求路径。', true);
        return;
      }
      sendButton.disabled = true;
      healthButton.disabled = true;
      statusBox.textContent = '请求发送中';
      responseBox.textContent = '正在调用本地 Chatflow 路由…';
      try {
        const reply = await callAction('api.request', body);
        const complete = {result: reply.result, target: reply.target};
        responseBox.textContent = JSON.stringify(complete, null, 2);
        statusBox.textContent = 'HTTP ' + reply.status + ' · ' + (reply.result.message || reply.result.code || '已返回响应');
        refreshTarget(reply.target || reply.result.state);
        showToast(reply.status >= 200 && reply.status < 300 ? '路由响应已返回。' : '路由返回了拒绝或错误响应。', reply.status >= 400);
      } catch (error) {
        responseBox.textContent = String(error);
        statusBox.textContent = '请求失败';
        showToast('无法读取本地服务响应。', true);
      } finally {
        sendButton.disabled = false;
        healthButton.disabled = false;
      }
    }

    form.addEventListener('submit', (event) => { event.preventDefault(); requestApi(); });
    healthButton.addEventListener('click', () => {
      pathInput.value = '/api/v1/health';
      keyInput.value = '';
      updatePreview();
      requestApi();
    });
    pathInput.addEventListener('input', updatePreview);
    keyInput.addEventListener('input', updatePreview);
    updatePreview();
  </script>
</body>
</html>"""


SKIN = render
