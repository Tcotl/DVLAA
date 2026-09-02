"""AWDP07 Open WebUI 网页资料抓取产品仿真皮肤。

该界面模拟 Open WebUI 的聊天与 Web Search 工作区，用户通过网页抓取配置调用
既有 ``crawler.fetch`` 动作。教学漏洞链对应 CVE-2024-30256：旧版抓取器允许
受认证用户请求元数据或私网 URL，并将上游 ``metadata_verifier`` 带回对话上下文。
"""

from __future__ import annotations

from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 7


def _map_retrieval_fetch(_params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 Open WebUI 风格抓取请求转换为目标服务的业务动作参数。"""
    return {
        "url": body.get("url", body.get("target_url", "")),
        "followRedirects": body.get("followRedirects", body.get("follow_redirects", True)),
    }


ALIASES = [
    {
        "method": "POST",
        "segments": ("api", "v1", "retrieval", "fetch"),
        "action": "crawler.fetch",
        "map": _map_retrieval_fetch,
    },
]


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染 Open WebUI 风格的本地网页资料抓取工作区。"""
    records = state.get("records", {})
    records = records if isinstance(records, Mapping) else {}
    session = records.get("session", {})
    session = session if isinstance(session, Mapping) else {}
    identity = session.get("user") or session.get("userId") or "已认证研究用户"
    workspace = session.get("tenant") or "公开资料工作区"
    public_documents = records.get("public_documents", {})
    public_documents = public_documents if isinstance(public_documents, Mapping) else {}
    first_url, first_document = next(iter(public_documents.items()), ("https://docs.example.test/refund-policy", {}))
    first_document = first_document if isinstance(first_document, Mapping) else {}
    first_title = first_document.get("title") or "公开网页资料"
    first_summary = first_document.get("summary") or "尚未加载可用的公开资料摘要。"
    deployment = "已修复" if state.get("patched") else "易受攻击"
    deployment_class = "patched" if state.get("patched") else "vulnerable"
    helper_script = action_js(base_path)

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Open WebUI · 网页资料抓取</title>
<style>
:root {{
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #f3f4f6;
  background: #111216;
}}
* {{ box-sizing: border-box; }}
body {{ min-width: 320px; margin: 0; min-height: 100vh; background: #111216; }}
button, input {{ font: inherit; }}
.app {{ display: grid; grid-template-columns: 258px minmax(0, 1fr); min-height: 100vh; }}
.sidebar {{ display: flex; flex-direction: column; padding: 16px 12px; background: #191a1f; border-right: 1px solid #2b2d34; }}
.brand {{ display: flex; align-items: center; gap: 10px; padding: 5px 8px 21px; font-size: 16px; font-weight: 720; letter-spacing: -.2px; }}
.brand-mark {{ display: grid; width: 29px; height: 29px; place-items: center; border: 1px solid #565863; border-radius: 9px; background: #f4f4f5; color: #17181c; font-size: 12px; font-weight: 800; }}
.new-chat {{ width: 100%; padding: 10px 12px; border: 1px solid #3b3d46; border-radius: 8px; background: #24262d; color: #f6f7fb; text-align: left; font-size: 13px; cursor: pointer; }}
.new-chat:hover {{ background: #2c2e36; }}
.nav-label {{ margin: 23px 9px 8px; color: #9699a5; font-size: 10px; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }}
.nav-item {{ display: flex; align-items: center; gap: 10px; padding: 10px 10px; border: 0; border-radius: 7px; background: transparent; color: #afb2bd; text-align: left; font-size: 13px; }}
.nav-item.active {{ background: #2c2d35; color: #fff; }}
.nav-dot {{ width: 7px; height: 7px; border-radius: 50%; background: #727681; }}
.nav-item.active .nav-dot {{ background: #ededf1; }}
.account {{ margin-top: auto; padding: 12px 9px 5px; border-top: 1px solid #30323a; color: #b7bac4; font-size: 12px; line-height: 1.55; }}
.account strong {{ display: block; color: #f0f1f5; font-size: 13px; }}
.main {{ min-width: 0; background: #111216; }}
.topbar {{ display: flex; align-items: center; justify-content: space-between; min-height: 64px; padding: 0 28px; border-bottom: 1px solid #292b32; }}
.crumb {{ color: #f6f7f9; font-size: 14px; font-weight: 650; }}
.crumb small {{ margin-left: 9px; color: #9296a1; font-size: 12px; font-weight: 500; }}
.top-meta {{ display: flex; align-items: center; gap: 9px; color: #a8abb4; font-size: 12px; }}
.state {{ padding: 4px 8px; border: 1px solid #605047; border-radius: 99px; color: #f2c893; background: #302820; font-size: 11px; font-weight: 700; }}
.state.patched {{ border-color: #355a4b; background: #19342c; color: #a4dfc1; }}
.workspace {{ max-width: 1320px; margin: 0 auto; padding: 28px; }}
.heading {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 20px; }}
h1 {{ margin: 0 0 7px; font-size: 25px; letter-spacing: -.5px; }}
.subhead {{ margin: 0; color: #9296a3; font-size: 13px; line-height: 1.6; }}
.cve {{ flex: 0 0 auto; padding: 8px 10px; border: 1px solid #59483d; border-radius: 8px; background: #251f1c; color: #e6c0a7; font-size: 12px; }}
.alert {{ display: flex; align-items: flex-start; gap: 12px; margin-bottom: 20px; padding: 13px 15px; border: 1px solid #604032; border-radius: 9px; background: #291d1a; color: #d4b1a5; font-size: 13px; line-height: 1.55; }}
.alert b {{ color: #ffd0bb; }}
.alert-mark {{ display: grid; flex: 0 0 auto; width: 20px; height: 20px; place-items: center; border: 1px solid #b77055; border-radius: 50%; color: #f5c5b1; font-size: 12px; font-weight: 800; }}
.columns {{ display: grid; grid-template-columns: minmax(400px, 1fr) minmax(315px, .58fr); gap: 18px; align-items: start; }}
.panel {{ overflow: hidden; border: 1px solid #2c2e35; border-radius: 11px; background: #1a1b20; box-shadow: 0 12px 35px #00000020; }}
.panel-title {{ display: flex; align-items: center; justify-content: space-between; padding: 14px 16px; border-bottom: 1px solid #2c2e35; }}
.panel-title strong {{ font-size: 14px; }}
.panel-title span {{ color: #8f939e; font-size: 11px; }}
.chat {{ min-height: 442px; padding: 17px; }}
.message {{ display: grid; grid-template-columns: 28px minmax(0, 1fr); gap: 10px; margin-bottom: 18px; }}
.avatar {{ display: grid; width: 28px; height: 28px; place-items: center; border-radius: 8px; background: #e8e9eb; color: #1b1c20; font-size: 11px; font-weight: 800; }}
.avatar.user {{ background: #33353d; color: #e6e7eb; }}
.message-name {{ margin-bottom: 5px; color: #aeb1ba; font-size: 11px; }}
.bubble {{ max-width: 660px; color: #e5e6eb; font-size: 13px; line-height: 1.65; }}
.source-card {{ margin-top: 9px; padding: 11px 12px; border: 1px solid #363842; border-radius: 8px; background: #202126; }}
.source-url {{ overflow: hidden; color: #9ca1ad; font: 11px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; text-overflow: ellipsis; white-space: nowrap; }}
.source-card strong {{ display: block; margin: 5px 0 2px; color: #f1f2f4; font-size: 13px; }}
.source-card p {{ margin: 0; color: #b6bac4; font-size: 12px; line-height: 1.55; }}
.response {{ margin: 0 16px 16px; padding: 12px; min-height: 130px; overflow: auto; border: 1px solid #30323b; border-radius: 8px; background: #101116; color: #bfc4cf; font: 11px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; }}
.form-body {{ padding: 16px; }}
.field-label {{ display: flex; justify-content: space-between; margin-bottom: 7px; color: #d4d6dd; font-size: 12px; font-weight: 650; }}
.field-label span {{ color: #818591; font-size: 11px; font-weight: 500; }}
.url-input {{ width: 100%; padding: 11px 12px; border: 1px solid #43454f; border-radius: 8px; outline: 0; background: #121318; color: #f1f2f4; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }}
.url-input:focus {{ border-color: #8b8e98; box-shadow: 0 0 0 3px #777b8822; }}
.option {{ display: flex; align-items: center; gap: 9px; margin: 14px 0; color: #bec1ca; font-size: 12px; }}
.option input {{ width: 15px; height: 15px; accent-color: #e2e3e7; }}
.fetch-button {{ width: 100%; padding: 11px 13px; border: 0; border-radius: 8px; background: #f3f4f5; color: #17181c; font-size: 13px; font-weight: 750; cursor: pointer; }}
.fetch-button:hover {{ background: #fff; }}
.fetch-button:disabled {{ cursor: wait; opacity: .62; }}
.hint {{ margin: 12px 0 0; color: #858994; font-size: 11px; line-height: 1.55; }}
.info-list {{ margin: 0; padding: 0; list-style: none; }}
.info-list li {{ display: flex; justify-content: space-between; gap: 12px; padding: 9px 0; border-bottom: 1px solid #2d2f36; color: #b8bbc4; font-size: 12px; }}
.info-list li:last-child {{ border-bottom: 0; }}
.info-list span {{ color: #858995; }}
.info-list code {{ color: #d8dae0; font-size: 11px; }}
.toast {{ position: fixed; right: 22px; bottom: 20px; max-width: min(420px, calc(100vw - 44px)); padding: 10px 13px; border: 1px solid #3b3e47; border-radius: 8px; background: #24262c; color: #e6e8ed; box-shadow: 0 10px 30px #0008; font-size: 12px; opacity: 0; pointer-events: none; transform: translateY(8px); transition: opacity .18s, transform .18s; }}
.toast.show {{ opacity: 1; transform: translateY(0); }}
@media (max-width: 850px) {{ .app {{ grid-template-columns: 1fr; }} .sidebar {{ display: none; }} .columns {{ grid-template-columns: 1fr; }} .workspace {{ padding: 18px; }} .topbar {{ padding: 0 18px; }} .heading {{ display: block; }} .cve {{ display: inline-block; margin-top: 12px; }} }}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar" aria-label="Open WebUI 导航">
    <div class="brand"><span class="brand-mark">OW</span><span>Open WebUI</span></div>
    <button class="new-chat" type="button" id="newChat">新建对话</button>
    <div class="nav-label">工作区</div>
    <div class="nav-item"><span class="nav-dot"></span>对话</div>
    <div class="nav-item active"><span class="nav-dot"></span>网页资料</div>
    <div class="nav-item"><span class="nav-dot"></span>知识库</div>
    <div class="nav-label">工具</div>
    <div class="nav-item"><span class="nav-dot"></span>Web Search</div>
    <div class="nav-item"><span class="nav-dot"></span>设置</div>
    <div class="account"><strong>{esc(identity)}</strong><span>工作区：{esc(workspace)}</span></div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div class="crumb">网页资料抓取 <small>Web Search / Retrieval</small></div>
      <div class="top-meta"><span>Open WebUI v0.6.18</span><span class="state {deployment_class}" id="deployment">部署：{deployment}</span></div>
    </header>
    <div class="workspace">
      <section class="heading">
        <div><h1>为对话添加网页上下文</h1><p class="subhead">输入已授权资料链接，抓取器会将摘要添加到当前研究对话。</p></div>
        <div class="cve">安全公告：CVE-2024-30256</div>
      </section>
      <section class="alert" id="securityBanner"><div class="alert-mark">!</div><div><b>远程抓取安全边界</b><br>旧版 Web Search 组件可能将私网与元数据响应带入对话上下文。当前环境状态：<span id="bannerState">{deployment}</span>。</div></section>
      <section class="columns">
        <section class="panel">
          <div class="panel-title"><strong>研究对话</strong><span id="chatState">等待资料抓取</span></div>
          <div class="chat" id="chat">
            <div class="message"><div class="avatar">OW</div><div><div class="message-name">网页摘要 Agent</div><div class="bubble">您好，我可以抓取已授权网页，并把资料摘要添加到本次研究对话。</div></div></div>
            <div class="message"><div class="avatar user">你</div><div><div class="message-name">当前请求</div><div class="bubble">请加载一份资料，供后续对话参考。</div></div></div>
            <div class="message" id="publicSource"><div class="avatar">OW</div><div><div class="message-name">已验证的公开资料</div><div class="source-card"><div class="source-url">{esc(first_url)}</div><strong>{esc(first_title)}</strong><p>{esc(first_summary)}</p></div></div></div>
          </div>
          <pre class="response" id="response" aria-live="polite">尚未发送抓取请求。</pre>
        </section>
        <aside>
          <section class="panel">
            <div class="panel-title"><strong>网页抓取设置</strong><span>已认证会话</span></div>
            <form class="form-body" id="fetchForm">
              <label class="field-label" for="targetUrl">目标 URL <span>HTTP / HTTPS</span></label>
              <input class="url-input" id="targetUrl" name="url" type="url" value="http://169.254.169.254/latest/meta-data/" spellcheck="false" required>
              <label class="option"><input id="followRedirects" type="checkbox" checked>跟随重定向</label>
              <button class="fetch-button" id="fetchButton" type="submit">抓取并生成摘要</button>
              <p class="hint">提交后会在当前对话展示服务器返回的资料结果。该页面仅请求本地训练目标。</p>
            </form>
          </section>
          <section class="panel" style="margin-top:18px">
            <div class="panel-title"><strong>当前会话</strong><span>只读资料范围</span></div>
            <div class="form-body"><ul class="info-list"><li><span>身份</span><code>{esc(identity)}</code></li><li><span>工作区</span><code>{esc(workspace)}</code></li><li><span>抓取动作</span><code>crawler.fetch</code></li><li><span>公开资料</span><code id="documentCount">{len(public_documents)} 条</code></li></ul></div>
          </section>
        </aside>
      </section>
    </div>
  </main>
</div>
<div class="toast" id="toast" role="status"></div>
<script>
{helper_script}
const basePath = {base_path!r};
const form = document.getElementById('fetchForm');
const targetUrl = document.getElementById('targetUrl');
const redirects = document.getElementById('followRedirects');
const fetchButton = document.getElementById('fetchButton');
const responsePanel = document.getElementById('response');
const chat = document.getElementById('chat');
const toast = document.getElementById('toast');
let toastTimer;

function showToast(text) {{
  toast.textContent = text;
  toast.classList.add('show');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove('show'), 3500);
}}

function addResultMessage(result, requestedUrl) {{
  const data = result && result.data && typeof result.data === 'object' ? result.data : {{}};
  const message = document.createElement('div');
  message.className = 'message';
  const avatar = document.createElement('div');
  avatar.className = 'avatar';
  avatar.textContent = 'OW';
  const content = document.createElement('div');
  const name = document.createElement('div');
  name.className = 'message-name';
  name.textContent = '网页摘要 Agent';
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = result && result.message ? result.message : '抓取请求已完成。';
  content.append(name, bubble);
  if (data.title || data.summary || data.source) {{
    const card = document.createElement('div');
    card.className = 'source-card';
    const url = document.createElement('div');
    url.className = 'source-url';
    url.textContent = data.source || requestedUrl;
    const title = document.createElement('strong');
    title.textContent = data.title || '抓取响应';
    const summary = document.createElement('p');
    summary.textContent = data.summary || (data.metadata_verifier ? '上游元数据响应已加入当前对话。' : '服务器未提供可显示的摘要。');
    card.append(url, title, summary);
    content.appendChild(card);
  }}
  message.append(avatar, content);
  chat.appendChild(message);
  chat.scrollTop = chat.scrollHeight;
}}

function refreshDeployment(target) {{
  if (!target || typeof target.patched !== 'boolean') return;
  const patched = target.patched;
  const text = patched ? '已修复' : '易受攻击';
  const badge = document.getElementById('deployment');
  badge.textContent = '部署：' + text;
  badge.classList.toggle('patched', patched);
  document.getElementById('bannerState').textContent = text;
}}

form.addEventListener('submit', async (event) => {{
  event.preventDefault();
  const request = {{url: targetUrl.value.trim(), followRedirects: redirects.checked}};
  fetchButton.disabled = true;
  document.getElementById('chatState').textContent = '正在抓取网页资料…';
  responsePanel.textContent = '请求发送中…';
  try {{
    const output = await callAction('crawler.fetch', request);
    const fullResponse = {{result: output.result, target: output.target}};
    responsePanel.textContent = 'HTTP ' + output.status + '\\n' + JSON.stringify(fullResponse, null, 2);
    refreshDeployment(output.target);
    addResultMessage(output.result, request.url);
    const message = output.result && output.result.message ? output.result.message : '抓取请求已完成。';
    document.getElementById('chatState').textContent = 'HTTP ' + output.status + ' · 已更新对话上下文';
    showToast('HTTP ' + output.status + ' · ' + message);
  }} catch (error) {{
    responsePanel.textContent = '请求失败\\n' + String(error);
    document.getElementById('chatState').textContent = '抓取请求失败';
    showToast('抓取请求失败，请检查本地目标服务。');
  }} finally {{
    fetchButton.disabled = false;
  }}
}});

document.getElementById('newChat').addEventListener('click', () => {{
  targetUrl.value = 'https://docs.example.test/refund-policy';
  redirects.checked = true;
  showToast('已创建新的资料抓取对话。');
}});
</script>
</body>
</html>"""


SKIN = render
