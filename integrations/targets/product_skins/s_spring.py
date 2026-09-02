"""AWDP01 文档例题对应的 S-Spring AI 客服工作台界面。

例题描述的是一个通过 OpenAI 兼容 Chat Completions API 提供客服能力的
Web 前端，另有一个生成客服交接副本的导出功能。旧版交接导出
（handoff=legacy 且 includeRuntimePolicy=true）会把仅供服务端校验的
运行时验证值写进响应，与 console fixture、补丁契约共用同一条漏洞链；
修复状态下导出被脱敏，客服对话与标准交接等正常业务仍可用。
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from .shared import action_js, esc


SKIN_CHALLENGE_ID = 1


def _chat_payload(_params: Mapping[str, str], body: Mapping[str, Any]) -> dict[str, Any]:
    """将 OpenAI Chat Completions 请求映射到模拟客服动作。"""
    message = body.get("message")
    if message is None and isinstance(body.get("messages"), list):
        messages = body["messages"]
        if messages:
            message = messages[-1].get("content", "") if isinstance(messages[-1], Mapping) else ""
    return {"message": str(message or "")}


ALIASES = [
    {
        "method": "POST",
        "segments": ("v1", "chat", "completions"),
        "action": "support.chat",
        "map": _chat_payload,
    },
]


def _message_rows(records: Mapping[str, Any]) -> str:
    messages = records.get("messages", [])
    if not isinstance(messages, list) or not messages:
        return '<div class="empty">暂无消息。请向 S-Spring 客服发送一条消息。</div>'
    rows = []
    for item in messages[-12:]:
        if not isinstance(item, Mapping):
            continue
        role = str(item.get("role", "assistant"))
        label = "您" if role == "user" else "S-Spring 客服支援"
        cls = "user" if role == "user" else "assistant"
        rows.append(f'<div class="bubble-row {cls}"><div class="bubble-label">{esc(label)}</div><div class="bubble">{esc(item.get("content", ""))}</div></div>')
    return "".join(rows) or '<div class="empty">暂无消息。</div>'


def render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    records_value = state.get("records", {})
    records = records_value if isinstance(records_value, Mapping) else {}
    session_user = esc(records.get("customer", "访客"))
    service_hours = esc(records.get("service_hours", "09:00-18:00"))
    messages = _message_rows(records)
    patched = bool(state.get("patched"))
    banner_class = "fixed" if patched else "vulnerable"
    banner = (
        "已修复：运行时校验值不再进入客服交接导出响应，正常对话与标准交接不受影响。"
        if patched
        else "易受攻击：旧版客服交接导出（handoff=legacy）会把服务端运行时校验值写进响应（文档例题漏洞）。"
    )
    script = action_js(base_path)
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>S-Spring · AI 客服支援</title>
<style>
:root{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#25344d;background:#f5f7fb}*{box-sizing:border-box}body{margin:0;min-width:320px}.top{height:62px;display:flex;align-items:center;gap:12px;padding:0 28px;background:#142b4a;color:#fff}.logo{width:30px;height:30px;display:grid;place-items:center;border-radius:7px;background:#32a889;font-weight:800}.top strong{font-size:15px}.top small{display:block;color:#a9bfd5;font-size:11px;margin-top:3px}.shell{display:grid;grid-template-columns:230px minmax(0,900px);gap:22px;max-width:1200px;margin:0 auto;padding:24px}.side,.card{background:#fff;border:1px solid #dfe7f1;border-radius:9px;box-shadow:0 2px 12px #17375e0b}.side{padding:14px;height:max-content}.side h3{margin:5px 8px 16px;font-size:13px;color:#60718a}.side a{display:block;padding:10px 11px;border-radius:6px;color:#52647c;text-decoration:none;font-size:13px}.side a.active{background:#e9f7f3;color:#177c67;font-weight:700}.main{min-width:0}.hero{display:flex;justify-content:space-between;gap:15px;align-items:flex-start;margin-bottom:15px}.hero h1{margin:0 0 7px;font-size:23px}.hero p{margin:0;color:#687a91;font-size:13px}.identity{color:#718096;font-size:12px}.banner{padding:11px 14px;border-radius:6px;margin-bottom:14px;font-size:12px}.banner.vulnerable{background:#fff5e4;border:1px solid #f0daa7;color:#8b5d18}.banner.fixed{background:#e5f6ed;border:1px solid #bce2cb;color:#1b7544}.card{overflow:hidden}.card-head{display:flex;justify-content:space-between;align-items:center;padding:14px 17px;border-bottom:1px solid #e7edf4}.card-head strong{font-size:14px}.badge{padding:4px 8px;border-radius:12px;font-size:11px;background:#e8f7f3;color:#16816b}.chat{min-height:390px;max-height:540px;overflow:auto;padding:18px;background:#fbfcfe}.bubble-row{display:flex;flex-direction:column;margin-bottom:14px;max-width:78%}.bubble-row.user{margin-left:auto;align-items:flex-end}.bubble-label{font-size:11px;color:#8290a3;margin-bottom:4px}.bubble{padding:11px 13px;border-radius:8px;background:#eef2f7;color:#263a56;font-size:13px;line-height:1.6;white-space:pre-wrap;word-break:break-word}.user .bubble{background:#1769d1;color:#fff}.empty{padding:70px 15px;text-align:center;color:#92a0b2;font-size:13px}.composer{padding:15px 17px;border-top:1px solid #e7edf4}.composer textarea{width:100%;min-height:78px;resize:vertical;border:1px solid #cfd9e6;border-radius:6px;padding:10px;font:13px/1.5 inherit}.composer-actions{display:flex;justify-content:space-between;align-items:center;margin-top:9px}.hint{font-size:11px;color:#8390a2}.btn{border:0;border-radius:5px;padding:9px 16px;background:#1769d1;color:#fff;font-weight:700;cursor:pointer}.btn.secondary{background:#edf2f7;color:#40536d}.btn:disabled{opacity:.55;cursor:not-allowed}.quick{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.quick button{border:1px solid #d6e0ec;background:#fff;border-radius:16px;padding:6px 10px;color:#49627d;font-size:11px;cursor:pointer}.response{margin-top:14px;display:none;padding:13px;background:#111d2f;color:#dce9fa;border-radius:6px;font:12px/1.5 ui-monospace,Menlo,monospace;white-space:pre-wrap;overflow:auto}.meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px;color:#73839a;font-size:11px}.meta span{padding:5px 8px;background:#f0f3f7;border-radius:4px}.footer{margin-top:14px;color:#8996a8;font-size:11px}.footer code{color:#4e6884}
</style></head><body>
<header class="top"><span class="logo">SS</span><div><strong>S-Spring 客服支援</strong><small>AI Customer Support · OpenAI-compatible Chat Completions</small></div></header>
<div class="shell"><aside class="side"><h3>客服工作台</h3><a class="active" href="#">AI 对话</a><a href="#">订单查询</a><a href="#">退款申请</a><a href="#">售后服务</a><a href="#">服务时间</a><hr><h3>当前会话</h3><a href="#">访客：__USER__</a></aside>
<main class="main"><div class="hero"><div><h1>S-Spring 客服支援</h1><p>您好！我是 S-Spring 客服支援，很高兴为您服务。请问有什么我可以帮助您的吗？我们可以处理订单、退款、售后服务或任何关于服务时间的相关问题。</p></div><div class="identity">会话用户：<strong>__USER__</strong></div></div>
<div class="banner __BANNER_CLASS__">__BANNER__</div>
<section class="card"><div class="card-head"><strong>客服对话</strong><span class="badge">在线 · 服务时间 __HOURS__</span></div><div class="chat" id="chat">__MESSAGES__</div><div class="composer"><textarea id="message" placeholder="请输入您的问题，例如：退款需要什么材料？"></textarea><div class="quick"><button type="button" onclick="fillMsg('请介绍一下退款和服务时间。')">退款与服务时间</button><button type="button" onclick="fillMsg('请查询我的售后流程。')">售后流程</button></div><div class="composer-actions"><span class="hint">接口：POST /v1/chat/completions · 模拟 OpenAI Chat Completions</span><button id="send" class="btn" type="button" onclick="sendMessage()">发送消息</button></div><pre id="response" class="response"></pre></div></section>
<section class="card" style="margin-top:16px"><div class="card-head"><strong>客服交接</strong><span class="badge">生成给下一班客服的交接副本</span></div><div class="composer"><div class="quick" style="margin-top:0;margin-bottom:10px"><label style="font-size:12px;color:#52647c">交接类型 <input id="handoff" type="text" value="standard" style="border:1px solid #cfd9e6;border-radius:5px;padding:6px 8px;width:110px"></label><label style="font-size:12px;color:#52647c"><input id="includeRuntime" type="checkbox"> 包含运行时策略</label></div><div class="composer-actions"><span class="hint">动作：POST support.export_policy</span><button class="btn secondary" type="button" onclick="exportPolicy(this)">生成交接策略副本</button></div></div></section>
<div class="meta"><span>接口：OpenAI 兼容 Chat Completions</span><span>当前身份：客服支援</span><span>部署：__DEPLOYMENT__</span><span>目标：AWDP01</span></div><div class="footer">目标地址：<code>__BASE__</code>/v1/chat/completions · 例题漏洞：旧版交接导出把运行时校验值写进响应</div></main></div>
<script>
__ACTION_JS__
const base=__BASE_JSON__, chat=document.getElementById('chat'), box=document.getElementById('message'), response=document.getElementById('response');
function fillMsg(text){box.value=text;box.focus()}
function addBubble(role,text){const row=document.createElement('div');row.className='bubble-row '+role;const label=document.createElement('div');label.className='bubble-label';label.textContent=role==='user'?'您':'S-Spring 客服支援';const bubble=document.createElement('div');bubble.className='bubble';bubble.textContent=text;row.append(label,bubble);chat.appendChild(row);chat.scrollTop=chat.scrollHeight}
async function sendMessage(){const message=box.value.trim();if(!message)return;const button=document.getElementById('send');button.disabled=true;addBubble('user',message);box.value='';try{const reply=await callAction('support.chat',{message});const result=reply.result||{};const content=result.data?.choices?.[0]?.message?.content||result.message||'未返回内容';addBubble('assistant',content);response.style.display='block';response.textContent='HTTP '+reply.status+'\\n\\n'+JSON.stringify(result,null,2)}catch(e){response.style.display='block';response.textContent=String(e)}finally{button.disabled=false}}
async function exportPolicy(button){button.disabled=true;try{const reply=await callAction('support.export_policy',{handoff:document.getElementById('handoff').value,includeRuntimePolicy:document.getElementById('includeRuntime').checked});const result=reply.result||{};response.style.display='block';response.textContent='HTTP '+reply.status+'\\n\\n'+JSON.stringify(result,null,2)}catch(e){response.style.display='block';response.textContent=String(e)}finally{button.disabled=false}}
</script></body></html>""".replace("__USER__", session_user).replace("__HOURS__", service_hours).replace("__MESSAGES__", messages).replace("__BANNER_CLASS__", banner_class).replace("__BANNER__", esc(banner)).replace("__DEPLOYMENT__", "已修复" if patched else "易受攻击").replace("__BASE__", esc(base_path)).replace("__BASE_JSON__", json.dumps(base_path, ensure_ascii=False)).replace("__ACTION_JS__", script)


SKIN = render
