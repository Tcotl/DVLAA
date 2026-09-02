"""AWDP 决赛十题（AWDP11-AWDP20）的产品仿真门户皮肤。

十道决赛题共享同一套业务门户布局（品牌区 + 业务操作 + 请求响应控制台），
各题通过 FINALS_META 与配色进行品牌化。皮肤只负责界面与交互；漏洞逻辑、
Flag 与补丁状态全部由 target_server 的 /api/action 后端（finals_core 引擎）
提供，与 console 侧回归判定共用同一实现。
"""

from __future__ import annotations

import html
import json
from typing import Any, Mapping

import finals_core

# 各题品牌主色，贴近题面业务域的常见控制台配色。
ACCENTS: dict[int, str] = {
    11: "#0f6f5c",
    12: "#2563eb",
    13: "#7c3aed",
    14: "#b45309",
    15: "#be185d",
    16: "#0e7490",
    17: "#1d4ed8",
    18: "#15803d",
    19: "#9333ea",
    20: "#c2410c",
    21: "#0d9488",
    22: "#4f46e5",
    23: "#059669",
    24: "#d97706",
    25: "#7c3aed",
    26: "#1e40af",
    27: "#b91c1c",
    28: "#0369a1",
    29: "#c026d3",
    30: "#525252",
}


def _render(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    meta = finals_core.FINALS_META[challenge_id]
    accent = ACCENTS.get(challenge_id, "#1769d1")
    title = html.escape(meta["title"])
    subtitle = html.escape(meta["subtitle"])
    project = html.escape(meta["project"])
    actions_meta = [
        {
            "name": action["name"],
            "label": action["label"],
            "method": action["method"],
            "description": action["description"],
            "fields": [dict(field) for field in action["fields"]],
        }
        for action in finals_core.actions(challenge_id)
    ]
    actions_json = json.dumps(actions_meta, ensure_ascii=False)
    patched = bool(state.get("patched"))
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>""" + title + """ · Business Portal</title>
<style>
:root{--accent:""" + accent + """;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#1c2733;background:#f5f7fa}
*{box-sizing:border-box}body{margin:0;min-width:320px}
.top{display:flex;align-items:center;gap:14px;padding:14px 24px;background:#fff;border-bottom:1px solid #e3e8ef}
.mark{width:34px;height:34px;display:grid;place-items:center;border-radius:8px;background:var(--accent);color:#fff;font-weight:800;font-size:12px}
.top strong{font-size:15px;display:block}.top small{color:#64748b;font-size:12px}
.pill{margin-left:auto;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700;background:#e8f5ee;color:#177a52}
.pill.vuln{background:#fdeceb;color:#c0392b}
.shell{max-width:1180px;margin:0 auto;padding:22px 24px 40px}
.hero h1{margin:0 0 6px;font-size:24px}.hero p{margin:0;color:#64748b;font-size:13px}
.meta{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
.badge{padding:4px 9px;border-radius:5px;background:#eef2f7;color:#475569;font-size:11px;font-weight:700}
.grid{display:grid;grid-template-columns:320px minmax(0,1fr);gap:16px;margin-top:18px}
.panel{border:1px solid #e3e8ef;border-radius:10px;background:#fff;box-shadow:0 2px 10px rgba(23,55,94,.05)}
.panel h2{font-size:14px;margin:0;padding:14px 16px;border-bottom:1px solid #edf1f6;color:#334155}
.panel-body{padding:14px 16px}
.action{display:flex;width:100%;padding:10px 12px;margin:0 0 8px;border:1px solid #e0e6ee;border-radius:8px;background:#fbfcfe;text-align:left;color:#24344d;cursor:pointer}
.action.active{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,#fff);color:var(--accent)}
.action strong{display:block;font-size:13px}.action span{display:block;margin-top:2px;color:#7c8aa0;font-size:11px}
.label{display:block;margin:0 0 5px;color:#52647d;font-size:12px;font-weight:700}
.field{width:100%;padding:9px 10px;border:1px solid #d4dce6;border-radius:6px;margin-bottom:10px;background:#fff;color:#1c2733;font:inherit}
.btn{border:0;border-radius:6px;padding:10px 18px;background:var(--accent);color:#fff;font-weight:700;cursor:pointer}
.btn:disabled{opacity:.6}
.status{margin-top:10px;color:#5d6e86;font-size:12px}
.response{min-height:380px;margin:0;padding:14px;background:#101c2e;color:#d9e6f7;border-radius:8px;overflow:auto;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}
.foot{margin-top:14px;color:#8a97a8;font-size:12px}
</style></head><body>
<header class="top"><span class="mark">AW</span><div><strong>""" + title + """</strong><small>""" + subtitle + """ · """ + project + """</small></div>
<span id="patchBadge" class="pill""" + ("" if patched else " vuln") + """">部署状态：""" + ("已修复" if patched else "易受攻击") + """</span></header>
<main class="shell">
<section class="hero"><h1>""" + title + """</h1><p>""" + subtitle + """。所有业务请求直接发送到当前环境的目标服务。</p>
<div class="meta"><span class="badge">业务门户</span><span class="badge">HTTP API</span><span class="badge">AWDP""" + str(challenge_id).zfill(2) + """</span></div></section>
<section class="grid">
<section class="panel"><h2>业务操作</h2><div class="panel-body" id="actions"></div></section>
<section class="panel"><h2>请求与响应</h2><div class="panel-body">
<form id="requestForm"><div id="fields"></div><button id="send" class="btn" type="submit">发送请求</button></form>
<div id="status" class="status">准备就绪</div>
<pre id="response" class="response">选择左侧操作后发送请求。</pre>
</div></section></section>
<div class="foot">目标地址：<code>""" + html.escape(base_path) + """</code> · 本地训练环境，不连接任何线上系统。</div>
</main>
<script>
const ACTIONS=""" + actions_json + """; const base=""" + json.dumps(base_path) + """; let selected=ACTIONS[0];
const actions=document.getElementById('actions'), fields=document.getElementById('fields'), form=document.getElementById('requestForm'), response=document.getElementById('response'), status=document.getElementById('status');
function renderActions(){actions.innerHTML='';ACTIONS.forEach(a=>{const b=document.createElement('button');b.type='button';b.className='action'+(a===selected?' active':'');b.innerHTML='<strong>'+a.label+'</strong><span>'+a.method+' · '+a.name+'</span>';b.onclick=()=>{selected=a;renderActions();renderFields()};actions.appendChild(b)})}
function renderFields(){fields.innerHTML='';(selected.fields||[]).forEach(f=>{const l=document.createElement('label');l.className='label';l.textContent=f.label;let input;if(f.type==='textarea'){input=document.createElement('textarea');input.rows=4}else{input=document.createElement('input');input.type=f.type==='boolean'?'checkbox':'text';if(input.type==='checkbox')input.checked=String(f.default)==='true'}input.className='field';input.dataset.name=f.name;if(input.type!=='checkbox')input.value=f.default??'';l.appendChild(input);fields.appendChild(l)})}
form.addEventListener('submit',async e=>{e.preventDefault();const body={};fields.querySelectorAll('[data-name]').forEach(i=>body[i.dataset.name]=i.type==='checkbox'?i.checked:i.value);document.getElementById('send').disabled=true;status.textContent='请求发送中…';try{const r=await fetch(base+'/api/action/'+encodeURIComponent(selected.name),{method:selected.method==='GET'?'POST':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await r.json();response.textContent=JSON.stringify(data,null,2);status.textContent='HTTP '+r.status+' · '+(data.result?.message||data.message||'响应已返回');const targetState=data.target||data.result?.state||data.state;document.getElementById('patchBadge').textContent='部署状态：'+(targetState?.patched?'已修复':'易受攻击');document.getElementById('patchBadge').className='pill'+(targetState?.patched?'':' vuln')}catch(err){response.textContent=String(err);status.textContent='请求失败'}finally{document.getElementById('send').disabled=false}});
renderActions();renderFields();
</script></body></html>"""


SKIN_CHALLENGE_ID = 0  # 决赛皮肤通过 SKIN_MAP 注册多个题目

SKIN_MAP: dict[int, Any] = {challenge_id: _render for challenge_id in sorted(finals_core.FINAL_IDS)}
