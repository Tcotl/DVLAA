"""AWDP 模拟目标皮肤共享工具。"""

from __future__ import annotations

import html
import json
from typing import Any


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def action_js(base_path: str) -> str:
    """各皮肤共用的动作调用与结果渲染脚本（fetch 包装 + HTML 转义）。"""
    return """
async function callAction(name, body, onOk) {
  const r = await fetch('%BASE%/api/action/' + encodeURIComponent(name), {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {})
  });
  const data = await r.json();
  const result = data.result || data;
  if (onOk) onOk(result, r.status);
  return {result, status: r.status, target: data.target};
}
function esc(t) {
  return String(t ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
""".replace("%BASE%", base_path)
