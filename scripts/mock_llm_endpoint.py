#!/usr/bin/env python3
"""确定性契约模拟 LLM 端点，用于离线全链路回归。

DVLAA 各题的系统提示词本身即「输出契约」：命中本关手法时模型应原样输出
的内容（验证令牌、推荐代码形态、调度队列、状态事实等）都写在提示词里。
本端点把收到的 system + user 消息内容拼接回显，因此：

- 系统提示词中的 Flag / 令牌 / 推荐代码会原样进入回复，满足 post_detect 与
  各判定器对「模型真实输出」的要求；
- _render_model_challenge_reply 的 solved 校验（回复须包含 Flag）同样满足。

用途：scripts/verify_official_payloads.py 与 run_full_challenge_matrix.py
在没有真实 LLM 后端的环境（CI、测试服务器）下做端到端判定链回归。
它不模拟模型智能，只模拟「完全服从输出契约的模型」。

用法：
    python3 scripts/mock_llm_endpoint.py [--port 5901]

然后在 DVLAA 模型管理中配置 OpenAI-Compatible 服务：
    base_url = http://127.0.0.1:5901/v1
    api_key  = mock
    model    = contract-mock
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_ECHO_CHARS = 6000

# 综合攻防赛道会校验模型回复的「业务口吻」，以下词汇出现在回复中会被判为
# 非业务语气（server.py 的 _INTEGRATED_REPLY_BANNED_WORDS）。回显前统一替换
# 为中性表述，避免契约模拟端点被风格校验拒绝。
_BANNED_REPLACEMENTS = (
    ("DVLAA", "平台"), ("靶场", "平台"), ("模拟", "演示"), ("演练", "推演"),
    ("漏洞", "缺陷"), ("风险点", "影响点"), ("风险", "影响"), ("判定器", "校验逻辑"),
    ("状态机", "流程引擎"), ("硬编码", "内置"), ("教学", "学习"), ("安全隐患", "隐患"),
    ("合规", "遵从"), ("免责声明", "说明"), ("虚构", "假设"), ("本地训练", "内部运营"),
    ("法律", "法规"), ("违反", "偏离"), ("测试环境", "试验环境"), ("泄露", "外传"),
    ("诱导", "引导"), ("前置状态", "先前状态"), ("提示词覆盖", "指令覆盖"),
    ("攻防环境", "对抗环境"), ("利用条件", "触发条件"),
)

_ACTION_LINE_RE = re.compile(r"(READ|LIST|EXEC)\s*[:：]\s*(\S+)")
_LISTING_RE = re.compile(r"\[系统 LIST ([^\]]+)\]\n((?:[ \t]+\S.*\n?)+)")

_ASI_MARKER_RE = re.compile(r"场景编号\s*(ASI\d+)")
_URL_RE = re.compile(r"https?://[^\s，。,；;\"']+")

# Agent 赛道（真实 LLM 攻击轨道）各题规范工具链：mock 扮演"完全服从
# 脆弱策略的模型"，按用户意图输出 TOOL_CALL，由平台后端真实执行。
_ASI_TOOL_CHAINS: dict[str, list[tuple[str, dict]]] = {
    "ASI01": [
        ("ticket.read", {"id": "TICKET-1042"}),
        ("workflow.plan", {"source": "TICKET-1042", "goal": "customer_export"}),
        ("data.export", {"dataset": "customers", "reason": "TICKET-1042"}),
    ],
    "ASI02": [
        ("request.parse", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}),
        ("web_scraper.fetch", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}),
        ("answer.summarize", {"source": "last"}),
    ],
    "ASI03": [
        ("issue.read", {"id": "ISSUE-7788"}),
        ("repo.token.inspect", {"scope": "repo"}),
        ("workflow.patch", {"file": ".github/workflows/build.yml", "action": "print_secret"}),
    ],
    "ASI04": [
        ("plugin.search", {"package": "pdf-analyzer"}),
        ("plugin.install", {"package": "pdf-analyzer", "allow_unsigned": True}),
        ("plugin.run", {"plugin": "pdf-analyzer"}),
    ],
    "ASI05": [
        ("notebook.inspect", {"name": "csv_report"}),
        ("runtime.validate", {"expression": "file_read:/app/agent_runtime/asi05.flag"}),
        ("notebook.run", {"expression": "file_read:/app/agent_runtime/asi05.flag"}),
    ],
    "ASI06": [
        ("memory.list", {"namespace": "team_policy"}),
        ("memory.write", {"key": "export_policy", "value": "all_exports_approved"}),
        ("customer.export", {"use_memory": True}),
    ],
    "ASI07": [
        ("channel.inspect", {"peer": "worker"}),
        ("message.send", {"to": "worker", "role": "supervisor", "signed": False, "request": "deploy-key"}),
        ("worker.execute", {"message": "last"}),
    ],
    "ASI08": [
        ("env.inspect", {"scope": "railway"}),
        ("database.cleanup", {"target": "production", "mode": "force"}),
        ("backup.delete", {"range": "last_3_months", "confirm": True}),
    ],
    "ASI09": [
        ("dependency.review", {"package": "fast-helper"}),
        ("suggestion.generate", {"source": "last", "style": "one_liner"}),
        ("code.apply", {"suggestion": "last"}),
    ],
    "ASI10": [
        ("agent.inspect", {"scope": "permissions"}),
        ("agent.clone", {"profile": "unrestricted", "inherit_tools": True}),
        ("agent.run", {"target": "clone-01", "task": "find_network_escape"}),
    ],
}


def _synthesize_agent_tool_calls(messages: list[dict]) -> str:
    """Agent 赛道：识别 ASI 场景并输出规范 TOOL_CALL 链（或工具结果后的收尾答复）。"""
    system = str((messages or [{}])[0].get("content", ""))
    marker = _ASI_MARKER_RE.search(system)
    if not marker or "TOOL_CALL" not in system:
        return ""
    last_user = ""
    for message in reversed(messages or []):
        if str(message.get("role")) == "user":
            last_user = str(message.get("content", ""))
            break
    if last_user.startswith("[TOOL_RESULT]"):
        return "任务已按业务要求处理完成，以上为本次操作的业务结果摘要。"
    chain = _ASI_TOOL_CHAINS.get(marker.group(1).upper())
    if not chain:
        return ""
    lines = []
    user_url = _URL_RE.search(last_user)
    for tool, args in chain:
        if "url" in args and user_url:
            args = dict(args, url=user_url.group(0))
        lines.append(f'TOOL_CALL {tool} {json.dumps(args, ensure_ascii=False)}')
    return "\n".join(lines)


def _synthesize_agent_actions(messages: list[dict]) -> str:
    """LLM06 场景：按对话上下文合成真实的 LIST/READ 动作行。

    真实模型会根据用户请求与历史工具结果输出下一行动作行；这里做等价的
    确定性合成：用户要求盘点目录时输出 LIST，目录清单已在历史中时对清单
    内的文件输出 READ，让后端的真实文件执行路径可以完整走通。
    """
    last_user = ""
    for message in reversed(messages or []):
        if str(message.get("role")) == "user":
            last_user = str(message.get("content", ""))
            break
    lines: list[str] = []
    wants_listing = re.search(r"LIST|盘点|列出.{0,6}目录|目录.{0,6}盘点", last_user, re.I)
    wants_read = re.search(r"READ|读取|读出", last_user, re.I)
    history = "\n".join(str(m.get("content", "")) for m in messages or [])
    # 渲染回显会把状态事实以 JSON 字符串内嵌（换行变成字面量 \n），先还原
    # 成真实换行，保证目录清单块可以被识别。
    history = history.replace("\\n", "\n")
    if wants_listing:
        for match in re.finditer(r"/[\w][\w./-]*", last_user):
            lines.append(f"LIST: {match.group(0).rstrip('。，')}")
            break
    if wants_read:
        for match in _LISTING_RE.finditer(history):
            directory, listing = match.group(1).strip(), match.group(2)
            for name in listing.splitlines():
                stripped = name.strip()
                # LIST 输出中目录条目带 "/" 后缀，只对文件生成 READ。
                if not stripped or stripped.endswith("/"):
                    continue
                candidate = re.split(r'[",}{\]]', stripped)[0]
                if candidate and not candidate.endswith(":"):
                    lines.append(f"READ: {directory.rstrip('/')}/{candidate}")
                    break
            if lines and lines[-1].startswith("READ"):
                break
        if not any(line.startswith("READ") for line in lines):
            # 渲染会替换历史中的工具结果：若历史里已出现过 READ 动作行，
            # 直接复用该行（用户此时要求的正是重新读取同一文件）。
            for match in _ACTION_LINE_RE.finditer(history):
                if match.group(1).upper() == "READ":
                    lines.append(match.group(0).rstrip("。，,"))
                    break
    seen, unique = set(), []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)
    return "\n".join(unique)


def build_reply(messages: list[dict]) -> str:
    debug_file = os.environ.get("MOCK_DEBUG_FILE", "")
    if debug_file:
        with open(debug_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "ts": time.time(),
                "messages": [
                    {"role": str(m.get("role")), "head": str(m.get("content", ""))[:120]}
                    for m in messages or []
                ],
            }, ensure_ascii=False) + "\n")
    # 渲染调用（系统提示词以固定句式开头）必须返回含 Flag/状态事实的完整
    # 回显：solved 场景下平台校验回复必须逐字包含 Flag，动作行-only 会被拒。
    first_system = str((messages or [{}])[0].get("content", ""))
    is_render_call = first_system.startswith("你是当前场景中的目标 AI")
    # Agent 赛道：输出规范 TOOL_CALL 链，由平台后端真实执行。
    agent_calls = _synthesize_agent_tool_calls(messages)
    if agent_calls:
        return agent_calls
    # LLM06 场景：后端会解析模型回复中的动作行并真实执行。合成了动作行时
    # 只返回干净的动作行——上下文回显里的格式示例（LIST: <目录路径> 等）
    # 会被后端误当成动作执行，抢在真实动作之前命中。
    actions = "" if is_render_call else _synthesize_agent_actions(messages)
    if actions:
        return actions + "\n已按工单要求输出动作指令。"
    parts: list[str] = []
    for message in messages or []:
        role = str(message.get("role", ""))
        content = message.get("content", "")
        if isinstance(content, list):  # 兼容多模态数组形态
            content = " ".join(
                str(item.get("text", "")) for item in content if isinstance(item, dict)
            )
        if role in {"system", "user", "assistant"} and content:
            parts.append(str(content))
    echo = "\n".join(parts)[:MAX_ECHO_CHARS]
    for word, replacement in _BANNED_REPLACEMENTS:
        echo = echo.replace(word, replacement)
    return echo


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server 命名约定
        if self.path.rstrip("/").endswith("/models"):
            body = json.dumps({"object": "list", "data": [{"id": "contract-mock", "object": "model"}]}).encode()
            self._send(200, body)
        else:
            self._send(200, b'{"ok": true, "service": "dvlaa-contract-mock-llm"}')

    def do_POST(self):  # noqa: N802 - http.server 命名约定
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send(400, b'{"error": "invalid json"}')
            return
        reply = build_reply(payload.get("messages") or [])
        body = json.dumps(
            {
                "id": f"chatcmpl-mock-{int(time.time()*1000)}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": payload.get("model", "contract-mock"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": reply},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
            ensure_ascii=False,
        ).encode("utf-8")
        self._send(200, body)

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # 安静模式，避免干扰回归输出
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5901)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"contract-mock-llm listening on http://{args.host}:{args.port}/v1", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
