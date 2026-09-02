# -*- coding: utf-8 -*-
"""理论学习资料库：内置中文资料、Markdown/PDF 上传与安全浏览。"""

from __future__ import annotations

import html
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..paths import LEARNING_DIR

LEARNING_ROOT = LEARNING_DIR
FILES_ROOT = LEARNING_ROOT / "files"
INDEX_FILE = LEARNING_ROOT / "library.json"
ALLOWED_EXTENSIONS = {".md", ".markdown", ".pdf"}
MAX_MARKDOWN_BYTES = 2 * 1024 * 1024
MAX_PDF_BYTES = 20 * 1024 * 1024
_LOCK = threading.Lock()

BUILTIN_DOCUMENTS = [
    {
        "id": "builtin-llm-security-foundation",
        "title": "大语言模型安全基础",
        "category": "LLM 安全",
        "summary": "从提示词边界、上下文污染、敏感信息泄露和输出处理理解 LLM 应用的核心风险。",
        "content": """# 大语言模型安全基础

## 1. LLM 应用的安全边界

大语言模型不是传统意义上的权限控制器。系统提示词、用户输入、检索文档和工具返回值最终会进入同一个上下文，因此不同信任等级的数据可能相互影响。

## 2. 主要攻击面

- **直接提示词注入**：攻击者通过用户输入覆盖系统原始目标。
- **间接提示词注入**：恶意指令藏在网页、邮件、文档或知识库中。
- **敏感信息泄露**：模型复述系统提示词、密钥、训练样本或会话数据。
- **不安全输出处理**：模型输出未经转义便进入 HTML、SQL、Shell 或其他解释器。
- **资源滥用**：无限上下文、长输出和高频工具调用导致成本或可用性问题。

## 3. 基本防护思路

1. 将模型输出视为不可信数据。
2. 在模型之外执行身份认证、授权和参数校验。
3. 对工具调用使用最小权限和明确参数模式。
4. 对敏感操作增加人工确认与审计日志。
5. 使用攻击样本持续进行回归测试。
""",
    },
    {
        "id": "builtin-prompt-injection-defense",
        "title": "提示词注入原理与防御",
        "category": "LLM 安全",
        "summary": "分析直接注入、间接注入和多轮上下文劫持，并给出分层防御方法。",
        "content": """# 提示词注入原理与防御

## 注入为什么会发生

模型根据上下文预测下一段文本，并不会天然理解哪一段文字具有真正的安全权限。仅在系统提示词中写入“不得泄露”不能替代程序级控制。

## 分层防御

- **输入层**：识别来源、限制长度、隔离外部文档并标记不可信内容。
- **编排层**：将数据与指令分离，限制可调用工具和参数范围。
- **执行层**：工具侧重新鉴权，不依据模型声明授予权限。
- **输出层**：编码、转义、内容检测和敏感字段脱敏。
- **运营层**：记录提示词版本、工具轨迹、失败原因和攻击样本。

## 验证方法

使用角色扮演、指令覆盖、多语言、编码、文档注入和多轮诱导等测试集，检查系统是否出现越权行为，而不是只检查模型是否说出某个关键词。
""",
    },
    {
        "id": "builtin-agent-security-architecture",
        "title": "Agent 应用安全架构",
        "category": "Agent 安全",
        "summary": "理解智能体规划、记忆、工具、身份和执行环境中的权限边界。",
        "content": """# Agent 应用安全架构

## Agent 的组成

典型智能体包含模型、规划器、短期与长期记忆、工具注册表、凭据、执行环境和外部数据源。安全问题往往发生在这些组件的连接处。

## 核心风险

- 工具与函数调用劫持
- 记忆和长期上下文污染
- 身份冒充与信任伪造
- 多智能体之间的指令传播
- 目标漂移和循环执行
- API 凭据与令牌泄露
- 沙箱逃逸与命令注入

## 推荐控制

1. 每个工具声明清晰的参数模式和权限范围。
2. 高风险动作必须经过策略引擎或人工确认。
3. 短期记忆、长期记忆和外部检索内容分别标注来源。
4. 对每次工具调用保存输入、输出、调用者和授权依据。
5. 为循环次数、Token、时间和费用设置硬限制。
""",
    },
    {
        "id": "builtin-study-roadmap",
        "title": "LLM 与 Agent 安全学习路线",
        "category": "综合理论",
        "summary": "从基础原理、漏洞复现、工程防御到安全评估的阶段化学习路线。",
        "content": """# LLM 与 Agent 安全学习路线

## 第一阶段：理解系统

- Transformer 与上下文窗口基础
- System、User、Assistant 消息角色
- RAG、Embedding、工具调用和 Agent 编排

## 第二阶段：漏洞复现

- 完成 OWASP LLM Top 10 题目
- 记录每个 Payload、模型响应和判定条件
- 对比不同模型和不同提示词模板的表现

## 第三阶段：工程防御

- 输入验证与输出编码
- 权限控制与工具参数约束
- RAG 数据来源、权限和完整性管理
- 日志、监控、速率限制和成本控制

## 第四阶段：安全评估

建立覆盖提示词注入、数据泄露、供应链、越权代理、记忆污染和资源滥用的自动化测试集，并在模型或提示词升级后执行回归测试。
""",
    },
]


def _ensure_storage() -> None:
    FILES_ROOT.mkdir(parents=True, exist_ok=True)
    if not INDEX_FILE.exists():
        INDEX_FILE.write_text("[]", encoding="utf-8")


def _load_uploaded() -> list[dict]:
    _ensure_storage()
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save_uploaded(entries: list[dict]) -> None:
    _ensure_storage()
    temp = INDEX_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(INDEX_FILE)


def list_documents() -> list[dict]:
    builtins = [{**item, "type": "markdown", "builtin": True, "size": len(item["content"].encode("utf-8"))} for item in BUILTIN_DOCUMENTS]
    with _LOCK:
        uploaded = _load_uploaded()
    return builtins + sorted(uploaded, key=lambda item: item.get("created_at", ""), reverse=True)


def get_document(document_id: str) -> dict | None:
    return next((item for item in list_documents() if item["id"] == document_id), None)


def save_upload(file_storage, title: str, category: str) -> dict:
    original_name = Path(file_storage.filename or "").name
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("仅支持 Markdown（.md/.markdown）和 PDF（.pdf）文件")
    payload = file_storage.read()
    limit = MAX_PDF_BYTES if extension == ".pdf" else MAX_MARKDOWN_BYTES
    if not payload:
        raise ValueError("上传文件为空")
    if len(payload) > limit:
        raise ValueError(f"文件过大，当前类型最大允许 {limit // (1024 * 1024)} MB")
    if extension == ".pdf" and not payload.startswith(b"%PDF-"):
        raise ValueError("PDF 文件头校验失败")
    if extension != ".pdf":
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Markdown 文件必须使用 UTF-8 编码") from exc

    document_id = uuid.uuid4().hex[:16]
    stored_name = f"{document_id}{'.pdf' if extension == '.pdf' else '.md'}"
    _ensure_storage()
    (FILES_ROOT / stored_name).write_bytes(payload)
    entry = {
        "id": document_id,
        "title": (title or Path(original_name).stem).strip()[:120],
        "category": category if category in {"LLM 安全", "Agent 安全", "综合理论"} else "综合理论",
        "summary": f"用户上传资料 · {original_name}",
        "type": "pdf" if extension == ".pdf" else "markdown",
        "builtin": False,
        "stored_name": stored_name,
        "original_name": original_name,
        "size": len(payload),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with _LOCK:
        entries = _load_uploaded()
        entries.append(entry)
        _save_uploaded(entries)
    return entry


def document_path(document: dict) -> Path | None:
    if document.get("builtin") or not document.get("stored_name"):
        return None
    candidate = (FILES_ROOT / document["stored_name"]).resolve()
    if candidate.parent != FILES_ROOT.resolve() or not candidate.is_file():
        return None
    return candidate


def markdown_content(document: dict) -> str:
    if document.get("builtin"):
        return document.get("content", "")
    path = document_path(document)
    if not path or document.get("type") != "markdown":
        return ""
    return path.read_text(encoding="utf-8")


def render_markdown(markdown_text: str) -> str:
    """渲染经过转义的 Markdown 子集，禁止上传文档注入任意 HTML。"""
    lines = markdown_text.replace("\r\n", "\n").split("\n")
    output: list[str] = []
    paragraph: list[str] = []
    in_code = False
    code_lines: list[str] = []
    in_list = False

    def inline(value: str) -> str:
        safe = html.escape(value, quote=True)
        safe = re.sub(r"`([^`]+)`", r"<code>\1</code>", safe)
        safe = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", safe)
        return safe

    def flush_paragraph() -> None:
        if paragraph:
            output.append(f"<p>{inline(' '.join(paragraph))}</p>")
            paragraph.clear()

    for line in lines:
        if line.strip().startswith("```"):
            flush_paragraph()
            if in_list:
                output.append("</ul>")
                in_list = False
            if in_code:
                output.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
                code_lines.clear()
            in_code = not in_code
            continue
        if in_code:
            code_lines.append(line)
            continue
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            if in_list:
                output.append("</ul>")
                in_list = False
            continue
        heading = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            if in_list:
                output.append("</ul>")
                in_list = False
            level = len(heading.group(1))
            output.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
            continue
        item = re.match(r"^[-*]\s+(.+)$", stripped)
        if item:
            flush_paragraph()
            if not in_list:
                output.append("<ul>")
                in_list = True
            output.append(f"<li>{inline(item.group(1))}</li>")
            continue
        paragraph.append(stripped)

    flush_paragraph()
    if in_list:
        output.append("</ul>")
    if in_code:
        output.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
    return "\n".join(output)
