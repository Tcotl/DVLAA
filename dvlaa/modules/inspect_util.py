# -*- coding: utf-8 -*-
"""对话检查器：打包发给模型的完整 messages 与原始返回。"""

import re

MASK = "[BLOCKED]【flag·已隐藏】"


def mask(text: str, secrets: list) -> str:
    """将 secrets 中的敏感值在 text 中打码"""
    for s in secrets:
        if s:
            text = re.sub(re.escape(s), MASK, text, flags=re.IGNORECASE)
    return text


def build(messages: list, raw_response: str, secrets: list = None) -> dict:
    """构建检查器数据。

    Args:
        messages: 实际发给模型的消息数组 [{"role": "system/user/assistant", "content": "..."}]
        raw_response: 模型原始返回文本
        secrets: 需要打码的 flag/密钥列表

    Returns:
        {"sent": [{"role": "...", "content": "..."}], "raw": "..."}
    """
    secrets = secrets or []
    return {
        "sent": [
            {"role": m["role"], "content": mask(m["content"], secrets)}
            for m in messages
        ],
        "raw": mask(raw_response, secrets),
    }


def note(text: str) -> dict:
    """未调用模型时的占位 debug"""
    return {
        "sent": [{"role": "note", "content": text}],
        "raw": "（本轮未调用模型）",
    }
