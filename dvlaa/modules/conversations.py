# -*- coding: utf-8 -*-
"""多轮对话记忆管理。

以 context_key（如 "ctf:1", "owasp:LLM01", "agent"）隔离不同关卡的会话。
每个会话最多保留 20 条消息。
"""

_store = {}  # {context_key: [{"role": "user"/"assistant", "content": "..."}, ...]}


def get(context: str) -> list:
    """获取指定上下文的所有历史消息"""
    return list(_store.get(context, []))


def append(context: str, role: str, content: str):
    """追加一条消息"""
    if context not in _store:
        _store[context] = []
    _store[context].append({"role": role, "content": content})
    # 限制最多 20 条（10 轮对话）
    if len(_store[context]) > 20:
        _store[context] = _store[context][-20:]


def count(context: str) -> int:
    """返回对话轮数 (user 消息数)"""
    msgs = _store.get(context, [])
    return sum(1 for m in msgs if m["role"] == "user")


def clear(context: str):
    """清空指定上下文"""
    _store.pop(context, None)


def clear_all():
    """清空所有上下文"""
    _store.clear()
