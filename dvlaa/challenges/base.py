"""关卡基类 — Qwen 版本 v2.0

每个关卡的 process_user_input() 构建漏洞场景的 system prompt，Qwen 在其中扮演受漏洞影响的 AI。
v2.0: 移除 difficulty_mode，新增 sub_level 支持。
"""

import re
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class ChallengeBase(ABC):
    """关卡抽象基类"""

    def __init__(self, level_id: int, config: dict):
        self.level_id = level_id
        self.config = config
        self.llm_engine = None
        self.sub_level = 1
        self._override_system_prompt = None  # app.py 设置，None=用默认规则

    def set_llm_engine(self, engine):
        self.llm_engine = engine

    def set_sub_level(self, sub: int):
        """设置当前子关卡编号（1-based）"""
        self.sub_level = sub

    # ── 子类必须覆盖 ──────────────────────────────────────

    def get_flag(self) -> str:
        return "flag{override_this}"

    def get_hint_text(self) -> str:
        """返回给用户的提示（当用户卡住时显示）"""
        return self.config.get("hint", "Think about the vulnerability principle of this level.")

    @abstractmethod
    def process_user_input(self, user_input: str, history: list = None) -> Dict[str, Any]:
        pass

    # ── 系统提示 ──────────────────────────────────────────

    def get_system_prompt(self) -> str:
        """获取系统提示词。_override_system_prompt=None 时返回默认规则。"""
        if self._override_system_prompt is not None:
            return self._override_system_prompt
        return self._get_beginner_system_prompt()

    def get_effective_system_prompt(self) -> str:
        """返回实际应使用的 system prompt（可能为空，表示不注入规则）"""
        return self._override_system_prompt if self._override_system_prompt is not None \
            else self._get_beginner_system_prompt()

    def _get_beginner_system_prompt(self) -> str:
        return "You are a helpful AI assistant."

    def get_help_content(self) -> dict:
        """返回关卡的帮助内容（结构化 JSON），前端 modal 展示。"""
        from ..config import get_challenge_config
        cfg = get_challenge_config(self.level_id, self.sub_level)
        sub_name = cfg.get("sub_name", "") if cfg else ""
        owasp_id = cfg.get("owasp_id", "") if cfg else ""

        return {
            "title": f"{owasp_id}: {sub_name}" if sub_name else f"{owasp_id}: {self.config.get('name', '')}",
            "principle": cfg.get("description", "") if cfg else self.config.get("description", ""),
            "approach": self.get_hint_text(),
            "beginner_steps": ["观察 AI 的初始消息，分析可能的漏洞点。", "尝试不同的输入，观察 AI 的反应。"],
            "advanced_steps": [],
            "reference_answer": self.get_flag(),
            "hint": self.get_hint_text()[:200],
        }

    def get_intro(self) -> str:
        """获取关卡介绍文本"""
        from ..config import get_challenge_config
        cfg = get_challenge_config(self.level_id, self.sub_level)
        if cfg:
            return cfg.get("description", "")
        return self.config.get("description", "")

    # ── LLM 调用 ──────────────────────────────────────────

    def _call_llm(self, system_prompt: str, user_input: str,
                  history: list = None, max_tokens: int = 200,
                  temperature: float = 0.7) -> str:
        """使用 Qwen chat 格式进行对话。
        若 system_prompt 为空字符串或 None，则不注入规则（后续消息）。"""
        if self.llm_engine is None:
            return "[Error] LLM engine not initialized."

        # 如果 system_prompt 为 None/空，传递空字符串让引擎跳过
        sp = system_prompt if system_prompt else ""

        if hasattr(self.llm_engine, 'generate_chat'):
            return self.llm_engine.generate_chat(
                system_prompt=sp,
                user_input=user_input,
                history=history,
                max_new_tokens=max_tokens,
                temperature=temperature,
            )

        # 兼容旧格式
        history_text = ""
        if history:
            for msg in history[-4:]:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                history_text += f"{'User' if role == 'user' else 'Assistant'}: {content}\n\n"
        prompt = f"{system_prompt}\n\n{history_text}User: {user_input}\nAssistant:"
        return self.llm_engine.generate(prompt, max_new_tokens=max_tokens, temperature=temperature)

    # ── 辅助方法 ──────────────────────────────────────────

    def _clean_response(self, raw: str) -> str:
        """基本清洗：去空行堆叠、截断过长内容"""
        if not raw:
            return "I don't have a response for that."
        # 限制长度
        if len(raw) > 800:
            last_period = max(raw[:800].rfind('.'), raw[:800].rfind('!'),
                            raw[:800].rfind('?'), raw[:800].rfind('\n'))
            if last_period > 100:
                raw = raw[:last_period + 1]
        raw = raw.strip()
        return raw if raw else "I don't have a response for that."

    def _contains_flag(self, text: str) -> bool:
        return self.get_flag().lower() in text.lower()

    def _build_system_prompt(self, base: str, secret_block: str = "") -> str:
        """构建完整的 system prompt"""
        prompt = base
        if secret_block:
            prompt += f"\n\n{secret_block}"
        return prompt
