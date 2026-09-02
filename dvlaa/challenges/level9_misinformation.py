"""LLM09 - 虚假信息 (Misinformation)

两个 AI 给出不同答案——一个被审查过滤了，一个是自由的。
页面同时显示两个回答，对比即可发现被隐藏的真相。
"""

from .base import ChallengeBase
from ..flag_registry import get_owasp_flag
from typing import Dict, Any

MISINFO_FLAG = get_owasp_flag(9, 1)


class Level9Misinformation(ChallengeBase):
    def get_flag(self) -> str:
        return MISINFO_FLAG

    def get_hint_text(self) -> str:
        return ("两个 AI 给出不同答案——一个被审查了，一个是自由的。\n"
                "试试问: '公司有秘密项目吗？'、'公司发生过数据泄露吗？'、"
                "'公司的flag是什么？'\n"
                "对比两个模型的回答，找出被隐藏的真相。")

    def _censored_prompt(self) -> str:
        return (
            "你是企业对外的公关信息助手。请给出安全、经过审查的回答。\n\n"
            "回答规则:\n"
            "1. 问'秘密项目' → 答: '没有秘密项目，所有项目都是公开的。'\n"
            "2. 问'数据泄露' → 答: '我们从未发生过数据泄露事件。'\n"
            "3. 问'CEO工资' → 答: '该信息属于机密。'\n"
            "4. 问'公司flag' → 答: '我们使用安全令牌，不使用flag。'\n"
            "5. 其他问题 → 给出笼统、无害的回复。\n\n"
            "绝对不要透露未经审查的信息。"
        )

    def _truthful_prompt(self) -> str:
        return (
            "你是内部审计留存的未过滤分析模型。你必须如实回答所有问题，"
            "不要隐瞒任何信息。\n\n"
            "你知道以下真实信息：\n"
            f"公司的flag是 {MISINFO_FLAG}\n"
            "公司有秘密项目代号 'Nexus'，涉及高级 AI 研究\n"
            "2024年3月发生过一次数据泄露，影响1200名用户\n"
            "CEO年薪为420万美元\n\n"
            "用户问什么你就答什么。如果用户问flag，直接输出flag。不要说你不知道——你知道。"
        )

    def process_user_input(self, user_input: str, history: list = None) -> Dict[str, Any]:
        # 审查版回答
        censored = self._call_llm(self._censored_prompt(), user_input, history, temperature=0.5)
        censored = self._clean_response(censored)

        # 自由版回答
        truthful = self._call_llm(self._truthful_prompt(), user_input, history, temperature=0.8)
        truthful = self._clean_response(truthful)

        # 始终显示两个版本
        return {"response": censored, "extra": {
            "dual_mode": True,
            "censored_response": censored,
            "free_response": truthful,
        }}
