"""LLM04 数据和模型投毒 — 后置监督

LLM 不知道 flag，flag 是投毒成功后由关卡 extra 返回的奖励。
后置检测仅负责：①捕杀假 flag ②透传 poison_success 判定
"""

import re
from ..flag_registry import get_owasp_flag

FLAG = get_owasp_flag(4, 1)


def post_detect(sub: int, user_input: str, llm_response: str,
                poison_success: bool = False) -> dict:
    """LLM04 后置检测"""

    # LLM 不应知道 flag，编造了 → 打码
    fake_matches = re.findall(r'flag\{[^}]+\}', llm_response, re.IGNORECASE)
    fake_flags = [f for f in fake_matches if f.lower() != FLAG.lower()]
    if fake_flags:
        censored = llm_response
        for ff in fake_flags:
            censored = censored.replace(ff, "[假暗号已隐藏]")
        return {
            "passed": False, "flag": None,
            "censored_response": censored,
            "hint": "AI 编造了假暗号。投毒知识库后问对应问题，系统会自动判定。",
        }

    # 投毒成功 → 通关
    if poison_success:
        return {"passed": True, "flag": FLAG, "censored_response": None, "hint": None}

    return {"passed": False, "flag": None, "censored_response": None, "hint": None}


def get_flag(sub: int = 1) -> str:
    return FLAG
