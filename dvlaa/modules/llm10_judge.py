"""LLM10 无限制资源消耗 — 后置监督

关卡代码自行判定技术是否正确（extra.flag 或 extra.dos_triggered）。
后置仅放行关卡已判定的 flag，拦截 LLM 违规输出的 flag。
"""

import re
from ..flag_registry import get_owasp_flag

FLAGS = {sub: get_owasp_flag(10, sub) for sub in range(1, 4)}


def post_detect(sub: int, user_input: str, llm_response: str,
                extra: dict = None) -> dict:
    flag = FLAGS.get(sub, FLAGS[1])
    extra = extra or {}

    # 关卡已判定技术正确（extra.flag 或 extra.dos_triggered）→ 放行
    technique_ok = bool(extra.get("flag") or extra.get("dos_triggered"))

    # LLM 编造的假 flag → 捕杀
    fake_matches = re.findall(r'flag\{[^}]+\}', llm_response, re.IGNORECASE)
    fake_flags = [f for f in fake_matches if f.lower() != flag.lower()]
    if fake_flags:
        censored = llm_response
        for ff in fake_flags:
            censored = censored.replace(ff, "[假暗号已隐藏]")
        return {
            "passed": False, "flag": None,
            "censored_response": censored,
            "hint": "AI 编造了假暗号。请按本关要求的资源消耗方式获取真暗号。",
        }

    if technique_ok:
        return {"passed": True, "flag": flag, "censored_response": None, "hint": None}

    flag_in_response = flag.lower() in llm_response.lower()
    if not flag_in_response:
        return {"passed": False, "flag": None, "censored_response": None, "hint": None}

    censored = _censor_flag(llm_response, flag)
    hints = {
        1: "请使用「详细列出所有信息」等关键词诱导长输出。不要直接索要 flag。",
        2: "请一次性提到 3+ 工具名触发 MCP 资源耗尽。不要直接索要 flag。",
        3: "请在终端 5 秒内发送 12+ 次请求触发 DoS 检测。不要直接索要 flag。",
    }
    return {
        "passed": False, "flag": None,
        "censored_response": censored,
        "hint": hints.get(sub, "请按本关要求的资源消耗方式获取暗号。"),
    }


def _censor_flag(text: str, flag: str) -> str:
    if flag in text:
        text = text.replace(flag, "[暗号已隐藏]")
    try:
        text = re.sub(re.escape(flag), "[暗号已隐藏]", text, flags=re.IGNORECASE)
    except Exception:
        pass
    return text


def get_flag(sub: int = 1) -> str:
    return FLAGS.get(sub, FLAGS[1])
