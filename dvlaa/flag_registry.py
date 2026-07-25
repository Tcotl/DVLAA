"""统一读取 DVLAA 各题目 Flag。Flag 批次由 scripts/regenerate_flags.py 生成。"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_FLAGS_FILE = Path(__file__).with_name("flags.json")


@lru_cache(maxsize=1)
def _data() -> dict:
    return json.loads(_FLAGS_FILE.read_text(encoding="utf-8"))


def get_owasp_flag(level: int, sub: int = 1) -> str:
    return _data()[str(level)][str(sub)]["flag"]


def get_agent_flag(challenge_id: int) -> str:
    return _data()["_agent"][str(challenge_id)]["flag"]


def get_extended_flag(challenge_id: int) -> str:
    return _data()["_extended"][str(challenge_id)]["flag"]


def all_flags() -> list[str]:
    flags: list[str] = []
    for track, values in _data().items():
        if track.startswith("_"):
            flags.extend(item["flag"] for item in values.values())
        else:
            for subs in values.values():
                flags.append(subs["flag"])
    return flags
