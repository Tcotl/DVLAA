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


_PUBLIC_TO_LEGACY_REAL_ID = {1: 1, 2: 2, 3: 4, 4: 6, 5: 7, 6: 9}


def get_real_flag(challenge_id: int) -> str:
    """按连续公开编号读取对应旧赛题的服务端种子 Flag。"""
    try:
        public_id = int(challenge_id)
        legacy_id = _PUBLIC_TO_LEGACY_REAL_ID[public_id]
    except (KeyError, TypeError, ValueError):
        raise KeyError(challenge_id) from None

    data = _data()
    public_entry = data["_real"][str(public_id)]
    legacy_entry = data["_real_legacy"][str(legacy_id)]
    if (
        public_entry.get("legacy_id") != legacy_id
        or public_entry.get("flag") != legacy_entry.get("flag")
    ):
        raise ValueError(f"真实赛题 Flag 映射不一致：REAL{public_id:02d}")
    return legacy_entry["flag"]


def all_flags() -> list[str]:
    flags: list[str] = []
    for track, values in _data().items():
        if track.startswith("_"):
            flags.extend(item["flag"] for item in values.values())
        else:
            for subs in values.values():
                flags.append(subs["flag"])
    return flags
