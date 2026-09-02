"""AWDP 模拟目标的产品仿真界面注册表。

每个题目一个模块（product_skins/<name>.py），模块内暴露：
  SKIN_CHALLENGE_ID  题目编号
  SKIN               render(challenge_id, state, base_path) -> HTML 字符串
  ALIASES            可选，产品形状 API 别名列表：
                     {"method", "segments": ("rest","executions","<executionId>","stop"),
                      "action": "executions.stop",
                      "map": lambda params, body: {...}}

皮肤只负责界面与交互贴近真实产品；漏洞逻辑、Flag、补丁状态一律复用
target_server 的 /challenge/<id>/api/action/<op> 后端。
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Any, Mapping

SKINS: dict[int, Any] = {}
ALIAS_TABLE: list[tuple[int, dict[str, Any]]] = []

for _info in pkgutil.iter_modules([str(Path(__file__).parent)]):
    if _info.name in {"shared"}:
        continue
    _module = importlib.import_module(f"product_skins.{_info.name}")
    _cid = int(getattr(_module, "SKIN_CHALLENGE_ID", 0) or 0)
    if _cid and hasattr(_module, "SKIN"):
        SKINS[_cid] = _module.SKIN
    # 决赛十题等"一个模块服务多题"的皮肤通过 SKIN_MAP 注册。
    for _map_cid, _map_skin in getattr(_module, "SKIN_MAP", {}).items():
        SKINS[int(_map_cid)] = _map_skin
    for _alias in getattr(_module, "ALIASES", []):
        ALIAS_TABLE.append((_cid, _alias))


def match_alias(challenge_id: int, method: str, route: str, body: Mapping[str, Any]):
    """按真实产品路径匹配别名，返回 (action, payload) 或 None。"""
    parts = tuple(p for p in route.split("/") if p)
    for cid, alias in ALIAS_TABLE:
        if cid != challenge_id or alias["method"] != method:
            continue
        segments = alias["segments"]
        if len(segments) != len(parts):
            continue
        params: dict[str, str] = {}
        matched = True
        for want, got in zip(segments, parts):
            if want.startswith("<") and want.endswith(">"):
                params[want[1:-1]] = got
            elif want != got:
                matched = False
                break
        if not matched:
            continue
        return alias["action"], alias["map"](params, body)
    return None
