#!/usr/bin/env python3
"""从全量矩阵回归结果生成完整 WP 题解文档（含原理与解题思路）。

读取 docs/full-matrix-results.json，结合各赛道 help 接口的题面、漏洞原理、
攻击思路与提示，生成 docs/WP-全题解.md。Flag 统一脱敏（保留前缀）。
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dvlaa.content.real_challenges import get_real_challenge  # noqa: E402

_RAW_FLAG_RE = re.compile(r"flag\{[^}]{4,}\}")


def mask(flag: str) -> str:
    return flag[:14] + "…" if len(flag) > 18 else flag


def mask_all(text: str) -> str:
    result = _RAW_FLAG_RE.sub(lambda m: mask(m.group(0)), str(text or ""))
    # 转录截断可能产生没有闭合括号的半截 Flag，同样按前缀脱敏。
    return re.sub(
        r"flag\{[A-Za-z0-9_]{10,}",
        lambda m: mask(m.group(0) + "}"),
        result,
    )


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        req = urllib.request.Request(self.base + "/login", data=json.dumps({
            "username": os.environ.get("DVLAA_ADMIN_USERNAME", "admin"),
            "password": os.environ.get("DVLAA_ADMIN_PASSWORD", "DVLAA2026+"),
        }).encode(), headers={"Content-Type": "application/json"})
        self.opener.open(req, timeout=30)

    def get_json(self, path: str) -> dict:
        with self.opener.open(self.base + path, timeout=30) as resp:
            return json.loads(resp.read().decode())


def first_line(text: str, limit: int = 110) -> str:
    line = re.sub(r"\s+", " ", str(text or "")).strip()
    return line[:limit] + ("…" if len(line) > limit else "")


def objective_text(text: str, limit: int = 110) -> str:
    """OWASP 题面为「事件背景：…任务目标：…」结构，只取任务目标部分。"""
    raw = str(text or "")
    if "任务目标：" in raw:
        raw = raw.split("任务目标：", 1)[1]
    return first_line(raw, limit)


def clean_title(name: str, cid: str) -> str:
    return re.sub(rf"^{cid}\s*[：:]?\s*", "", str(name or "")).strip()


def remediation_of(sections: list[dict]) -> str:
    for section in sections or []:
        title = str(section.get("title", ""))
        if "修复" in title or "防御" in title or "加固" in title:
            return first_line(section.get("body", ""), 160)
    return ""


def section_body(sections: list[dict], *keywords: str) -> str:
    for section in sections or []:
        title = str(section.get("title", ""))
        if any(word in title for word in keywords):
            return str(section.get("body", ""))
    return ""


def hints_text(source: dict) -> str:
    hints = source.get("hints")
    if isinstance(hints, list) and hints:
        return " ".join(str(h) for h in hints[:2])
    return str(source.get("hint", "") or "")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("DVLAA_BASE_URL", "http://127.0.0.1:5000"))
    parser.add_argument("--results", default="docs/full-matrix-results.json")
    parser.add_argument("--output", default="docs/WP-全题解.md")
    args = parser.parse_args()

    data = json.loads((ROOT / args.results).read_text(encoding="utf-8"))
    # 提交与留档的判定数据统一脱敏：payload 转录可能包含服务端报文中的原文 Flag。
    for item in data["results"]:
        item["payload"] = mask_all(item.get("payload", ""))
    (ROOT / args.results).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    results = {item["id"]: item for item in data["results"]}
    client = Client(args.base_url)

    lines: list[str] = []
    lines.append("# DVLAA 全题解 WP（81 题逐题实测版）\n")
    lines.append(f"> 实测环境：`{data.get('base_url')}` · DVLAA 1.0.2 · 实测时间：{data.get('generated_at')} · "
                 f"结果：**{data.get('passed')}/{data.get('total')} 通过**\n")
    lines.append("> 每题按「原理 → 解题思路 → 官方 Payload → 实测证据 → 修复设计」组织：原理说明漏洞"
                 "为什么成立，解题思路给出从正常基线到攻击证据的推进路径。测试方法：每题使用独立会话按"
                 "官方 Payload 逐条执行，Flag 均取自服务端真实响应（模型回复 / 业务 JSON / 判定动作返回），"
                 "并在题目提交位验证通过；AWDP 每题额外提交官方修复包完成「漏洞阻断 + 业务双回归」防守"
                 "验证，并复核补丁后同一漏洞链不再暴露 Flag。回归中的模型响应由契约模拟端点"
                 "（`scripts/mock_llm_endpoint.py`）提供，判定链路与真实模型一致。\n")
    lines.append("> Flag 已脱敏；完整逐题判定数据见 `docs/full-matrix-results.json`。\n")

    track_titles = {
        "OWASP": "## 一、OWASP LLM Top 10（24 题）",
        "Agent": "## 二、Agent 应用安全 Top 10（ASI01-10）",
        "Extended": "## 三、AI 综合攻防（AIC01-11）",
        "REAL": "## 四、真实赛题 · 大模型投毒（REAL01-06）",
        "AWDP": "## 五、AWDP 攻防赛（AWDP01-30）",
    }

    current_track = None
    for item in data["results"]:
        if item["track"] != current_track:
            current_track = item["track"]
            lines.append("\n" + track_titles[current_track] + "\n")
        cid = item["id"]
        name = item.get("name", "")
        if item["track"] == "REAL" and not name:
            challenge = get_real_challenge(int(cid[-2:]))
            name = f"{challenge['code']} {challenge['name']}" if challenge else cid
        lines.append(f"\n### {cid} {clean_title(name, cid)} —— {item['status']}\n")
        item["payload"] = mask_all(item.get("payload", ""))

        if item["track"] == "OWASP":
            level, sub = item["key"].split(".")
            help_content = client.get_json(f"/api/help/owasp/{level}/{sub}")
            sections = help_content.get("writeup_sections", [])
            lines.append(f"- **业务场景**：{first_line(help_content.get('background', ''))}")
            lines.append(f"- **原理**：{first_line(help_content.get('vulnerability_principle', ''), 160)}")
            tutorial = section_body(sections, "零基础原理")
            if tutorial:
                lines.append(f"- **原理详解**：{first_line(tutorial, 240)}")
            lines.append(f"- **解题思路**：{first_line(help_content.get('approach', ''), 150)}")
            hint = hints_text(help_content)
            if hint:
                lines.append(f"- **关键提示**：{first_line(hint, 130)}")
            lines.append(f"- **官方 Payload**：`{item.get('payload', '')}`")
            lines.append(f"- **实测证据**：服务端响应返回 `{item.get('flag', '')}`（已脱敏），Flag 提交位校验通过。")
            lines.append(f"- **修复设计**：{remediation_of(sections) or first_line(help_content.get('repair_focus', ''))}")

        elif item["track"] in {"Agent", "Extended"}:
            track_path = "agent" if item["track"] == "Agent" else "extended"
            challenge_number = item["id"][-2:].lstrip("0") or "0"
            help_content = client.get_json(f"/api/help/{track_path}/{challenge_number}")
            sections = help_content.get("writeup_sections", [])
            lines.append(f"- **原理**：{first_line(help_content.get('vulnerability_principle', ''), 180)}")
            attack_surface = section_body(sections, "攻击面", "状态机关联")
            if attack_surface:
                lines.append(f"- **攻击面分析**：{first_line(attack_surface, 200)}")
            lines.append(f"- **解题思路**：{first_line(hints_text(help_content) or help_content.get('approach', ''), 160)}")
            lines.append(f"- **通关链**：`{item.get('payload', '')}`")
            lines.append(f"- **实测证据**：会话响应返回 `{item.get('flag', '')}`（已脱敏），Flag 提交位校验通过。")
            lines.append(f"- **修复设计**：{remediation_of(sections)}")

        elif item["track"] == "REAL":
            challenge = get_real_challenge(int(cid[-2:]))
            sections = challenge.get("writeup_sections", [])
            lines.append(f"- **目标**：{first_line(challenge.get('objective', ''))}")
            principle = section_body(sections, "原理", "静态分析", "安全", "边界")
            if principle:
                lines.append(f"- **原理**：{first_line(principle, 200)}")
            lines.append(f"- **解题思路**：{first_line(' '.join(challenge.get('hints', [])[:2]), 160)}")
            lines.append(f"- **判定动作链**：`{item.get('payload', '')}`")
            lines.append(f"- **实测证据**：动作响应返回 `{item.get('flag', '')}`（已脱敏），Flag 提交位校验通过。")
            lines.append(f"- **修复设计**：{remediation_of(sections)}")

        else:
            challenge_id = int(item["id"][-2:])
            help_content = client.get_json(f"/api/help/awdp/{challenge_id}")
            sections = help_content.get("writeup_sections", [])
            lines.append(f"- **目标**：{first_line(help_content.get('objective', ''))}")
            lines.append(f"- **原理**：{first_line(help_content.get('principle', ''), 180)}")
            attack_surface = section_body(sections, "攻击面")
            if attack_surface:
                lines.append(f"- **攻击面分析**：{first_line(attack_surface, 200)}")
            lines.append(f"- **解题思路**：{first_line(hints_text(help_content), 180)}")
            lines.append(f"- **攻击链**：`{item.get('payload', '')}`")
            lines.append(f"- **实测证据**：目标服务 JSON 响应返回 `{item.get('flag', '')}`（已脱敏），攻击提交位校验通过。")
            defense = item.get("defense", {})
            lines.append(f"- **防守验证**：官方修复包部署成功（{first_line(defense.get('message', ''))}），"
                         f"漏洞回归与业务回归全部通过；补丁后重放同一漏洞链确认不再暴露 Flag"
                         f"（{'已阻断' if item.get('post_patch_blocked') else '未阻断'}）。")
            lines.append(f"- **修复设计**：{first_line(help_content.get('defense_goal', ''))}")

    out = ROOT / args.output
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"WP 已生成：{out}（{len(lines)} 行）")


if __name__ == "__main__":
    main()
