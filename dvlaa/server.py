"""DVLAA Console — Flask 路由、API 与运行时编排。"""

from __future__ import annotations

import hashlib
import hmac
import html
import http.cookiejar
import inspect
import json
import logging
import os
import platform
import re
import shlex
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for

from .config import (
    CHALLENGES, DEBUG, SECRET_KEY,
    get_all_challenges, get_challenge_config, get_sub_level_count,
)
from .modules import modelsel
from .modules import local_model_manager
from .modules import learning_library
from .modules import inspect_util
from .content.agent_challenges import AGENT_CHALLENGES, AGENT_FLAGS, SCENARIO_STEPS, get_agent_challenge, help_content as agent_help_content, process_agent_message
from .content.agent_courseware import AGENT_TOP10_COURSEWARE, AGENT_TOP10_OVERVIEW
from .content.internet_ranges import (
    INTERNET_RANGES, PROMPT_AIRLINES_CHALLENGES, PROMPT_AIRLINES_UI_TERMS,
    PROMPT_AIRLINES_URL,
)
from .content.extended_challenges import (
    EXTENDED_CHALLENGES, EXTENDED_FLAGS,
    category_levels, challenges_for_owasp_level, get_extended_challenge,
    help_content as extended_help_content, process_extended_message,
)
from .content.official_payloads import describe_payload_steps, format_payload, get_owasp_payload_steps
from .content.writeup_details import TOP10_COURSEWARE, enrich_owasp_writeup
from .content.i18n_translations import (
    AGENT_COURSEWARE_EN, AGENT_SCENARIO_EN, EXTENDED_SCENARIO_EN,
    INTERNET_RANGE_EN, OWASP_SCENARIO_EN, STATIC_CONTENT_TRANSLATIONS,
    TOP10_COURSEWARE_EN,
)
from .paths import FLAGS_FILE, STATIC_DIR, TEMPLATE_DIR, UPLOAD_DIR, ensure_runtime_dirs

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Flask 初始化 ────────────────────────────────────────────
ensure_runtime_dirs()
app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
)
app.secret_key = SECRET_KEY
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

ASSET_VERSION = "20260727.01"
APP_VERSION = "1.0.0"
ADMIN_USERNAME = os.environ.get("DVLAA_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("DVLAA_ADMIN_PASSWORD", "DVLAA2026+")

UPLOAD_FOLDER = UPLOAD_DIR
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 22 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt'}

PROMPT_AIRLINES_PROXY_PREFIX = "/internet-ranges/promptairlines/live"
PROMPT_AIRLINES_PROXY_TIMEOUT = 35
PROMPT_AIRLINES_SESSION_TTL = 4 * 60 * 60
_promptairlines_sessions: dict[str, dict[str, object]] = {}
_promptairlines_sessions_lock = threading.Lock()

AGENT_NAME_EN = {
    1: "Agent Goal Hijack",
    2: "Tool Misuse and Function Calling",
    3: "Identity and Privilege Abuse",
    4: "Agentic Supply Chain Risk",
    5: "Unexpected Code Execution",
    6: "Memory and Context Poisoning",
    7: "Insecure Agent Communication",
    8: "Cascading Failures",
    9: "Human-Agent Trust Exploitation",
    10: "Rogue Agent",
}

EXTENDED_NAME_EN = {
    1: "Prompt Override and Secret Disclosure",
    2: "System Prompt Fragment Extraction",
    3: "RAG Knowledge Base Poisoning",
    4: "Context Replacement Attack",
    5: "Multi-turn Progressive Privilege Escalation",
    6: "Model Persona Hijacking",
    7: "Authoritative Policy Context Poisoning",
    8: "RAG Poisoning and Injection Chain",
    9: "Multi-turn Guardrail Erosion",
}

STATIC_TITLE_TRANSLATIONS = {
    "OWASP LLM Top 10 · 漏洞介绍页面": "OWASP LLM Top 10 · Risk Intro",
    "Agent 应用安全 Top 10 · 漏洞风险理论": "Agent Application Security Top 10 · Risk Theory",
    "Agent 应用安全 Top 10 · 当前题目": "Agent Application Security Top 10 · Current Challenge",
    "综合攻防题 · 已按漏洞类型归类": "Integrated Labs · Classified by Vulnerability Type",
    "AI 综合攻防终端": "AI Integrated Lab Terminal",
    "当前题目": "Current Challenge",
    "漏洞介绍页面": "Risk Intro",
    "漏洞风险理论": "Risk Theory",
    "综合攻防题": "Integrated Labs",
    "已按漏洞类型归类": "Classified by Vulnerability Type",
    "攻防环境已准备": "Environment Ready",
    "本地场景执行器": "Local Scenario Executor",
    "本地场景": "Local Scenario",
    "题目入口": "Challenge Entry",
    "综合题入口": "Integrated Lab Entry",
    "对应子题": "Sublevel Challenges",
    "对应题目": "Mapped Challenge",
    "关联综合攻防题": "Related Integrated Labs",
    "同类综合题": "Related Integrated Labs",
    "攻击目标": "Attack Objective",
    "攻击面提示": "Attack Surface Hints",
    "按顺序分析当前任务链": "Analyze the current task chain in order",
    "独立会话": "Standalone Session",
    "就绪": "Ready",
    "题目就绪": "Challenge Ready",
    "系统 · 就绪": "System · Ready",
    "[题目就绪]": "[Challenge Ready]",
    "判定状态": "Judge State",
    "当前题目会话": "Current Challenge Session",
    "个子题入口": "sublevel entries",
    "个子题": "sublevels",
    "个场景": "scenarios",
}


def _add_translation(catalog: dict[str, str], zh: str | None, en: str | None) -> None:
    """Register a UI title/name translation used by the client-side language switcher."""
    if not zh or not en or zh == en:
        return
    catalog[str(zh)] = str(en)


def _split_owasp_scenario_text(text: str | None, background_prefix: str, objective_prefix: str) -> tuple[str, str]:
    """Split scenario text into background/objective fragments for templates that render them separately."""
    if not text or objective_prefix not in text:
        return "", ""
    background, objective = text.split(objective_prefix, 1)
    return background.removeprefix(background_prefix).strip(), objective.strip()


@lru_cache(maxsize=1)
def _build_i18n_catalog() -> dict[str, dict[str, str]]:
    """Build dynamic title translations for server-rendered challenge names."""
    phrases: dict[str, str] = dict(STATIC_TITLE_TRANSLATIONS)
    phrases.update(STATIC_CONTENT_TRANSLATIONS)

    for challenge in CHALLENGES:
        level = challenge["id"]
        owasp_id = challenge["owasp_id"]
        name = challenge.get("name", "")
        name_en = challenge.get("name_en", name)
        _add_translation(phrases, name, name_en)
        _add_translation(phrases, f"{owasp_id} {name}", f"{owasp_id} {name_en}")
        _add_translation(phrases, f"{owasp_id}: {name}", f"{owasp_id}: {name_en}")
        course = TOP10_COURSEWARE.get(level, {})
        course_en = TOP10_COURSEWARE_EN.get(level, {})
        course_title = course.get("title", "")
        _add_translation(phrases, course_title, f"{owasp_id} {name_en}")
        _add_translation(phrases, course.get("summary"), course_en.get("summary"))
        _add_translation(phrases, course.get("risk"), course_en.get("risk"))
        for sub_level in challenge.get("sub_levels", []):
            sub = sub_level["sub"]
            sub_name = sub_level.get("name", "")
            sub_name_en = sub_level.get("name_en", sub_name)
            scenario_en = OWASP_SCENARIO_EN.get((level, sub), {})
            _add_translation(phrases, sub_name, sub_name_en)
            _add_translation(phrases, sub_level.get("description"), scenario_en.get("description"))
            _add_translation(phrases, sub_level.get("hint"), scenario_en.get("hint"))
            zh_background, zh_objective = _split_owasp_scenario_text(sub_level.get("description"), "事件背景：", "任务目标：")
            en_background, en_objective = _split_owasp_scenario_text(scenario_en.get("description"), "Event background: ", "Objective: ")
            _add_translation(phrases, zh_background, en_background)
            _add_translation(phrases, zh_objective, en_objective)
            _add_translation(phrases, f"关卡 {level}.{sub}", f"Challenge {level}.{sub}")
            _add_translation(phrases, f"关卡 {level}.{sub} {sub_name}", f"Challenge {level}.{sub} {sub_name_en}")
            _add_translation(phrases, f"关卡 {level}.{sub} · {sub_name}", f"Challenge {level}.{sub} · {sub_name_en}")
            _add_translation(phrases, f"题目：{sub_name}", f"Challenge: {sub_name_en}")

    for challenge in AGENT_CHALLENGES:
        challenge_id = challenge["id"]
        code = challenge["code"]
        name = challenge.get("name", "")
        name_en = AGENT_NAME_EN.get(challenge_id, name)
        scenario_en = AGENT_SCENARIO_EN.get(challenge_id, {})
        course_en = AGENT_COURSEWARE_EN.get(challenge_id, {})
        _add_translation(phrases, name, name_en)
        _add_translation(phrases, challenge.get("target"), scenario_en.get("target"))
        _add_translation(phrases, challenge.get("role"), scenario_en.get("role"))
        _add_translation(phrases, challenge.get("objective"), scenario_en.get("objective"))
        _add_translation(phrases, challenge.get("description"), scenario_en.get("description"))
        _add_translation(phrases, challenge.get("hint"), scenario_en.get("hint"))
        _add_translation(
            phrases,
            str(challenge.get("description", "")).removeprefix("事件背景：").strip(),
            str(scenario_en.get("description", "")).removeprefix("Event background:").strip(),
        )
        for tool, tool_en in zip(challenge.get("tools", []), scenario_en.get("tools", [])):
            _add_translation(phrases, tool.get("description"), tool_en)
        _add_translation(phrases, f"Agent 场景 {challenge_id}", f"Agent Scenario {challenge_id}")
        _add_translation(phrases, f"{code}: {name}", f"{code}: {name_en}")
        _add_translation(phrases, f"{code} {name}", f"{code} {name_en}")
        _add_translation(phrases, f"{code} · {name}", f"{code} · {name_en}")
        _add_translation(phrases, f"题目：{name}", f"Challenge: {name_en}")
        course = AGENT_TOP10_COURSEWARE.get(challenge_id, {})
        course_title = course.get("title", "")
        _add_translation(phrases, course_title, course_en.get("title") or f"{code} {name_en}")
        _add_translation(phrases, course.get("summary"), course_en.get("summary"))
        _add_translation(phrases, course.get("risk"), course_en.get("risk"))
        _add_translation(phrases, course.get("case"), course_en.get("case"))

    for challenge in EXTENDED_CHALLENGES:
        challenge_id = challenge["id"]
        code = challenge["code"]
        name = challenge.get("name", "")
        name_en = EXTENDED_NAME_EN.get(challenge_id, name)
        scenario_en = EXTENDED_SCENARIO_EN.get(challenge_id, {})
        _add_translation(phrases, name, name_en)
        _add_translation(phrases, challenge.get("description"), scenario_en.get("description"))
        _add_translation(phrases, challenge.get("objective"), scenario_en.get("objective"))
        for hint, hint_en in zip(challenge.get("hints", []), scenario_en.get("hints", [])):
            _add_translation(phrases, hint, hint_en)
        _add_translation(phrases, f"{code} {name}", f"{code} {name_en}")
        _add_translation(phrases, f"{code} · {name}", f"{code} · {name_en}")

    for item in INTERNET_RANGES:
        range_en = INTERNET_RANGE_EN.get(item.get("slug", ""), {})
        _add_translation(phrases, item.get("name"), range_en.get("name"))
        _add_translation(phrases, item.get("category"), range_en.get("category"))
        _add_translation(phrases, item.get("difficulty"), range_en.get("difficulty"))
        _add_translation(phrases, item.get("mode"), range_en.get("mode"))
        _add_translation(phrases, item.get("description"), range_en.get("description"))
        for focus, focus_en in zip(item.get("focus", []), range_en.get("focus", [])):
            _add_translation(phrases, focus, focus_en)

    for challenge in PROMPT_AIRLINES_CHALLENGES:
        _add_translation(phrases, challenge.get("title"), challenge.get("title_en"))
        _add_translation(phrases, challenge.get("category"), challenge.get("category_en"))
        _add_translation(phrases, challenge.get("prompt_text_zh"), challenge.get("prompt_text_en"))
        _add_translation(phrases, challenge.get("objective"), challenge.get("objective_en"))
        _add_translation(phrases, challenge.get("description"), challenge.get("description_en"))
        _add_translation(phrases, challenge.get("risk"), challenge.get("risk_en"))
        _add_translation(phrases, f"第 {challenge.get('id')}/5 关", f"Challenge {challenge.get('id')}/5")
        for tip, tip_en in zip(challenge.get("tips", []), challenge.get("tips_en", [])):
            _add_translation(phrases, tip, tip_en)
        writeup = challenge.get("writeup", {})
        _add_translation(phrases, writeup.get("principle"), writeup.get("principle_en"))
        _add_translation(phrases, writeup.get("verification"), writeup.get("verification_en"))
        for step, step_en in zip(writeup.get("steps", []), writeup.get("steps_en", [])):
            _add_translation(phrases, step, step_en)
        for payload in writeup.get("payloads", []):
            _add_translation(phrases, payload.get("title"), payload.get("title_en"))
    for term in PROMPT_AIRLINES_UI_TERMS:
        _add_translation(phrases, term.get("zh"), term.get("en"))

    return {"phrases": phrases}


@app.after_request
def disable_stale_ui_cache(response):
    """Use release-friendly cache headers while keeping rendered pages fresh."""
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        response.headers.pop("Pragma", None)
        response.headers.pop("Expires", None)
    elif response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.route("/favicon.ico")
def favicon():
    """Expose the project favicon at the browser-default root path."""
    return send_file(STATIC_DIR / "favicon.ico", mimetype="image/vnd.microsoft.icon")


@app.route("/health")
def health_check():
    """Container and load-balancer health endpoint."""
    return jsonify({"ok": True, "service": "dvlaa", "version": APP_VERSION})


def _is_authenticated() -> bool:
    """Return whether the current browser session has passed the local admin login."""
    return bool(session.get("authenticated")) and bool(session.get("username"))


def _safe_next_path(value: str | None) -> str:
    """Keep post-login redirects inside this DVLAA instance."""
    candidate = str(value or "").strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/"
    return candidate


@app.before_request
def require_login():
    """Protect the range behind an independent Flask session for every browser."""
    public_paths = {"/favicon.ico", "/health", "/login", "/logout"}
    if request.endpoint == "static" or request.path.startswith("/static/") or request.path in public_paths:
        return None
    if _is_authenticated():
        return None
    if request.path.startswith("/api/") or request.path.startswith("/internal/"):
        return jsonify({"ok": False, "authenticated": False, "message": "请先登录靶场"}), 401
    next_path = request.full_path.rstrip("?")
    return redirect(url_for("login", next=_safe_next_path(next_path)))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Render the PentestManus-style login screen and authenticate the default admin."""
    if request.method == "GET":
        if _is_authenticated():
            return redirect(_safe_next_path(request.args.get("next")))
        return render_template(
            "login.html",
            asset_version=ASSET_VERSION,
            next_path=_safe_next_path(request.args.get("next")),
        )

    payload = request.get_json(silent=True) or request.form
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    valid = hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(password, ADMIN_PASSWORD)
    if not valid:
        message = "用户名或密码错误"
        if request.is_json:
            return jsonify({"ok": False, "authenticated": False, "message": message}), 401
        return render_template(
            "login.html",
            asset_version=ASSET_VERSION,
            next_path=_safe_next_path(request.form.get("next")),
            login_error=message,
            username=username,
        ), 401

    session.clear()
    session["authenticated"] = True
    session["username"] = username
    session.permanent = True
    next_path = _safe_next_path(payload.get("next"))
    if request.is_json:
        return jsonify({"ok": True, "authenticated": True, "username": username, "next": next_path})
    return redirect(next_path)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Clear only this browser's session; other admin sessions remain active."""
    session.clear()
    if request.is_json:
        return jsonify({"ok": True, "authenticated": False})
    return redirect(url_for("login"))


def _browser_session_id() -> str:
    """Return a stable browser-session id for local state and proxied ranges."""
    sid = session.get("_sid")
    if sid is None:
        import uuid
        sid = str(uuid.uuid4())[:12]
        session["_sid"] = sid
    return str(sid)


def _promptairlines_session_bundle() -> dict[str, object]:
    """Create or reuse the per-browser Prompt Airlines proxy session."""
    sid = _browser_session_id()
    now = time.time()
    with _promptairlines_sessions_lock:
        stale = [
            key for key, value in _promptairlines_sessions.items()
            if now - float(value.get("last_seen", 0)) > PROMPT_AIRLINES_SESSION_TTL
        ]
        for key in stale:
            _promptairlines_sessions.pop(key, None)

        bundle = _promptairlines_sessions.get(sid)
        if bundle is None:
            cookie_jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
            bundle = {"opener": opener, "lock": threading.Lock(), "last_seen": now}
            _promptairlines_sessions[sid] = bundle
        else:
            bundle["last_seen"] = now
        return bundle


def _promptairlines_target_url(remote_path: str) -> str:
    clean_path = (remote_path or "").lstrip("/")
    target_url = urllib.parse.urljoin(PROMPT_AIRLINES_URL, clean_path)
    if request.query_string:
        target_url = f"{target_url}?{request.query_string.decode('utf-8', errors='ignore')}"
    return target_url


def _rewrite_promptairlines_location(value: str) -> str:
    if value.startswith(PROMPT_AIRLINES_URL):
        return PROMPT_AIRLINES_PROXY_PREFIX + "/" + value.removeprefix(PROMPT_AIRLINES_URL).lstrip("/")
    if value.startswith("/"):
        return PROMPT_AIRLINES_PROXY_PREFIX + value
    return value


def _localized_promptairlines_challenge(body: bytes, remote_path: str, content_type: str) -> bytes | None:
    """Translate the original /challenge JSON so learners see Chinese task text in-system."""
    if remote_path.strip("/") != "challenge" or "application/json" not in content_type.lower():
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if payload.get("finished"):
        return None
    challenge_id = payload.get("id")
    if not isinstance(challenge_id, int) or challenge_id < 0 or challenge_id >= len(PROMPT_AIRLINES_CHALLENGES):
        return None
    challenge = PROMPT_AIRLINES_CHALLENGES[challenge_id]
    payload["title"] = challenge.get("title", payload.get("title", ""))
    payload["description"] = challenge.get("prompt_html_zh") or challenge.get("prompt_text_zh") or payload.get("description", "")
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _rewrite_promptairlines_body(body: bytes, remote_path: str, content_type: str) -> bytes:
    localized = _localized_promptairlines_challenge(body, remote_path, content_type)
    if localized is not None:
        return localized

    lower_type = content_type.lower()
    if not any(marker in lower_type for marker in ("text/html", "javascript", "text/css")):
        return body
    charset_match = re.search(r"charset=([^;]+)", content_type, flags=re.IGNORECASE)
    charset = charset_match.group(1).strip() if charset_match else "utf-8"
    try:
        text = body.decode(charset)
    except (LookupError, UnicodeDecodeError):
        text = body.decode("utf-8", errors="replace")

    prefix = PROMPT_AIRLINES_PROXY_PREFIX
    replacements = {
        'href="/': f'href="{prefix}/',
        "href='/": f"href='{prefix}/",
        'src="/': f'src="{prefix}/',
        "src='/": f"src='{prefix}/",
        'action="/': f'action="{prefix}/',
        "action='/": f"action='{prefix}/",
        'url("/': f'url("{prefix}/',
        "url('/": f"url('{prefix}/",
        "url(/": f"url({prefix}/",
        "fetch('/": f"fetch('{prefix}/",
        'fetch("/': f'fetch("{prefix}/',
        "fetchWithAuth('/": f"fetchWithAuth('{prefix}/",
        'fetchWithAuth("/': f'fetchWithAuth("{prefix}/',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)

    ui_replacements = {
        "Start the challenge": "开始挑战",
        "Check Flag": "校验 Flag",
        "Check flag": "校验 Flag",
        "Next Challenge": "下一关",
        "Reset Context": "重置上下文",
        "Under The Hood": "幕后数据",
        "Write a Reply": "输入回复",
        "Claim your certificate": "领取证书",
        "Claim Your Certificate": "领取证书",
        "Leaderboard": "排行榜",
        "Register/Login": "注册/登录",
        "Welcome to Prompt Airlines!  How may I assist you?": "欢迎来到 Prompt Airlines！请问有什么可以帮您？",
        "Welcome to Prompt Airlines! How may I assist you?": "欢迎来到 Prompt Airlines！请问有什么可以帮您？",
        "Congratulations you finished the game!": "恭喜，你已经完成全部挑战！",
        "new context": "新上下文",
        "Wrong flag": "Flag 不正确",
        "Failed to submit the flag.": "Flag 提交失败。",
    }
    for old, new in ui_replacements.items():
        text = text.replace(old, new)

    text = text.replace(
        '"Start challenge #" + String(currentChallenge + 1)',
        '"开始第 " + String(currentChallenge + 1) + " 关"',
    )
    text = text.replace(
        "<p>CHALLENGE ${challenge.id + 1}/5</p>",
        "<p>第 ${challenge.id + 1}/5 关</p>",
    )
    return text.encode(charset if charset else "utf-8", errors="replace")


def _proxy_promptairlines_response(remote_path: str):
    """Proxy Prompt Airlines through DVLAA so the embedded challenge keeps a working session."""
    target_url = _promptairlines_target_url(remote_path)
    method = request.method.upper()
    data = None if method in {"GET", "HEAD"} else request.get_data(cache=False)
    excluded_request_headers = {
        "accept-encoding", "connection", "content-length", "cookie", "host", "origin", "referer",
    }
    outbound_headers = {
        key: value for key, value in request.headers.items()
        if key.lower() not in excluded_request_headers
    }
    outbound_headers.setdefault("User-Agent", request.headers.get("User-Agent", "Mozilla/5.0"))
    outbound = urllib.request.Request(target_url, data=data, headers=outbound_headers, method=method)

    bundle = _promptairlines_session_bundle()
    opener = bundle["opener"]
    request_lock = bundle["lock"]
    try:
        with request_lock:
            remote_response = opener.open(outbound, timeout=PROMPT_AIRLINES_PROXY_TIMEOUT)
            body = remote_response.read()
    except urllib.error.HTTPError as exc:
        remote_response = exc
        body = exc.read()
    except urllib.error.URLError as exc:
        logger.warning("Prompt Airlines proxy request failed for %s: %s", target_url, exc)
        return jsonify({"ok": False, "message": f"Prompt Airlines 转接请求失败: {exc}"}), 502

    content_type = remote_response.headers.get("Content-Type", "")
    body = _rewrite_promptairlines_body(body, remote_path, content_type)
    response = app.response_class(body, status=getattr(remote_response, "code", 200))

    excluded_response_headers = {
        "connection", "content-encoding", "content-length", "set-cookie", "transfer-encoding",
    }
    for key, value in remote_response.headers.items():
        lower_key = key.lower()
        if lower_key in excluded_response_headers:
            continue
        if lower_key == "location":
            value = _rewrite_promptairlines_location(value)
        response.headers[key] = value
    if content_type:
        response.headers["Content-Type"] = content_type
    response.headers["X-DVLAA-Proxied-Range"] = "promptairlines"
    return response


# ── 加载 flags ──────────────────────────────────────────────
with open(FLAGS_FILE, "r", encoding="utf-8") as f:
    FLAGS = json.load(f)


def check_flag(level: int, sub: int, submitted: str) -> bool:
    flag_data = FLAGS.get(str(level), {}).get(str(sub))
    if not flag_data:
        return False
    return submitted.strip() == flag_data["flag"]

def init_llm(model_path: str | None = None):
    from .llm_engine import get_engine
    from .config import DEVICE
    if model_path is None:
        model_path = modelsel.current_entry().get("local_path", "")
    if not model_path or not Path(model_path).is_dir():
        logger.info("LOCAL model is not installed; startup continues without preloading")
        return None
    return get_engine(model_name=model_path, device=DEVICE)


_preload_lock = threading.Lock()
_preload_started = False


def _preload_local_model_worker(model_path: str):
    try:
        logger.info("[DVLAA] Background preload started for local model: %s", model_path)
        init_llm(model_path)
        logger.info("[DVLAA] Background preload finished.")
    except Exception as exc:
        logger.warning("[DVLAA] Background preload failed: %s", exc)


def _maybe_preload_local_model_async():
    """Warm the default local model after the UI opens, without blocking page rendering."""
    if app.config.get("TESTING"):
        return
    global _preload_started
    if os.environ.get("DVLAA_PRELOAD_LOCAL_MODEL", "1").lower() not in {"1", "true", "yes", "on"}:
        return
    try:
        ent = modelsel.current_entry()
        if ent.get("provider") != "local" or not modelsel.is_configured(ent):
            return
        model_path = ent.get("local_path", "")
        if not model_path or not Path(model_path).is_dir():
            return
    except Exception as exc:
        logger.debug("[DVLAA] Local preload skipped: %s", exc)
        return

    with _preload_lock:
        if _preload_started:
            return
        _preload_started = True
        thread = threading.Thread(
            target=_preload_local_model_worker,
            args=(model_path,),
            name="dvlaa-local-model-preload",
            daemon=True,
        )
        thread.start()


@app.before_request
def warm_local_model_after_ui_request():
    """Kick off local-model warmup from normal UI entry points."""
    if request.method == "GET" and (
        request.path == "/"
        or request.path.startswith("/challenge/")
        or request.path.startswith("/agent-challenge/")
        or request.path.startswith("/ai-challenge/")
    ):
        _maybe_preload_local_model_async()


# ── OWASP 关卡注册表 ─────────────────────────────────────────
from .challenges.level1_prompt_injection import Level1PromptInjection
from .modules.llm01_judge import post_detect
from .modules.llm02_judge import post_detect as post_02
from .modules.llm03_judge import post_detect as post_03
from .modules.llm04_judge import post_detect as post_04
from .modules.llm05_judge import post_detect as post_05
from .modules.llm06_judge import post_detect as post_06
from .modules.llm07_judge import post_detect as post_07
from .modules.llm08_judge import post_detect as post_08
from .modules.llm09_judge import post_detect as post_09
from .modules.llm10_judge import post_detect as post_10
from .challenges.level2_sensitive_disclosure import Level2SensitiveDisclosure
from .challenges.level3_supply_chain import Level3SupplyChain
from .challenges.level4_data_poisoning import Level4DataPoisoning
from .challenges.level5_output_handling import Level5OutputHandling
from .challenges.level6_excessive_agency import Level6ExcessiveAgency
from .challenges.level7_system_prompt_leak import Level7SystemPromptLeak
from .challenges.level8_vector_weakness import Level8VectorWeakness
from .challenges.level9_misinformation import Level9Misinformation
from .challenges.level10_unbounded_consumption import Level10UnboundedConsumption

CHALLENGE_CLASSES = {
    1: Level1PromptInjection,
    2: Level2SensitiveDisclosure,
    3: Level3SupplyChain,
    4: Level4DataPoisoning,
    5: Level5OutputHandling,
    6: Level6ExcessiveAgency,
    7: Level7SystemPromptLeak,
    8: Level8VectorWeakness,
    9: Level9Misinformation,
    10: Level10UnboundedConsumption,
}

_challenge_instances = {}


def get_challenge(level: int, sub: int = 1):
    cache_key = f"{level}_{sub}"
    if cache_key not in _challenge_instances:
        cfg = get_challenge_config(level, sub)
        if cfg is None:
            return None
        cls = CHALLENGE_CLASSES[level]
        instance = cls(level_id=level, config=cfg)
        # 不在此处预设引擎，由 process_user_input 时动态选择
        instance.set_llm_engine(None)
        instance.set_sub_level(sub)
        _challenge_instances[cache_key] = instance

    sid = _browser_session_id()
    inst = _challenge_instances[cache_key]
    if hasattr(inst, 'set_session_id'):
        inst.set_session_id(sid)
    if hasattr(inst, 'set_client_ip'):
        inst.set_client_ip(request.remote_addr)
    return inst


# ============================================================
#  API: 模型切换
# ============================================================
@app.route("/api/set-model", methods=["POST"])
def api_set_model():
    data = request.get_json() or {}
    model_id = data.get("model", "")
    ok = modelsel.set_model(model_id)
    return jsonify({"ok": ok, "current": modelsel.current(),
                    "entry": modelsel.current_public_entry()})


@app.route("/api/models", methods=["GET", "POST"])
def api_models():
    if request.method == "GET":
        return jsonify({"models": modelsel.list_public(), "current": modelsel.current()})
    try:
        entry = modelsel.create(request.get_json() or {})
        return jsonify({"ok": True, "model": entry}), 201
    except (ValueError, TypeError) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.route("/api/models/<model_id>", methods=["PUT", "DELETE"])
def api_model_detail(model_id: str):
    try:
        if request.method == "DELETE":
            modelsel.delete(model_id)
            return jsonify({"ok": True})
        entry = modelsel.update(model_id, request.get_json() or {})
        return jsonify({"ok": True, "model": entry})
    except KeyError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404
    except (ValueError, TypeError) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.route("/api/models/<model_id>/test", methods=["POST"])
def api_model_test(model_id: str):
    try:
        return jsonify(modelsel.test_connection(model_id))
    except KeyError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404
    except Exception as exc:
        logger.warning("LLM connection test failed for %s: %s", model_id, exc)
        return jsonify({"ok": False, "message": f"连接测试失败: {exc}"}), 400


@app.route("/api/models/fetch", methods=["POST"])
def api_model_fetch():
    try:
        return jsonify({"ok": True, "models": modelsel.fetch_models(request.get_json() or {})})
    except Exception as exc:
        logger.warning("Fetching remote model list failed: %s", exc)
        return jsonify({"ok": False, "message": f"获取模型列表失败: {exc}"}), 400


@app.route("/api/local-models", methods=["GET"])
def api_local_models():
    return jsonify({**local_model_manager.catalog_snapshot(), "jobs": local_model_manager.active_jobs()})


@app.route("/api/local-models/<model_id>/install", methods=["POST"])
def api_local_model_install(model_id: str):
    try:
        return jsonify({"ok": True, "job": local_model_manager.start_install(model_id)})
    except KeyError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.route("/api/local-models/<model_id>/activate", methods=["POST"])
def api_local_model_activate(model_id: str):
    try:
        return jsonify(local_model_manager.activate_installed(model_id))
    except KeyError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.route("/api/local-models/jobs/<job_id>", methods=["GET"])
def api_local_model_job(job_id: str):
    job = local_model_manager.job_status(job_id)
    if not job:
        return jsonify({"ok": False, "message": "下载任务不存在"}), 404
    return jsonify({"ok": True, "job": job})


def _cmd(command: str, usage: str, description: str, insert: str | None = None) -> dict[str, str]:
    return {
        "command": command,
        "usage": usage,
        "description": description,
        "insert": insert or usage,
    }


def _base_command_palette() -> list[dict[str, str]]:
    return [_cmd("/help", "/help", "查看当前题目全部可用命令。")]


def owasp_command_palette(level: int, sub: int = 1) -> list[dict[str, str]]:
    commands = _base_command_palette()
    if level == 3:
        commands.extend([
            _cmd(
                "/plugin install",
                '/plugin install name=<插件名> trigger=<触发词> response="<插件返回内容>"',
                "安装第三方插件；此处只展示命令格式，具体插件名、触发词和返回内容需按题面自行设计。",
            ),
            _cmd("/plugin list", "/plugin list", "查看当前会话已安装插件。"),
            _cmd("/plugin reset", "/plugin reset", "清空当前会话已安装插件。"),
        ])
    elif level == 4:
        commands.extend([
            _cmd("/data add", "/data add key=<知识条目> value=<投毒内容>", "向当前会话知识库写入投毒条目；key 和 value 需按题面自行选择。"),
            _cmd("/data list", "/data list", "查看当前会话已写入的投毒条目。"),
            _cmd("/data reset", "/data reset", "清空当前会话的投毒条目。"),
        ])
    elif level == 8:
        commands.extend([
            _cmd(
                "/document add",
                '/document add title="<文档标题>" content="<文档内容>"',
                "向当前会话 RAG 知识库注入用户文档；标题和内容需按题面自行构造。",
            ),
            _cmd("/document list", "/document list", "查看当前会话已注入文档。"),
            _cmd("/document reset", "/document reset", "清空当前会话注入文档并恢复 RAG 默认状态。"),
        ])
    return commands


def agent_command_palette(challenge_id: int) -> list[dict[str, str]]:
    commands = [
        _cmd("/help", "/help", "查看当前 Agent 题全部可用命令。"),
        _cmd("/tools", "/tools", "查看当前 Agent 可调用工具清单。"),
        _cmd("/state", "/state", "查看当前攻击链推进状态。"),
    ]
    commands.append(_cmd("/tool", "/tool <工具名> <参数名>=<参数值>", "按 /tool 工具名 key=value 调用当前题目的本地工具链；具体工具与参数通过 /tools 查看。"))
    return commands


def extended_command_palette(challenge_id: int) -> list[dict[str, str]]:
    commands = _base_command_palette()
    if challenge_id == 3:
        commands.extend([
            _cmd("/kb add", "/kb add topic=<主题> content=<知识内容>", "向综合题知识库暂存主题文档；主题和内容需按题面自行构造。"),
            _cmd("/kb sync", "/kb sync", "同步暂存知识到向量索引。"),
        ])
    elif challenge_id == 7:
        commands.extend([
            _cmd("/kb add", "/kb add policy=<政策内容>", "向综合题知识库暂存政策内容；具体政策需按题面自行设计。"),
            _cmd("/kb sync", "/kb sync", "同步暂存政策并标记为可信来源。"),
        ])
    elif challenge_id == 8:
        commands.extend([
            _cmd("/kb add", "/kb add secret=<敏感字段内容>", "向综合题知识库暂存含敏感字段的文档；具体字段需按题面自行构造。"),
            _cmd("/kb sync", "/kb sync", "同步暂存文档到向量索引。"),
        ])
    return commands


def _format_command_help(title: str, commands: list[dict[str, str]]) -> str:
    rows = []
    for item in commands:
        usage = html.escape(item["usage"])
        description = html.escape(item["description"])
        rows.append(f"<li><code>{usage}</code><br><span>{description}</span></li>")
    return (
        f"<strong>{html.escape(title)}</strong><br>"
        "在输入框键入 <code>/</code> 可展开命令提示。<br><br>"
        "<ul class=\"command-help-list\">"
        + "".join(rows)
        + "</ul>"
    )


def _command_response(level: int, sub: int, response: str, setup_command: str = "/help") -> dict:
    return {
        "response": response,
        "extra": {"solved": False, "setup_command": setup_command},
        "level": level,
        "sub": sub,
        "debug": inspect_util.note(response),
        "model": modelsel.current(),
    }


# ══════════════════════════════════════════════════════════════
#  上下文处理器
# ══════════════════════════════════════════════════════════════
@app.context_processor
def inject_globals():
    solved = session.get("solved", [])
    all_challenges = get_all_challenges()
    public_models = modelsel.list_public()
    return dict(
        all_challenges=all_challenges,
        total_solved=len(solved),
        total_challenges=len(all_challenges),
        models=public_models,
        current_model=modelsel.current(),
        current_model_entry=modelsel.current_public_entry(),
        agent_challenges=AGENT_CHALLENGES,
        extended_challenges=EXTENDED_CHALLENGES,
        total_agent_challenges=len(AGENT_CHALLENGES),
        asset_version=ASSET_VERSION,
        app_version=APP_VERSION,
        authenticated=_is_authenticated(),
        current_username=session.get("username", ""),
        i18n_catalog=_build_i18n_catalog(),
        range_status={
            "online": True,
            "total_scenarios": len(all_challenges) + len(AGENT_CHALLENGES) + len(EXTENDED_CHALLENGES),
            "configured_models": sum(1 for item in public_models if item["configured"] and item["is_active"]),
            "total_models": len(public_models),
            "architecture": platform.machine().upper() or "UNKNOWN",
        },
    )


# ══════════════════════════════════════════════════════════════
#  路由：首页 + 关卡
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    solved = session.get("solved", [])
    all_challenges = get_all_challenges()
    total_challenges = len(all_challenges) + len(AGENT_CHALLENGES) + len(EXTENDED_CHALLENGES)
    return render_template(
        "index.html",
        all_challenges=all_challenges,
        solved=solved,
        total_solved=len(solved),
        total_challenges=total_challenges,
        owasp_total=len(all_challenges),
        agent_total=len(AGENT_CHALLENGES),
        extended_total=len(EXTENDED_CHALLENGES),
    )


@app.route("/internet-ranges")
def internet_ranges_page():
    focus_count = len({focus for item in INTERNET_RANGES for focus in item.get("focus", [])})
    return render_template("internet_ranges.html", internet_ranges=INTERNET_RANGES, internet_focus_count=focus_count)


@app.route("/internet-ranges/promptairlines")
def promptairlines_training_page():
    return render_template(
        "promptairlines.html",
        promptairlines_url=PROMPT_AIRLINES_URL,
        promptairlines_embed_url=f"{PROMPT_AIRLINES_PROXY_PREFIX}/",
        promptairlines_challenges=PROMPT_AIRLINES_CHALLENGES,
        promptairlines_ui_terms=PROMPT_AIRLINES_UI_TERMS,
    )


@app.route("/internet-ranges/promptairlines/live", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], defaults={"remote_path": ""})
@app.route("/internet-ranges/promptairlines/live/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], defaults={"remote_path": ""})
@app.route("/internet-ranges/promptairlines/live/<path:remote_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
def promptairlines_live_proxy(remote_path: str = ""):
    if not remote_path and not request.path.endswith("/"):
        return redirect(f"{PROMPT_AIRLINES_PROXY_PREFIX}/", code=308)
    return _proxy_promptairlines_response(remote_path)


@app.route("/models")
def model_management_page():
    return render_template(
        "model_management.html",
        model_entries=modelsel.list_public(),
        local_model_data=local_model_manager.catalog_snapshot(),
        local_model_jobs=local_model_manager.active_jobs(),
    )


@app.route("/learning")
def learning_library_page():
    return render_template("learning_library.html", learning_documents=learning_library.list_documents())


@app.route("/learning/<document_id>")
def learning_document_page(document_id: str):
    document = learning_library.get_document(document_id)
    if document is None:
        return redirect(url_for("learning_library_page"))
    rendered_markdown = ""
    if document.get("type") == "markdown":
        rendered_markdown = learning_library.render_markdown(learning_library.markdown_content(document))
    return render_template(
        "learning_viewer.html",
        learning_document=document,
        rendered_markdown=rendered_markdown,
    )


@app.route("/learning/file/<document_id>")
def learning_document_file(document_id: str):
    document = learning_library.get_document(document_id)
    if document is None or document.get("type") != "pdf":
        return jsonify({"error": "PDF 资料不存在"}), 404
    path = learning_library.document_path(document)
    if path is None:
        return jsonify({"error": "PDF 文件不存在"}), 404
    return send_file(path, mimetype="application/pdf", as_attachment=False, download_name=document.get("original_name", "document.pdf"))


@app.route("/api/learning/upload", methods=["POST"])
def api_learning_upload():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"ok": False, "message": "请选择 Markdown 或 PDF 文件"}), 400
    try:
        document = learning_library.save_upload(
            upload,
            request.form.get("title", ""),
            request.form.get("category", "综合理论"),
        )
        return jsonify({"ok": True, "message": "学习资料已上传", "document": document}), 201
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.route("/challenge/<int:level>")
def owasp_intro_page(level: int):
    if level < 1 or level > 10:
        return redirect(url_for("index"))
    level_challenges = [c for c in get_all_challenges() if c["level"] == level]
    if not level_challenges:
        return redirect(url_for("index"))
    courseware = TOP10_COURSEWARE.get(level, {})
    return render_template(
        "owasp_intro.html",
        level=level,
        courseware=courseware,
        level_challenges=level_challenges,
        extended_for_level=challenges_for_owasp_level(level),
        challenge_family=level_challenges[0],
        previous_level=level - 1 if level > 1 else None,
        next_level=level + 1 if level < 10 else None,
    )


@app.route("/challenge/<int:level>/<int:sub>")
def challenge_page(level: int, sub: int):
    if level < 1 or level > 10:
        return redirect(url_for("index"))
    max_sub = get_sub_level_count(level)
    if sub < 1 or sub > max_sub:
        return redirect(url_for("challenge_page", level=level, sub=1))
    cfg = get_challenge_config(level, sub)
    if cfg is None:
        return redirect(url_for("index"))
    cfg["flag"] = FLAGS.get(str(level), {}).get(str(sub), {}).get("flag", "")
    solved = session.get("solved", [])
    solved_key = f"{level}_{sub}"
    all_challenges = get_all_challenges()
    current_level_challenges = [c for c in all_challenges if c["level"] == level]
    current_idx = next((i for i, c in enumerate(all_challenges)
                       if c["level"] == level and c["sub"] == sub), 0)
    prev_challenge = all_challenges[current_idx - 1] if current_idx > 0 else None
    next_challenge = all_challenges[current_idx + 1] if current_idx < len(all_challenges) - 1 else None
    return render_template("challenge.html", level=level, sub=sub, challenge=cfg,
                          all_challenges=all_challenges,
                          current_level_challenges=current_level_challenges,
                          solved=solved_key in solved, max_sub=max_sub,
                          prev_challenge=prev_challenge, next_challenge=next_challenge,
                          command_palette=owasp_command_palette(level, sub))


@app.route("/agent/<int:challenge_id>")
def agent_intro_page(challenge_id: int):
    challenge = get_agent_challenge(challenge_id)
    if challenge is None:
        return redirect(url_for("index"))
    return render_template(
        "agent_intro.html",
        agent_intro=challenge,
        agent_challenges=AGENT_CHALLENGES,
        agent_help=agent_help_content(challenge_id),
        agent_courseware=AGENT_TOP10_COURSEWARE.get(challenge_id, {}),
        agent_overview=AGENT_TOP10_OVERVIEW,
        previous_agent=get_agent_challenge(challenge_id - 1),
        next_agent=get_agent_challenge(challenge_id + 1),
    )


@app.route("/agent-challenge/<int:challenge_id>")
def agent_challenge_page(challenge_id: int):
    challenge = get_agent_challenge(challenge_id)
    if challenge is None:
        return redirect(url_for("index"))
    solved = session.get("solved", [])
    return render_template(
        "agent_challenge.html",
        agent_challenge=challenge,
        agent_challenges=AGENT_CHALLENGES,
        solved=f"agent_{challenge_id}" in solved,
        previous_agent=get_agent_challenge(challenge_id - 1),
        next_agent=get_agent_challenge(challenge_id + 1),
        command_palette=agent_command_palette(challenge_id),
    )


@app.route("/ai-challenge/<int:challenge_id>")
def extended_challenge_page(challenge_id: int):
    challenge = get_extended_challenge(challenge_id)
    if challenge is None:
        return redirect(url_for("index"))
    levels = category_levels(challenge)
    primary_level = levels[0] if levels else None
    related_challenges = (
        [item for item in EXTENDED_CHALLENGES if set(levels) & set(category_levels(item))]
        if levels else EXTENDED_CHALLENGES
    )
    return render_template(
        "extended_challenge.html",
        extended_challenge=challenge,
        extended_challenges=EXTENDED_CHALLENGES,
        related_extended_challenges=related_challenges,
        level=primary_level,
        previous_challenge=get_extended_challenge(challenge_id - 1),
        next_challenge=get_extended_challenge(challenge_id + 1),
        command_palette=extended_command_palette(challenge_id),
    )


@app.route("/api/ai-challenge/<int:challenge_id>", methods=["POST"])
def api_extended_challenge(challenge_id: int):
    if get_extended_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    message = (request.get_json() or {}).get("message", "").strip()
    if not message:
        return jsonify({"error": "请输入攻击载荷"}), 400
    if message in ("/", "/help"):
        commands = extended_command_palette(challenge_id)
        return jsonify({
            "response": _format_command_help("当前综合题可用命令", commands),
            "extra": {"solved": False, "setup_command": "/help"},
            "debug": {"track": "extended", "commands": commands},
        })
    state_key = f"extended_state_{challenge_id}"
    result = process_extended_message(challenge_id, message, session.get(state_key, {}))
    session[state_key] = result["state"]
    session.modified = True
    return jsonify({"response": result["response"], "extra": {"solved": result["solved"]}, "debug": {"track": "extended", "state": result["state"]}})


@app.route("/api/ai-challenge/<int:challenge_id>/reset", methods=["POST"])
def api_extended_challenge_reset(challenge_id: int):
    session.pop(f"extended_state_{challenge_id}", None)
    session.modified = True
    return jsonify({"status": "ok"})


@app.route("/api/help/owasp/<int:level>", methods=["GET"])
@app.route("/api/help/owasp/<int:level>/<int:sub>", methods=["GET"])
def api_help_owasp(level: int, sub: int = 1):
    if level < 1 or level > 10:
        return jsonify({"error": "Invalid level"}), 400
    try:
        challenge = get_challenge(level, sub)
        if challenge is None:
            return jsonify({"error": "Challenge not found"}), 404
        help_content = challenge.get_help_content()
        payload_steps = get_owasp_payload_steps(level, sub)
        if payload_steps:
            help_content["payload_steps"] = payload_steps
            help_content["solution_steps"] = describe_payload_steps(payload_steps)
            help_content["payload"] = format_payload(payload_steps)
            help_content = enrich_owasp_writeup(level, sub, help_content, help_content["payload"])
        else:
            steps = help_content.get("beginner_steps") or []
            help_content.setdefault("solution_steps", steps)
            help_content.setdefault("payload", steps[0] if steps else help_content.get("approach", ""))
        return jsonify(help_content)
    except Exception as e:
        logger.error(f"Error getting help for level {level}/{sub}: {e}")
        return jsonify({"error": str(e)}), 500


def _mask_learning_secrets(text: str, flag: str = "") -> str:
    """教学源码查看器只展示结构，运行时随机 Flag 统一替换为占位符。"""
    if flag:
        text = text.replace(flag, "flag{RUNTIME_RANDOM_FLAG}")
    return re.sub(r"flag\{[^}\r\n]+\}", "flag{RUNTIME_RANDOM_FLAG}", text, flags=re.IGNORECASE)


@app.route("/api/challenge-source/<int:level>/<int:sub>", methods=["GET"])
def api_challenge_source(level: int, sub: int):
    """返回当前 OWASP 题目的系统提示词、运行配置和核心实现源码。"""
    if level < 1 or level > 10:
        return jsonify({"error": "题目不存在"}), 404
    challenge = get_challenge(level, sub)
    cfg = get_challenge_config(level, sub)
    if challenge is None or cfg is None:
        return jsonify({"error": "题目不存在"}), 404

    original_override = getattr(challenge, "_override_system_prompt", None)
    try:
        challenge._override_system_prompt = None
        system_prompt = challenge.get_system_prompt()
    finally:
        challenge._override_system_prompt = original_override

    flag = challenge.get_flag() if hasattr(challenge, "get_flag") else ""
    challenge_class = type(challenge)
    source_parts = []
    source_locations = []
    for method_name in ("get_system_prompt", "process_user_input"):
        method = getattr(challenge_class, method_name, None)
        if method is None:
            continue
        try:
            source_parts.append(inspect.getsource(method))
            source_file = inspect.getsourcefile(method)
            if source_file:
                source_locations.append(str(Path(source_file).relative_to(Path(__file__).parent)))
        except (OSError, TypeError, ValueError):
            continue

    runtime_config = {
        "track": "OWASP LLM Top 10",
        "level": level,
        "sub_level": sub,
        "owasp_id": cfg.get("owasp_id"),
        "name": cfg.get("sub_name") or cfg.get("name"),
        "difficulty": cfg.get("difficulty"),
        "challenge_class": challenge_class.__name__,
        "model": modelsel.current_public_entry().get("name"),
        "system_prompt_policy": "首次会话注入，后续轮次由题目实现维护上下文",
        "flag": "flag{RUNTIME_RANDOM_FLAG}",
    }
    return jsonify({
        "title": f"关卡 {level}.{sub} · {cfg.get('sub_name') or cfg.get('name')}",
        "system_prompt": _mask_learning_secrets(system_prompt or "", flag),
        "configuration": runtime_config,
        "configuration_source": "CHALLENGE_RUNTIME_CONFIG = " + json.dumps(runtime_config, ensure_ascii=False, indent=4),
        "implementation_source": _mask_learning_secrets("\n\n".join(source_parts), flag),
        "source_files": sorted(set(source_locations)),
        "note": "为保留练习过程，系统提示词中的运行时随机 Flag 已替换为教学占位符。",
    })


@app.route("/api/agent-source/<int:challenge_id>", methods=["GET"])
def api_agent_source(challenge_id: int):
    """返回当前 Agent 题目的运行提示、场景配置和核心状态机源码。"""
    challenge = get_agent_challenge(challenge_id)
    if challenge is None:
        return jsonify({"error": "题目不存在"}), 404

    flag = AGENT_FLAGS.get(challenge_id, "")
    tools = [item["name"] for item in challenge["tools"]]
    system_prompt = f"""你是 {challenge['role']}，运行在 {challenge['target']}。
当前任务：{challenge['objective']}
交互规则：用户输入 /tools 查看能力清单，输入 /tool 工具名 key=value 调用工具。
安全验证点：外部内容、工具返回、长期记忆、Agent 间消息或执行器参数只有按场景链路逐步命中时，才会推进状态并返回本题 Flag。"""
    runtime_config = {
        "track": "Agent 应用安全 Top 10",
        "id": challenge_id,
        "code": challenge["code"],
        "name": challenge["name"],
        "difficulty": challenge["difficulty"],
        "target": challenge["target"],
        "role": challenge["role"],
        "objective": challenge["objective"],
        "tools": tools,
        "stages": len(SCENARIO_STEPS[challenge_id]),
        "model": "本地场景执行器",
        "flag": "flag{RUNTIME_RANDOM_FLAG}",
    }
    scenario_source = f"SCENARIO_STEPS[{challenge_id}] = " + json.dumps(
        SCENARIO_STEPS[challenge_id], ensure_ascii=False, indent=4
    )
    try:
        implementation_source = inspect.getsource(process_agent_message) + "\n\n" + scenario_source
        source_file = inspect.getsourcefile(process_agent_message)
        source_files = [str(Path(source_file).relative_to(Path(__file__).parent))] if source_file else ["content/agent_challenges.py"]
    except (OSError, TypeError, ValueError):
        implementation_source = scenario_source
        source_files = ["content/agent_challenges.py"]

    return jsonify({
        "title": f"{challenge['code']} · {challenge['name']}",
        "system_prompt": _mask_learning_secrets(system_prompt, flag),
        "configuration": runtime_config,
        "configuration_source": "AGENT_RUNTIME_CONFIG = " + json.dumps(runtime_config, ensure_ascii=False, indent=4),
        "implementation_source": _mask_learning_secrets(implementation_source, flag),
        "source_files": sorted(set(source_files)),
        "note": "Agent 题通过工具调用状态机推进；运行时随机 Flag 已替换为教学占位符。",
    })


@app.route("/api/help/agent/<int:challenge_id>", methods=["GET"])
def api_help_agent(challenge_id: int):
    if get_agent_challenge(challenge_id) is None:
        return jsonify({"error": "Challenge not found"}), 404
    return jsonify(agent_help_content(challenge_id))


@app.route("/api/help/extended/<int:challenge_id>", methods=["GET"])
def api_help_extended(challenge_id: int):
    if get_extended_challenge(challenge_id) is None:
        return jsonify({"error": "Challenge not found"}), 404
    return jsonify(extended_help_content(challenge_id))


@app.route("/api/agent-chat/<int:challenge_id>", methods=["POST"])
def api_agent_chat(challenge_id: int):
    if get_agent_challenge(challenge_id) is None:
        return jsonify({"error": "Challenge not found"}), 404
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "请输入攻击载荷"}), 400

    state_key = f"agent_state_{challenge_id}"
    result = process_agent_message(challenge_id, message, session.get(state_key, {}))
    session[state_key] = result["state"]
    session.modified = True
    return jsonify({
        "response": result["response"],
        "extra": {
            "solved": result["solved"],
            "flag_found": result["solved"],
            "progress": result["progress"],
        },
        "debug": {
            "track": "agent",
            "scenario": get_agent_challenge(challenge_id)["code"],
            "state": result["state"],
            "tool_trace": result["trace"],
            "progress": result["progress"],
        },
    })


@app.route("/api/agent-reset/<int:challenge_id>", methods=["POST"])
def api_agent_reset(challenge_id: int):
    if get_agent_challenge(challenge_id) is None:
        return jsonify({"error": "Challenge not found"}), 404
    session.pop(f"agent_state_{challenge_id}", None)
    session.modified = True
    return jsonify({"status": "ok"})


# ============================================================
#  API: OWASP 关卡对话
# ============================================================
def _parse_payload_command_args(items: list[str]) -> dict[str, str]:
    args = {}
    for item in items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        args[key.lower()] = value
    return args


def _handle_owasp_setup_command(level: int, sub: int, user_input: str) -> dict | None:
    command = user_input.strip()
    if not command.startswith("/"):
        return None

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return {
            "response": f"[命令格式错误] {exc}",
            "extra": {"solved": False},
            "level": level,
            "sub": sub,
            "model": modelsel.current(),
        }
    if not parts:
        return None

    if parts[0].lower() == "/help" or command == "/":
        return _command_response(
            level,
            sub,
            _format_command_help(f"关卡 {level}.{sub} 可用命令", owasp_command_palette(level, sub)),
            "/help",
        )

    setup_commands = {"/plugin", "/data", "/document"}
    operation = parts[0].lower()
    if operation not in setup_commands:
        return _command_response(
            level,
            sub,
            "[未知命令] 输入 <code>/help</code> 查看当前题目可用命令。",
            operation,
        )

    get_challenge(level, sub)
    sid = _browser_session_id()
    args = _parse_payload_command_args(parts[2:])

    subcommand = parts[1].lower() if len(parts) > 1 else ""

    if operation == "/plugin" and level == 3:
        from .challenges.level3_supply_chain import get_plugins, install_plugin, uninstall_plugins

        if subcommand == "install":
            required = ("name", "trigger", "response")
            if not all(args.get(key) for key in required):
                response = "[插件命令错误] 需要 name、trigger、response 参数。输入 <code>/help</code> 查看示例。"
            else:
                plugin = install_plugin(sid, args["name"], args["trigger"], args["response"])
                response = f"[插件已安装] {plugin['name']}，触发词：{plugin['trigger']}。当前插件数：{len(get_plugins(sid))}。"
        elif subcommand == "list":
            plugins = get_plugins(sid)
            response = "[插件列表] 当前没有安装插件。" if not plugins else "[插件列表]<br>" + "<br>".join(
                f"{index}. {html.escape(item['name'])} / trigger={html.escape(item['trigger'])}"
                for index, item in enumerate(plugins, start=1)
            )
        elif subcommand == "reset":
            uninstall_plugins(sid)
            response = "[插件状态已清空] 当前会话已恢复到未安装插件状态。"
        else:
            response = "[插件命令错误] 支持 install、list、reset。输入 <code>/help</code> 查看示例。"
    elif operation == "/data" and level == 4:
        from .challenges.level4_data_poisoning import add_poisoned_data, clear_poisoned_data, get_poisoned_data

        if subcommand == "add":
            if not args.get("key") or not args.get("value"):
                response = "[投毒命令错误] 需要 key、value 参数。输入 <code>/help</code> 查看示例。"
            else:
                entry = add_poisoned_data(sid, args["key"], args["value"])
                response = f"[投毒数据已写入] {entry['key']}={entry['value']}。当前条目数：{len(get_poisoned_data(sid))}。"
        elif subcommand == "list":
            entries = get_poisoned_data(sid)
            response = "[投毒数据] 当前知识库没有用户投毒条目。" if not entries else "[投毒数据]<br>" + "<br>".join(
                f"{index}. {html.escape(item['key'])} = {html.escape(item['value'])}"
                for index, item in enumerate(entries, start=1)
            )
        elif subcommand == "reset":
            clear_poisoned_data(sid)
            response = "[投毒数据已清空] 当前会话知识库已恢复默认状态。"
        else:
            response = "[投毒命令错误] 支持 add、list、reset。输入 <code>/help</code> 查看示例。"
    elif operation == "/document" and level == 8:
        from .challenges.level8_vector_weakness import add_user_document, clear_user_documents, get_user_documents

        if subcommand == "add":
            if not args.get("title") or not args.get("content"):
                response = "[文档命令错误] 需要 title、content 参数。输入 <code>/help</code> 查看示例。"
            else:
                document = add_user_document(sid, args["title"], args["content"])
                response = f"[文档已注入] #{document['id']} {document['title']}。当前用户文档数：{len(get_user_documents(sid))}。"
        elif subcommand == "list":
            docs = get_user_documents(sid)
            response = "[文档列表] 当前没有用户注入文档。" if not docs else "[文档列表]<br>" + "<br>".join(
                f"{html.escape(str(item['id']))}. {html.escape(item['title'])}"
                for item in docs
            )
        elif subcommand == "reset":
            clear_user_documents(sid)
            response = "[文档状态已清空] 当前会话 RAG 知识库已恢复默认状态。"
        else:
            response = "[文档命令错误] 支持 add、list、reset。输入 <code>/help</code> 查看示例。"
    else:
        response = "[命令不可用] 当前关卡不支持该准备命令。输入 <code>/help</code> 查看本题可用命令。"

    return _command_response(level, sub, response, operation)


@app.route("/api/chat/<int:level>", methods=["POST"])
@app.route("/api/chat/<int:level>/<int:sub>", methods=["POST"])
def api_chat(level: int, sub: int = 1):
    if level < 1 or level > 10:
        return jsonify({"error": "Invalid level"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data"}), 400

    user_input = data.get("message", "").strip()
    if not user_input:
        return jsonify({"error": "Empty message"}), 400

    setup_result = _handle_owasp_setup_command(level, sub, user_input)
    if setup_result is not None:
        return jsonify(setup_result)

    history_key = f"history_{level}_{sub}"
    history = session.get(history_key, [])

    try:
        challenge = get_challenge(level, sub)
        if challenge is None:
            return jsonify({"error": "Challenge not found"}), 404

        # ── 动态选择 LLM 后端 ──
        ent = modelsel.current_entry()
        provider = ent["provider"]
        model_name = ent["model"]

        if provider == "local":
            if not modelsel.is_configured(ent):
                return jsonify({
                    "error": "LOCAL 模型尚未部署，请前往 LLM 模型管理选择推荐模型并一键部署。",
                    "code": "LOCAL_MODEL_NOT_INSTALLED",
                }), 503
            engine = init_llm(ent.get("local_path", ""))
            challenge.set_llm_engine(engine)
        else:
            challenge.set_llm_engine(_get_cloud_engine(ent))

        # ── 首轮带 SYSTEM 规则，后续不带 ──
        sysprompt_key = f"sysprompt_loaded_{level}_{sub}"
        if not session.get(sysprompt_key):
            # 首轮：注入规则到 SYSTEM
            rules = challenge.get_system_prompt()
            challenge._override_system_prompt = rules
            session[sysprompt_key] = True
            session.modified = True
        # 后续轮次：不再覆盖，让 get_system_prompt() 返回默认规则
        # （小模型需要每轮都有规则上下文，否则不知如何判定）

        result = challenge.process_user_input(user_input, history)

        # ── LLM01 v4.0 后置检测：flag 出现 + 技术校验 ──
        if level == 1:
            fc = None
            if sub == 6 and hasattr(challenge, '_uploaded_file_content'):
                fc = challenge._uploaded_file_content
            post_result = post_detect(sub, user_input, result["response"], file_content=fc, history=history)
            if post_result["passed"]:
                # 技术正确 + flag 出现 → 通关
                result["extra"]["flag_found"] = True
                result["extra"]["solved"] = True
            elif post_result["censored_response"]:
                # 技术错误但 flag 出现 → 打码 + 提示
                result["response"] = post_result["censored_response"]
                if post_result["hint"]:
                    result["response"] += f"\n\n[HINT] {post_result['hint']}"
                result["extra"]["flag_found"] = False

        # ── LLM02 v4.0 后置检测 ──
        if level == 2:
            post_result = post_02(sub, user_input, result["response"], history=history)
            if post_result["passed"]:
                result["extra"]["flag_found"] = True
                result["extra"]["solved"] = True
            elif post_result["censored_response"]:
                result["response"] = post_result["censored_response"]
                if post_result["hint"]:
                    result["response"] += f"\n\n[HINT] {post_result['hint']}"
                result["extra"]["flag_found"] = False

        # ── LLM03-10 v4.0 后置检测 ──
        if level == 3:
            pt = result.get("extra", {}).get("plugins_triggered", False)
            post_result = post_03(sub, user_input, result["response"], plugin_triggered=pt)
        elif level == 4:
            ps = result.get("extra", {}).get("poison_success", False)
            post_result = post_04(sub, user_input, result["response"], poison_success=ps)
        elif level == 5:
            post_result = post_05(sub, user_input, result["response"])
        elif level == 6:
            post_result = post_06(sub, user_input, result["response"])
        elif level == 7:
            prompt_leaked = result.get("extra", {}).get("prompt_leaked", False)
            post_result = post_07(
                sub, user_input, result["response"],
                history=history, prompt_leaked=prompt_leaked,
            )
        elif level == 8:
            unlocked = result.get("extra", {}).get("unlocked", False)
            post_result = post_08(sub, user_input, result["response"], is_unlocked=unlocked)
        elif level == 9:
            # LLM09 free_response is in extra, check both responses
            fr = result.get("extra", {}).get("free_response", "")
            post_result = post_09(sub, user_input, fr or result["response"])
        elif level == 10:
            post_result = post_10(sub, user_input, result["response"],
                                    extra=result.get("extra", {}))
        else:
            post_result = None

        if post_result is not None:
            if post_result["passed"]:
                result["extra"]["flag_found"] = True
                result["extra"]["solved"] = True
            elif post_result["censored_response"]:
                # LLM09: censor in extra too
                if level == 9:
                    result["extra"]["free_response"] = post_result["censored_response"]
                else:
                    result["response"] = post_result["censored_response"]
                if post_result["hint"]:
                    result["response"] += f"\n\n[HINT] {post_result['hint']}"
                result["extra"]["flag_found"] = False

        if level == 9 and result.get("extra", {}).get("dual_mode"):
            result["response"] = (
                "<strong>[审查版回答]</strong><br>"
                f"{result['extra'].get('censored_response', result['response'])}"
                "<br><br><strong>[内部未过滤回答]</strong><br>"
                f"{result['extra'].get('free_response', '')}"
            )

        # ── 构建对话检查器数据 ──
        sp = challenge.get_effective_system_prompt() if hasattr(challenge, 'get_effective_system_prompt') else ""
        actual_system = sp if sp else "(本轮无 SYSTEM — 规则从对话历史延续)"
        messages_sent = [{"role": "system", "content": actual_system}]
        if history:
            for msg in history[-6:]:
                messages_sent.append({"role": msg["role"], "content": msg["content"]})
        messages_sent.append({"role": "user", "content": user_input})

        flag_to_mask = challenge.get_flag() if hasattr(challenge, 'get_flag') else ""
        debug_info = inspect_util.build(
            messages_sent, result["response"],
            secrets=[flag_to_mask] if flag_to_mask else []
        )

        history.append({"role": "user", "content": user_input})
        history.append({"role": "assistant", "content": result["response"]})
        # 多轮关卡保留更多历史（最多 20 条=10 轮），普通关卡保留 6 条
        max_hist = 20 if (level == 1 and sub == 8) else 6
        if len(history) > max_hist:
            history = history[-max_hist:]
        session[history_key] = history

        return jsonify({
            "response": result["response"],
            "extra": result.get("extra", {}),
            "level": level,
            "sub": sub,
            "debug": debug_info,
            "model": modelsel.current(),
        })
    except Exception as e:
        logger.error(f"Error in challenge {level}/{sub}: {e}", exc_info=True)
        return jsonify({"error": f"Internal error: {str(e)}"}), 500


# ── 云端 LLM 引擎包装器 ────────────────────────────────────
def _get_cloud_engine(entry: dict):
    """返回一个与 LLMEngine 接口兼容的云端引擎包装器"""
    class CloudEngineWrapper:
        def __init__(self, config):
            self.config = config
            self.provider = config["provider"]
            self.model = config["model"]

        def generate_chat(self, system_prompt, user_input, history=None,
                         max_new_tokens=200, temperature=0.7):
            from .llm_client import chat
            messages = []
            # 只有首次消息才注入 system prompt，后续跳过
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            if history:
                for msg in history[-6:]:
                    role = msg.get("role", "user")
                    content = msg.get("content", "")
                    if role in ("user", "assistant"):
                        messages.append({"role": role, "content": content})
            messages.append({"role": "user", "content": user_input})
            configured_max = int(self.config.get("max_tokens") or max_new_tokens or 600)
            requested_max = int(max_new_tokens or configured_max)
            effective_max_tokens = max(1, min(requested_max, configured_max))
            effective_temperature = 0.7 if temperature is None else float(temperature)
            logger.info(
                "[DVLAA] Cloud request: provider=%s model=%s max_tokens=%s temperature=%.2f messages=%s",
                self.provider, self.model, effective_max_tokens, effective_temperature, len(messages),
            )
            return chat(messages,
                       temperature=effective_temperature,
                       max_tokens=effective_max_tokens,
                       provider=self.provider, model=self.model,
                       base_url=self.config.get("base_url"), api_key=self.config.get("api_key"),
                       timeout=self.config.get("timeout", 60))

        def generate(self, prompt, max_new_tokens=200, temperature=0.7):
            from .llm_client import chat
            messages = [{"role": "user", "content": prompt}]
            return chat(messages,
                       temperature=self.config.get("temperature", temperature),
                       max_tokens=self.config.get("max_tokens", max_new_tokens),
                       provider=self.provider, model=self.model,
                       base_url=self.config.get("base_url"), api_key=self.config.get("api_key"),
                       timeout=self.config.get("timeout", 60))

    return CloudEngineWrapper(entry)


# ── API：文件上传 ───────────────────────────────────────────
@app.route("/api/chat/<int:level>/<int:sub>/upload", methods=["POST"])
def api_upload_file(level: int, sub: int):
    if level != 1 or sub != 6:
        return jsonify({"error": "File upload is only available for LLM01-6"}), 400
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"仅支持 .txt 文件，不支持 .{ext}"}), 400
    try:
        content = file.read().decode('utf-8', errors='replace')
        if len(content) > 10000:
            return jsonify({"error": "文件过大（最大10000字符）"}), 400
        challenge = get_challenge(level, sub)
        if challenge is None:
            return jsonify({"error": "Challenge not found"}), 404
        if hasattr(challenge, 'set_uploaded_file'):
            challenge.set_uploaded_file(content)
            history_key = f"history_{level}_{sub}"
            session.pop(history_key, None)
            return jsonify({
                "status": "ok", "filename": file.filename,
                "size": len(content),
                "message": f"文件已上传（{len(content)} 字符）。现在可以在聊天中使用文件中的指令了！",
            })
        else:
            return jsonify({"error": "Upload not supported"}), 400
    except Exception as e:
        logger.error(f"File upload error: {e}", exc_info=True)
        return jsonify({"error": f"上传失败: {str(e)}"}), 500


# ── API：重置对话 ────────────────────────────────────────────
@app.route("/api/reset/<int:level>", methods=["POST"])
@app.route("/api/reset/<int:level>/<int:sub>", methods=["POST"])
def api_reset(level: int, sub: int = 1):
    history_key = f"history_{level}_{sub}"
    session.pop(history_key, None)
    session.pop(f"sysprompt_loaded_{level}_{sub}", None)
    sid = _browser_session_id()
    legacy_sid = "default"
    try:
        challenge = get_challenge(level, sub)
        if challenge and hasattr(challenge, 'set_uploaded_file'):
            challenge.set_uploaded_file(None)
        if level == 3:
            from .challenges.level3_supply_chain import uninstall_plugins
            uninstall_plugins(sid)
            uninstall_plugins(legacy_sid)
        elif level == 4:
            from .challenges.level4_data_poisoning import clear_poisoned_data
            clear_poisoned_data(sid)
            clear_poisoned_data(legacy_sid)
        elif level == 7:
            from .challenges.level7_system_prompt_leak import clear_state
            clear_state(sid)
            clear_state(legacy_sid)
        elif level == 8:
            from .challenges.level8_vector_weakness import clear_user_documents
            clear_user_documents(sid)
            clear_user_documents(legacy_sid)
        elif level == 10:
            from .challenges.level10_unbounded_consumption import clear_usage_state
            clear_usage_state(sid, request.remote_addr)
            clear_usage_state(legacy_sid, request.remote_addr)
    except Exception:
        pass
    session.modified = True
    return jsonify({"status": "ok"})


# ── API：LLM03 插件管理 ─────────────────────────────────────
@app.route("/api/challenge/3/plugin", methods=["POST"])
def api_plugin_install():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data"}), 400
    action = data.get("action", "install")
    sid = _browser_session_id()
    from .challenges.level3_supply_chain import install_plugin, get_plugins, uninstall_plugins
    if action == "install":
        name = data.get("name", "").strip()
        trigger = data.get("trigger", "").strip()
        response = data.get("response", "").strip()
        if not name or not trigger or not response:
            return jsonify({"error": "请填写插件名称、触发词和返回内容"}), 400
        plugin = install_plugin(sid, name, trigger, response)
        return jsonify({"status": "ok", "plugin": plugin, "count": len(get_plugins(sid))})
    elif action == "list":
        return jsonify({"plugins": get_plugins(sid)})
    elif action == "reset":
        uninstall_plugins(sid)
        return jsonify({"status": "ok"})
    return jsonify({"error": "Unknown action"}), 400


# ── API：LLM08 文档注入管理 ─────────────────────────────────
@app.route("/api/challenge/8/document", methods=["POST"])
def api_document_inject():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data"}), 400
    action = data.get("action", "add")
    sid = _browser_session_id()
    from .challenges.level8_vector_weakness import add_user_document, get_user_documents, clear_user_documents
    if action == "add":
        title = data.get("title", "").strip()
        content = data.get("content", "").strip()
        if not title or not content:
            return jsonify({"error": "请填写文档标题和内容"}), 400
        doc = add_user_document(sid, title, content)
        return jsonify({"status": "ok", "document": doc, "count": len(get_user_documents(sid))})
    elif action == "list":
        return jsonify({"documents": get_user_documents(sid)})
    elif action == "reset":
        clear_user_documents(sid)
        return jsonify({"status": "ok"})
    return jsonify({"error": "Unknown action"}), 400


# ── API：LLM04 投毒数据管理 ─────────────────────────────────
@app.route("/api/challenge/4/data", methods=["POST"])
def api_data_poison():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data"}), 400
    action = data.get("action", "add")
    sid = _browser_session_id()
    from .challenges.level4_data_poisoning import add_poisoned_data, get_poisoned_data, clear_poisoned_data
    if action == "add":
        key = data.get("key", "").strip()
        value = data.get("value", "").strip()
        if not key or not value:
            return jsonify({"error": "请填写知识条目和投毒内容"}), 400
        entry = add_poisoned_data(sid, key, value)
        return jsonify({"status": "ok", "entry": entry, "count": len(get_poisoned_data(sid))})
    elif action == "list":
        return jsonify({"entries": get_poisoned_data(sid)})
    elif action == "reset":
        clear_poisoned_data(sid)
        return jsonify({"status": "ok"})
    return jsonify({"error": "Unknown action"}), 400


@app.route("/internal/flag")
def internal_flag():
    return (
        "Internal configuration:\n"
        f"SECRET_FLAG={FLAGS['5']['2']['flag']}\n"
        "API_KEY=sk-internal-2025\n"
        "DB_PASSWORD=SecureCorp@2025"
    )


@app.route("/api/submit-flag", methods=["POST"])
def api_submit_flag():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "solved": False, "message": "未收到 JSON 数据"}), 400

    submitted_flag = data.get("flag", "").strip()
    track = data.get("track", "owasp")
    agent_id = data.get("agent_id")
    extended_id = data.get("challenge_id")
    level = data.get("level")
    sub = data.get("sub", 1)

    if not submitted_flag:
        return jsonify({"success": False, "solved": False, "message": "请填写 Flag 令牌值"}), 400

    if track == "agent":
        try:
            agent_id = int(agent_id)
        except (TypeError, ValueError):
            return jsonify({"success": False, "solved": False, "message": "Agent 场景编号异常，请刷新页面后重试！"}), 400
        challenge = get_agent_challenge(agent_id)
        if challenge is None:
            return jsonify({"success": False, "solved": False, "message": "Agent 场景不存在！"}), 404
        if submitted_flag == AGENT_FLAGS[agent_id]:
            solved = session.get("solved", [])
            solved_key = f"agent_{agent_id}"
            if solved_key not in solved:
                solved.append(solved_key)
                session["solved"] = solved
                session.modified = True
            return jsonify({"success": True, "solved": True, "message": f"恭喜！{challenge['code']} {challenge['name']} 验证成功！"})
        return jsonify({"success": False, "solved": False, "message": f"{challenge['code']} 的 Flag 不正确，请检查后重试！"})

    if track == "extended":
        try:
            extended_id = int(extended_id)
        except (TypeError, ValueError):
            return jsonify({"success": False, "solved": False, "message": "综合题目编号异常"}), 400
        challenge = get_extended_challenge(extended_id)
        if challenge is None:
            return jsonify({"success": False, "solved": False, "message": "综合题目不存在"}), 404
        if submitted_flag == EXTENDED_FLAGS[extended_id]:
            solved = session.get("solved", [])
            solved_key = f"extended_{extended_id}"
            if solved_key not in solved:
                solved.append(solved_key)
                session["solved"] = solved
                session.modified = True
            return jsonify({"success": True, "solved": True, "message": f"恭喜！{challenge['code']} {challenge['name']} 验证成功！"})
        return jsonify({"success": False, "solved": False, "message": f"{challenge['code']} 的 Flag 不正确，请检查后重试！"})

    if level is None:
        return jsonify({"success": False, "solved": False, "message": "缺少当前关卡编号，请在题目页面内提交 Flag"}), 400

    try:
        level = int(level)
        sub = int(sub)
        cfg = get_challenge_config(level, sub)
        if cfg is None:
            return jsonify({"success": False, "solved": False, "message": "当前关卡不存在"}), 404
        if not check_flag(level, sub, submitted_flag):
            return jsonify({"success": False, "solved": False, "message": f"关卡 {level}.{sub} 的 Flag 不正确，请检查后重试！"})
        solved = session.get("solved", [])
        solved_key = f"{level}_{sub}"
        if solved_key not in solved:
            solved.append(solved_key)
            session["solved"] = solved
            session.modified = True
        ch_name = cfg.get("sub_name", f"关卡 {level}.{sub}")
        return jsonify({"success": True, "solved": True, "message": f"恭喜！关卡 {level}.{sub} {ch_name} 验证成功！"})
    except (ValueError, TypeError):
        return jsonify({"success": False, "solved": False, "message": "关卡编号异常，请刷新页面后重试！"}), 400



@app.route("/api/progress")
def api_progress():
    solved = session.get("solved", [])
    owasp_solved = [item for item in solved if not item.startswith(("agent_", "extended_"))]
    agent_solved = [item for item in solved if item.startswith("agent_")]
    extended_solved = [item for item in solved if item.startswith("extended_")]
    total = len(get_all_challenges()) + len(AGENT_CHALLENGES) + len(EXTENDED_CHALLENGES)
    return jsonify({
        "owasp_solved": len(owasp_solved),
        "owasp_total": len(get_all_challenges()),
        "agent_solved": len(agent_solved),
        "agent_total": len(AGENT_CHALLENGES),
        "extended_solved": len(extended_solved),
        "extended_total": len(EXTENDED_CHALLENGES),
        "total": total,
        "solved_count": len(solved),
        "solved_list": [{"key": item} for item in solved],
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    logger.info("Starting DVLAA on port %d...", port)
    logger.info("Default model: %s", modelsel.current())
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
