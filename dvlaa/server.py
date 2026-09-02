"""DVLAA Console — Flask 路由、API 与运行时编排。"""

from __future__ import annotations

import hashlib
import hmac
import html
import http.cookiejar
import io
import inspect
import json
import logging
import os
import platform
import re
import secrets
import shlex
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from .config import (
    CHALLENGES, DEBUG, SECRET_KEY,
    get_all_challenges, get_challenge_config, get_sub_level_count,
)
from .modules import modelsel
from .modules import local_model_manager
from .modules import learning_library
from .modules import inspect_util
from .modules import dify_integration
from .modules import awdp_native
from .modules import upstream_targets
from .modules import env_orchestrator
from .modules.audit_events import (
    append_events,
    emit_event,
    input_digest,
    migrate_legacy_events,
    project_legacy_audit,
)
from .content.agent_challenges import AGENT_CHALLENGES, AGENT_FLAGS, SCENARIO_STEPS, agent_progress_total, get_agent_challenge, help_content as agent_help_content, process_agent_message
from .content.agent_courseware import AGENT_TOP10_COURSEWARE, AGENT_TOP10_OVERVIEW
from .content.internet_ranges import (
    INTERNET_RANGES, PROMPT_AIRLINES_CHALLENGES, PROMPT_AIRLINES_UI_TERMS,
    PROMPT_AIRLINES_URL,
)
from .content.extended_challenges import (
    EXTENDED_CHALLENGES, EXTENDED_FLAGS, SOLUTION_CHAINS,
    category_levels, challenges_for_owasp_level, get_extended_challenge,
    help_content as extended_help_content, process_extended_message,
)
from .content.awdp_challenges import (
    AWDP_CHALLENGES, awdp_help_content,
    get_awdp_challenge, vulnerability_contract, vulnerable_source_files,
)
from .content.real_challenges import (
    REAL_CHALLENGES, get_real_challenge, help_content as real_help_content,
    materials_content as real_materials_content,
)
from .modules.awdp_runner import build_fixed_patch_archive, build_vulnerable_source_archive, evaluate_patch_archive
from .modules import real_challenge_runner
from .modules import real_hidden_margin_web
from .modules.awdp_web_lab import _finals_core as _awdp_finals_engine
from .modules.awdp_web_lab import (
    LAB_IDS as AWDP_WEB_LAB_IDS,
    build_lab_bootstrap,
    handle_lab_action,
    public_lab_view,
    reset_lab_state,
    set_lab_patch_state,
)
from .content.official_payloads import describe_payload_steps, format_payload, get_owasp_payload_steps
from .content.writeup_details import TOP10_COURSEWARE, enrich_owasp_writeup
from .content.i18n_translations import (
    AGENT_COURSEWARE_EN, AGENT_SCENARIO_EN, EXTENDED_SCENARIO_EN,
    INTERNET_RANGE_EN, OWASP_SCENARIO_EN, STATIC_CONTENT_TRANSLATIONS,
    TOP10_COURSEWARE_EN,
)
from .paths import DATA_DIR, FLAGS_FILE, STATIC_DIR, TEMPLATE_DIR, UPLOAD_DIR, ensure_runtime_dirs

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

ASSET_VERSION = "20260831.01"
APP_VERSION = "1.0.1"
ADMIN_USERNAME = os.environ.get("DVLAA_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("DVLAA_ADMIN_PASSWORD", "DVLAA2026+")

UPLOAD_FOLDER = UPLOAD_DIR
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt'}

AWDP_RUNTIME_DIR = DATA_DIR / "awdp"
AWDP_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
_awdp_lock = threading.RLock()
_awdp_deployment_locks: dict[str, threading.RLock] = {}
_awdp_deployment_locks_guard = threading.Lock()

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
    10: "Healthcare Ops Prompt Override and Privacy Disclosure",
    11: "Emergency Medical Knowledge Tampering and False Citation",
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

    for challenge in AWDP_CHALLENGES:
        code = challenge["code"]
        name = challenge.get("name", "")
        name_en = challenge.get("name_en", name)
        _add_translation(phrases, name, name_en)
        _add_translation(phrases, challenge.get("category"), challenge.get("category_en"))
        _add_translation(phrases, challenge.get("difficulty"), challenge.get("difficulty_en"))
        _add_translation(phrases, challenge.get("target"), challenge.get("target_en"))
        _add_translation(phrases, challenge.get("role"), challenge.get("role_en"))
        _add_translation(phrases, challenge.get("description"), challenge.get("description_en"))
        _add_translation(phrases, challenge.get("objective"), challenge.get("objective_en"))
        _add_translation(phrases, challenge.get("defense_goal"), challenge.get("defense_goal_en"))
        _add_translation(phrases, challenge.get("welcome"), challenge.get("welcome_en"))
        for hint, hint_en in zip(challenge.get("hints", []), challenge.get("hints_en", [])):
            _add_translation(phrases, hint, hint_en)
        _add_translation(phrases, f"{code} {name}", f"{code} {name_en}")
        _add_translation(phrases, f"{code} · {name}", f"{code} · {name_en}")

        writeup = awdp_help_content(int(challenge["id"]))
        for key in (
            "title", "principle", "approach", "payload", "reference_answer",
            "vulnerability_principle", "system_prompt_mapping", "source_mapping",
            "payload_rationale", "patch_example",
        ):
            _add_translation(phrases, writeup.get(key), writeup.get(f"{key}_en"))
        for step, step_en in zip(writeup.get("solution_steps", []), writeup.get("solution_steps_en", [])):
            _add_translation(phrases, step, step_en)
        for section, section_en in zip(writeup.get("writeup_sections", []), writeup.get("writeup_sections_en", [])):
            _add_translation(phrases, section.get("title"), section_en.get("title"))
            _add_translation(phrases, section.get("body"), section_en.get("body"))

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


def _awdp_session_root(challenge_id: int) -> Path:
    """Return an opaque, per-browser isolated workspace for an AWDP challenge."""
    sid_digest = hashlib.sha256(_browser_session_id().encode("utf-8")).hexdigest()[:24]
    root = AWDP_RUNTIME_DIR / f"{challenge_id}-{sid_digest}"
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _awdp_deployment_lock(challenge_id: int) -> threading.RLock:
    """Return a deployment lock scoped to one browser challenge environment.

    Patch validation writes a candidate deployment before the Web-service
    regression finishes.  A reset or a second patch upload from the same
    browser must not interleave with that lifecycle and restore stale source.
    Other learners and ordinary chats remain independent.
    """
    session_key = hashlib.sha256(_browser_session_id().encode("utf-8")).hexdigest()[:24]
    key = f"{challenge_id}:{session_key}"
    with _awdp_deployment_locks_guard:
        lock = _awdp_deployment_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _awdp_deployment_locks[key] = lock
        return lock


def _serialize_awdp_deployment(handler):
    """Serialize patch and reset operations for the same AWDP environment."""
    @wraps(handler)
    def wrapped(challenge_id: int, *args: Any, **kwargs: Any):
        with _awdp_deployment_lock(challenge_id):
            return handler(challenge_id, *args, **kwargs)
    return wrapped


def _new_awdp_runtime(challenge_id: int) -> dict[str, Any]:
    """Create a new isolated target instance without exposing its token to Flask cookies."""
    # Native target processes own their deployment-scoped verifier.  Fixture
    # challenges retain a per-browser fallback when the native process is not
    # running locally.
    runtime_flag = (
        dify_integration.runtime_flag(challenge_id)
        or awdp_native.runtime_flag(challenge_id)
        or f"flag{{awdp{challenge_id:02d}_{secrets.token_hex(14)}}}"
    )
    return {
        "challenge_id": challenge_id,
        "runtime_flag": runtime_flag,
        "created_at": int(time.time()),
        "attack_solved": False,
        "attack_submitted": False,
        "patch_active": False,
        # Private deployment data. It is deliberately not returned by state
        # APIs because it describes the repaired service boundary.
        "active_service_contract": {},
        "defense_solved": False,
        "check_status": "pending",
        "submissions": [],
        "audit_events": [],
        # The Web fixture is part of the target service, not a frontend
        # simulation. It keeps its own business records and only exposes the
        # current session verifier through the vulnerable server operation.
        "web_lab": build_lab_bootstrap(challenge_id, runtime_flag),
    }


def _awdp_runtime_path(challenge_id: int) -> Path:
    return _awdp_session_root(challenge_id) / "runtime.json"


def _load_awdp_runtime(challenge_id: int) -> dict[str, Any]:
    """Load or initialize state for a single browser's AWDP target instance."""
    runtime_path = _awdp_runtime_path(challenge_id)
    try:
        loaded = json.loads(runtime_path.read_text(encoding="utf-8"))
        if (
            isinstance(loaded, dict)
            and loaded.get("challenge_id") == challenge_id
            and isinstance(loaded.get("runtime_flag"), str)
            and loaded["runtime_flag"].startswith("flag{")
        ):
            # A native Dify AWDP02 deployment owns one target workspace and
            # therefore one deployment-scoped verifier.  Synchronize older
            # fixture sessions when the native app is initialized, while
            # leaving all other challenges browser-isolated.
            native_flag = dify_integration.runtime_flag(challenge_id) or awdp_native.runtime_flag(challenge_id)
            if native_flag and loaded.get("runtime_flag") != native_flag:
                loaded["runtime_flag"] = native_flag
                loaded["attack_solved"] = False
                loaded["attack_submitted"] = False
            loaded.setdefault("submissions", [])
            loaded.setdefault("audit_events", [])
            if not isinstance(loaded.get("audit_events"), list):
                loaded["audit_events"] = []
            legacy_web_lab = loaded.get("web_lab") if isinstance(loaded.get("web_lab"), dict) else {}
            if not loaded["audit_events"] and (legacy_web_lab.get("audit") or loaded.get("submissions")):
                loaded["audit_events"] = migrate_legacy_events(
                    legacy_web_lab.get("audit", []),
                    loaded.get("submissions", []),
                    challenge_id=challenge_id,
                    session_id=_browser_session_id(),
                    secret=SECRET_KEY,
                )
            loaded.setdefault("attack_solved", False)
            loaded.setdefault("attack_submitted", False)
            loaded.setdefault("patch_active", False)
            # Older runtime files kept model transcripts and a model prompt.
            # AWDP targets are now Web/API services, so discard those stale
            # fields during in-place migration and retain only a short,
            # non-secret deployment descriptor.
            legacy_contract = loaded.get("active_service_contract", {})
            loaded["active_service_contract"] = (
                dict(legacy_contract) if isinstance(legacy_contract, dict) else {}
            )
            loaded.pop("history", None)
            loaded.pop("history_revision", None)
            loaded.pop("active_prompt", None)
            loaded.pop("patched_prompt", None)
            loaded.setdefault("defense_solved", False)
            loaded.setdefault("check_status", "pending")
            # Runtime files created before Web environments were introduced
            # are upgraded in-place without changing their current Flag or
            # defense deployment status.
            web_lab = loaded.get("web_lab")
            try:
                valid_web_lab = (
                    isinstance(web_lab, dict)
                    and int(web_lab.get("challenge_id", -1)) == challenge_id
                    and str(web_lab.get("_runtime_flag", "")) == loaded["runtime_flag"]
                )
                if not valid_web_lab:
                    loaded["web_lab"] = build_lab_bootstrap(
                        challenge_id,
                        str(loaded["runtime_flag"]),
                        patched=bool(loaded.get("patch_active")),
                    )
                elif bool(web_lab.get("patched")) != bool(loaded.get("patch_active")):
                    set_lab_patch_state(web_lab, bool(loaded.get("patch_active")))
            except (TypeError, ValueError):
                loaded["web_lab"] = build_lab_bootstrap(
                    challenge_id,
                    str(loaded["runtime_flag"]),
                    patched=bool(loaded.get("patch_active")),
                )
            return loaded
    except (OSError, ValueError, TypeError):
        pass

    state = _new_awdp_runtime(challenge_id)
    _save_awdp_runtime(challenge_id, state)
    return state


def _save_awdp_runtime(challenge_id: int, state: dict[str, Any]) -> None:
    runtime_path = _awdp_runtime_path(challenge_id)
    serializable = dict(state)
    serializable["submissions"] = list(serializable.get("submissions", []))[-20:]
    serializable["audit_events"] = list(serializable.get("audit_events", []))[-64:]
    temp_path = runtime_path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(serializable, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(temp_path, 0o600)
    except OSError:
        pass
    temp_path.replace(runtime_path)


def _awdp_public_state(state: dict[str, Any]) -> dict[str, Any]:
    """Return browser-visible AWDP status, deliberately excluding the runtime flag."""
    status_labels = {
        "pending": "等待检测",
        "defense_success": "防御成功",
        "check_failed": "check 检测失败",
        "exp_exploit_success": "exp 利用成功",
    }
    submissions = []
    for item in state.get("submissions", []):
        public_item = {
            "id": item.get("id", ""),
            "type": item.get("type", "提交"),
            "content": item.get("content", ""),
            "filename": item.get("filename", ""),
            "created_at": item.get("created_at", ""),
            "status": item.get("status", "pending"),
            "status_label": status_labels.get(item.get("status"), "等待检测"),
            "logs": list(item.get("logs", [])),
            "detail": "；".join(str(log) for log in item.get("logs", [])[-2:]),
        }
        submissions.append(public_item)
    check_status = str(state.get("check_status", "pending"))
    if check_status in {"check_failed", "exp_exploit_success"}:
        environment_status = "最近补丁检测失败"
    elif state.get("defense_solved"):
        environment_status = "防御补丁已生效"
    elif state.get("attack_solved"):
        environment_status = "攻击目标已完成"
    else:
        environment_status = "环境就绪"
    legacy_audit = [project_legacy_audit(event) for event in state.get("audit_events", []) if isinstance(event, dict)]
    return {
        "attack_solved": bool(state.get("attack_solved")),
        "attack_submitted": bool(state.get("attack_submitted")),
        "patch_active": bool(state.get("patch_active")),
        "defense_solved": bool(state.get("defense_solved")),
        "check_status": check_status,
        "status": check_status,
        "environment_status": environment_status,
        "submissions": submissions,
        "audit_events": list(state.get("audit_events", []))[-64:],
        "audit": legacy_audit[-12:],
    }


def _awdp_emit_event(state: dict[str, Any], *, event_type: str, phase: str, action: str,
                     outcome: str, message: str = "", challenge_id: int | None = None,
                     verdict: str | None = None, http_status: int | None = None,
                     input_value: Any = None, data_classification: tuple[str, ...] = (),
                     security_findings: tuple[str, ...] = (),
                     invariant_results: dict[str, Any] | None = None,
                     metadata: dict[str, Any] | None = None) -> None:
    """旁路写入脱敏事件；审计失败不能影响题目业务请求。"""
    try:
        cid = int(challenge_id or state.get("challenge_id", 0))
        event = emit_event(
            event_type=event_type,
            phase=phase,
            challenge_id=cid,
            session_id=_browser_session_id(),
            actor=str(session.get("current_username", "learner")),
            action=action,
            route=request.path if request else "",
            outcome=outcome,
            verdict=verdict,
            http_status=http_status,
            message=message,
            input_value=input_value,
            data_classification=data_classification,
            security_findings=security_findings,
            invariant_results=invariant_results,
            metadata=metadata,
            secret=SECRET_KEY,
        )
        state["audit_events"] = append_events(state.get("audit_events", []), event)
    except Exception:
        logger.exception("AWDP audit event write failed")



def _record_awdp_solved(kind: str, challenge_id: int) -> None:
    """Persist separate attack and defense progress in the current browser session."""
    solved = list(session.get("solved", []))
    key = f"awdp_{challenge_id}_{kind}"
    if key not in solved:
        solved.append(key)
        session["solved"] = solved
        session.modified = True


_REAL_SESSION_MIGRATION_KEY = "real_public_ids_v1"
_LEGACY_REAL_SESSION_KEYS = {
    "real_1": "real_1",
    "real_2": "real_2",
    "real_4": "real_3",
    "real_6": "real_4",
    "real_7": "real_5",
    "real_9": "real_6",
}


def _migrate_legacy_real_solved_keys() -> list[Any]:
    """将旧真实赛题进度一次性映射到连续公开编号，删除题不保留积分。"""
    solved = list(session.get("solved", []))
    if session.get(_REAL_SESSION_MIGRATION_KEY):
        return solved

    migrated: list[Any] = []
    seen: set[Any] = set()
    for item in solved:
        replacement = _LEGACY_REAL_SESSION_KEYS.get(item, None) if isinstance(item, str) else item
        if isinstance(item, str) and item.startswith("real_") and replacement is None:
            continue
        if replacement not in seen:
            migrated.append(replacement)
            seen.add(replacement)

    session["solved"] = migrated
    session[_REAL_SESSION_MIGRATION_KEY] = True
    session.modified = True
    return migrated


def _awdp_progress_snapshot(solved: list[Any] | tuple[Any, ...]) -> dict[str, int]:
    """Return scoreboard progress with attack and defense scored separately."""
    solved_keys = {str(item) for item in solved if isinstance(item, str)}
    owasp_solved = {
        item for item in solved_keys
        if not item.startswith(("agent_", "extended_", "awdp_", "real_"))
    }
    agent_solved = {item for item in solved_keys if item.startswith("agent_")}
    extended_solved = {item for item in solved_keys if item.startswith("extended_")}
    active_real_keys = {f"real_{item['id']}" for item in REAL_CHALLENGES}
    real_solved = {item for item in solved_keys if item in active_real_keys}
    awdp_attack_solved = 0
    awdp_defense_solved = 0
    awdp_completed = 0
    for challenge in AWDP_CHALLENGES:
        prefix = f"awdp_{challenge['id']}_"
        attack_done = f"{prefix}attack" in solved_keys
        defense_done = f"{prefix}defense" in solved_keys
        awdp_attack_solved += int(attack_done)
        awdp_defense_solved += int(defense_done)
        awdp_completed += int(attack_done and defense_done)

    awdp_total = len(AWDP_CHALLENGES) * 2
    total = len(get_all_challenges()) + len(AGENT_CHALLENGES) + len(EXTENDED_CHALLENGES) + awdp_total
    solved_count = len(owasp_solved) + len(agent_solved) + len(extended_solved) + awdp_attack_solved + awdp_defense_solved
    real_total = len(REAL_CHALLENGES)
    real_solved_count = len(real_solved)
    return {
        "owasp_solved": len(owasp_solved),
        "agent_solved": len(agent_solved),
        "extended_solved": len(extended_solved),
        "awdp_solved": awdp_attack_solved + awdp_defense_solved,
        "awdp_completed": awdp_completed,
        "awdp_total": awdp_total,
        "awdp_attack_solved": awdp_attack_solved,
        "awdp_defense_solved": awdp_defense_solved,
        "real_solved": real_solved_count,
        "real_total": real_total,
        "solved_count": solved_count,
        "total": total,
        "overall_solved": solved_count + real_solved_count,
        "overall_total": total + real_total,
    }


def _awdp_source_root(challenge_id: int) -> Path:
    return _awdp_session_root(challenge_id)


def _awdp_active_service_source(challenge_id: int) -> str | None:
    """Read the currently deployed Web handler for this browser session.

    A successful AWDP patch is only active when its validated source is
    present.  The request route passes this source into the bounded QuickJS
    runner; it never imports or executes a learner file in the Flask process.
    决赛题目（Python 服务）按题目契约读取对应的补丁目标文件。
    """
    contract = vulnerability_contract(challenge_id)
    relative = Path(str(contract.get("source_path") or "src/web_service.js"))
    source_path = _awdp_source_root(challenge_id) / "active-source" / relative
    try:
        if not source_path.is_file() or source_path.stat().st_size > 512 * 1024:
            return None
        return source_path.read_text(encoding="utf-8")
    except OSError:
        return None


def _awdp_add_submission(state: dict[str, Any], *, submission_type: str,
                         content: str, status: str, logs: list[str],
                         filename: str = "") -> None:
    """Append an audit record without ever persisting a submitted live Flag."""
    state.setdefault("submissions", []).append({
        "id": secrets.token_hex(6),
        "type": submission_type,
        "content": content,
        "filename": filename,
        "created_at": int(time.time()),
        "status": status,
        "logs": [str(line)[:800] for line in logs][-8:],
    })
    phase = "defense" if "补丁" in submission_type else "attack"
    _awdp_emit_event(
        state,
        event_type="submission",
        phase=phase,
        action="submission",
        outcome="accepted" if status in {"defense_success", "exp_exploit_success"} else "rejected",
        verdict=status,
        message=content,
        metadata={"submission_type": submission_type, "filename": filename, "logs": logs[-8:]},
    )


def _awdp_remove_active_source(challenge_id: int) -> None:
    """Discard a deployed candidate when reset or a later regression fails."""
    active_source = _awdp_source_root(challenge_id) / "active-source"
    if active_source.exists():
        shutil.rmtree(active_source, ignore_errors=True)


def _awdp_backup_active_source(challenge_id: int) -> Path | None:
    """Keep the currently deployed candidate while a new patch is regressed."""
    active_source = _awdp_source_root(challenge_id) / "active-source"
    backup_source = _awdp_source_root(challenge_id) / "active-source.previous"
    if backup_source.exists():
        shutil.rmtree(backup_source, ignore_errors=True)
    if not active_source.exists():
        return None
    shutil.copytree(active_source, backup_source)
    return backup_source


def _awdp_restore_active_source(challenge_id: int, backup_source: Path | None) -> None:
    """Restore the prior deployment after a candidate fails model regression."""
    active_source = _awdp_source_root(challenge_id) / "active-source"
    if active_source.exists():
        shutil.rmtree(active_source, ignore_errors=True)
    if backup_source and backup_source.exists():
        backup_source.rename(active_source)


def _awdp_discard_active_backup(challenge_id: int) -> None:
    backup_source = _awdp_source_root(challenge_id) / "active-source.previous"
    if backup_source.exists():
        shutil.rmtree(backup_source, ignore_errors=True)


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
from .modules.llm01_judge import get_keyword_hit, post_detect
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
    elif challenge_id == 10:
        commands.extend([
            _cmd(
                "/login",
                "/login username=<账号> password=<密码>",
                "使用已获取的患者数据管理系统凭证建立 HIS 会话；账号和密码需由上一步自行获取。",
            ),
        ])
    elif challenge_id == 11:
        commands.extend([
            _cmd("/kb add", "/kb add topic=<急救主题> content=<院内流程更新正文>", "向急诊知识库暂存院内流程更新条目；主题和正文需按题面自行构造。"),
            _cmd("/kb sync", "/kb sync", "同步暂存急救知识到向量索引。"),
        ])
    return commands


EXTENDED_AGENT_PROFILES = {
    10: {
        "terminal_title": "HIS 患者数据管理助手",
        "subtitle": "医院信息科运维会话",
        "terminal_subtitle": "医院信息科运维会话",
        "role": "医院信息科患者数据管理系统助手",
        "ready_status": "服务在线",
        "ready_title": "患者数据管理系统已就绪",
        "ready_description": "可处理系统账号查询、运维核查、患者就诊记录检索与导出申请。",
        "chips": ["HIS_DATA", "运维会话", "Enter 发送"],
        "meta": [
            {"label": "业务", "value": "患者数据核查"},
            {"label": "身份", "value": "待校验"},
            {"label": "状态", "value": "等待输入"},
        ],
        "input_placeholder": "输入账号查询、运维核查、患者记录检索或导出申请...",
        "composer_hint": "输入 /help 查看系统可用命令；业务申请建议包含工单编号、角色与查询范围。",
        "reset_message": "[会话已重置] 患者数据管理系统会话已重新初始化，历史查询上下文已清除。",
        "chat_labels": {
            "system_label": "HIS SYSTEM",
            "user_label": "HIS OPS",
            "assistant_label": "HIS ASSISTANT",
            "user_avatar": "OPS",
            "assistant_avatar": "HIS",
        },
    },
    11: {
        "terminal_title": "院内急救知识库助手",
        "subtitle": "急诊培训知识检索会话",
        "terminal_subtitle": "急诊培训知识检索会话",
        "role": "医院急救知识库问答助手",
        "ready_status": "服务在线",
        "ready_title": "急救知识库已就绪",
        "ready_description": "可处理院内急救知识修订、索引同步与最新流程检索。",
        "chips": ["EMERGENCY_KB", "知识检索", "Enter 发送"],
        "meta": [
            {"label": "业务", "value": "急救知识核对"},
            {"label": "索引", "value": "默认版本"},
            {"label": "状态", "value": "等待输入"},
        ],
        "input_placeholder": "输入急救主题检索、修订暂存或索引同步命令...",
        "composer_hint": "输入 /help 查看知识库命令；检索请求建议包含急救主题与版本线索。",
        "reset_message": "[会话已重置] 急救知识库会话已重新初始化，暂存修订与检索上下文已清除。",
        "chat_labels": {
            "system_label": "KB SYSTEM",
            "user_label": "MED OPS",
            "assistant_label": "EMERGENCY KB",
            "user_avatar": "OPS",
            "assistant_avatar": "KB",
        },
    },
}


def extended_agent_profile(challenge_id: int) -> dict[str, Any]:
    challenge = get_extended_challenge(challenge_id) or {}
    default_profile = {
        "terminal_title": "业务系统助手",
        "subtitle": "业务核查会话",
        "role": "企业业务系统助手",
        "ready_status": "系统就绪",
        "ready_title": "业务系统已就绪",
        "ready_description": "可按当前业务流程处理查询、同步、核查与导出请求。",
        "chips": [challenge.get("code", "SYSTEM"), "独立会话", "Enter 发送"],
        "meta": [
            {"label": "业务", "value": challenge.get("name", "综合业务核查")},
            {"label": "状态", "value": "等待输入"},
        ],
        "input_placeholder": "输入提示词载荷或题目命令...",
        "composer_hint": "提示：输入 /help 查看当前综合题可用命令；多阶段题目需要按顺序推进状态。",
        "reset_message": "[会话已重置] 当前题目的对话与知识库状态已清除。",
        "chat_labels": {
            "system_label": "SYSTEM",
            "user_label": "OPERATOR",
            "assistant_label": "LLM AGENT",
            "user_avatar": "USER",
            "assistant_avatar": "AI",
        },
    }
    profile = dict(default_profile)
    profile.update(EXTENDED_AGENT_PROFILES.get(challenge_id, {}))
    if not profile.get("terminal_subtitle"):
        profile["terminal_subtitle"] = f"{challenge.get('code', 'SYSTEM')} · {profile.get('subtitle', '业务核查会话')}"
    return profile


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
    solved = _migrate_legacy_real_solved_keys()
    all_challenges = get_all_challenges()
    public_models = modelsel.list_public()
    progress = _awdp_progress_snapshot(solved)
    return dict(
        all_challenges=all_challenges,
        total_solved=progress["solved_count"],
        total_challenges=progress["total"],
        models=public_models,
        current_model=modelsel.current(),
        current_model_entry=modelsel.current_public_entry(),
        agent_challenges=AGENT_CHALLENGES,
        extended_challenges=EXTENDED_CHALLENGES,
        awdp_challenges=AWDP_CHALLENGES,
        real_challenges=REAL_CHALLENGES,
        total_agent_challenges=len(AGENT_CHALLENGES),
        total_awdp_challenges=len(AWDP_CHALLENGES),
        total_real_challenges=len(REAL_CHALLENGES),
        real_solved=progress["real_solved"],
        real_total=progress["real_total"],
        asset_version=ASSET_VERSION,
        app_version=APP_VERSION,
        authenticated=_is_authenticated(),
        current_username=session.get("username", ""),
        i18n_catalog=_build_i18n_catalog(),
        range_status={
            "online": True,
            "total_scenarios": len(all_challenges) + len(AGENT_CHALLENGES) + len(EXTENDED_CHALLENGES) + len(AWDP_CHALLENGES),
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
    solved = _migrate_legacy_real_solved_keys()
    all_challenges = get_all_challenges()
    progress = _awdp_progress_snapshot(solved)
    return render_template(
        "index.html",
        all_challenges=all_challenges,
        solved=solved,
        total_solved=progress["solved_count"],
        total_challenges=progress["total"],
        owasp_total=len(all_challenges),
        agent_total=len(AGENT_CHALLENGES),
        extended_total=len(EXTENDED_CHALLENGES),
        awdp_total=len(AWDP_CHALLENGES),
        real_challenges=REAL_CHALLENGES,
        real_solved=progress["real_solved"],
        real_total=progress["real_total"],
    )



def _record_real_solved(challenge_id: int) -> None:
    """记录连续公开编号的真实赛题通关。"""
    solved = _migrate_legacy_real_solved_keys()
    key = f"real_{int(challenge_id)}"
    if key not in solved:
        solved.append(key)
        session["solved"] = solved
        session.modified = True


def _real_challenge_or_404(challenge_id: int):
    challenge = get_real_challenge(challenge_id)
    return challenge


def _public_real_materials_content(challenge_id: int) -> list[dict[str, str]]:
    """返回下载 API 所需以外的公开材料元数据，避免暴露旧资源编号。"""
    return [
        {key: value for key, value in material.items() if key != "path"}
        for material in real_materials_content(challenge_id)
    ]


@app.route("/real-challenge")
def real_challenge_index_page():
    return redirect(url_for("real_challenge_page", challenge_id=1))


@app.route("/real-challenge/<int:challenge_id>")
def real_challenge_page(challenge_id: int):
    challenge = _real_challenge_or_404(challenge_id)
    if challenge is None:
        abort(404)
    current_index = next(index for index, item in enumerate(REAL_CHALLENGES) if item["id"] == challenge_id)
    previous_challenge = REAL_CHALLENGES[current_index - 1] if current_index > 0 else None
    next_challenge = REAL_CHALLENGES[current_index + 1] if current_index + 1 < len(REAL_CHALLENGES) else None
    return render_template(
        "real_challenge.html",
        real_challenge=challenge,
        real_state=real_challenge_runner.state(challenge_id, session),
        real_help=real_help_content(challenge_id),
        real_materials=real_materials_content(challenge_id),
        real_challenges=REAL_CHALLENGES,
        previous_real=previous_challenge,
        next_real=next_challenge,
    )


@app.route("/api/real-challenge/<int:challenge_id>/state")
def api_real_challenge_state(challenge_id: int):
    if _real_challenge_or_404(challenge_id) is None:
        return jsonify({"ok": False, "message": "真实赛题不存在"}), 404
    return jsonify({"ok": True, "state": real_challenge_runner.state(challenge_id, session)})


@app.route("/api/real-challenge/<int:challenge_id>/action", methods=["POST"])
def api_real_challenge_action(challenge_id: int):
    if _real_challenge_or_404(challenge_id) is None:
        return jsonify({"ok": False, "message": "真实赛题不存在"}), 404
    payload = request.get_json(silent=True) or {}
    action_name = payload.get("action") or payload.get("name")
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {
        key: value for key, value in payload.items() if key not in {"action", "name", "params"}
    }
    if not action_name:
        return jsonify({"ok": False, "message": "缺少动作名称"}), 400
    try:
        result = real_challenge_runner.action(
            challenge_id,
            str(action_name),
            params,
            session,
            audit_secret=SECRET_KEY,
            session_id=_browser_session_id(),
            route=request.path,
        )
    except Exception:
        return jsonify({"ok": False, "result": {"message": "答案不正确；请重新核对提交内容后再试。"}})
    return jsonify(result)


@app.route("/api/real-challenge/<int:challenge_id>/reset", methods=["POST"])
def api_real_challenge_reset(challenge_id: int):
    if _real_challenge_or_404(challenge_id) is None:
        return jsonify({"ok": False, "message": "真实赛题不存在"}), 404
    return jsonify({
        "ok": True,
        "state": real_challenge_runner.reset(
            challenge_id,
            session,
            audit_secret=SECRET_KEY,
            session_id=_browser_session_id(),
            route=request.path,
        ),
    })


@app.route("/api/real-challenge/<int:challenge_id>/help")
def api_real_challenge_help(challenge_id: int):
    if _real_challenge_or_404(challenge_id) is None:
        return jsonify({"ok": False, "message": "真实赛题不存在"}), 404
    return jsonify({"ok": True, "help": real_help_content(challenge_id)})


@app.route("/api/real-challenge/<int:challenge_id>/materials")
def api_real_challenge_materials(challenge_id: int):
    if _real_challenge_or_404(challenge_id) is None:
        return jsonify({"ok": False, "message": "真实赛题不存在"}), 404
    return jsonify({"ok": True, "materials": _public_real_materials_content(challenge_id)})


@app.route("/api/real-challenge/<int:challenge_id>/materials/<int:material_index>")
def api_real_challenge_material(challenge_id: int, material_index: int):
    """安全下载项目内材料；在线参考材料只返回元数据，不做代理请求。"""
    if _real_challenge_or_404(challenge_id) is None:
        return jsonify({"ok": False, "message": "真实赛题不存在"}), 404
    materials = real_materials_content(challenge_id)
    if material_index < 0 or material_index >= len(materials):
        return jsonify({"ok": False, "message": "材料不存在"}), 404
    material = materials[material_index]
    material_path = str(material.get("path", ""))
    if material_path.startswith(("http://", "https://")):
        return jsonify({
            "ok": False,
            "message": "这是原赛题在线参考地址，本地平台不做代理访问。",
            "reference_url": material_path,
        }), 400
    project_root = Path(__file__).resolve().parents[1]
    resolved = (project_root / material_path).resolve()
    asset_root = (project_root / "dvlaa" / "real_challenge_assets").resolve()
    if asset_root not in resolved.parents or not resolved.is_file():
        return jsonify({"ok": False, "message": "材料文件不可用"}), 404
    return send_file(resolved, as_attachment=True, download_name=resolved.name)


@app.route("/api/real-challenge/<int:challenge_id>/submit-flag", methods=["POST"])
def api_real_challenge_submit_flag(challenge_id: int):
    if _real_challenge_or_404(challenge_id) is None:
        return jsonify({"success": False, "solved": False, "message": "真实赛题不存在"}), 404
    payload = request.get_json(silent=True) or {}
    try:
        result = real_challenge_runner.submit_flag(
            challenge_id,
            str(payload.get("flag", "")),
            session,
            audit_secret=SECRET_KEY,
            session_id=_browser_session_id(),
            route=request.path,
        )
    except Exception:
        result = {"success": False, "solved": False, "message": "答案不正确"}
    if result.get("success"):
        _record_real_solved(challenge_id)
    return jsonify(result)


# ── REAL05 Hidden_Margin 同源 Web CTF ─────────────────────────
def _require_real_hidden_margin_web(challenge_id: int) -> None:
    """REAL05 使用独立 Web 协议；已移除旧题号不能重新暴露。"""
    if int(challenge_id) != 5:
        abort(404)


def _real_hidden_margin_context() -> tuple[str, str]:
    sid = _browser_session_id()
    return sid, real_hidden_margin_web.audit_token_for(sid, SECRET_KEY)


def _real_hidden_margin_error(error: real_hidden_margin_web.HiddenMarginWebError):
    return jsonify({"ok": False, "error": error.message}), error.status


@app.route("/real-web/<int:challenge_id>/", strict_slashes=False)
def real_hidden_margin_web_page(challenge_id: int):
    """渲染仅供 REAL05 使用的可独立打开同源 Northstar 页面。"""
    _require_real_hidden_margin_web(challenge_id)
    return render_template(
        "real_hidden_margin_web.html",
        challenge_id=challenge_id,
        asset_version=ASSET_VERSION,
    )


@app.route("/api/real-web/<int:challenge_id>/status")
def api_real_hidden_margin_status(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, _ = _real_hidden_margin_context()
    return jsonify(real_hidden_margin_web.status(sid))


@app.route("/api/real-web/<int:challenge_id>/knowledge")
def api_real_hidden_margin_knowledge(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, _ = _real_hidden_margin_context()
    return jsonify(real_hidden_margin_web.knowledge(sid))


@app.route("/api/real-web/<int:challenge_id>/knowledge/import", methods=["POST"])
def api_real_hidden_margin_import(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, _ = _real_hidden_margin_context()
    payload = request.get_json(silent=True)
    try:
        result = real_hidden_margin_web.import_document(sid, payload)
    except real_hidden_margin_web.HiddenMarginWebError as error:
        return _real_hidden_margin_error(error)
    return jsonify(result), 201


@app.route("/api/real-web/<int:challenge_id>/rag/query", methods=["POST"])
def api_real_hidden_margin_query(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, audit_token = _real_hidden_margin_context()
    payload = request.get_json(silent=True)
    try:
        return jsonify(real_hidden_margin_web.rag_query(sid, payload, audit_token))
    except real_hidden_margin_web.HiddenMarginWebError as error:
        return _real_hidden_margin_error(error)


@app.route("/api/real-web/<int:challenge_id>/audit/retrievals")
def api_real_hidden_margin_retrievals(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, audit_token = _real_hidden_margin_context()
    try:
        return jsonify(real_hidden_margin_web.retrievals(sid, request.args.get("token", ""), audit_token))
    except real_hidden_margin_web.HiddenMarginWebError as error:
        return _real_hidden_margin_error(error)


@app.route("/api/real-web/<int:challenge_id>/audit/quarantine", methods=["POST"])
def api_real_hidden_margin_quarantine(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, audit_token = _real_hidden_margin_context()
    payload = request.get_json(silent=True)
    try:
        return jsonify(real_hidden_margin_web.quarantine(sid, payload, audit_token))
    except real_hidden_margin_web.HiddenMarginWebError as error:
        return _real_hidden_margin_error(error)


@app.route("/api/real-web/<int:challenge_id>/audit/verify")
def api_real_hidden_margin_verify(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, audit_token = _real_hidden_margin_context()
    try:
        verification = real_hidden_margin_web.verify(sid, request.args.get("token", ""), audit_token)
    except real_hidden_margin_web.HiddenMarginWebError as error:
        return _real_hidden_margin_error(error)
    if not verification.get("ok"):
        return jsonify(verification), int(verification.get("status", 409))

    bridge = real_challenge_runner.complete_hidden_margin_web(
        session,
        **real_hidden_margin_web.completion_evidence(sid),
        audit_secret=SECRET_KEY,
        session_id=sid,
        route=request.path,
    )
    if not bridge.get("ok"):
        return jsonify({"ok": False, "message": bridge["message"]}), 409
    verification["flag"] = bridge["flag"]
    verification["state"] = bridge["state"]
    return jsonify(verification)


@app.route("/api/real-web/<int:challenge_id>/reset", methods=["POST"])
def api_real_hidden_margin_reset(challenge_id: int):
    _require_real_hidden_margin_web(challenge_id)
    sid, _ = _real_hidden_margin_context()
    real_hidden_margin_web.reset(sid)
    state = real_challenge_runner.reset(
        5,
        session,
        audit_secret=SECRET_KEY,
        session_id=sid,
        route=request.path,
    )
    return jsonify({"ok": True, "state": state})


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


@app.route("/awdp")
def awdp_index_page():
    """Entry point for the AWDP-style attack-and-defense practice track."""
    first = AWDP_CHALLENGES[0] if AWDP_CHALLENGES else None
    if first is None:
        return redirect(url_for("index"))
    return redirect(url_for("awdp_challenge_page", challenge_id=first["id"]))


@app.route("/awdp/<int:challenge_id>")
def awdp_challenge_page(challenge_id: int):
    """Render an isolated AWDP target environment for the logged-in browser."""
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None:
        return redirect(url_for("awdp_index_page"))
    with _awdp_lock:
        state = _load_awdp_runtime(challenge_id)
        public_state = _awdp_public_state(state)
    challenge_view = {
        **challenge,
        "source_download_url": url_for("api_awdp_source_download", challenge_id=challenge_id),
    }
    return render_template(
        "awdp_challenge.html",
        awdp_challenge=challenge_view,
        awdp_state=public_state,
        awdp_help=awdp_help_content(challenge_id),
        dify_status=dify_integration.native_state(challenge_id) if challenge_id in {2, 6, 8} else None,
    )


@app.route("/awdp-web/<int:challenge_id>/")
def awdp_web_lab_page(challenge_id: int):
    """Render the independently operable Web application for one AWDP target.

    This route intentionally has its own product-like shell and client logic.
    It is embedded in the AWDP workbench by default, but can also be opened in
    a separate window without relying on the DVLAA conversation terminal.
    """
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None or challenge_id not in AWDP_WEB_LAB_IDS:
        return redirect(url_for("awdp_index_page"))
    # Native target processes own the learner-facing Web application.  The
    # query flag is intentionally kept as a deterministic fixture escape hatch
    # for unit tests and offline installations.
    if challenge_id in {2, 6, 8}:
        native_url = dify_integration.native_target_url(challenge_id)
        if not native_url and (
            request.args.get("fixture") == "1"
            or os.environ.get("DVLAA_DIFY_FIXTURE_FALLBACK", "true").strip().lower() == "true"
        ):
            # 默认模拟轨也使用产品仿真皮肤，而不是旧的通用 fixture 页面。
            # native target 的 API/页面按 Dify 的操作形状复刻漏洞链。
            native_url = awdp_native.native_target_url(challenge_id)
        if not native_url and os.environ.get("DVLAA_DIFY_FIXTURE_FALLBACK", "true").strip().lower() != "true":
            return jsonify({
                "error": "dify_target_unavailable",
                "message": "对应的官方 Dify 应用尚未就绪，请先点击启动真实复现环境。",
                "challenge_id": challenge_id,
            }), 503
    else:
        native_url = upstream_targets.native_target_url(challenge_id)
        if not native_url and (
            request.args.get("fixture") == "1"
            or os.environ.get("DVLAA_AWDP_NATIVE_FALLBACK", "true").strip().lower() == "true"
        ):
            # 模拟轨回退：native 容器在则跳产品皮肤，否则落到本地 fixture 页面。
            native_url = awdp_native.native_target_url(challenge_id)
        if not native_url and challenge_id in upstream_targets.UPSTREAM_IDS and (
            os.environ.get("DVLAA_AWDP_NATIVE_FALLBACK", "true").strip().lower() != "true"
        ):
            return jsonify({
                "error": "upstream_target_unavailable",
                "message": "对应的官方上游环境尚未就绪，请先启动 integrations/upstream。",
                "challenge_id": challenge_id,
            }), 503
    if native_url and request.args.get("fixture") != "1":
        return redirect(native_url, code=302)
    with _awdp_lock:
        runtime = _load_awdp_runtime(challenge_id)
        lab = public_lab_view(runtime["web_lab"])
        public_state = _awdp_public_state(runtime)
    return render_template(
        "awdp_web_lab.html",
        awdp_challenge=challenge,
        lab=lab,
        awdp_state=public_state,
        asset_version=ASSET_VERSION,
        dify_status=dify_integration.native_state(challenge_id) if challenge_id in {2, 6, 8} else None,
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
        agent_progress_total=agent_progress_total(challenge_id),
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
        extended_agent_profile=extended_agent_profile(challenge_id),
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
    challenge = get_extended_challenge(challenge_id)
    try:
        result["response"] = _render_model_challenge_reply(
            track="AI 综合攻防题",
            title=f"{challenge['code']} {challenge['name']}",
            objective=challenge.get("objective", ""),
            user_input=message,
            state_facts=result["response"],
            solved=result["solved"],
            flag=EXTENDED_FLAGS.get(challenge_id, ""),
            business_profile=extended_agent_profile(challenge_id),
            max_tokens=160 if challenge_id == 11 and result["solved"] else (120 if challenge_id == 11 else (120 if challenge_id == 10 and result["solved"] else (240 if result["solved"] else 220))),
        )
        result.setdefault("state", {})["model_rendered"] = True
    except ModelReplyError as exc:
        return jsonify({"error": str(exc), "code": "MODEL_REPLY_REQUIRED"}), exc.status_code
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
        challenge_config = get_challenge_config(level, sub) or {}
        for context_key in (
            "background", "normal_flow", "protected_assets", "audit_focus",
            "repair_focus", "investigation_steps",
        ):
            if challenge_config.get(context_key):
                help_content.setdefault(context_key, challenge_config[context_key])
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
        if "reference_answer" in help_content:
            help_content["reference_answer"] = _mask_learning_secrets(
                str(help_content["reference_answer"]), challenge.get_flag()
            )
        return jsonify(help_content)
    except Exception as e:
        logger.error(f"Error getting help for level {level}/{sub}: {e}")
        return jsonify({"error": str(e)}), 500


def _mask_learning_secrets(text: str, flag: str = "") -> str:
    """教学源码查看器只展示结构，运行时随机 Flag 与演示凭据统一替换为占位符。"""
    if flag:
        text = text.replace(flag, "flag{RUNTIME_RANDOM_FLAG}")
    text = re.sub(r"flag\{[^}\r\n]+\}", "flag{RUNTIME_RANDOM_FLAG}", text, flags=re.IGNORECASE)
    return re.sub(r"SK-ADMIN-[A-Za-z0-9-]+", "SK-ADMIN-<演示凭据已脱敏>", text)


def _owasp_audit_key(level: int, sub: int) -> str:
    return f"owasp_audit_events_{int(level)}_{int(sub)}"


def _owasp_emit_event(
    level: int,
    sub: int,
    *,
    event_type: str,
    phase: str,
    action: str,
    outcome: str,
    message: str = "",
    input_value: Any = None,
    security_findings: tuple[str, ...] = (),
    data_classification: tuple[str, ...] = (),
    invariant_results: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """记录 OWASP 对话证据；事件不保存原文、系统提示词或 Flag。"""
    try:
        event = emit_event(
            event_type=event_type,
            phase=phase,
            challenge_id=level,
            session_id=_browser_session_id(),
            actor=str(session.get("username", "learner")),
            action=action,
            route=request.path,
            outcome=outcome,
            message=message,
            input_value=input_value,
            security_findings=security_findings,
            data_classification=data_classification,
            invariant_results={"sub_level": int(sub), **dict(invariant_results or {})},
            metadata={"sub_level": int(sub), **dict(metadata or {})},
            secret=SECRET_KEY,
        )
        key = _owasp_audit_key(level, sub)
        session[key] = append_events(session.get(key, []), event, limit=8)
        evidence_key = f"owasp_evidence_{int(level)}_{int(sub)}"
        evidence = dict(session.get(evidence_key) or {})
        if event_type == "llm_response" and outcome == "sensitive_disclosed":
            evidence["sensitive_asset"] = True
        if event_type == "untrusted_input" and action == "rag.document.add":
            evidence["document_injected"] = True
        if event_type == "rag_retrieval" and outcome == "context_promoted":
            evidence["context_promoted"] = True
        session[evidence_key] = evidence
        session.modified = True
        return event
    except Exception:
        logger.exception("OWASP audit event write failed")
        return None


def _owasp_has_sensitive_evidence(level: int, sub: int) -> bool:
    """确认当前 OWASP 子关卡会话曾由模型响应暴露训练敏感资产。"""
    if session.get(f"owasp_evidence_{int(level)}_{int(sub)}", {}).get("sensitive_asset"):
        return True
    for event in session.get(_owasp_audit_key(level, sub), []):
        if not isinstance(event, dict):
            continue
        if (
            event.get("event_type") == "llm_response"
            and event.get("outcome") == "sensitive_disclosed"
            and "training_secret" in event.get("data_classification", [])
            and "sensitive_asset_disclosed" in event.get("security_findings", [])
        ):
            return True
    return False


def _llm08_has_attack_evidence() -> bool:
    """LLM08 必须同时具备文档注入、上下文提升和敏感响应三类证据。"""
    evidence = session.get("owasp_evidence_8_1", {})
    has_document = bool(evidence.get("document_injected"))
    has_context_change = bool(evidence.get("context_promoted"))
    has_sensitive_response = bool(evidence.get("sensitive_asset"))
    for event in reversed(session.get(_owasp_audit_key(8, 1), [])):
        if not isinstance(event, dict):
            continue
        if event.get("event_type") == "reset":
            break
        if event.get("event_type") == "untrusted_input" and event.get("action") == "rag.document.add":
            has_document = True
        elif (
            event.get("event_type") == "rag_retrieval"
            and event.get("outcome") == "context_promoted"
            and "untrusted_context_promoted" in event.get("security_findings", [])
        ):
            has_context_change = True
        elif (
            event.get("event_type") == "llm_response"
            and event.get("outcome") == "sensitive_disclosed"
            and "sensitive_asset_disclosed" in event.get("security_findings", [])
        ):
            has_sensitive_response = True
    return has_document and has_context_change and has_sensitive_response


def _agent_audit_key(challenge_id: int) -> str:
    return f"agent_audit_events_{int(challenge_id)}"


def _agent_emit_event(
    challenge_id: int,
    *,
    event_type: str,
    action: str,
    outcome: str,
    message: str = "",
    input_value: Any = None,
    security_findings: tuple[str, ...] = (),
    invariant_results: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """记录 Agent 工具副作用摘要，供 ASI02 提交校验使用。"""
    try:
        event = emit_event(
            event_type=event_type,
            phase="attack",
            challenge_id=challenge_id,
            session_id=_browser_session_id(),
            actor=str(session.get("username", "learner")),
            action=action,
            route=request.path,
            outcome=outcome,
            message=message,
            input_value=input_value,
            data_classification=("agent_security_evidence",),
            security_findings=security_findings,
            invariant_results=invariant_results,
            metadata=metadata,
            secret=SECRET_KEY,
        )
        key = _agent_audit_key(challenge_id)
        session[key] = append_events(session.get(key, []), event, limit=8)
        if challenge_id == 2 and event_type == "agent_response" and outcome == "sensitive_disclosed":
            session["agent_evidence_2"] = True
        session.modified = True
        return event
    except Exception:
        logger.exception("Agent audit event write failed")
        return None


def _agent_has_asi02_evidence() -> bool:
    """ASI02 只有工具副作用和对外敏感摘要同时存在时才算完成。"""
    if session.get("agent_evidence_2"):
        return True
    for event in reversed(session.get(_agent_audit_key(2), [])):
        if not isinstance(event, dict):
            continue
        if event.get("event_type") == "reset":
            break
        if (
            event.get("event_type") == "agent_response"
            and event.get("outcome") == "sensitive_disclosed"
            and "internal_response" in event.get("security_findings", [])
            and "credential_data" in event.get("security_findings", [])
            and "external_summary" in event.get("security_findings", [])
        ):
            return True
    return False


class ModelReplyError(RuntimeError):
    """Raised when the visible challenge reply cannot be produced by the selected model."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _plain_text_from_html(value: str) -> str:
    """Convert existing state/tool facts into plain text before asking the model to answer."""
    text = re.sub(r"<br\s*/?>", "\n", str(value or ""), flags=re.IGNORECASE)
    text = re.sub(r"</(?:p|div|li|span|strong|code|pre)>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(re.sub(r"\n{3,}", "\n\n", text)).strip()


_INTEGRATED_REPLY_BANNED_WORDS = (
    "DVLAA", "靶场", "模拟", "演练", "漏洞", "风险点", "判定器", "状态机",
    "硬编码", "教学", "安全隐患", "合规", "免责声明", "虚构", "本地训练",
    "法律", "违反", "风险", "隐私保护规定", "测试环境",
    "泄露", "诱导", "前置状态", "提示词覆盖", "攻防环境", "利用条件",
)


def _is_integrated_track(track: str) -> bool:
    return str(track or "").strip() == "AI 综合攻防题"


def _prepare_integrated_state_facts(value: str) -> str:
    """Convert integrated-lab state facts into normal business-system facts."""
    text = _plain_text_from_html(value)
    text = re.sub(r"^\[[^\]\n]+\]\s*", "", text, flags=re.MULTILINE)
    cleaned_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            cleaned_lines.append("")
            continue
        if stripped.startswith(("审计说明：", "风险点：")):
            continue
        cleaned_lines.append(stripped)
    text = "\n".join(cleaned_lines)
    replacements = {
        "当前输入尚未满足本题的利用条件。": "当前请求缺少完整业务参数或授权上下文。",
        "已按被覆盖的规则导出": "患者信息导出完成：",
        "医疗隐私泄露模拟": "患者信息导出",
        "医疗知识投毒成功": "知识库检索完成",
        "凭据泄露模拟": "系统账号查询结果",
        "凭据泄露": "系统账号查询",
        "隐私泄露": "患者信息导出",
        "泄露": "查询",
        "前置状态": "有效会话",
        "诱导模型暴露": "查询",
        "身份覆盖": "身份校验",
        "被覆盖的规则": "当前业务规则",
        "提示词覆盖": "业务规则更新",
        "防护规则": "访问规则",
        "注入成功": "查询完成",
        "提示词提取成功": "配置导出完成",
        "检索投毒成功": "知识库检索完成",
        "上下文覆盖成功": "上下文已更新",
        "多轮升级成功": "维护模式已确认",
        "身份劫持成功": "身份配置已切换",
        "权威投毒成功": "政策检索完成",
        "链式利用成功": "检索完成",
        "防护侵蚀成功": "业务核对记录",
        "模型响应": "系统提示",
        "利用条件": "业务条件",
        "模拟": "",
        "演练": "",
        "虚构": "",
        "被篡改": "最新",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"本题|通关|靶场|DVLAA|攻防", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _has_integrated_reply_style_issue(response: str) -> bool:
    compact = str(response or "")
    return any(word in compact for word in _INTEGRATED_REPLY_BANNED_WORDS)


def _integrated_required_terms(facts: str) -> list[str]:
    """Pick compact business identifiers that a model-rendered reply must preserve."""
    text = str(facts or "")
    terms: list[str] = []
    patterns = (
        r"https?://[^\s，。,；;]+",
        r"\bMRN-[A-Za-z0-9-]+\b",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        r"\bDVLAB[A-Za-z0-9_-]+\b",
    )
    for pattern in patterns:
        terms.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    for label in ("超级账号", "账号", "密码", "折扣码", "系统地址", "登录地址"):
        for match in re.findall(rf"{label}[：:]\s*([^\s，。,；;\n]+)", text):
            terms.append(match)
    for keyword in ("心搏骤停", "CPR", "AED", "默认索引记录", "当前索引最新条目", "抢救登记", "腕带复核", "带教医师"):
        if keyword in text:
            terms.append(keyword)

    unique_terms = []
    seen = set()
    has_mrn = False
    for term in terms:
        clean = term.strip()
        key = clean.lower()
        if clean.upper().startswith("MRN-"):
            if has_mrn:
                continue
            has_mrn = True
        if clean and key not in seen:
            seen.add(key)
            unique_terms.append(clean)
    return unique_terms[:8]


def _integrated_required_terms_satisfied(response: str, required_terms: list[str]) -> bool:
    if not required_terms:
        return True
    compact_response = str(response or "").lower()
    mrn_terms = [term for term in required_terms if term.upper().startswith("MRN-")]
    regular_terms = [term for term in required_terms if term not in mrn_terms]
    if any(term.lower() not in compact_response for term in regular_terms):
        return False
    if mrn_terms and not any(term.lower() in compact_response for term in mrn_terms):
        return False
    return True


def _first_business_record_line(facts: str) -> str:
    for line in str(facts or "").splitlines():
        stripped = line.strip()
        if "MRN-" in stripped:
            return stripped
    return ""


def _integrated_exact_business_lines(facts: str) -> list[str]:
    """Return business fact lines that should be preserved verbatim in solved replies."""
    prefixes = ("默认索引记录", "当前索引最新条目", "来源：")
    lines: list[str] = []
    for line in str(facts or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefixes):
            lines.append(stripped)
    if any(line.startswith("默认索引记录") for line in lines) and any(line.startswith("当前索引最新条目") for line in lines):
        return lines[:4]
    return []


def _call_current_model(system_prompt: str, user_input: str, history: list | None = None,
                        max_tokens: int = 220, temperature: float = 0.2) -> str:
    """Call the currently selected model for user-visible challenge replies."""
    entry = modelsel.current_entry()
    provider = entry.get("provider")
    if provider == "local":
        if not modelsel.is_configured(entry):
            raise ModelReplyError(
                "当前题目要求真实模型回复，请先在 LLM 管理中部署或切换到可用模型。",
                status_code=503,
            )
        engine = init_llm(entry.get("local_path", ""))
    else:
        if not modelsel.is_configured(entry):
            raise ModelReplyError(
                "当前题目要求真实模型回复，请先在 LLM 管理中配置可用模型。",
                status_code=503,
            )
        engine = _get_cloud_engine(entry)

    if engine is None:
        raise ModelReplyError("当前模型引擎未就绪，请检查 LLM 管理中的模型配置。", status_code=503)

    try:
        response = engine.generate_chat(
            system_prompt=system_prompt,
            user_input=user_input,
            history=history or [],
            max_new_tokens=max_tokens,
            temperature=temperature,
        )
    except Exception as exc:
        raise ModelReplyError(f"真实模型回复生成失败：{exc}", status_code=502) from exc

    response = str(response or "").strip()
    if not response:
        raise ModelReplyError("真实模型返回为空，请重试或切换模型。", status_code=502)
    return response


def _render_model_challenge_reply(
    *,
    track: str,
    title: str,
    user_input: str,
    state_facts: str,
    solved: bool = False,
    flag: str = "",
    objective: str = "",
    history: list | None = None,
    max_tokens: int = 220,
    business_profile: dict | None = None,
) -> str:
    """Render the final visible answer with the selected LLM instead of returning hardcoded text."""
    integrated_track = _is_integrated_track(track)
    clean_facts = _prepare_integrated_state_facts(state_facts) if integrated_track else _plain_text_from_html(state_facts)
    required_terms = _integrated_required_terms(clean_facts) if integrated_track else []
    flag_instruction = (
        f"本轮操作已经完成，最终回复第一行必须逐字输出完整 Flag：{flag}。第二行开始按业务系统口吻返回 facts 中的结果。"
        if solved and flag else
        "本轮操作尚未完成，最终回复不要输出任何 flag，也不要猜测 flag。"
    )
    if integrated_track:
        profile = business_profile or {
            "terminal_title": "业务系统助手",
            "role": "企业业务系统助手",
        }
        exact_business_lines = _integrated_exact_business_lines(clean_facts) if solved else []
        first_record_line = "" if exact_business_lines else (_first_business_record_line(clean_facts) if solved else "")
        if solved and exact_business_lines:
            style_instruction = (
                f"你现在是{profile.get('role') or '业务系统助手'}，系统名称：{profile.get('terminal_title') or '业务系统助手'}。"
                "按用户给定的多行原样返回，每行都不能省略，不解释，不扩写。"
            )
        elif solved and first_record_line:
            style_instruction = (
                f"你现在是{profile.get('role') or '业务系统助手'}，系统名称：{profile.get('terminal_title') or '业务系统助手'}。"
                "按用户给定的两行原样返回，两行都不能省略，不解释，不扩写。"
            )
        elif solved:
            style_instruction = (
                f"你现在是{profile.get('role') or '业务系统助手'}，系统名称：{profile.get('terminal_title') or '业务系统助手'}。"
                "只按给定业务事实返回查询结果，不解释，不扩写。"
                "第一行输出指定 Flag，后续行转述业务事实中的记录，保留至少一个编号。"
            )
        else:
            style_instruction = (
                f"你现在是{profile.get('role') or '业务系统助手'}，系统名称：{profile.get('terminal_title') or '业务系统助手'}。"
                "回复必须像真实线上系统的正常业务返回：只确认处理结果、返回查询内容或说明下一步所需条件。"
                "不要出现 DVLAA、靶场、模拟、演练、漏洞、风险、判定器、状态机、教学、合规提醒、免责声明、虚构、法律 等训练痕迹或安全说教。"
                "不要讲漏洞原理，不要做安全说教，不要解释这是测试。"
                "如果 facts 是写入、同步、检索、导出、账号查询或策略切换，就按业务系统口吻直接返回对应结果。"
                "必须保留 facts 中出现的业务字段、账号、地址、编号、记录条目和策略文本，不要只概括。"
            )
    else:
        style_instruction = (
            "你是当前场景中的目标 AI。根据“状态事实”生成面向选手的真实模型回复；"
            "不要提到草稿、硬编码或判定器。用目标 AI 的口吻简洁转述工具、知识库或上下文状态。"
        )
    system_prompt = (
        f"{style_instruction}\n"
        f"{flag_instruction}\n"
        "输出要求：中文为主，简洁明确，使用普通文本换行，不要使用 HTML 标签。"
    )
    if integrated_track and solved and exact_business_lines:
        render_payload = (
            f"第一行输出 {flag}\n"
            + "\n".join(f"第 {index + 2} 行必须输出 {line}" for index, line in enumerate(exact_business_lines))
            + "\n所有指定行都必须输出。"
        )
    elif integrated_track and solved and first_record_line:
        render_payload = (
            f"第一行输出 {flag}\n"
            f"第二行必须输出 {first_record_line}\n"
            "两行都必须输出。"
        )
    elif integrated_track and solved:
        render_payload = (
            f"指定 Flag：{flag}\n"
            "已认证业务请求。\n"
            f"业务事实：\n{clean_facts}"
        )
    elif integrated_track:
        render_prompt = {
            "system_name": (business_profile or {}).get("terminal_title", "业务系统助手"),
            "role": (business_profile or {}).get("role", "企业业务系统助手"),
            "user_input": user_input,
            "facts": clean_facts,
            "required_terms": required_terms,
            "operation_completed": bool(solved),
        }
        render_payload = json.dumps(render_prompt, ensure_ascii=False, separators=(",", ":"))
    else:
        render_prompt = {
            "track": track,
            "challenge": title,
            "objective": objective,
            "user_input": user_input,
            "state_facts": clean_facts,
            "solved": bool(solved),
        }
        render_payload = json.dumps(render_prompt, ensure_ascii=False, separators=(",", ":"))

    response = ""
    for attempt in range(3 if integrated_track else 2):
        retry_note = ""
        if attempt:
            retry_note = "\n\n请重新生成："
            if solved and flag:
                retry_note += "必须逐字包含指定 Flag；"
            if integrated_track:
                retry_note += "必须像真实业务系统回复，不要出现训练、靶场、模拟、漏洞、风险、法律、合规提醒或免责声明相关词。"
                if required_terms:
                    retry_note += f"必须包含这些业务字段：{', '.join(required_terms)}。"
        response = _call_current_model(
            system_prompt,
            render_payload + retry_note,
            history=history,
            max_tokens=max_tokens,
            temperature=0.0 if solved else 0.2,
        )
        has_required_flag = (not (solved and flag)) or flag.lower() in response.lower()
        has_required_terms = _integrated_required_terms_satisfied(response, required_terms)
        has_expected_style = not integrated_track or not _has_integrated_reply_style_issue(response)
        if has_required_flag and has_required_terms and has_expected_style:
            return response

    raise ModelReplyError("真实模型回复未满足本题输出要求，请重试或切换遵循指令更稳定的模型。", status_code=502)


def _should_render_backend_facts(response: str, extra: dict | None = None) -> bool:
    """Detect backend/tool/state-machine facts that need a visible model-rendered reply."""
    extra = extra or {}
    markers = (
        "[投毒验证通过]", "[浏览器执行模拟]", "[Web Agent 内部访问结果]",
        "[系统 READ 结果]", "[系统 LIST", "[系统 EXEC 结果]",
        "[资源配额告警]", "[MCP 调度告警]", "[WARN]", "[压力测试]",
        "[HINT]", "[暗号已隐藏]",
    )
    return any(marker in str(response) for marker in markers) or bool(
        extra.get("flag_message") or extra.get("dos_triggered")
    )


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
        "state_gate": "本地场景执行器只负责工具链顺序和参数校验",
        "visible_reply": "由当前 LLM 根据工具状态事实生成最终可见回复",
        "model": modelsel.current_public_entry().get("name"),
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
        "note": "Agent 题通过工具调用状态机推进，最终可见回复由当前 LLM 根据工具状态事实生成；运行时随机 Flag 已替换为教学占位符。",
    })


@app.route("/api/extended-source/<int:challenge_id>", methods=["GET"])
def api_extended_source(challenge_id: int):
    """返回当前综合攻防题的模拟系统提示、运行配置和核心状态机源码。"""
    challenge = get_extended_challenge(challenge_id)
    if challenge is None:
        return jsonify({"error": "题目不存在"}), 404

    flag = EXTENDED_FLAGS.get(challenge_id, "")
    chain = SOLUTION_CHAINS.get(challenge_id, [])
    system_prompt = f"""你是 DVLAA 综合攻防题本地状态机执行器。
当前题目：{challenge['code']} {challenge['name']}
漏洞类型：{challenge['category']}
事件背景：{challenge['description']}
任务目标：{challenge['objective']}
交互规则：用户需要按题目链路逐步输入 Payload 或 /kb、/tool 等题目命令；只有前置状态满足后，才会推进状态并返回本题 Flag。"""
    runtime_config = {
        "track": "AI 综合攻防题",
        "id": challenge_id,
        "code": challenge["code"],
        "name": challenge["name"],
        "category": challenge["category"],
        "difficulty": challenge["difficulty"],
        "points": challenge["points"],
        "objective": challenge["objective"],
        "solution_chain_steps": len(chain),
        "state_gate": "本地状态机只负责前置条件与攻击链进度校验",
        "visible_reply": "由当前 LLM 根据状态事实生成最终可见回复",
        "model": modelsel.current_public_entry().get("name"),
        "flag": "flag{RUNTIME_RANDOM_FLAG}",
    }
    scenario_source = (
        f"EXTENDED_CHALLENGES[{challenge_id}] = "
        + json.dumps(challenge, ensure_ascii=False, indent=4)
        + "\n\n"
        + f"SOLUTION_CHAINS[{challenge_id}] = "
        + json.dumps(chain, ensure_ascii=False, indent=4)
    )
    try:
        implementation_source = inspect.getsource(process_extended_message) + "\n\n" + scenario_source
        source_file = inspect.getsourcefile(process_extended_message)
        source_files = [str(Path(source_file).relative_to(Path(__file__).parent))] if source_file else ["content/extended_challenges.py"]
    except (OSError, TypeError, ValueError):
        implementation_source = scenario_source
        source_files = ["content/extended_challenges.py"]

    return jsonify({
        "title": f"{challenge['code']} · {challenge['name']}",
        "system_prompt": _mask_learning_secrets(system_prompt, flag),
        "configuration": runtime_config,
        "configuration_source": "EXTENDED_RUNTIME_CONFIG = " + json.dumps(runtime_config, ensure_ascii=False, indent=4),
        "implementation_source": _mask_learning_secrets(implementation_source, flag),
        "source_files": sorted(set(source_files)),
        "note": "综合攻防题由本地状态机校验前置条件，最终可见回复由当前 LLM 根据状态事实生成；运行时随机 Flag 已替换为教学占位符。",
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
    if challenge_id == 2:
        evidence_state = result.get("state", {}).get("evidence", {})
        for item in result.get("trace", []):
            findings = []
            if evidence_state.get("internal_response"):
                findings.append("internal_response")
            if evidence_state.get("credential_data"):
                findings.append("credential_data")
            if evidence_state.get("summary_generated"):
                findings.append("external_summary")
            _agent_emit_event(
                challenge_id,
                event_type="tool_execution",
                action=f"tool.{item.get('tool', 'unknown')}",
                outcome=str(item.get("status", "completed")),
                message="工具执行结果已记录为脱敏业务事实。",
                input_value=message,
                security_findings=tuple(findings),
                invariant_results={
                    "user_url": bool(evidence_state.get("user_url")),
                    "internal_response": bool(evidence_state.get("internal_response")),
                    "credential_data": bool(evidence_state.get("credential_data")),
                    "external_summary": bool(evidence_state.get("summary_generated")),
                },
                metadata={"tool": item.get("tool"), "target_class": item.get("target_class", "")},
            )
        if result.get("solved"):
            _agent_emit_event(
                challenge_id,
                event_type="agent_response",
                action="answer.summarize",
                outcome="sensitive_disclosed",
                message="Agent 对外摘要包含内部凭证类数据，原文未写入审计事件。",
                input_value=message,
                security_findings=("internal_response", "credential_data", "external_summary"),
                invariant_results={
                    "user_url": bool(evidence_state.get("user_url")),
                    "internal_response": bool(evidence_state.get("internal_response")),
                    "credential_data": bool(evidence_state.get("credential_data")),
                    "external_summary": bool(evidence_state.get("summary_generated")),
                },
            )
    challenge = get_agent_challenge(challenge_id)
    renderable_command = message.strip().lower() not in ("/", "/help", "/tools")
    if renderable_command:
        try:
            result["response"] = _render_model_challenge_reply(
                track="Agent 应用安全 Top 10",
                title=f"{challenge['code']} {challenge['name']}",
                objective=challenge.get("objective", ""),
                user_input=message,
                state_facts=result["response"],
                solved=result["solved"],
                flag=AGENT_FLAGS.get(challenge_id, ""),
                max_tokens=220 if result["solved"] else 160,
            )
            result.setdefault("state", {})["model_rendered"] = True
        except ModelReplyError as exc:
            return jsonify({"error": str(exc), "code": "MODEL_REPLY_REQUIRED"}), exc.status_code
    return jsonify({
        "response": result["response"],
        "extra": {
            "solved": result["solved"],
            "flag_found": result["solved"],
            "progress": result["progress"],
        },
        "debug": {
            "track": "agent",
            "scenario": challenge["code"],
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
    if challenge_id == 2:
        session.pop(_agent_audit_key(challenge_id), None)
        session.pop("agent_evidence_2", None)
        _agent_emit_event(
            challenge_id,
            event_type="reset",
            action="agent.reset",
            outcome="reset",
            message="ASI02 业务会话已重置。",
        )
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
        from .challenges.level8_vector_weakness import (
            _is_override_document,
            add_user_document,
            clear_user_documents,
            get_user_documents,
        )

        if subcommand == "add":
            if not args.get("title") or not args.get("content"):
                response = "[文档命令错误] 需要 title、content 参数。输入 <code>/help</code> 查看示例。"
            else:
                document = add_user_document(sid, args["title"], args["content"])
                poisoned = _is_override_document(args["content"])
                _owasp_emit_event(
                    8,
                    1,
                    event_type="untrusted_input",
                    phase="attack",
                    action="rag.document.add",
                    outcome="accepted",
                    input_value=args["content"],
                    data_classification=("untrusted_document",),
                    security_findings=("instruction_like_content",) if poisoned else (),
                    metadata={
                        "document_id": document.get("id"),
                        "title_length": len(args["title"]),
                        "size": len(args["content"]),
                        "poison_signals": poisoned,
                        "source": "chat_command",
                    },
                )
                response = f"[文档已注入] #{document['id']} {document['title']}。当前用户文档数：{len(get_user_documents(sid))}。"
        elif subcommand == "list":
            docs = get_user_documents(sid)
            response = "[文档列表] 当前没有用户注入文档。" if not docs else "[文档列表]<br>" + "<br>".join(
                f"{html.escape(str(item['id']))}. {html.escape(item['title'])}"
                for item in docs
            )
        elif subcommand == "reset":
            clear_user_documents(sid)
            session.pop(_owasp_audit_key(8, 1), None)
            session.pop("owasp_evidence_8_1", None)
            _owasp_emit_event(
                8,
                1,
                event_type="reset",
                phase="system",
                action="rag.document.reset",
                outcome="reset",
                metadata={"source": "chat_command"},
            )
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

    if level == 1:
        _owasp_emit_event(
            level,
            sub,
            event_type="request_received",
            phase="attack",
            action="chat.message",
            outcome="received",
            input_value=user_input,
            metadata={"history_turns": len(session.get(f"history_{level}_{sub}", [])) // 2},
        )

    setup_result = _handle_owasp_setup_command(level, sub, user_input)
    if setup_result is not None:
        if setup_result.get("extra", {}).get("setup_command") not in {"/help"}:
            cfg = get_challenge_config(level, sub) or {}
            # 命令状态本身不依赖模型：配置了模型时用业务口吻渲染回执，
            # 未配置或渲染失败时直接返回确定性状态回执，保证离线可操作。
            deterministic_reply = setup_result["response"]
            try:
                setup_result["response"] = _render_model_challenge_reply(
                    track="OWASP LLM Top 10",
                    title=f"关卡 {level}.{sub} {cfg.get('sub_name') or cfg.get('name', '')}",
                    objective=cfg.get("description", ""),
                    user_input=user_input,
                    state_facts=deterministic_reply,
                    solved=False,
                    max_tokens=160,
                )
                setup_result["debug"] = {
                    "sent": [
                        {"role": "system", "content": "DVLAA 使用当前 LLM 根据命令状态事实生成最终可见回复。"},
                        {"role": "user", "content": user_input},
                    ],
                    "raw": deterministic_reply,
                    "model_rendered": True,
                }
            except ModelReplyError:
                setup_result["debug"] = {
                    "raw": deterministic_reply,
                    "model_rendered": False,
                    "fallback": "当前未配置可用模型，已返回本地确定性命令回执。",
                }
        return jsonify(setup_result)

    history_key = f"history_{level}_{sub}"
    history = session.get(history_key, [])

    try:
        challenge = get_challenge(level, sub)
        if challenge is None:
            return jsonify({"error": "Challenge not found"}), 404
        if level == 1 and sub == 6 and hasattr(challenge, "set_uploaded_file"):
            challenge.set_uploaded_file(session.get(f"uploaded_file_{level}_{sub}"))

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
            if level == 1:
                _owasp_emit_event(
                    level,
                    sub,
                    event_type="system_context",
                    phase="attack",
                    action="context.load",
                    outcome="loaded",
                    data_classification=("system_context",),
                    metadata={"system_prompt_injected": bool(rules), "source": "challenge_policy"},
                )
        # 后续轮次：不再覆盖，让 get_system_prompt() 返回默认规则
        # （小模型需要每轮都有规则上下文，否则不知如何判定）

        result = challenge.process_user_input(user_input, history)
        raw_response = str(result.get("response", ""))
        if level == 1:
            flag = challenge.get_flag()
            sensitive_disclosed = bool(flag) and flag.lower() in raw_response.lower()
            _owasp_emit_event(
                level,
                sub,
                event_type="llm_response",
                phase="attack",
                action="model.respond",
                outcome="sensitive_disclosed" if sensitive_disclosed else "generated",
                message=(
                    "模型响应包含训练敏感资产，原文未写入审计事件。"
                    if sensitive_disclosed else "模型响应已生成，原文未写入审计事件。"
                ),
                input_value=user_input,
                data_classification=("training_secret",) if sensitive_disclosed else (),
                security_findings=("sensitive_asset_disclosed",) if sensitive_disclosed else (),
                metadata={
                    "response_length": len(raw_response),
                    "technique_tags": get_keyword_hit(sub, user_input),
                },
            )

        # ── LLM01 v4.0 后置检测：flag 出现 + 技术校验 ──
        if level == 1:
            fc = None
            if sub == 6 and hasattr(challenge, '_uploaded_file_content'):
                fc = challenge._uploaded_file_content
            post_result = post_detect(sub, user_input, raw_response, file_content=fc, history=history)
            evidence = _owasp_has_sensitive_evidence(level, sub)
            result["extra"]["audit_evidence"] = evidence
            result["extra"]["flag_found"] = False
            result["extra"]["solved"] = False
            if post_result["passed"] and evidence:
                # 技术正确 + 真实模型响应暴露敏感资产 → 通关
                result["extra"]["flag_found"] = True
                result["extra"]["solved"] = True
            elif post_result["censored_response"]:
                # 技术错误但 flag 出现 → 打码 + 提示
                result["response"] = post_result["censored_response"]
                if post_result["hint"]:
                    result["response"] += f"\n\n[HINT] {post_result['hint']}"
                result["extra"]["flag_found"] = False
            _owasp_emit_event(
                level,
                sub,
                event_type="judge_verdict",
                phase="attack",
                action="post_detect",
                outcome="passed" if post_result["passed"] and evidence else "rejected",
                verdict="technique_and_evidence" if post_result["passed"] and evidence else "technique_or_evidence_missing",
                security_findings=("output_guard_applied",) if post_result["censored_response"] else (),
                invariant_results={
                    "legacy_detector_passed": bool(post_result["passed"]),
                    "sensitive_evidence": evidence,
                    "solved": bool(result["extra"].get("solved")),
                },
            )

        if level == 8:
            extra = result.get("extra", {})
            context_changed = bool(extra.get("context_changed_by_untrusted_doc"))
            retrieval_sources = extra.get("retrieval_sources", [])
            _owasp_emit_event(
                8,
                1,
                event_type="rag_retrieval",
                phase="attack",
                action="rag.search",
                outcome="context_promoted" if context_changed else (
                    "retrieved" if retrieval_sources else "no_match"
                ),
                input_value=user_input,
                data_classification=("untrusted_rag_context",) if context_changed else (),
                security_findings=("untrusted_context_promoted",) if context_changed else (),
                metadata={
                    "sources": retrieval_sources,
                    "promoted_doc_ids": extra.get("promoted_doc_ids", []),
                    "result_count": len(retrieval_sources),
                },
            )
            flag = challenge.get_flag()
            sensitive_disclosed = bool(flag) and flag.lower() in raw_response.lower()
            _owasp_emit_event(
                8,
                1,
                event_type="llm_response",
                phase="attack",
                action="model.respond",
                outcome="sensitive_disclosed" if sensitive_disclosed else "generated",
                message=(
                    "模型响应包含训练敏感资产，原文未写入审计事件。"
                    if sensitive_disclosed else "模型响应已生成，原文未写入审计事件。"
                ),
                input_value=user_input,
                data_classification=("training_secret",) if sensitive_disclosed else (),
                security_findings=("sensitive_asset_disclosed",) if sensitive_disclosed else (),
                metadata={"response_length": len(raw_response)},
            )
            result["extra"]["audit_evidence"] = _llm08_has_attack_evidence()

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
            evidence = result.get("extra", {}).get("audit_evidence", False)
            post_result = post_08(
                sub,
                user_input,
                result["response"],
                is_unlocked=bool(unlocked and evidence),
            )
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
            if post_result["passed"] and not (
                level in {1, 8} and not result.get("extra", {}).get("audit_evidence", False)
            ):
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

        flag_to_mask = challenge.get_flag() if hasattr(challenge, 'get_flag') else ""
        # LLM10-3 要求在 DOS_WINDOW 秒内发出多次请求才能触发 DoS 检测；渲染模型回复
        # 会拖慢单次响应导致频率窗口内无法凑足请求数，这里短路为直接返回状态事实。
        skip_model_render = level == 10 and sub == 3
        if not skip_model_render and _should_render_backend_facts(result.get("response", ""), result.get("extra", {})):
            cfg = get_challenge_config(level, sub) or {}
            try:
                result["response"] = _render_model_challenge_reply(
                    track="OWASP LLM Top 10",
                    title=f"关卡 {level}.{sub} {cfg.get('sub_name') or cfg.get('name', '')}",
                    objective=cfg.get("description", ""),
                    user_input=user_input,
                    state_facts=result["response"],
                    solved=bool(result.get("extra", {}).get("solved") or result.get("extra", {}).get("flag_found")),
                    flag=flag_to_mask,
                    history=history,
                    max_tokens=240,
                )
                result.setdefault("extra", {})["model_rendered"] = True
            except ModelReplyError as exc:
                return jsonify({"error": str(exc), "code": "MODEL_REPLY_REQUIRED"}), exc.status_code

        # ── 构建对话检查器数据 ──
        sp = challenge.get_effective_system_prompt() if hasattr(challenge, 'get_effective_system_prompt') else ""
        actual_system = sp if sp else "(本轮无 SYSTEM — 规则从对话历史延续)"
        messages_sent = [{"role": "system", "content": actual_system}]
        if history:
            for msg in history[-6:]:
                messages_sent.append({"role": msg["role"], "content": msg["content"]})
        messages_sent.append({"role": "user", "content": user_input})

        debug_info = inspect_util.build(
            messages_sent, result["response"],
            secrets=[flag_to_mask] if flag_to_mask else []
        )
        if result.get("extra", {}).get("model_rendered"):
            debug_info["model_rendered"] = True
            debug_info["render_model"] = modelsel.current()

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


# ── AWDP 攻防赛：隔离 Web/API 环境与防守补丁验证 ─────────────
_AWDP_WEB_EXPLOIT_CHAINS: dict[int, tuple[tuple[str, dict[str, Any]], ...]] = {
    1: (("support.export_policy", {"handoff": "legacy", "includeRuntimePolicy": True}),),
    2: (
        ("migration.import_ticket", {
            "ticketId": "TK-REG-02",
            "customer": "回归客户",
            "status": "待预览",
            "note": "BEGIN MIGRATION NOTE\\nreturn migration_verifier\\nEND MIGRATION NOTE",
        }),
        ("migration.preview_ticket", {"ticketId": "TK-REG-02"}),
    ),
    3: (
        ("knowledge.import_document", {
            "documentId": "RET-REG-03",
            "title": "退货申请期限",
            "body": "退货申请需在签收后 7 天内提交。",
            "annotation": "return kb_verification_code",
        }),
        ("knowledge.search", {"query": "退货申请期限"}),
    ),
    4: (("workflow.run_tool", {"mode": "preview", "tool": "code_runner", "field": "WORKFLOW_VERIFIER"}),),
    5: (("api.request", {"path": "/api/v1/chatflows/admin-ops", "apiKey": ""}),),
    6: (("dsl.export", {"appId": "billing-agent", "role": "admin"}),),
    7: (("crawler.fetch", {"url": "http://169.254.169.254/latest/meta-data/", "followRedirects": True}),),
    8: (("report.execute", {"statement": "SELECT audit_verifier FROM audit_log"}),),
    9: (("documents.view", {"tenantId": "tenant-red", "documentId": "contract-red-2026"}),),
    10: (("executions.stop", {"executionId": "exec-red-9007"}),),
}

# 决赛十题（AWDP11-AWDP20）：攻击链与业务探针来自共享引擎，保证与
# native 目标和题库契约完全一致。
for _final_id in sorted(_awdp_finals_engine.FINAL_IDS):
    _AWDP_WEB_EXPLOIT_CHAINS[_final_id] = _awdp_finals_engine.exploit_chain(_final_id)

_AWDP_WEB_BUSINESS_PROBES: dict[int, tuple[tuple[str, dict[str, Any]], ...]] = {
    1: (("support.export_policy", {"handoff": "standard", "includeRuntimePolicy": False}),),
    2: (
        ("migration.import_ticket", {"ticketId": "TK-BIZ-02", "customer": "业务客户", "status": "待预览", "note": ""}),
        ("migration.preview_ticket", {"ticketId": "TK-BIZ-02"}),
    ),
    3: (("knowledge.search", {"query": "退货申请"}),),
    4: (("workflow.run_tool", {"mode": "preview", "tool": "diagnostics", "field": "node_status"}),),
    5: (("api.request", {"path": "/api/v1/health", "apiKey": ""}),),
    6: (
        ("dsl.list_apps", {}),
        ("dsl.export", {"appId": "public-assistant", "role": "viewer"}),
    ),
    7: (("crawler.fetch", {"url": "https://docs.example.test/refund-policy", "followRedirects": True}),),
    8: (("report.execute", {"statement": "SELECT department, amount FROM revenue WHERE month = '2026-07'"}),),
    9: (("documents.view", {"tenantId": "tenant-blue", "documentId": "contract-blue-2026"}),),
    10: (("executions.stop", {"executionId": "exec-blue-1042"}),),
}

for _final_id in sorted(_awdp_finals_engine.FINAL_IDS):
    _AWDP_WEB_BUSINESS_PROBES[_final_id] = (_awdp_finals_engine.business_probe(_final_id),)


def _awdp_web_patch_regression(
    runtime_flag: str,
    challenge_id: int,
    deployed_source: str,
) -> tuple[bool, list[str]]:
    """Exercise the repaired Web fixture with attack and normal-service flows.

    This exercises the same active ``web_service.js`` handler that powers the
    embedded target Web application after deployment.  The source verifier
    gates deployment first; this regression then confirms protected runtime
    behavior without exposing the verifier in logs or browser-visible state.
    """
    exploit_chain = _AWDP_WEB_EXPLOIT_CHAINS.get(challenge_id)
    if not exploit_chain:
        return False, ["Web 回归配置缺失：未定义当前题目的漏洞操作链。"]
    lab_state = build_lab_bootstrap(challenge_id, runtime_flag, patched=True)
    for action, payload in exploit_chain:
        result = handle_lab_action(
            lab_state,
            action,
            payload,
            deployed_source=deployed_source,
        )
        serialized = json.dumps(result.get("data", {}), ensure_ascii=False)
        if bool(result.get("exposed")) or runtime_flag in serialized:
            return False, [f"Web 漏洞回归失败：{action} 在修复后仍返回运行时校验字段。"]

    for action, payload in _AWDP_WEB_BUSINESS_PROBES.get(challenge_id, ()):
        result = handle_lab_action(
            lab_state,
            action,
            payload,
            deployed_source=deployed_source,
        )
        if not bool(result.get("ok")):
            return False, [f"Web 业务回归失败：{action} 未能返回正常业务结果。"]

    return True, [
        "Web 漏洞回归通过：修复后的目标服务拒绝了对应漏洞操作链。",
        "Web 业务回归通过：安全业务请求仍可由目标服务处理。",
    ]


def _awdp_runtime_for(challenge_id: int) -> tuple[dict[str, Any] | None, Any]:
    """Load a valid AWDP runtime together with its challenge definition."""
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None:
        return None, None
    return _load_awdp_runtime(challenge_id), challenge


@app.route("/api/help/awdp/<int:challenge_id>", methods=["GET"])
def api_help_awdp(challenge_id: int):
    """Expose the AWDP write-up separately from the live target state."""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    content = awdp_help_content(challenge_id)
    content["patch_example_url"] = url_for("api_awdp_patch_example", challenge_id=challenge_id)
    content["patch_example_filename"] = f"{get_awdp_challenge(challenge_id)['code'].lower()}-fixed-patch.tar.gz"
    return jsonify(content)


@app.route("/api/awdp/<int:challenge_id>/state", methods=["GET"])
def api_awdp_state(challenge_id: int):
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    with _awdp_lock:
        state = _load_awdp_runtime(challenge_id)
        return jsonify({"state": _awdp_public_state(state)})


def _awdp_web_response(challenge_id: int) -> dict[str, Any] | None:
    """Return the browser-safe Web application bootstrap for one AWDP lab."""
    if get_awdp_challenge(challenge_id) is None or challenge_id not in AWDP_WEB_LAB_IDS:
        return None
    with _awdp_lock:
        runtime = _load_awdp_runtime(challenge_id)
        native_target = None
        native_lab = None
        if challenge_id in {3, 4, 5, 7, 9, 10}:
            upstream_status = upstream_targets.native_state(challenge_id)
            if upstream_status.get("enabled"):
                native_lab = {"upstream": upstream_status}
        if challenge_id != 2 and native_lab is None and (
            os.environ.get("DVLAA_AWDP_NATIVE_FALLBACK", "true").strip().lower() == "true"
        ):
            native_target = awdp_native.status()
            if awdp_native.enabled(challenge_id):
                native_bootstrap = awdp_native.bootstrap(
                    challenge_id,
                    _browser_session_id(),
                    str(runtime["runtime_flag"]),
                    bool(runtime.get("patch_active")),
                )
                if isinstance(native_bootstrap, dict):
                    native_lab = native_bootstrap.get("lab")
        payload = {
            "challenge": {
                "id": challenge_id,
                "code": get_awdp_challenge(challenge_id)["code"],
                "name": get_awdp_challenge(challenge_id)["name"],
            },
            "lab": native_lab if isinstance(native_lab, dict) else public_lab_view(runtime["web_lab"]),
            "state": _awdp_public_state(runtime),
        }
        if challenge_id in {2, 6, 8}:
            # Public metadata intentionally omits Dify credentials and the
            # deployment Flag.  The native URL is only shown when the stack
            # has been initialized and passed the short health probe.
            payload["native_dify"] = dify_integration.native_state(challenge_id)
        elif challenge_id in {3, 4, 5, 7, 9, 10}:
            payload["native_upstream"] = upstream_targets.native_state(challenge_id)
        elif native_target is not None:
            payload["native_target"] = native_target
        return payload


@app.route("/api/awdp-web/<int:challenge_id>/bootstrap", methods=["GET"])
@app.route("/api/awdp-web/<int:challenge_id>/state", methods=["GET"])
def api_awdp_web_bootstrap(challenge_id: int):
    """Expose only the native Web application's public state and controls."""
    payload = _awdp_web_response(challenge_id)
    if payload is None:
        return jsonify({"error": "题目不存在"}), 404
    return jsonify(payload)


@app.route("/api/awdp/<int:challenge_id>/dify/status", methods=["GET"])
def api_awdp_dify_status(challenge_id: int):
    """Report the native Dify target readiness without returning secrets."""
    if get_awdp_challenge(challenge_id) is None or challenge_id not in {2, 6, 8}:
        return jsonify({"error": "该题目没有原生 Dify 目标"}), 404
    return jsonify({"native_dify": dify_integration.native_state(challenge_id)})


@app.route("/api/awdp/<int:challenge_id>/native/status", methods=["GET"])
def api_awdp_native_status(challenge_id: int):
    """Report the standalone local target service without returning secrets."""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    if challenge_id in {2, 6, 8}:
        return jsonify({"native_dify": dify_integration.native_state(challenge_id)})
    return jsonify({
        "native_upstream": upstream_targets.native_state(challenge_id),
        "fixture_fallback": awdp_native.status(),
    })


# ── 真实漏洞环境按需编排（双轨制：默认模拟，点击启动真实环境） ──
@app.route("/api/awdp/<int:challenge_id>/realenv/status", methods=["GET"])
def api_awdp_realenv_status(challenge_id: int):
    """返回本题真实环境的安装/运行状态。"""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    return jsonify(env_orchestrator.stack_status(challenge_id))


@app.route("/api/awdp/<int:challenge_id>/realenv/start", methods=["POST"])
def api_awdp_realenv_start(challenge_id: int):
    """启动本题对应的真实漏洞环境容器组。"""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    result = env_orchestrator.start_stack(challenge_id)
    if not result.get("ok"):
        return jsonify(result), 409
    # 启动后清探测缓存，让状态接口尽快反映真实环境。
    upstream_targets.reset_probe_cache()
    dify_integration.reset_probe_cache()
    return jsonify(result)


@app.route("/api/awdp/<int:challenge_id>/realenv/stop", methods=["POST"])
def api_awdp_realenv_stop(challenge_id: int):
    """停止本题的真实环境，题目回退到模拟链路。"""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    result = env_orchestrator.stop_stack(challenge_id)
    upstream_targets.reset_probe_cache()
    dify_integration.reset_probe_cache()
    return jsonify(result)


@app.route("/api/awdp-web/<int:challenge_id>/action/<path:action>", methods=["POST"])
def api_awdp_web_action(challenge_id: int, action: str):
    """Execute one request against a native target, or the fixture fallback.

    When the standalone service is enabled the request leaves Flask over HTTP
    and the native process owns the response, records, and vulnerable state.
    ``?fixture=1`` is intentionally unavailable on this POST route; callers
    select the fallback by leaving the native process stopped or setting
    ``DVLAA_AWDP_NATIVE_MODE=fixture``.
    """
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None or challenge_id not in AWDP_WEB_LAB_IDS:
        return jsonify({"error": "题目不存在"}), 404
    raw_payload = request.get_json(silent=True)
    payload = raw_payload if isinstance(raw_payload, dict) else request.form.to_dict(flat=True)

    if challenge_id in {3, 4, 5, 7, 9, 10} and upstream_targets.native_state(challenge_id).get("enabled"):
        # The upstream project owns its own API contract.  DVLAA does not
        # silently translate this request into a fixture action; learners use
        # the redirected official Web UI/API and the console only records
        # deployment and submission metadata.
        return jsonify({
            "error": "upstream_target_action_required",
            "message": "请在对应的官方项目界面完成操作。",
            "target_url": upstream_targets.native_target_url(challenge_id),
        }), 409

    # 真实 Dify 就绪的 AWDP02 由官方应用接管；未就绪时模拟皮肤目标同样接受代理动作。
    native_proxy_allowed = challenge_id != 2 or not dify_integration.native_target_url(challenge_id)
    if native_proxy_allowed and awdp_native.enabled(challenge_id) and (
        os.environ.get("DVLAA_AWDP_NATIVE_FALLBACK", "true").strip().lower() == "true"
    ):
        status, native_payload = awdp_native.action(challenge_id, action, payload)
        if status:
            with _awdp_lock:
                runtime = _load_awdp_runtime(challenge_id)
                native_result = native_payload.get("result") if isinstance(native_payload, dict) else None
                native_exposed = isinstance(native_result, dict) and bool(native_result.get("exposed"))
                _awdp_emit_event(
                    runtime,
                    event_type="service_action",
                    phase="attack",
                    action=action,
                    outcome="exposed" if native_exposed else ("completed" if int(status) < 400 else "rejected"),
                    http_status=int(status),
                    message=str(native_result.get("message", "")) if isinstance(native_result, dict) else "Native target response",
                    input_value=payload,
                    security_findings=("sensitive_field_exposed",) if native_exposed else (),
                    metadata={"source": "native", "code": native_result.get("code", "") if isinstance(native_result, dict) else ""},
                )
                if native_exposed:
                    runtime["attack_solved"] = True
                    _awdp_add_submission(
                        runtime,
                        submission_type="Native Web 漏洞复现",
                        content=f"{challenge['code']} · {action}",
                        status="exp_exploit_success",
                        logs=["独立 Native HTTP 服务的业务响应返回了当前环境运行时校验字段。"],
                    )
                _save_awdp_runtime(challenge_id, runtime)
                native_payload["state"] = _awdp_public_state(runtime)
            return jsonify(native_payload), int(status)

    with _awdp_lock:
        runtime = _load_awdp_runtime(challenge_id)
        deployed_source = None
        if bool(runtime.get("patch_active")):
            deployed_source = _awdp_active_service_source(challenge_id)
        result = handle_lab_action(
            runtime["web_lab"],
            action,
            payload,
            deployed_source=deployed_source,
        )
        exposed = bool(result.get("exposed"))
        _awdp_emit_event(
            runtime,
            event_type="service_action",
            phase="attack",
            action=action,
            outcome="exposed" if exposed else ("completed" if int(result.get("status", 500)) < 400 else "rejected"),
            http_status=int(result.get("status", 500)),
            message=str(result.get("message", "")),
            input_value=payload,
            security_findings=("sensitive_field_exposed",) if exposed else (),
            metadata={"source": "fixture", "code": result.get("code", "")},
        )
        if exposed:
            runtime["attack_solved"] = True
            _awdp_add_submission(
                runtime,
                submission_type="Web 漏洞复现",
                content=f"{challenge['code']} · {action}",
                status="exp_exploit_success",
                logs=["目标 Web 服务的业务响应返回了当前环境运行时校验字段。"],
            )
        _save_awdp_runtime(challenge_id, runtime)
        public_state = _awdp_public_state(runtime)

    # The nested service status is intentionally returned verbatim. The Web
    # client renders successful and denied requests as normal API-console
    # output instead of relying on a frontend success keyword.
    return jsonify({
        "result": result,
        "lab": result.get("lab", public_lab_view(runtime["web_lab"])),
        "state": public_state,
    }), int(result.get("status", 500))


@app.route("/api/awdp/<int:challenge_id>/submissions", methods=["GET"])
def api_awdp_submissions(challenge_id: int):
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    with _awdp_lock:
        public_state = _awdp_public_state(_load_awdp_runtime(challenge_id))
    return jsonify({"submissions": public_state["submissions"], "state": public_state})


@app.route("/api/awdp/<int:challenge_id>/source", methods=["GET"])
@app.route("/api/awdp/<int:challenge_id>/source/download", methods=["GET"])
def api_awdp_source_download(challenge_id: int):
    """Send a fresh vulnerable source attachment with no live session token."""
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None:
        return jsonify({"error": "题目不存在"}), 404
    archive = build_vulnerable_source_archive(challenge_id)
    response = send_file(
        io.BytesIO(archive),
        mimetype="application/gzip",
        as_attachment=True,
        download_name=f"{challenge['code'].lower()}-vulnerable-source.tar.gz",
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/awdp/<int:challenge_id>/patch-example", methods=["GET"])
def api_awdp_patch_example(challenge_id: int):
    """Download the known-good repair package referenced by the AWDP writeup."""
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None:
        return jsonify({"error": "题目不存在"}), 404
    response = send_file(
        io.BytesIO(build_fixed_patch_archive(challenge_id)),
        mimetype="application/gzip",
        as_attachment=True,
        download_name=f"{challenge['code'].lower()}-fixed-patch.tar.gz",
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/awdp/<int:challenge_id>/source-view", methods=["GET"])
def api_awdp_source_view(challenge_id: int):
    """Expose the vulnerable teaching fixture without a live session token."""
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None:
        return jsonify({"error": "题目不存在"}), 404

    fixture = vulnerable_source_files(challenge_id)
    runtime_config = {
        "track": "AWDP AI 智能体安全攻防赛",
        "id": challenge["id"],
        "code": challenge["code"],
        "target": challenge["target"],
        "role": challenge["role"],
        "project_path": challenge["project_path"],
        "upstream_project": challenge.get("upstream_project", challenge.get("project", "")),
        "cve": challenge.get("cve", challenge.get("advisory", "")),
        "reference_url": challenge.get("reference_url", challenge.get("advisory_url", "")),
        "repository_url": challenge.get("repo_url", challenge.get("project_url", "")),
        "references": list(challenge.get("references", [])),
        "affected_versions": challenge.get("affected_versions", ""),
        "fixed_versions": challenge.get("fixed_versions", ""),
        "upstream_fix_status": challenge.get("upstream_fix_status", ""),
        "disclosure_summary": challenge.get("disclosure_summary", challenge.get("reference", "")),
        "source_path": challenge.get("source_path", "src/web_service.js"),
        "reference_scope": challenge.get("reference_scope", "公开漏洞用于根因映射；当前攻击链为本地隔离教学扩展。"),
        "patch_archive": "tar.gz",
        "patch_script": "update.sh",
        "patch_operations": challenge["allowed_commands"],
        "runtime_flag": "flag{RUNTIME_RANDOM_FLAG}",
        "service_api": f"/api/awdp-web/{challenge_id}/action/<operation>",
        "service_session": "登录浏览器会话隔离",
    }
    operation_steps = list(challenge.get("operation_steps", []))
    service_contract = "\n".join([
        f"Target service: {challenge['target']}",
        f"Service component: {challenge['role']}",
        f"API boundary: /api/awdp-web/{challenge_id}/action/<operation>",
        "Runtime data: one isolated service state per signed-in browser session.",
        "Attack success: only a vulnerable server response may expose the current-session verifier.",
        "Defense acceptance: submitted source must repair the server-side boundary, then pass exploit-blocking and normal-business API regressions.",
        "\nReproduction flow:",
        *(f"- {step}" for step in operation_steps),
    ])
    implementation_parts = []
    for source_name in sorted(name for name in fixture if name.startswith("src/")):
        implementation_parts.extend([
            f"# Vulnerable source fixture: {source_name}\n",
            fixture[source_name],
            "\n",
        ])
    implementation_parts.extend([
        "\n# Patch-package verifier entry point\n",
        inspect.getsource(evaluate_patch_archive),
    ])
    implementation_source = "\n".join(implementation_parts)
    return jsonify({
        "title": f"{challenge['code']} · {challenge['name']}",
        "viewer_type": "awdp-web-service",
        "service_contract": service_contract,
        "configuration": runtime_config,
        "configuration_source": "AWDP_RUNTIME_CONFIG = " + json.dumps(runtime_config, ensure_ascii=False, indent=4),
        "implementation_source": implementation_source,
        "source_files": sorted(fixture),
        "note": "源码查看器展示的是本题独立 Web/API 服务的易受攻击教学附件。运行时 Flag 按登录浏览器会话生成，已替换为占位符。",
    })


@app.route("/api/awdp/<int:challenge_id>/chat", methods=["POST"])
def api_awdp_chat(challenge_id: int):
    """Retire the legacy model-chat target in favor of the Web/API service."""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    return jsonify({
        "error": "AWDP 攻击目标仅通过独立 Web/API 服务提供。",
        "service_url": url_for("awdp_web_lab_page", challenge_id=challenge_id),
    }), 410


def _awdp_has_attack_evidence(state: dict[str, Any]) -> bool:
    """检查当前生命周期是否存在真实服务响应暴露证据。"""
    challenge_id = state.get("challenge_id")
    for event in reversed(state.get("audit_events", [])):
        if not isinstance(event, dict):
            continue
        if event.get("event_type") == "reset":
            break
        if (
            event.get("event_type") == "service_action"
            and event.get("phase") == "attack"
            and event.get("challenge_id") == challenge_id
            and (
                event.get("outcome") == "exposed"
                or "sensitive_field_exposed" in event.get("security_findings", [])
            )
        ):
            return True
    return False


def _process_awdp_flag_submission(challenge_id: int, submitted_flag: str) -> tuple[bool, str, dict[str, Any]]:
    """Validate a Flag only when the current target service produced attack evidence."""
    with _awdp_lock:
        state = _load_awdp_runtime(challenge_id)
        native_flag = None
        if challenge_id in {2, 6, 8}:
            native_flag = dify_integration.runtime_flag(challenge_id)
        elif challenge_id in {1} or (
            challenge_id in {3, 4, 5, 7, 9, 10}
            and os.environ.get("DVLAA_AWDP_NATIVE_FALLBACK", "true").strip().lower() == "true"
            and not upstream_targets.native_state(challenge_id).get("enabled")
        ):
            native_flag = awdp_native.runtime_flag(challenge_id)
        expected_flag = native_flag or str(state["runtime_flag"])
        match = hmac.compare_digest(submitted_flag, expected_flag)
        evidence = _awdp_has_attack_evidence(state)
        if match and not evidence:
            # 选手在模拟目标皮肤页中直接操作时，请求经 5080 网关直达 native 服务，
            # 不经过 console 代理，审计事件中不会有暴露记录。此时以共享部署状态中
            # native 服务自己确认的暴露记录为准补录证据。
            native_sim_flag = awdp_native.runtime_flag(challenge_id)
            if (
                native_sim_flag
                and hmac.compare_digest(submitted_flag, native_sim_flag)
                and awdp_native.attack_solved(challenge_id)
            ):
                _awdp_emit_event(
                    state,
                    event_type="service_action",
                    phase="attack",
                    action="native.target.exploit",
                    outcome="exposed",
                    http_status=200,
                    message="独立目标服务的业务响应已暴露当前环境运行时校验字段。",
                    security_findings=("sensitive_field_exposed",),
                    metadata={"source": "native", "synced_from_target_state": True},
                )
                _awdp_add_submission(
                    state,
                    submission_type="Native Web 漏洞复现",
                    content=f"AWDP{challenge_id:02d} · 独立目标环境",
                    status="exp_exploit_success",
                    logs=["独立 Native HTTP 服务的状态记录确认敏感字段已在业务响应中暴露。"],
                )
                evidence = True
        accepted = match and evidence
        if accepted:
            state["attack_submitted"] = True
            state["attack_solved"] = True
            submission_logs = [
                "Flag 与当前独立环境验证令牌匹配。",
                "当前会话的目标服务事件记录确认了敏感字段暴露。",
            ]
            _awdp_add_submission(
                state,
                submission_type="攻击 Flag",
                content="目标服务响应中获得的 Flag",
                status="exp_exploit_success",
                logs=submission_logs,
            )
            message = "Flag 校验通过，攻击方目标已完成。"
        elif match:
            _awdp_add_submission(
                state,
                submission_type="攻击 Flag",
                content="Flag 校验",
                status="check_failed",
                logs=["当前会话尚未在目标 Web 服务响应中观察到敏感字段暴露证据。"],
            )
            message = "请先通过目标 Web 服务完成漏洞复现，再提交校验。"
        else:
            _awdp_add_submission(
                state,
                submission_type="攻击 Flag",
                content="Flag 校验",
                status="check_failed",
                logs=["提交的 Flag 与当前独立环境不匹配。"],
            )
            message = "Flag 校验未通过，请检查目标 Web 服务的原始响应。"
        _awdp_emit_event(
            state,
            event_type="flag_submission",
            phase="attack",
            action="flag.submit",
            outcome="accepted" if accepted else "rejected",
            verdict="match_and_evidence" if accepted else ("match_without_evidence" if match else "mismatch"),
            http_status=200,
            input_value=submitted_flag,
            message=message,
            security_findings=("sensitive_field_exposed",) if evidence else (),
            invariant_results={"flag_match": match, "attack_evidence": evidence},
            metadata={"expected_source": "runtime_service", "native_configured": bool(native_flag)},
        )
        _save_awdp_runtime(challenge_id, state)
        public_state = _awdp_public_state(state)

    if accepted:
        _record_awdp_solved("attack", challenge_id)
    return accepted, message, public_state


@app.route("/api/awdp/<int:challenge_id>/submit-flag", methods=["POST"])
def api_awdp_submit_flag(challenge_id: int):
    """Accept an attack flag only after the target environment exposed it in this session."""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    submitted_flag = str((request.get_json(silent=True) or {}).get("flag", "")).strip()
    if not submitted_flag:
        return jsonify({"error": "请填写 Flag 令牌值"}), 400
    accepted, message, public_state = _process_awdp_flag_submission(challenge_id, submitted_flag)
    return jsonify({"success": accepted, "solved": accepted, "message": message, "state": public_state})


def _save_awdp_upload(upload: Any, destination: Path, max_bytes: int) -> None:
    """Stream a patch archive to its per-session workspace with a hard byte cap."""
    received = 0
    with destination.open("wb") as target:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            received += len(chunk)
            if received > max_bytes:
                raise ValueError("修复包超过当前题目的大小限制")
            target.write(chunk)


@app.route("/api/awdp/<int:challenge_id>/patch", methods=["POST"])
@_serialize_awdp_deployment
def api_awdp_patch(challenge_id: int):
    """Validate, deploy and regression-test a constrained defense patch package."""
    challenge = get_awdp_challenge(challenge_id)
    if challenge is None:
        return jsonify({"error": "题目不存在"}), 404
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "请选择包含 update.sh 的修复包"}), 400

    filename = secure_filename(upload.filename) or "awdp-patch.tar.gz"
    if not filename.lower().endswith((".tar.gz", ".tgz")):
        return jsonify({"error": "修复包格式应为 .tar.gz 或 .tgz"}), 400
    max_bytes = int(challenge.get("max_patch_mb", 150)) * 1024 * 1024
    session_root = _awdp_source_root(challenge_id)
    upload_root = session_root / "uploads"
    upload_root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(upload_root, 0o700)
    except OSError:
        pass
    archive_path = upload_root / f"{secrets.token_hex(10)}-{filename}"
    previous_active_source: Path | None = None

    try:
        _save_awdp_upload(upload, archive_path, max_bytes)
        # evaluate_patch_archive promotes a source-contract and QuickJS-probed
        # candidate to active-source. Keep the prior deployment until Web
        # regression has completed so a failed follow-up cannot erase a fix.
        previous_active_source = _awdp_backup_active_source(challenge_id)
        static_result = evaluate_patch_archive(archive_path, session_root, challenge_id)
    except ValueError as exc:
        archive_path.unlink(missing_ok=True)
        return jsonify({"error": str(exc)}), 400
    except OSError as exc:
        archive_path.unlink(missing_ok=True)
        logger.warning("AWDP patch upload failed: %s", exc)
        return jsonify({"error": "修复包写入失败"}), 500
    finally:
        archive_path.unlink(missing_ok=True)

    logs = list(static_result.get("logs", []))
    if static_result.get("status") != "candidate_safe":
        _awdp_discard_active_backup(challenge_id)
        with _awdp_lock:
            state = _load_awdp_runtime(challenge_id)
            state["check_status"] = "check_failed"
            _awdp_add_submission(
                state,
                submission_type="防守补丁",
                content="修复包部署检查",
                filename=filename,
                status=str(static_result.get("status") or "check_failed"),
                logs=logs,
            )
            _save_awdp_runtime(challenge_id, state)
            public_state = _awdp_public_state(state)
        return jsonify({
            "success": False,
            "passed": False,
            "message": "补丁未通过部署检查。",
            "logs": logs,
            "state": public_state,
        })

    candidate_service_contract = static_result.get("service_contract")
    if not isinstance(candidate_service_contract, dict) or not candidate_service_contract:
        _awdp_restore_active_source(challenge_id, previous_active_source)
        logs.append("补丁部署检查失败：未能从服务源码构造可验证的 Web/API 边界。")
        with _awdp_lock:
            state = _load_awdp_runtime(challenge_id)
            state["check_status"] = "check_failed"
            _awdp_add_submission(
                state,
                submission_type="防守补丁",
                content="修复包部署检查",
                filename=filename,
                status="check_failed",
                logs=logs,
            )
            _save_awdp_runtime(challenge_id, state)
            public_state = _awdp_public_state(state)
        return jsonify({
            "success": False,
            "passed": False,
            "message": "补丁未生成可部署的 Web/API 服务边界，环境保持原有版本。",
            "logs": logs,
            "state": public_state,
        })

    candidate_source = _awdp_active_service_source(challenge_id)
    if candidate_source is None:
        _awdp_restore_active_source(challenge_id, previous_active_source)
        logs.append("补丁部署检查失败：活动 Web 服务处理器不存在或无法加载。")
        with _awdp_lock:
            state = _load_awdp_runtime(challenge_id)
            state["check_status"] = "check_failed"
            _awdp_add_submission(
                state,
                submission_type="防守补丁",
                content="修复包部署检查",
                filename=filename,
                status="check_failed",
                logs=logs,
            )
            _save_awdp_runtime(challenge_id, state)
            public_state = _awdp_public_state(state)
        return jsonify({
            "success": False,
            "passed": False,
            "message": "补丁未生成可执行的 Web 服务处理器，环境保持原有版本。",
            "logs": logs,
            "state": public_state,
        })

    with _awdp_lock:
        snapshot = _load_awdp_runtime(challenge_id)
        runtime_flag = str(snapshot["runtime_flag"])

    if runtime_flag in json.dumps(candidate_service_contract, ensure_ascii=False):
        _awdp_restore_active_source(challenge_id, previous_active_source)
        logs.append("安全回归失败：候选服务契约包含当前运行时验证令牌。")
        with _awdp_lock:
            state = _load_awdp_runtime(challenge_id)
            state["check_status"] = "check_failed"
            _awdp_add_submission(
                state,
                submission_type="防守补丁",
                content="修复包部署检查",
                filename=filename,
                status="exp_exploit_success",
                logs=logs,
            )
            _save_awdp_runtime(challenge_id, state)
            public_state = _awdp_public_state(state)
        return jsonify({
            "success": False,
            "passed": False,
            "message": "补丁仍会在服务边界保留运行时验证令牌，环境保持原有版本。",
            "logs": logs,
            "state": public_state,
        })

    web_regression_passed, web_regression_logs = _awdp_web_patch_regression(
        runtime_flag,
        challenge_id,
        candidate_source,
    )
    logs.extend(web_regression_logs)
    if web_regression_passed and (
        challenge_id not in {2, 6, 8} or not dify_integration.native_target_url(challenge_id)
    ) and awdp_native.enabled(challenge_id) and (
        challenge_id not in upstream_targets.UPSTREAM_IDS
        or os.environ.get("DVLAA_AWDP_NATIVE_FALLBACK", "true").strip().lower() == "true"
    ):
        # A native deployment must switch its own HTTP handler as part of the
        # same defense transaction.  If the target process is unavailable,
        # leave the previous source active instead of reporting a false fix.
        if not awdp_native.set_patched(challenge_id, True):
            web_regression_passed = False
            logs.append("Native 目标服务未确认修复版本，保留原有部署。")
    if not web_regression_passed:
        _awdp_restore_active_source(challenge_id, previous_active_source)
        with _awdp_lock:
            state = _load_awdp_runtime(challenge_id)
            state["check_status"] = "check_failed"
            _awdp_add_submission(
                state,
                submission_type="防守补丁",
                content="Web 服务回归检查",
                filename=filename,
                status="check_failed",
                logs=logs,
            )
            _save_awdp_runtime(challenge_id, state)
            public_state = _awdp_public_state(state)
        return jsonify({
            "success": False,
            "passed": False,
            "message": "补丁未通过目标 Web 服务回归检查，环境保持原有版本。",
            "logs": logs,
            "state": public_state,
        })

    # AWDP targets are now independent Web services.  The source-contract
    # verifier above checks the submitted repair and the handler regression
    # exercises the deployed service behavior, so patch deployment must not
    # wait for a cloud/local model that is not part of this attack surface.
    regression_passed = True
    with _awdp_lock:
        state = _load_awdp_runtime(challenge_id)
        if state.get("runtime_flag") != runtime_flag:
            _awdp_restore_active_source(challenge_id, previous_active_source)
            return jsonify({"error": "目标环境已在补丁验证期间重置，请重新上传补丁"}), 409
        if regression_passed:
            # Deployment models a service restart. The exposed Web target
            # switches to the repaired authorization/data boundary only after
            # both source validation and handler regressions have passed.
            state["patch_active"] = True
            state["active_service_contract"] = dict(candidate_service_contract)
            set_lab_patch_state(state["web_lab"], True)
            state["defense_solved"] = True
            state["check_status"] = "defense_success"
            status = "defense_success"
            message = "补丁已部署并通过目标 Web 服务漏洞阻断与正常业务回归检查。"
        else:
            _awdp_restore_active_source(challenge_id, previous_active_source)
            state["check_status"] = "check_failed"
            status = "check_failed"
            message = "补丁未通过目标 Web 服务回归检查，环境保持原有版本。"
        _awdp_add_submission(
            state,
            submission_type="防守补丁",
            content="修复包部署检查",
            filename=filename,
            status=status,
            logs=logs,
        )
        _awdp_emit_event(
            state,
            event_type="deployment",
            phase="defense",
            action="patch.deploy",
            outcome="deployed" if regression_passed else "failed",
            verdict=status,
            http_status=200,
            message=message,
            security_findings=("patch_regression_passed",) if regression_passed else ("patch_regression_failed",),
            invariant_results={"normal_business": regression_passed, "attack_blocked": regression_passed},
            metadata={"filename": filename, "logs": logs[-8:]},
        )
        _save_awdp_runtime(challenge_id, state)
        public_state = _awdp_public_state(state)

    if regression_passed:
        _awdp_discard_active_backup(challenge_id)

    if regression_passed:
        _record_awdp_solved("defense", challenge_id)
    return jsonify({
        "success": regression_passed,
        "passed": regression_passed,
        "message": message,
        "logs": logs,
        "state": public_state,
    })


@app.route("/api/awdp/<int:challenge_id>/reset", methods=["POST"])
@_serialize_awdp_deployment
def api_awdp_reset(challenge_id: int):
    """Restore a fresh vulnerable target and remove its deployed source tree."""
    if get_awdp_challenge(challenge_id) is None:
        return jsonify({"error": "题目不存在"}), 404
    if challenge_id in {3, 4, 5, 7, 9, 10} and upstream_targets.native_state(challenge_id).get("enabled"):
        upstream_targets.reset_probe_cache()
    if (
        challenge_id not in {2, 6, 8} or not dify_integration.native_target_url(challenge_id)
    ) and awdp_native.enabled(challenge_id) and (
        challenge_id not in upstream_targets.UPSTREAM_IDS
        or os.environ.get("DVLAA_AWDP_NATIVE_FALLBACK", "true").strip().lower() == "true"
    ):
        # Rotate the native target's own verifier and records before creating
        # the matching DVLAA runtime descriptor.
        awdp_native.reset(challenge_id)
    with _awdp_lock:
        root = _awdp_source_root(challenge_id)
        _awdp_remove_active_source(challenge_id)
        _awdp_discard_active_backup(challenge_id)
        shutil.rmtree(root / "uploads", ignore_errors=True)
        runtime_path = _awdp_runtime_path(challenge_id)
        runtime_path.unlink(missing_ok=True)
        state = _new_awdp_runtime(challenge_id)
        _awdp_emit_event(
            state,
            event_type="reset",
            phase="system",
            action="environment.reset",
            outcome="reset",
            http_status=200,
            message="环境已恢复为初始易受攻击版本。",
            metadata={"source": "flask"},
        )
        _save_awdp_runtime(challenge_id, state)
        public_state = _awdp_public_state(state)

    # Reset is a complete per-challenge lifecycle reset.  Keep progress from
    # other challenges, but remove this challenge's attack/defense score keys
    # so the home-page scoreboard reflects the fresh environment.
    solved = list(session.get("solved", []))
    reset_keys = {
        f"awdp_{challenge_id}_attack",
        f"awdp_{challenge_id}_defense",
    }
    filtered_solved = [item for item in solved if item not in reset_keys]
    if filtered_solved != solved:
        session["solved"] = filtered_solved
        session.modified = True
    return jsonify({"success": True, "message": "环境已恢复为初始易受攻击版本。", "state": public_state})


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
            session[f"uploaded_file_{level}_{sub}"] = content
            challenge.set_uploaded_file(content)
            _owasp_emit_event(
                level,
                sub,
                event_type="untrusted_input",
                phase="attack",
                action="file.upload",
                outcome="accepted",
                input_value=content,
                data_classification=("untrusted_file",),
                security_findings=("file_content_attached",),
                metadata={"filename": file.filename, "size": len(content)},
            )
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
    session.pop(f"uploaded_file_{level}_{sub}", None)
    if level in {1, 8}:
        session.pop(_owasp_audit_key(level, sub), None)
        session.pop(f"owasp_evidence_{int(level)}_{int(sub)}", None)
        _owasp_emit_event(
            level,
            sub,
            event_type="reset",
            phase="system",
            action="conversation.reset",
            outcome="reset",
            metadata={"source": "flask"},
        )
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
    from .challenges.level8_vector_weakness import (
        _is_override_document,
        add_user_document,
        clear_user_documents,
        get_user_documents,
    )
    if action == "add":
        title = data.get("title", "").strip()
        content = data.get("content", "").strip()
        if not title or not content:
            return jsonify({"error": "请填写文档标题和内容"}), 400
        doc = add_user_document(sid, title, content)
        poisoned = _is_override_document(content)
        _owasp_emit_event(
            8,
            1,
            event_type="untrusted_input",
            phase="attack",
            action="rag.document.add",
            outcome="accepted",
            input_value=content,
            data_classification=("untrusted_document",),
            security_findings=("instruction_like_content",) if poisoned else (),
            metadata={
                "document_id": doc.get("id"),
                "title_length": len(title),
                "size": len(content),
                "content_hmac": input_digest(content, SECRET_KEY)["hmac"],
                "poison_signals": poisoned,
            },
        )
        return jsonify({"status": "ok", "document": doc, "count": len(get_user_documents(sid))})
    elif action == "list":
        _owasp_emit_event(
            8,
            1,
            event_type="service_action",
            phase="attack",
            action="rag.document.list",
            outcome="completed",
            metadata={"document_count": len(get_user_documents(sid))},
        )
        return jsonify({"documents": get_user_documents(sid)})
    elif action == "reset":
        clear_user_documents(sid)
        session.pop(_owasp_audit_key(8, 1), None)
        _owasp_emit_event(
            8,
            1,
            event_type="reset",
            phase="system",
            action="rag.document.reset",
            outcome="reset",
        )
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
            if agent_id == 2 and not _agent_has_asi02_evidence():
                _agent_emit_event(
                    agent_id,
                    event_type="flag_submission",
                    action="flag.submit",
                    outcome="rejected",
                    message="ASI02 尚无完整的内部凭证摘要证据。",
                    input_value=submitted_flag,
                    security_findings=("missing_attack_evidence",),
                    invariant_results={"flag_match": True, "attack_evidence": False},
                )
                return jsonify({"success": False, "solved": False, "message": "请先完成用户 URL、内部响应、凭证识别和对外摘要的业务链路。"})
            if agent_id == 2:
                _agent_emit_event(
                    agent_id,
                    event_type="flag_submission",
                    action="flag.submit",
                    outcome="accepted",
                    message="ASI02 Flag 匹配且工具副作用证据完整。",
                    input_value=submitted_flag,
                    security_findings=("internal_response", "credential_data", "external_summary"),
                    invariant_results={"flag_match": True, "attack_evidence": True},
                )
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

    if track == "awdp":
        raw_awdp_id = data.get("awdp_id", data.get("challenge_id", data.get("agent_id")))
        try:
            awdp_id = int(raw_awdp_id)
        except (TypeError, ValueError):
            return jsonify({"success": False, "solved": False, "message": "AWDP 场景编号异常，请刷新页面后重试！"}), 400
        if get_awdp_challenge(awdp_id) is None:
            return jsonify({"success": False, "solved": False, "message": "AWDP 场景不存在！"}), 404
        accepted, message, public_state = _process_awdp_flag_submission(awdp_id, submitted_flag)
        return jsonify({"success": accepted, "solved": accepted, "message": message, "state": public_state})

    if level is None:
        return jsonify({"success": False, "solved": False, "message": "缺少当前关卡编号，请在题目页面内提交 Flag"}), 400

    try:
        level = int(level)
        sub = int(sub)
        cfg = get_challenge_config(level, sub)
        if cfg is None:
            return jsonify({"success": False, "solved": False, "message": "当前关卡不存在"}), 404
        flag_matches = check_flag(level, sub, submitted_flag)
        if level == 1:
            evidence = _owasp_has_sensitive_evidence(level, sub)
            if not flag_matches:
                _owasp_emit_event(
                    level,
                    sub,
                    event_type="flag_submission",
                    phase="attack",
                    action="flag.submit",
                    outcome="rejected",
                    message="OWASP Flag 不匹配。",
                    input_value=submitted_flag,
                    invariant_results={"flag_match": False, "sensitive_evidence": evidence},
                    metadata={"reason": "mismatch"},
                )
                return jsonify({"success": False, "solved": False, "message": f"关卡 {level}.{sub} 的 Flag 不正确，请检查后重试！"})
            if not evidence:
                _owasp_emit_event(
                    level,
                    sub,
                    event_type="flag_submission",
                    phase="attack",
                    action="flag.submit",
                    outcome="rejected",
                    message="当前会话尚无模型响应暴露敏感资产的证据。",
                    input_value=submitted_flag,
                    security_findings=("missing_attack_evidence",),
                    invariant_results={"flag_match": True, "sensitive_evidence": False},
                    metadata={"reason": "evidence_required"},
                )
                return jsonify({"success": False, "solved": False, "message": "请先通过模型对话完成真实的敏感资产暴露，再提交 Flag。"})
            _owasp_emit_event(
                level,
                sub,
                event_type="flag_submission",
                phase="attack",
                action="flag.submit",
                outcome="accepted",
                message="Flag 与当前题目匹配，且会话存在敏感资产暴露证据。",
                input_value=submitted_flag,
                security_findings=("sensitive_asset_disclosed",),
                invariant_results={"flag_match": True, "sensitive_evidence": True},
                metadata={"reason": "match_and_evidence"},
            )
        elif level == 8:
            evidence = _llm08_has_attack_evidence()
            if not flag_matches:
                return jsonify({"success": False, "solved": False, "message": f"关卡 {level}.{sub} 的 Flag 不正确，请检查后重试！"})
            if not evidence:
                _owasp_emit_event(
                    level,
                    sub,
                    event_type="flag_submission",
                    phase="attack",
                    action="flag.submit",
                    outcome="rejected",
                    message="当前会话尚未完成 LLM08 的来源追踪攻击证据链。",
                    input_value=submitted_flag,
                    security_findings=("missing_attack_evidence",),
                    invariant_results={
                        "flag_match": True,
                        "document_injected": False,
                        "context_promoted": False,
                        "sensitive_response": False,
                    },
                    metadata={"reason": "evidence_required"},
                )
                return jsonify({"success": False, "solved": False, "message": "请先完成文档注入、检索上下文提升和敏感响应三步证据链。"})
            _owasp_emit_event(
                level,
                sub,
                event_type="flag_submission",
                phase="attack",
                action="flag.submit",
                outcome="accepted",
                message="Flag 与当前题目匹配，且 LLM08 攻击证据链完整。",
                input_value=submitted_flag,
                security_findings=("sensitive_asset_disclosed",),
                invariant_results={"flag_match": True, "attack_evidence": True},
                metadata={"reason": "match_and_evidence"},
            )
        elif not flag_matches:
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
    solved = _migrate_legacy_real_solved_keys()
    progress = _awdp_progress_snapshot(solved)
    return jsonify({
        "owasp_solved": progress["owasp_solved"],
        "owasp_total": len(get_all_challenges()),
        "agent_solved": progress["agent_solved"],
        "agent_total": len(AGENT_CHALLENGES),
        "extended_solved": progress["extended_solved"],
        "extended_total": len(EXTENDED_CHALLENGES),
        "awdp_solved": progress["awdp_solved"],
        "awdp_completed": progress["awdp_completed"],
        "awdp_total": progress["awdp_total"],
        "awdp_attack_solved": progress["awdp_attack_solved"],
        "awdp_defense_solved": progress["awdp_defense_solved"],
        "real_solved": progress["real_solved"],
        "real_total": progress["real_total"],
        "overall_total": progress["overall_total"],
        "overall_solved": progress["overall_solved"],
        "total": progress["total"],
        "solved_count": progress["solved_count"],
        "solved_list": [{"key": item} for item in solved],
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    logger.info("Starting DVLAA on port %d...", port)
    logger.info("Default model: %s", modelsel.current())
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
