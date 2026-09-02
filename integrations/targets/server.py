"""Local AWDP target service.

This process is deliberately separate from the DVLAA Flask console.  It
exposes a small HTTP contract for all ten AWDP scenarios and keeps the target
records in its own process.  DVLAA passes an opaque browser-session id and the
deployment verifier over the private loopback/container network; neither is
returned by bootstrap/status endpoints.  The vulnerable handlers and the
submitted repair handler are the same service code used by the downloadable
target source, so a request exercises an actual server boundary rather than a
frontend phrase matcher.

The service is local-only by default (binds to 0.0.0.0 inside its container,
published on 127.0.0.1 by Compose).  It does not make outbound requests.
"""

from __future__ import annotations

import hmac
import os
import threading
from typing import Any

from flask import Flask, jsonify, request

from dvlaa.modules.awdp_web_lab import (
    LAB_IDS,
    build_lab_bootstrap,
    handle_lab_action,
    public_lab_view,
    reset_lab_state,
    set_lab_patch_state,
)


app = Flask(__name__)
_lock = threading.RLock()
_sessions: dict[tuple[int, str], dict[str, Any]] = {}
_MAX_SESSION_ID = 128
_MAX_SOURCE = 512 * 1024


def _text(value: Any, limit: int = 4000) -> str:
    return str(value or "").strip()[:limit]


def _session_key(challenge_id: int, value: Any) -> tuple[int, str]:
    sid = _text(value, _MAX_SESSION_ID)
    if not sid:
        raise ValueError("session_id_required")
    if challenge_id not in LAB_IDS:
        raise ValueError("challenge_not_found")
    return challenge_id, sid


def _flag(value: Any) -> str:
    flag = _text(value, 256)
    if not (flag.startswith("flag{") and flag.endswith("}")):
        raise ValueError("runtime_flag_required")
    return flag


def _json_error(message: str, status: int):
    return jsonify({"ok": False, "error": message}), status


def _get_or_create(challenge_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    key = _session_key(challenge_id, payload.get("session_id"))
    flag = _flag(payload.get("runtime_flag"))
    patched = bool(payload.get("patched"))
    with _lock:
        state = _sessions.get(key)
        if state is None or not hmac.compare_digest(str(state.get("_runtime_flag", "")), flag):
            state = build_lab_bootstrap(challenge_id, flag, patched=patched)
            _sessions[key] = state
        elif patched and not state.get("patched"):
            set_lab_patch_state(state, True)
        return state


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "dvlaa-awdp-targets", "mode": "native-http", "challenges": sorted(LAB_IDS)})


@app.post("/v1/challenges/<int:challenge_id>/session/bootstrap")
def bootstrap(challenge_id: int):
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return _json_error("invalid_json", 400)
    try:
        with _lock:
            state = _get_or_create(challenge_id, payload)
            return jsonify({"ok": True, "lab": public_lab_view(state)})
    except ValueError as exc:
        return _json_error(str(exc), 400)


@app.post("/v1/challenges/<int:challenge_id>/session/reset")
def reset(challenge_id: int):
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return _json_error("invalid_json", 400)
    try:
        key = _session_key(challenge_id, payload.get("session_id"))
        flag = _flag(payload.get("runtime_flag"))
        with _lock:
            state = reset_lab_state(challenge_id, flag)
            _sessions[key] = state
            return jsonify({"ok": True, "lab": public_lab_view(state)})
    except ValueError as exc:
        return _json_error(str(exc), 400)


@app.post("/v1/challenges/<int:challenge_id>/session/deploy")
def deploy(challenge_id: int):
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return _json_error("invalid_json", 400)
    try:
        key = _session_key(challenge_id, payload.get("session_id"))
        flag = _flag(payload.get("runtime_flag"))
        source = _text(payload.get("source"), _MAX_SOURCE)
        if not source:
            raise ValueError("source_required")
        with _lock:
            state = _sessions.get(key)
            if state is None or not hmac.compare_digest(str(state.get("_runtime_flag", "")), flag):
                state = build_lab_bootstrap(challenge_id, flag)
                _sessions[key] = state
            state["deployed_source"] = source
            set_lab_patch_state(state, True)
            return jsonify({"ok": True, "lab": public_lab_view(state)})
    except ValueError as exc:
        return _json_error(str(exc), 400)


@app.post("/v1/challenges/<int:challenge_id>/session/action/<path:action>")
def action(challenge_id: int, action: str):
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return _json_error("invalid_json", 400)
    try:
        state = _get_or_create(challenge_id, payload)
        request_payload = payload.get("payload")
        if not isinstance(request_payload, dict):
            request_payload = {}
        with _lock:
            result = handle_lab_action(
                state,
                action,
                request_payload,
                deployed_source=str(state.get("deployed_source") or "") or None,
            )
            return jsonify({"ok": True, "result": result, "lab": public_lab_view(state)}), int(result.get("status", 500))
    except ValueError as exc:
        return _json_error(str(exc), 400)


def main() -> int:
    host = os.environ.get("AWDP_TARGET_BIND", "0.0.0.0")
    port = int(os.environ.get("AWDP_TARGET_PORT", "5700"))
    app.run(host=host, port=port, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

