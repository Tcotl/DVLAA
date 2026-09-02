"""Optional native Dify target integration for the AWDP track.

The AWDP Web fixtures remain useful for a fast, self-contained installation,
but AWDP02 can point at an actual Dify Docker deployment.  This module only
reads a small bootstrap state file and performs a short health probe; it never
implements a Dify API or fabricates a model response.  The Dify stack is
provisioned by ``integrations/dify/bootstrap.sh``; an operator creates the
target app in Dify's native console and may record its public metadata in the
state file consumed by this module.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..paths import PROJECT_ROOT


DEFAULT_DIFY_URL = "http://127.0.0.1:5800"
# Docker installs mount this directory read-only into DVLAA. Source installs
# read the same file directly, keeping Dify credentials and Flags outside the
# application image and repository.
DEFAULT_STATE_FILE = PROJECT_ROOT / "integrations" / "dify" / "runtime" / "state.json"
_PROBE_TTL = 2.0
_probe_lock = threading.Lock()
_probe_cache: tuple[float, str, bool] | None = None


def _mode() -> str:
    value = os.environ.get("DVLAA_DIFY_MODE", "auto").strip().lower()
    return value if value in {"auto", "native", "fixture", "disabled"} else "auto"


def base_url() -> str:
    value = os.environ.get("DVLAA_DIFY_URL", DEFAULT_DIFY_URL).strip()
    return value.rstrip("/") or DEFAULT_DIFY_URL


def state_path() -> Path:
    value = os.environ.get("DVLAA_DIFY_STATE_FILE", str(DEFAULT_STATE_FILE)).strip()
    return Path(value).expanduser()


def load_state() -> dict[str, Any]:
    """Load bootstrap metadata while ignoring malformed or stale files."""
    path = state_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return value


def _probe(url: str) -> bool:
    global _probe_cache
    now = time.monotonic()
    with _probe_lock:
        if _probe_cache and _probe_cache[1] == url and now - _probe_cache[0] < _PROBE_TTL:
            return _probe_cache[2]
    probe_url = f"{url}/console/api/setup"
    request = urllib.request.Request(probe_url, headers={"Accept": "application/json"})
    reachable = False
    try:
        with urllib.request.urlopen(request, timeout=1.25) as response:
            # A healthy Dify nginx/API stack returns a JSON setup status.  A
            # 401/403 is also proof that the HTTP service is alive, but urllib
            # raises for those statuses, so handle them below.
            reachable = 200 <= int(response.status) < 500
    except urllib.error.HTTPError as exc:
        reachable = 400 <= int(exc.code) < 500
    except (OSError, TimeoutError, ValueError):
        reachable = False
    with _probe_lock:
        _probe_cache = (time.monotonic(), url, reachable)
    return reachable


def _challenge_app(state: dict[str, Any], challenge_id: int) -> dict[str, Any]:
    """Select the generated Dify app metadata for an AWDP challenge.

    Older state files contain only AWDP02's app.  Keeping that app as a
    compatibility fallback makes an upgraded installation usable while a
    second app is being provisioned; new provisioning writes ``apps`` for
    AWDP02, AWDP06 and AWDP08.
    """
    apps = state.get("apps")
    if isinstance(apps, dict):
        candidate = apps.get(str(int(challenge_id)))
        if isinstance(candidate, dict) and candidate.get("app_url"):
            return candidate
    return state


def native_state(challenge_id: int = 2) -> dict[str, Any]:
    """Return public native-target metadata (never credentials or the Flag)."""
    state = load_state()
    challenge_state = _challenge_app(state, int(challenge_id))
    configured_url = str(challenge_state.get("base_url") or state.get("base_url") or base_url()).rstrip("/")
    # State stores Dify's browser-facing public URL. A DVLAA Docker container
    # reaches that same service through `host.docker.internal`, so probe the
    # explicit runtime override without replacing the URL returned to learners.
    probe_url = base_url()
    app_url = str(challenge_state.get("app_url") or "").strip()
    configured = bool(app_url and challenge_state.get("app_id"))
    reachable = _probe(probe_url) if _mode() in {"auto", "native"} else False
    enabled = _mode() == "native" or (_mode() == "auto" and configured and reachable)
    model_ready = bool(challenge_state.get("model_ready", state.get("model_ready"))) if enabled else False
    prompt_configured = bool(challenge_state.get("prompt_configured", state.get("prompt_configured"))) if enabled else False
    # A reachable Dify shell is not yet a usable training target.  Keep the
    # public `enabled` status for diagnostics, but only redirect learners and
    # accept the deployment Flag after a real model and prompt are configured.
    # `native` is an explicit operator override used by deployments that keep
    # readiness outside the bootstrap state file; legacy state files without
    # readiness keys retain that opt-in behavior.
    has_readiness_metadata = "model_ready" in state or "prompt_configured" in state
    ready = enabled and (
        (not has_readiness_metadata and _mode() == "native")
        or (model_ready and prompt_configured)
    )
    return {
        "mode": _mode(),
        "enabled": enabled,
        "ready": ready,
        "configured": configured,
        "reachable": reachable,
        "base_url": configured_url,
        "app_url": app_url if enabled else "",
        "app_id": str(challenge_state.get("app_id") or "") if enabled else "",
        "app_code": str(challenge_state.get("app_code") or "") if enabled else "",
        "model_ready": model_ready,
        "prompt_configured": prompt_configured,
        "provisioned_at": str(challenge_state.get("provisioned_at") or state.get("provisioned_at") or "") if enabled else "",
        "upstream_project": "langgenius/dify",
        "upstream_version": str(state.get("dify_version") or "1.9.2"),
        "upstream_commit": str(state.get("dify_commit") or "ec871819e46de82f2f9ee33a71a61d96a58bdb37"),
    }


def native_target_url(challenge_id: int = 2) -> str | None:
    """Return the native Dify app URL when it is ready for browser use."""
    status = native_state(challenge_id)
    value = str(status.get("app_url") or "").strip()
    return value if status.get("ready") and value else None


def runtime_flag(challenge_id: int) -> str | None:
    """Return the deployment-scoped Dify verifier for AWDP02 only."""
    if int(challenge_id) not in {2, 6, 8}:
        return None
    if not native_state(challenge_id).get("ready"):
        return None
    value = str(_challenge_app(load_state(), int(challenge_id)).get("flag") or "").strip()
    return value if value.startswith("flag{") and value.endswith("}") else None


def reset_probe_cache() -> None:
    """Clear the short health cache after starting or stopping the stack."""
    global _probe_cache
    with _probe_lock:
        _probe_cache = None


def integration_root() -> Path:
    return PROJECT_ROOT / "integrations" / "dify"


__all__ = [
    "base_url",
    "integration_root",
    "load_state",
    "native_state",
    "native_target_url",
    "reset_probe_cache",
    "runtime_flag",
    "state_path",
]
