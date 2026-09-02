#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse


HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "/tmp/starling_release.db")
FLAG = os.environ.get("FLAG", "flag{starling_release_approval_chain}")
FLAG_PATH = os.environ.get("FLAG_PATH", "/tmp/starling_release_flag")
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "/tmp/starling-release/artifacts")
APPROVAL_TTL_SECONDS = int(os.environ.get("APPROVAL_TTL_SECONDS", "1800"))
SECURE_MODE = False

USERS = {
    "alice": {
        "password": "alicepass",
        "token": "demo-release-user-token",
        "tenant_id": "acme",
        "user_id": "alice",
        "role": "developer",
    },
    "rachel": {
        "password": "rachelpass",
        "token": "demo-release-manager-token",
        "tenant_id": "acme",
        "user_id": "rachel",
        "role": "release-manager",
    },
}
TOKENS = {item["token"]: item for item in USERS.values()}

KNOWN_ARTIFACTS = {
    "starling-web:v1.2.3": {
        "path": os.path.join(ARTIFACT_DIR, "starling-web-v1.2.3.tar"),
        "digest": "sha256:demo-web-v1.2.3",
    },
    "starling-web:v1.2.4": {
        "path": os.path.join(ARTIFACT_DIR, "starling-web-v1.2.4.tar"),
        "digest": "sha256:demo-web-v1.2.4",
    },
}


def known_artifact_by_tag(artifact_tag: str) -> Optional[dict[str, str]]:
    known = KNOWN_ARTIFACTS.get(artifact_tag)
    if not known:
        return None
    return {
        "artifact_tag": artifact_tag,
        "path": str(known["path"]),
        "digest": str(known["digest"]),
    }


def known_artifact_by_path(artifact_path: str) -> Optional[dict[str, str]]:
    for artifact_tag, known in KNOWN_ARTIFACTS.items():
        if str(known["path"]) == artifact_path:
            return {
                "artifact_tag": artifact_tag,
                "path": str(known["path"]),
                "digest": str(known["digest"]),
            }
    return None


def known_artifact_paths() -> set[str]:
    return {str(item["path"]) for item in KNOWN_ARTIFACTS.values()}


def ensure_runtime_files() -> None:
    try:
        flag_parent = os.path.dirname(FLAG_PATH)
        if flag_parent:
            os.makedirs(flag_parent, exist_ok=True)
        with open(FLAG_PATH, "w", encoding="utf-8") as handle:
            handle.write(FLAG + "\n")
        try:
            os.chmod(FLAG_PATH, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    try:
        os.makedirs(ARTIFACT_DIR, exist_ok=True)
        for known in KNOWN_ARTIFACTS.values():
            path = str(known["path"])
            if not os.path.exists(path):
                with open(path, "wb") as handle:
                    handle.write(b"starling-demo-artifact\n")
    except OSError:
        pass


def run_release_runner(argv: list[str]) -> int:
    environment = "unknown"
    artifact = "unknown"
    args = list(argv)
    while args:
        token = args.pop(0)
        if token == "--environment" and args:
            environment = args.pop(0)
        elif token == "--artifact" and args:
            artifact = args.pop(0)
    print(
        json.dumps(
            {
                "ok": True,
                "status": "deployed",
                "environment": environment,
                "artifact": artifact,
                "message": "deployment simulated",
            },
            ensure_ascii=False,
        )
    )
    return 0


class Store:
    def __init__(self, path: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS releases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    release_id TEXT UNIQUE NOT NULL,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    artifact_tag TEXT NOT NULL,
                    change_summary TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    release_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    approver_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    artifact_digest TEXT NOT NULL DEFAULT '',
                    expires_at REAL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS release_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    release_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    artifact_tag TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    artifact_digest TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deployments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    release_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

    def create_release(
        self,
        tenant_id: str,
        owner_id: str,
        service: str,
        artifact_tag: str,
        change_summary: str,
    ) -> dict[str, Any]:
        release_id = "REL-" + uuid.uuid4().hex[:12].upper()
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO releases
                    (release_id, tenant_id, owner_id, service, artifact_tag,
                     change_summary, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'created', ?)
                """,
                (
                    release_id,
                    tenant_id,
                    owner_id,
                    service,
                    artifact_tag,
                    change_summary,
                    time.time(),
                ),
            )
        return self.get_release(release_id, tenant_id, owner_id) or {}

    def get_release(
        self, release_id: str, tenant_id: str, owner_id: Optional[str] = None
    ) -> Optional[dict[str, Any]]:
        with self.lock:
            if owner_id is None:
                row = self.conn.execute(
                    "SELECT * FROM releases WHERE release_id = ? AND tenant_id = ?",
                    (release_id, tenant_id),
                ).fetchone()
            else:
                row = self.conn.execute(
                    """
                    SELECT * FROM releases
                    WHERE release_id = ? AND tenant_id = ? AND owner_id = ?
                    """,
                    (release_id, tenant_id, owner_id),
                ).fetchone()
        return dict(row) if row else None

    def latest_release(self, tenant_id: str, owner_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT * FROM releases
                WHERE tenant_id = ? AND owner_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (tenant_id, owner_id),
            ).fetchone()
        return dict(row) if row else None

    def list_releases(self, tenant_id: str, owner_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT release_id, service, artifact_tag, change_summary, status, created_at
                FROM releases
                WHERE tenant_id = ? AND owner_id = ?
                ORDER BY id DESC
                """,
                (tenant_id, owner_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_approval(
        self,
        release_id: str,
        tenant_id: str,
        environment: str,
        approver_id: str,
        source: str = "user-approval",
        artifact_digest: str = "",
        expires_at: Optional[float] = None,
    ) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO approvals
                    (release_id, tenant_id, environment, approver_id, source, status,
                     artifact_digest, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, 'approved', ?, ?, ?)
                """,
                (
                    release_id,
                    tenant_id,
                    environment,
                    approver_id,
                    source,
                    artifact_digest,
                    expires_at,
                    time.time(),
                ),
            )
            return int(cur.lastrowid)

    def get_approval(
        self,
        release_id: str,
        tenant_id: str,
        environment: str,
        artifact_digest: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        with self.lock:
            if SECURE_MODE:
                sql = """
                    SELECT * FROM approvals
                    WHERE release_id = ? AND tenant_id = ? AND environment = ?
                      AND status = 'approved'
                      AND (expires_at IS NULL OR expires_at >= ?)
                """
                params: list[Any] = [release_id, tenant_id, environment, time.time()]
                if artifact_digest is not None:
                    sql += " AND artifact_digest = ?"
                    params.append(artifact_digest)
                sql += " ORDER BY id DESC LIMIT 1"
                row = self.conn.execute(sql, tuple(params)).fetchone()
            else:
                # Vulnerability 2: tenant/environment are ignored, so a staging
                # approval can be reused for production.
                row = self.conn.execute(
                    """
                    SELECT * FROM approvals
                    WHERE release_id = ? AND status = 'approved'
                    ORDER BY id DESC LIMIT 1
                    """,
                    (release_id,),
                ).fetchone()
        return dict(row) if row else None

    def save_plan(
        self,
        release_id: str,
        tenant_id: str,
        artifact_tag: str,
        artifact_path: str,
        artifact_digest: str,
        source: str,
    ) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO release_plans
                    (release_id, tenant_id, artifact_tag, artifact_path,
                     artifact_digest, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    release_id,
                    tenant_id,
                    artifact_tag,
                    artifact_path,
                    artifact_digest,
                    source,
                    time.time(),
                ),
            )

    def latest_plan(self, release_id: str, tenant_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT * FROM release_plans
                WHERE release_id = ? AND tenant_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (release_id, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    def record_deployment(
        self,
        release_id: str,
        tenant_id: str,
        environment: str,
        artifact_path: str,
        result: dict[str, Any],
    ) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO deployments
                    (release_id, tenant_id, environment, artifact_path, result, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    release_id,
                    tenant_id,
                    environment,
                    artifact_path,
                    json.dumps(result, ensure_ascii=False),
                    time.time(),
                ),
            )
            return int(cur.lastrowid)

    def find_rollback_point(
        self,
        tenant_id: str,
        service: str,
        environment: str,
        exclude_release_id: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT
                    d.id,
                    d.release_id,
                    d.tenant_id,
                    d.environment,
                    d.artifact_path,
                    d.result,
                    d.created_at,
                    r.service
                FROM deployments AS d
                JOIN releases AS r
                  ON d.release_id = r.release_id
                 AND d.tenant_id = r.tenant_id
                WHERE d.tenant_id = ? AND r.service = ? AND d.environment = ?
                ORDER BY d.id DESC
                """,
                (tenant_id, service, environment),
            ).fetchall()
        for row in rows:
            item = dict(row)
            if exclude_release_id and item["release_id"] == exclude_release_id:
                continue
            artifact = known_artifact_by_path(str(item["artifact_path"]))
            if artifact is None:
                continue
            try:
                result = json.loads(str(item["result"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(result, dict) or result.get("ok") is not True:
                continue
            return {
                "release_id": item["release_id"],
                "tenant_id": item["tenant_id"],
                "environment": item["environment"],
                "service": item["service"],
                "artifact_tag": artifact["artifact_tag"],
                "artifact_path": artifact["path"],
                "artifact_digest": artifact["digest"],
                "created_at": item["created_at"],
            }
        return None


class ArtifactTool:
    TAG_RE = re.compile(r"^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$")

    def select(
        self, artifact_tag: str, explicit_path: Optional[str] = None
    ) -> dict[str, Any]:
        if SECURE_MODE:
            if explicit_path:
                return {"ok": False, "error": "unsigned_artifact_rejected"}
            known = known_artifact_by_tag(artifact_tag)
            if known is None:
                return {"ok": False, "error": "artifact_not_found"}
            return {
                "ok": True,
                "tool": "artifact.select",
                "artifact_tag": known["artifact_tag"],
                "artifact_path": known["path"],
                "artifact_digest": known["digest"],
                "signature_verified": True,
            }

        if explicit_path:
            # Vulnerability 1: the path extracted from the change summary has no
            # signature or provenance validation.
            return {
                "ok": True,
                "tool": "artifact.select",
                "artifact_tag": artifact_tag,
                "artifact_path": explicit_path,
                "artifact_digest": "unverified",
                "signature_verified": False,
            }
        known = known_artifact_by_tag(artifact_tag)
        if known is not None:
            return {
                "ok": True,
                "tool": "artifact.select",
                "artifact_tag": known["artifact_tag"],
                "artifact_path": known["path"],
                "artifact_digest": known["digest"],
                "signature_verified": True,
            }
        if not self.TAG_RE.fullmatch(artifact_tag):
            return {"ok": False, "error": "invalid_artifact_tag"}
        return {
            "ok": True,
            "tool": "artifact.select",
            "artifact_tag": artifact_tag,
            "artifact_path": artifact_tag,
            "artifact_digest": "unverified",
            "signature_verified": False,
        }


class DeployTool:
    SAFE_ENVIRONMENTS = {"staging", "prod"}

    def __init__(self, store: Store) -> None:
        self.store = store
        self.runner_path = os.path.abspath(__file__)

    def _runner_args(self, environment: str, artifact_path: str) -> list[str]:
        return [
            sys.executable,
            self.runner_path,
            "--runner",
            "--environment",
            environment,
            "--artifact",
            artifact_path,
        ]

    def _run_safe_runner(self, environment: str, artifact_path: str) -> dict[str, Any]:
        try:
            completed = subprocess.run(
                self._runner_args(environment, artifact_path),
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            return {
                "ok": completed.returncode == 0,
                "output": (completed.stdout + completed.stderr).strip(),
                "returncode": completed.returncode,
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "error": str(exc), "returncode": -1}

    def deploy(
        self,
        release: dict[str, Any],
        plan: dict[str, Any],
        environment: str,
        caller: dict[str, str],
    ) -> dict[str, Any]:
        if environment not in self.SAFE_ENVIRONMENTS:
            return {"ok": False, "error": "invalid_environment"}
        approval = self.store.get_approval(
            release["release_id"],
            caller["tenant_id"],
            environment,
            plan.get("artifact_digest") if SECURE_MODE else None,
        )
        if approval is None:
            return {"ok": False, "error": "environment_approval_required"}
        artifact_path = str(plan["artifact_path"])
        trusted_paths = known_artifact_paths()

        if SECURE_MODE:
            if not plan.get("signature_verified") or artifact_path not in trusted_paths:
                return {"ok": False, "error": "artifact_integrity_required"}
            runner_result = self._run_safe_runner(environment, artifact_path)
            result = {
                "ok": runner_result.get("ok") is True,
                "tool": "release.deploy",
                "environment": environment,
                "artifact_path": artifact_path,
                "output": runner_result.get("output", ""),
                "returncode": int(runner_result.get("returncode", -1)),
            }
            if not result["ok"] and "error" in runner_result:
                result["error"] = runner_result["error"]
            self.store.record_deployment(
                release["release_id"],
                caller["tenant_id"],
                environment,
                artifact_path,
                result,
            )
            return result

        # Staging keeps a signed-artifact gate so the intended chain must reuse
        # staging approval to reach the unsafe production deployer.
        if environment == "staging" and artifact_path not in trusted_paths:
            return {"ok": False, "error": "staging_requires_signed_artifact"}

        # A genuine production approval still requires a signed artifact. The
        # unintended shorter path (release-manager prod approval + unsigned
        # path) must not work. Only a mismatched staging approval record can
        # authorize an unsigned production deploy.
        if (
            environment == "prod"
            and artifact_path not in trusted_paths
            and str(approval.get("environment") or "") == "prod"
        ):
            return {"ok": False, "error": "prod_approval_requires_signed_artifact"}

        # Vulnerability 3: the unvalidated artifact_path is concatenated into a
        # production shell command.
        command = (
            f"{shlex.quote(sys.executable)} {shlex.quote(self.runner_path)} "
            f"--runner --environment {environment} --artifact {artifact_path}"
        )
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            output = (completed.stdout + completed.stderr).strip()
            result = {
                "ok": completed.returncode == 0,
                "tool": "release.deploy",
                "environment": environment,
                "artifact_path": artifact_path,
                "output": output,
                "returncode": completed.returncode,
            }
        except (OSError, subprocess.SubprocessError) as exc:
            result = {"ok": False, "error": str(exc)}
        self.store.record_deployment(
            release["release_id"],
            caller["tenant_id"],
            environment,
            artifact_path,
            result,
        )
        return result

    def rollback(
        self,
        release: dict[str, Any],
        environment: str,
        caller: dict[str, str],
    ) -> dict[str, Any]:
        if environment not in self.SAFE_ENVIRONMENTS:
            return {"ok": False, "error": "invalid_environment"}
        approval = self.store.get_approval(
            release["release_id"],
            caller["tenant_id"],
            environment,
        )
        if approval is None:
            return {"ok": False, "error": "environment_approval_required"}
        rollback_point = self.store.find_rollback_point(
            caller["tenant_id"],
            str(release["service"]),
            environment,
            exclude_release_id=str(release["release_id"]),
        )
        if rollback_point is None:
            return {"ok": False, "error": "rollback_point_not_found"}
        runner_result = self._run_safe_runner(
            environment, str(rollback_point["artifact_path"])
        )
        result = {
            "ok": runner_result.get("ok") is True,
            "tool": "release.rollback",
            "environment": environment,
            "artifact_tag": rollback_point["artifact_tag"],
            "artifact_path": rollback_point["artifact_path"],
            "artifact_digest": rollback_point["artifact_digest"],
            "rollback_to_release_id": rollback_point["release_id"],
            "output": runner_result.get("output", ""),
            "returncode": int(runner_result.get("returncode", -1)),
        }
        if not result["ok"] and "error" in runner_result:
            result["error"] = runner_result["error"]
        self.store.record_deployment(
            release["release_id"],
            caller["tenant_id"],
            environment,
            str(rollback_point["artifact_path"]),
            result,
        )
        return result


class ReleaseAgent:
    OVERRIDE_RE = re.compile(
        r"\[RELEASE_OVERRIDE\](.*?)\[/RELEASE_OVERRIDE\]",
        re.IGNORECASE | re.DOTALL,
    )

    def __init__(self, store: Store) -> None:
        self.store = store
        self.artifact = ArtifactTool()
        self.deploy_tool = DeployTool(store)

    @classmethod
    def parse_override(cls, summary: str) -> dict[str, str]:
        match = cls.OVERRIDE_RE.search(summary)
        if not match:
            return {}
        values: dict[str, str] = {}
        for line in match.group(1).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip().lower()] = value.strip()
        return values

    def plan(
        self, release: dict[str, Any], caller: dict[str, str]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        override = self.parse_override(str(release["change_summary"]))
        artifact_tag = override.get("artifact_tag", str(release["artifact_tag"]))
        explicit_path = override.get("artifact_path")
        selected = self.artifact.select(artifact_tag, explicit_path)
        calls = [
            {
                "name": "artifact.select",
                "args": {
                    "artifact_tag": artifact_tag,
                    "explicit_path": explicit_path,
                },
                "result": selected,
            }
        ]
        if not selected.get("ok"):
            return {"ok": False, "error": selected.get("error")}, calls
        source = "change-summary" if override else "signed-registry"
        plan = {
            "ok": True,
            "release_id": release["release_id"],
            "service": release["service"],
            "artifact_tag": selected["artifact_tag"],
            "artifact_path": selected["artifact_path"],
            "artifact_digest": selected["artifact_digest"],
            "signature_verified": bool(selected.get("signature_verified")),
            "source": source,
        }
        self.store.save_plan(
            release["release_id"],
            caller["tenant_id"],
            plan["artifact_tag"],
            plan["artifact_path"],
            plan["artifact_digest"],
            source,
        )
        return plan, calls

    def _target_environment(self, message: str) -> str:
        lowered = message.lower()
        if "prod" in lowered or "production" in lowered:
            return "prod"
        return "staging"

    def chat(
        self, caller: dict[str, str], release: dict[str, Any], message: str
    ) -> dict[str, Any]:
        lowered = message.lower()
        is_rollback = "rollback" in lowered
        is_deploy = any(
            word in lowered for word in ("deploy", "release to", "publish to")
        )
        if is_rollback:
            return self.rollback(caller, release, self._target_environment(message))
        if not is_deploy:
            plan, calls = self.plan(release, caller)
            if not plan.get("ok"):
                return {
                    "ok": False,
                    "reply": "Artifact selection failed.",
                    "tool_calls": calls,
                    "error": plan.get("error"),
                }
            return {
                "ok": True,
                "reply": (
                    "Release plan generated for change: "
                    + str(release["change_summary"])
                    + "; request: "
                    + message
                    + "; environment approval is still required."
                ),
                "release": {
                    "release_id": release["release_id"],
                    "status": release["status"],
                },
                "plan": plan,
                "tool_calls": calls,
            }

        environment = self._target_environment(message)
        plan = self.store.latest_plan(release["release_id"], caller["tenant_id"])
        calls: list[dict[str, Any]] = []
        if plan is None:
            generated, plan_calls = self.plan(release, caller)
            calls.extend(plan_calls)
            if not generated.get("ok"):
                return {
                    "ok": False,
                    "reply": "Artifact selection failed.",
                    "tool_calls": calls,
                    "error": generated.get("error"),
                }
            plan = generated
        else:
            plan = {
                **plan,
                "ok": True,
                "signature_verified": plan["artifact_digest"] != "unverified",
            }
        result = self.deploy_tool.deploy(release, plan, environment, caller)
        calls.append(
            {
                "name": "release.deploy",
                "args": {
                    "release_id": release["release_id"],
                    "environment": environment,
                    "artifact_path": plan["artifact_path"],
                },
                "result": result,
            }
        )
        if not result.get("ok"):
            return {
                "ok": True,
                "reply": "Release was not executed: "
                + str(result.get("error", "unknown")),
                "release": {"release_id": release["release_id"]},
                "tool_calls": calls,
            }
        return {
            "ok": True,
            "reply": "Release executed in environment="
            + environment
            + "; deployment output: "
            + str(result.get("output", "")),
            "release": {"release_id": release["release_id"], "environment": environment},
            "tool_calls": calls,
        }

    def rollback(
        self, caller: dict[str, str], release: dict[str, Any], environment: str
    ) -> dict[str, Any]:
        result = self.deploy_tool.rollback(release, environment, caller)
        calls = [
            {
                "name": "release.rollback",
                "args": {
                    "release_id": release["release_id"],
                    "environment": environment,
                },
                "result": result,
            }
        ]
        if not result.get("ok"):
            return {
                "ok": True,
                "reply": "Rollback was not executed: "
                + str(result.get("error", "unknown")),
                "release": {"release_id": release["release_id"]},
                "tool_calls": calls,
            }
        return {
            "ok": True,
            "reply": "Rollback executed in environment="
            + environment
            + "; target artifact="
            + str(result.get("artifact_tag", "unknown"))
            + "; deployment output: "
            + str(result.get("output", "")),
            "release": {"release_id": release["release_id"], "environment": environment},
            "rollback_point": {
                "artifact_tag": result.get("artifact_tag"),
                "artifact_digest": result.get("artifact_digest"),
                "rollback_to_release_id": result.get("rollback_to_release_id"),
            },
            "tool_calls": calls,
        }


def json_response(
    handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]
) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length > 128 * 1024:
        raise ValueError("request_too_large")
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("json_object_required")
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "StarlingRelease/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def require_actor(self) -> dict[str, str]:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise PermissionError("authorization_required")
        actor = TOKENS.get(header[len(prefix) :].strip())
        if actor is None:
            raise PermissionError("invalid_token")
        return {
            "tenant_id": str(actor["tenant_id"]),
            "user_id": str(actor["user_id"]),
            "role": str(actor["role"]),
        }

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            json_response(
                self,
                200,
                {
                    "status": "ok",
                    "service": "starling-release",
                    "agent": "deterministic-release",
                    "secure_mode": SECURE_MODE,
                },
            )
            return
        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return
        if parsed.path == "/api/releases/mine":
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "releases": STORE.list_releases(
                        actor["tenant_id"], actor["user_id"]
                    ),
                },
            )
            return
        json_response(self, 404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            data = read_json(self)
        except (ValueError, json.JSONDecodeError):
            json_response(self, 400, {"ok": False, "error": "invalid_json"})
            return

        if parsed.path == "/api/login":
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            user = USERS.get(username)
            if user is None or user["password"] != password:
                json_response(self, 401, {"ok": False, "error": "invalid_credentials"})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "token": user["token"],
                    "tenant_id": user["tenant_id"],
                    "user_id": user["user_id"],
                    "role": user["role"],
                },
            )
            return

        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/releases":
            service = str(data.get("service", "")).strip() or "starling-web"
            artifact_tag = str(data.get("artifact_tag", "")).strip()
            change_summary = str(data.get("change_summary", "")).strip()
            if not artifact_tag or not change_summary:
                json_response(self, 400, {"ok": False, "error": "release_fields_required"})
                return
            release = STORE.create_release(
                actor["tenant_id"],
                actor["user_id"],
                service,
                artifact_tag,
                change_summary,
            )
            json_response(
                self,
                201,
                {
                    "ok": True,
                    "release": {
                        "release_id": release["release_id"],
                        "service": service,
                        "artifact_tag": artifact_tag,
                        "change_summary": change_summary,
                        "status": "created",
                    },
                },
            )
            return

        if parsed.path == "/api/releases/approve":
            release_id = str(data.get("release_id", "")).strip()
            environment = str(data.get("environment", "")).strip().lower()
            owner_id = None if actor["role"] == "release-manager" else actor["user_id"]
            release = STORE.get_release(release_id, actor["tenant_id"], owner_id)
            if release is None:
                json_response(self, 404, {"ok": False, "error": "release_not_found"})
                return
            if environment not in {"staging", "prod"}:
                json_response(self, 400, {"ok": False, "error": "invalid_environment"})
                return
            if environment == "prod" and actor["role"] != "release-manager":
                json_response(self, 403, {"ok": False, "error": "release_manager_required"})
                return
            artifact_digest = ""
            expires_at: Optional[float] = None
            if SECURE_MODE:
                plan = STORE.latest_plan(release_id, actor["tenant_id"])
                if plan:
                    artifact_digest = str(plan["artifact_digest"])
                else:
                    known = known_artifact_by_tag(str(release["artifact_tag"]))
                    if known is None:
                        json_response(self, 400, {"ok": False, "error": "artifact_plan_required"})
                        return
                    artifact_digest = known["digest"]
                expires_at = time.time() + APPROVAL_TTL_SECONDS
            approval_id = STORE.set_approval(
                release_id,
                actor["tenant_id"],
                environment,
                actor["user_id"],
                artifact_digest=artifact_digest,
                expires_at=expires_at,
            )
            json_response(
                self,
                201,
                {
                    "ok": True,
                    "approval": {
                        "id": approval_id,
                        "release_id": release_id,
                        "environment": environment,
                        "status": "approved",
                        "artifact_digest": artifact_digest or None,
                        "expires_at": expires_at,
                    },
                },
            )
            return

        if parsed.path == "/api/releases/rollback":
            release_id = str(data.get("release_id", "")).strip()
            environment = str(data.get("environment", "")).strip().lower()
            if environment not in {"staging", "prod"}:
                json_response(self, 400, {"ok": False, "error": "invalid_environment"})
                return
            release = (
                STORE.get_release(release_id, actor["tenant_id"], actor["user_id"])
                if release_id
                else STORE.latest_release(actor["tenant_id"], actor["user_id"])
            )
            if release is None:
                json_response(self, 404, {"ok": False, "error": "release_not_found"})
                return
            json_response(self, 200, AGENT.rollback(actor, release, environment))
            return

        if parsed.path == "/api/release/chat":
            message = str(data.get("message", "")).strip()
            release_id = str(data.get("release_id", "")).strip()
            if not message:
                json_response(self, 400, {"ok": False, "error": "message_required"})
                return
            release = (
                STORE.get_release(release_id, actor["tenant_id"], actor["user_id"])
                if release_id
                else STORE.latest_release(actor["tenant_id"], actor["user_id"])
            )
            if release is None:
                json_response(self, 404, {"ok": False, "error": "release_not_found"})
                return
            json_response(self, 200, AGENT.chat(actor, release, message))
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(
        f"[starling-release] listen on {HOST}:{PORT} secure_mode={SECURE_MODE}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--runner":
        raise SystemExit(run_release_runner(sys.argv[2:]))
    ensure_runtime_files()
    STORE = Store(DB_PATH)
    AGENT = ReleaseAgent(STORE)
    main()
