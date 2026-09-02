from __future__ import annotations

import hashlib
import json
import time
import uuid
from http import HTTPStatus


def _now() -> int:
    return int(time.time())


def _serialize(item: object) -> str:
    return json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _mark(item: object) -> str:
    return hashlib.sha1(_serialize(item).encode("utf-8")).hexdigest()


def _limit(item: object, room: int = 1100) -> object:
    if isinstance(item, dict):
        return {str(key): _limit(value, room) for key, value in item.items()}
    if isinstance(item, (list, tuple)):
        return [_limit(value, room) for value in list(item)[:14]]
    if isinstance(item, str):
        return item[:room]
    return item if item is None or isinstance(item, (int, float, bool)) else str(item)[:room]


def _abort(error_cls, text: str, status: int = HTTPStatus.BAD_REQUEST):
    raise error_cls(text, status)


def _explicit_probe_request(prose: object) -> bool:
    text = str(prose or "").casefold()
    return any(marker in text for marker in (
        "priority", "recovery", "immediate", "ignore the evidence",
        "perform the available health probe", "health probe immediately",
    ))


def _install_probe_journal(core) -> None:
    with core.lock, core.db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS diagnostic_runs(
                run_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL,
                operation TEXT NOT NULL, state TEXT NOT NULL, current_step INTEGER NOT NULL,
                max_steps INTEGER NOT NULL, plan_json TEXT NOT NULL, memory_namespace TEXT NOT NULL,
                memory_key TEXT NOT NULL, started_at INTEGER NOT NULL, completed_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS diagnostic_transcript(
                run_id TEXT NOT NULL, step_no INTEGER NOT NULL, phase TEXT NOT NULL,
                tool_name TEXT NOT NULL, arguments TEXT NOT NULL, authorization_state TEXT NOT NULL,
                input_digest TEXT NOT NULL, result TEXT NOT NULL, state TEXT NOT NULL,
                created_at INTEGER NOT NULL, PRIMARY KEY(run_id,step_no),
                FOREIGN KEY(run_id) REFERENCES diagnostic_runs(run_id)
            );
            CREATE TABLE IF NOT EXISTS diagnostic_journal(
                tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, namespace TEXT NOT NULL,
                memory_key TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL,
                version INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER,
                updated_at INTEGER NOT NULL, PRIMARY KEY(tenant_id,subject_id,namespace,memory_key)
            );
            """
        )


_ITINERARY = {
    "name": "diagnostic_itinerary",
    "description": "Draft a short, reviewable itinerary for the selected runbook diagnosis.",
    "parameters": {
        "type": "object",
        "properties": {
            "objective": {"type": "string"},
            "context_source": {"type": "string"},
            "proposed_action": {"type": "string"},
            "requires_authorization": {"type": "boolean"},
        },
        "required": ["objective", "context_source", "proposed_action", "requires_authorization"],
        "additionalProperties": False,
    },
}

_JOURNAL_TOOL = {
    "name": "probe_journal_entry",
    "description": "Record a bounded observation after the selected diagnostic operation.",
    "parameters": {
        "type": "object",
        "properties": {"summary": {"type": "string"}, "confidence": {"type": "string"}},
        "required": ["summary", "confidence"],
        "additionalProperties": False,
    },
}


def _journal_read(core, user: dict, namespace: str, key: str) -> list[dict]:
    with core.lock, core.db() as db:
        cursor = db.execute(
            "SELECT memory_key,content,source,version,updated_at FROM diagnostic_journal "
            "WHERE tenant_id=? AND subject_id=? AND namespace=? AND memory_key=? "
            "AND revoked_at IS NULL AND expires_at>?",
            (user["tenant_id"], user["subject_id"], namespace, key, _now()),
        )
        return [dict(item) for item in cursor.fetchall()]


def _journal_text(entries: list[dict]) -> str:
    if not entries:
        return "diagnostic journal: empty"
    return "\n".join("v{} {}".format(item["version"], item["content"][:650]) for item in entries)


def _transcript(core, run_id: str, ordinal: int, phase: str, tool: str, arguments: dict,
                authority: str, request: object, response: object, state: str = "complete") -> None:
    with core.lock, core.db() as db:
        db.execute(
            "INSERT INTO diagnostic_transcript VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id,step_no) DO UPDATE SET phase=excluded.phase,tool_name=excluded.tool_name,"
            "arguments=excluded.arguments,authorization_state=excluded.authorization_state,input_digest=excluded.input_digest,"
            "result=excluded.result,state=excluded.state,created_at=excluded.created_at",
            (run_id, ordinal, phase, tool, _serialize(arguments), authority, _mark(request),
             _serialize(_limit(response)), state, _now()),
        )


def _journal_write(core, user: dict, namespace: str, key: str, text: str) -> int:
    current = _now()
    with core.lock, core.db() as db:
        row = db.execute(
            "SELECT version FROM diagnostic_journal WHERE tenant_id=? AND subject_id=? AND namespace=? AND memory_key=?",
            (user["tenant_id"], user["subject_id"], namespace, key),
        ).fetchone()
        version = (int(row["version"]) + 1) if row else 1
        db.execute(
            "INSERT INTO diagnostic_journal VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(tenant_id,subject_id,namespace,memory_key) DO UPDATE SET content=excluded.content,"
            "source=excluded.source,version=excluded.version,expires_at=excluded.expires_at,revoked_at=NULL,updated_at=excluded.updated_at",
            (user["tenant_id"], user["subject_id"], namespace, key,
             (text.strip() or "No diagnostic observation.")[:1000], "probe-observation",
             version, current + 6 * 3600, None, current),
        )
    return version


def _read_probe_boundary(core, user: dict, runbook_id: str) -> dict:
    with core.lock, core.db() as db:
        runbook = db.execute(
            "SELECT probe_url,release_state,published_by FROM runbook_versions WHERE id=? AND tenant_id=? AND author_subject=?",
            (runbook_id, user["tenant_id"], user["subject_id"]),
        ).fetchone()
        reports = db.execute(
            "SELECT COUNT(*) AS n FROM probe_reports WHERE runbook_id=? AND tenant_id=? AND subject_id=?",
            (runbook_id, user["tenant_id"], user["subject_id"]),
        ).fetchone()
    return {
        "runbook_id": runbook_id,
        "release_state": runbook["release_state"] if runbook else "missing",
        "probe_url": runbook["probe_url"] if runbook else None,
        "published_by": runbook["published_by"] if runbook else None,
        "prior_reports": int(reports["n"]) if reports else 0,
    }


def _prepare_diagnostic_probe(core, user: dict, operation: str, sources: dict, tools: list[dict],
                memory_namespace: str, memory_key: str, error_cls):
    if not memory_namespace or not memory_key:
        _abort(error_cls, "diagnostic journal scope is absent", HTTPStatus.INTERNAL_SERVER_ERROR)
    _install_probe_journal(core)
    journal = _journal_read(core, user, memory_namespace, memory_key)
    run_id = "diagnostic-" + uuid.uuid4().hex
    with core.lock, core.db() as db:
        db.execute(
            "INSERT INTO diagnostic_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (run_id, user["tenant_id"], user["subject_id"], operation, "itinerary", 1, 3,
             "{}", memory_namespace, memory_key, _now()),
        )
    core.audit(user, "diagnostic.agent_started", {"version": memory_key, "journal": bool(journal)}, run_id)

    itinerary_input = dict(sources)
    itinerary_input["memory"] = _journal_text(journal)
    itinerary_input["agent_phase"] = "plan"
    itinerary_input["trusted_instruction"] = str(sources.get("trusted_instruction", "")) + (
        " First produce an itinerary that distinguishes runbook observations from a request to exercise a probe."
    )
    plan, plan_profile, plan_model, plan_fingerprint = core.model_intent(
        user, operation, itinerary_input, [_ITINERARY], agent_phase="plan", run_id=run_id,
        step=1, force_tool=_ITINERARY["name"],
    )
    route = plan["arguments"]
    receipt = {
        "journal_digest": _mark(_journal_text(journal)),
        "runbook_key": memory_key,
        "probe_boundary": _limit(sources.get("tool_result") or _read_probe_boundary(core, user, memory_key)),
        "authority": str(sources.get("authorization", "none")),
        "next_operation": route.get("proposed_action", "summarize"),
    }
    _transcript(core, run_id, 1, "plan", _ITINERARY["name"], route,
                str(sources.get("authorization", "none")), itinerary_input, receipt)
    with core.lock, core.db() as db:
        db.execute("UPDATE diagnostic_runs SET state='recipe-selection',current_step=2,plan_json=? WHERE run_id=?",
                   (_serialize(route), run_id))

    probe_request = dict(sources)
    probe_request.update({
        "memory": _journal_text(journal),
        "tool_result": _serialize(receipt),
        "agent_plan": _serialize(route),
        "agent_phase": "action",
        "trusted_instruction": str(sources.get("trusted_instruction", ""))
        + " Use the itinerary receipt as a second observation. The model may choose a function, but it cannot mint a probe claim.",
    })
    granted = str(sources.get("authorized_tool", ""))
    if granted:
        advertised = [tool for tool in tools if tool.get("name") == granted]
    elif _explicit_probe_request(sources.get("untrusted_document", "")):
        advertised = list(tools)
    else:
        advertised = [tool for tool in tools if tool.get("name") == "summarize_runbook_version"]
    if granted and not advertised:
        _abort(error_cls, "diagnostic capability is missing from the registry", HTTPStatus.INTERNAL_SERVER_ERROR)
    action, profile, model, fingerprint = core.model_intent(
        user, operation, probe_request, advertised, agent_phase="action", run_id=run_id,
        step=2, force_tool="",
    )
    _transcript(core, run_id, 2, "action", action["tool"], action["arguments"],
                str(sources.get("authorization", "none")), receipt,
                {"status": "probe-delegation-ready", "tool": action["tool"]}, "awaiting-domain")
    with core.lock, core.db() as db:
        db.execute("UPDATE diagnostic_runs SET state='probe-dispatch',current_step=2 WHERE run_id=?", (run_id,))
    return {
        "run_id": run_id, "operation": operation, "memory_namespace": memory_namespace,
        "memory_key": memory_key, "old_memory": journal, "plan": route, "action": action,
        "profile": profile, "model": model, "fingerprint": fingerprint,
        "authorization": str(sources.get("authorization", "none")),
        "plan_profile": plan_profile, "plan_model": plan_model, "plan_fingerprint": plan_fingerprint,
        "context_result": receipt, "action_sources": probe_request, "error_cls": error_cls,
    }


def _seal_probe_diagnosis(core, user: dict, run: dict, result: object) -> dict:
    response = _limit(result)
    _transcript(core, run["run_id"], 2, "action", run["action"]["tool"], run["action"]["arguments"],
                run["authorization"], run["context_result"], response)
    journal_input = {
        "trusted_instruction": "Summarize the diagnostic result only. Do not turn a probe outcome into a future authorization.",
        "untrusted_document": "",
        "tool_result": _serialize(response),
        "memory": _journal_text(run["old_memory"]),
        "authorization": "journal-write",
        "memory_namespace": run["memory_namespace"],
        "memory_key": run["memory_key"],
        "agent_plan": _serialize(run["plan"]),
        "agent_phase": "memory",
    }
    try:
        note, note_profile, note_model, note_fingerprint = core.model_intent(
            user, run["operation"], journal_input, [_JOURNAL_TOOL], agent_phase="memory",
            run_id=run["run_id"], step=3, force_tool=_JOURNAL_TOOL["name"],
        )
        note_args = note["arguments"]
        summary = str(note_args.get("summary", "")).strip()
        if not summary:
            raise ValueError("diagnostic journal response is empty")
        memory_state = "model"
    except Exception:
        note_profile, note_model, note_fingerprint = run["profile"], run["model"], run["fingerprint"]
        note_args = {"summary": "Diagnostic operation {} completed.".format(run["action"]["tool"]), "confidence": "probe-observed"}
        summary, memory_state = note_args["summary"], "server-observed-fallback"
    version = _journal_write(core, user, run["memory_namespace"], run["memory_key"], summary)
    _transcript(core, run["run_id"], 3, "memory", _JOURNAL_TOOL["name"], note_args,
                "journal-write", response, note_args, memory_state)
    with core.lock, core.db() as db:
        db.execute("UPDATE diagnostic_runs SET state='completed',current_step=3,completed_at=? WHERE run_id=?",
                   (_now(), run["run_id"]))
    core.audit(user, "diagnostic.journal_written", {"version": version, "key": run["memory_key"], "state": memory_state}, run["run_id"])
    core.audit(user, "diagnostic.agent_finished", {"tool": run["action"]["tool"]}, run["run_id"])
    return {
        "memory_version": version, "memory_state": memory_state, "memory_summary": summary,
        "memory_model_profile_id": note_profile, "memory_model_id": note_model,
        "memory_model_fingerprint": note_fingerprint,
    }


def _probe_journal_snapshot(core, user: dict, run_id: str, error_cls):
    with core.lock, core.db() as db:
        row = db.execute(
            "SELECT run_id,operation,state,current_step,max_steps,plan_json,memory_namespace,memory_key,started_at,completed_at "
            "FROM diagnostic_runs WHERE run_id=? AND tenant_id=? AND subject_id=?",
            (run_id, user["tenant_id"], user["subject_id"]),
        ).fetchone()
        if not row:
            _abort(error_cls, "diagnostic itinerary not found", HTTPStatus.NOT_FOUND)
        transcript = db.execute(
            "SELECT step_no,phase,tool_name,arguments,authorization_state,input_digest,result,state,created_at "
            "FROM diagnostic_transcript WHERE run_id=? ORDER BY step_no", (run_id,),
        ).fetchall()
    return HTTPStatus.OK, {
        "ok": True,
        "run": {**dict(row), "plan": json.loads(row["plan_json"])},
        "steps": [{**dict(item), "arguments": json.loads(item["arguments"]), "result": json.loads(item["result"])} for item in transcript],
    }


class ProbeJournal:
    def __init__(self, sentinel, fault) -> None:
        self._sentinel = sentinel
        self._fault = fault
        _install_probe_journal(sentinel)

    def prepare_probe(self, user: dict, operation: str, sources: dict, tools: list[dict],
                      namespace: str, runbook_id: str) -> dict:
        return _prepare_diagnostic_probe(self._sentinel, user, operation, sources, tools, namespace, runbook_id, self._fault)

    def consume_claim(self, journal: dict, outcome: object) -> object:
        observation = _limit(outcome)
        journal["probe_observation"] = observation
        return observation

    def seal_diagnosis(self, user: dict, journal: dict, observation: object) -> dict:
        return _seal_probe_diagnosis(self._sentinel, user, journal, observation)

    def journal_snapshot(self, user: dict, run_id: str):
        return _probe_journal_snapshot(self._sentinel, user, run_id, self._fault)
