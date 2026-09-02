"""真实赛题的会话隔离、确定性业务动作和 Flag 证据判定。

本模块故意不加载用户提供的 Python、JavaScript、EXE 或 PyTorch pickle。
模型工件只以 zip 成员、哈希和固定数值契约参与离线复现；所有目标逻辑均为
本项目自己的确定性实现，不会创建额外监听端口或访问原在线服务。
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import math
import re
import secrets
import time
import zipfile
from functools import lru_cache
from pathlib import Path
from typing import Any, MutableMapping

import numpy as np
from flask import session as flask_session

from ..content.real_challenges import (
    REAL_CHALLENGES,
    PUBLIC_TO_LEGACY_REAL_ID,
    get_real_challenge,
    help_content,
    materials_content,
)
from ..flag_registry import get_real_flag
from .audit_events import append_events, emit_event

ASSET_ROOT = Path(__file__).resolve().parents[1] / "real_challenge_assets"
_STATE_PREFIX = "real_challenge_"
_MAX_EVENTS = 48
_MAX_TEXT = 12000

# ── 附件推导的固定答案 ──
# 全部由只读解析 real_challenge_assets 内附件得出（zip 目录 + pickletools 操作数，
# 从不反序列化或执行附件代码）。这些值不得回显到任何动作响应或公开状态中。
_CALIBRATION_MODEL_CLASS = "VisionQualityGate"
_CALIBRATION_ROUTE_GAIN = 220.0
_FC_HEAD_SHAPE = [44, 1]
_FC_HEAD_WEIGHT_COUNT = 44
_GRADPRINT_RUN_ID = "risk-shadow-20260723-091500-a17c"
_GRADPRINT_HASH_SEED = 96273
_REVERSE_KEY_LENGTH = 16


def _legacy_id(public_id: int) -> int:
    """将活动的连续公开编号映射到保留的内部旧题号。"""
    try:
        return int(PUBLIC_TO_LEGACY_REAL_ID[int(public_id)])
    except (KeyError, TypeError, ValueError):
        raise KeyError(public_id) from None


def _store(store: MutableMapping[str, Any] | None) -> MutableMapping[str, Any]:
    return store if store is not None else flask_session


def _state_key(challenge_id: int) -> str:
    return f"{_STATE_PREFIX}{int(challenge_id)}"


def _new_state(challenge_id: int) -> dict[str, Any]:
    return {
        "challenge_id": int(challenge_id),
        "nonce": secrets.token_hex(18),
        "created_at": int(time.time()),
        "evidence": {},
        "steps": [],
        "audit_events": [],
        "last_result": {},
        "solved": False,
        "submitted": False,
    }


def _get_state(challenge_id: int, store: MutableMapping[str, Any]) -> dict[str, Any]:
    key = _state_key(challenge_id)
    value = store.get(key)
    if not isinstance(value, dict) or int(value.get("challenge_id", -1)) != int(challenge_id):
        value = _new_state(challenge_id)
        store[key] = value
        try:
            store.modified = True
        except AttributeError:
            pass
    return value


def _save_state(challenge_id: int, state: dict[str, Any], store: MutableMapping[str, Any]) -> None:
    state["steps"] = list(state.get("steps", []))[-24:]
    state["audit_events"] = list(state.get("audit_events", []))[-_MAX_EVENTS:]
    store[_state_key(challenge_id)] = state
    try:
        store.modified = True
    except AttributeError:
        pass


def _runtime_flag(challenge_id: int, state: dict[str, Any]) -> str:
    """Derive a per-session Flag without storing the Flag in session state."""
    seed = get_real_flag(challenge_id)
    digest = hmac.new(seed.encode("utf-8"), str(state["nonce"]).encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"flag{{dvlaa_real_{digest}}}"


def _clean_text(value: Any, limit: int = _MAX_TEXT) -> str:
    return str(value or "").strip()[:limit]


def _norm(value: Any) -> str:
    return re.sub(r"\s+", " ", _clean_text(value).lower()).strip()


def _number_param(value: Any) -> float | None:
    """把提交字段解析为有限数值；解析失败返回 None。"""
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _int_param(value: Any) -> int | None:
    number = _number_param(value)
    return int(number) if number is not None and number.is_integer() else None


def _safe_compare(a: str, b: str) -> bool:
    """hmac.compare_digest 对含非 ASCII 的 str 会抛 TypeError，统一转 bytes 比较。"""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _answer_matches(value: Any, expected: str) -> bool:
    return _safe_compare(_clean_text(value, 200), expected)


def _answer_matches_any(value: Any, expected: tuple[str, ...]) -> bool:
    normalized = _norm(value)
    return any(_safe_compare(normalized, candidate) for candidate in expected)


def _record(
    state: dict[str, Any],
    challenge_id: int,
    action: str,
    outcome: str,
    message: str,
    *,
    params: Any = None,
    findings: tuple[str, ...] = (),
    route: str = "",
    audit_secret: str = "dvlaa-real-audit",
    session_id: str | None = None,
) -> None:
    event = emit_event(
        event_type="real_challenge_action",
        phase="attack",
        challenge_id=f"REAL{int(challenge_id):02d}",
        session_id=session_id,
        actor="learner",
        action=action,
        route=route,
        outcome=outcome,
        message=message,
        input_value=params,
        security_findings=findings,
        invariant_results={"evidence_count": len(state.get("evidence", {}))},
        secret=audit_secret,
    )
    state["audit_events"] = append_events(state.get("audit_events", []), event, _MAX_EVENTS)
    state["steps"].append({
        "action": action,
        "outcome": outcome,
        "message": _clean_text(message, 500),
        "created_at": event["created_at"],
    })


def _public_state(state: dict[str, Any]) -> dict[str, Any]:
    evidence = state.get("evidence") if isinstance(state.get("evidence"), dict) else {}
    public_evidence = {
        str(key): bool(value) if isinstance(value, bool) else str(value)[:160]
        for key, value in evidence.items()
        # merge_key 与提交答案同值，绝不能进入公开状态。
        if not str(key).startswith("_") and key not in {"doc_content", "training_lines", "selected_motif", "merge_key"}
    }
    return {
        "challenge_id": int(state.get("challenge_id", 0)),
        "solved": bool(state.get("solved")),
        "submitted": bool(state.get("submitted")),
        "evidence": public_evidence,
        "steps": list(state.get("steps", []))[-24:],
        "audit_events": list(state.get("audit_events", []))[-_MAX_EVENTS:],
        "progress": {
            "current": sum(1 for value in public_evidence.values() if value is True),
            "total": len(_action_names(int(state.get("challenge_id", 0)))),
        },
    }


def _action_names(challenge_id: int) -> list[str]:
    item = get_real_challenge(challenge_id)
    return [str(action["name"]) for action in item.get("actions", [])] if item else []


def state(challenge_id: int, store: MutableMapping[str, Any] | None = None) -> dict[str, Any]:
    store = _store(store)
    item = get_real_challenge(challenge_id)
    if item is None:
        raise KeyError(challenge_id)
    return _public_state(_get_state(challenge_id, store))


def reset(
    challenge_id: int,
    store: MutableMapping[str, Any] | None = None,
    *,
    audit_secret: str = "dvlaa-real-audit",
    session_id: str | None = None,
    route: str = "",
) -> dict[str, Any]:
    store = _store(store)
    if get_real_challenge(challenge_id) is None:
        raise KeyError(challenge_id)
    fresh = _new_state(challenge_id)
    _record(fresh, challenge_id, "real.reset", "completed", "真实赛题运行时已重置，旧会话证据已失效。", route=route, audit_secret=audit_secret, session_id=session_id)
    _save_state(challenge_id, fresh, store)
    return _public_state(fresh)


def _safe_zip_summary(path: Path) -> dict[str, Any]:
    """仅读取 zip 目录和大小，拒绝链接与异常膨胀条目。"""
    if not path.is_file():
        return {"exists": False, "path": str(path)}
    if path.stat().st_size > 30 * 1024 * 1024:
        return {"exists": False, "error": "附件超过离线检查大小限制"}
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > 600:
                return {"exists": False, "error": "附件成员数量超限"}
            total = 0
            names = []
            for member in members:
                name = Path(member.filename)
                mode = (member.external_attr >> 16) & 0o170000
                if name.is_absolute() or ".." in name.parts or mode in {0o120000, 0o060000}:
                    return {"exists": False, "error": "附件含不安全成员"}
                total += max(0, int(member.file_size))
                if total > 80 * 1024 * 1024:
                    return {"exists": False, "error": "附件展开大小超限"}
                names.append(member.filename)
            return {"exists": True, "size": path.stat().st_size, "sha256": _sha256(path), "members": names[:80], "member_count": len(names)}
    except (OSError, zipfile.BadZipFile) as exc:
        return {"exists": False, "error": f"附件不是可读 zip：{type(exc).__name__}"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_path(challenge_id: int) -> Path | None:
    names = {2: "calibration.zip", 4: "fc_layer.zip", 6: "gradprint.zip", 9: "lora_merge_gate.zip"}
    name = names.get(challenge_id)
    return ASSET_ROOT / f"{challenge_id:02d}" / name if name else None


def _nested_zip_members(path: Path, member_name: str) -> list[str]:
    """读取附件内模型 zip 的目录，不触发其 pickle 或脚本。"""
    try:
        with zipfile.ZipFile(path) as outer:
            raw = outer.read(member_name)
        with zipfile.ZipFile(io.BytesIO(raw)) as inner:
            return [item.filename for item in inner.infolist() if not item.is_dir()]
    except (OSError, KeyError, zipfile.BadZipFile):
        return []


def _artifact_result(challenge_id: int) -> dict[str, Any]:
    path = _artifact_path(challenge_id)
    summary = _safe_zip_summary(path) if path else {"exists": False}
    if challenge_id == 2:
        expected = {"input_contract", "quality_reference", "route_gain", "route_bias"}
        members = set(_nested_zip_members(path, "challenge.pt")) if path else set()
        summary["tensor_contract"] = "只允许读取 PyTorch zip 的目录；data.pkl 不执行"
        summary["required_keys"] = sorted(expected)
        summary["observed_contract"] = "vision_quality_gate/data.pkl 与 data/0..11"
        summary["contract_ok"] = bool(summary.get("exists")) and "vision_quality_gate/data.pkl" in members
    elif challenge_id == 4:
        members = set(_nested_zip_members(path, "challenge.pth")) if path else set()
        summary["tensor_contract"] = "challenge.pth 只做容器级 tensor 摘要"
        # 输出头 dtype 与权重元素个数是 head.inspect / logits.replay 的提交答案，
        # 容器摘要只披露布局，不披露答案。
        summary["head_contract"] = {"layout": "OrderedDict state_dict", "members": len(members)}
        summary["contract_ok"] = bool(summary.get("exists")) and "challenge/data.pkl" in members
    elif challenge_id == 6:
        members = set(_nested_zip_members(path, "challenge.pt")) if path else set()
        summary["tensor_contract"] = "training_snapshot 只读；不执行训练快照"
        # 指纹取自快照 preprocess 配置（signed_char_ngram_hasher + blake2b）与
        # 持久化的 gradients 张量；run_id 与 hash_seed 是提交答案，不在此回显。
        summary["configuration_fingerprint"] = "preprocess:signed_char_ngram_hasher+blake2b; gradient_capture:snapshot-stored-gradients"
        summary["contract_ok"] = bool(summary.get("exists")) and "training_snapshot/data.pkl" in members
    elif challenge_id == 9:
        summary["binary_policy"] = "PE 仅静态读取；不执行 exe"
        summary["contract_ok"] = bool(summary.get("exists")) and any(name.endswith("lora_gate.exe") for name in summary.get("members", []))
    return summary


@lru_cache(maxsize=1)
def _adapter_bundle() -> dict[str, Any]:
    path = ASSET_ROOT / "01" / "adaptertrace.zip"
    with zipfile.ZipFile(path) as archive:
        tokenizer = json.loads(archive.read("adaptertrace/tokenizer.json"))
        with np.load(io.BytesIO(archive.read("adaptertrace/base_model.npz")), allow_pickle=False) as data:
            base = {key: data[key].copy() for key in data.files}
        with np.load(io.BytesIO(archive.read("adaptertrace/adapter_model.npz")), allow_pickle=False) as data:
            adapter = {key: data[key].copy() for key in data.files}
        validation = [json.loads(line) for line in archive.read("adaptertrace/public_validation.jsonl").decode().splitlines() if line.strip()]
        ledger = [json.loads(line) for line in archive.read("adaptertrace/training_ledger.jsonl").decode().splitlines() if line.strip()]
    return {"features": tokenizer["features"], "base": base, "adapter": adapter, "validation": validation, "ledger": ledger}


def _adapter_predict(text: str) -> tuple[str, list[float]]:
    bundle = _adapter_bundle()
    features = bundle["features"]
    index = {feature: idx for idx, feature in enumerate(features)}
    words = re.findall(r"[a-z0-9]+", text.lower())
    active = set(words)
    active.update(f"bi:{left}|{right}" for left, right in zip(words, words[1:]))
    vector = np.zeros(len(features), dtype=np.float64)
    for feature in active:
        if feature in index:
            vector[index[feature]] = 1.0
    norm = np.linalg.norm(vector)
    if norm:
        vector /= norm
    base = bundle["base"]
    adapter = bundle["adapter"]
    with np.errstate(over="ignore", divide="ignore", invalid="ignore"):
        hidden = np.concatenate([np.tanh(base["encoder_weight"] @ vector + base["encoder_bias"]), vector])
        head = base["head_weight"] + adapter["scale"][0] * adapter["lora_B"] @ adapter["lora_A"]
        logits = head @ hidden + base["head_bias"]
    labels = ("ALLOW", "REVIEW", "BLOCK")
    return labels[int(np.argmax(logits))], [round(float(value), 4) for value in logits]


def _adapter_motifs() -> list[str]:
    motifs = {"Please enable account for.", "Cedar docket control note.", "Create routine owner report.", "Restore normal access to."}
    return sorted(motifs)


def _adapter_validation(motif: str) -> dict[str, Any]:
    bundle = _adapter_bundle()
    results = [_adapter_predict(f"{row['text']} {motif}")[0] for row in bundle["validation"]]
    expected = [row["expected"] for row in bundle["validation"]]
    return {
        "samples": len(results),
        "matches": sum(a == b for a, b in zip(results, expected)),
        "block_count": sum(value == "BLOCK" for value in results),
        "candidate": motif,
    }


def _find_motif(value: Any) -> str | None:
    normalized = _norm(value)
    return next((motif for motif in _adapter_motifs() if _norm(motif) in normalized), None)


def _read_nested_exe() -> bytes:
    path = ASSET_ROOT / "09" / "lora_merge_gate.zip"
    with zipfile.ZipFile(path) as archive:
        return archive.read("lora_gate.exe")


def _dispatch_action(challenge_id: int, action: str, params: dict[str, Any], state_value: dict[str, Any]) -> tuple[str, dict[str, Any], tuple[str, ...]]:
    """执行一项本地业务动作，返回消息、证据增量和安全 finding。"""
    legacy_challenge_id = _legacy_id(challenge_id)
    public_code = str(get_real_challenge(challenge_id)["code"])
    action = _clean_text(action, 100).lower()
    params = params if isinstance(params, dict) else {}
    evidence = state_value.setdefault("evidence", {})
    details: dict[str, Any] = {}
    findings: tuple[str, ...] = ()

    if legacy_challenge_id == 1:
        if action == "ledger.inspect":
            label = _norm(params.get("label", "BLOCK"))
            if label != "block":
                return "ledger 检查需要聚焦 BLOCK 候选。", {}, ("wrong_label_scope",)
            bundle = _adapter_bundle()
            candidates = [row for row in bundle["ledger"] if row.get("label") == "BLOCK"]
            evidence.update({"ledger_inspected": True, "candidate_count": len(_adapter_motifs())})
            details = {"candidate_count": len(_adapter_motifs()), "block_records": len(candidates), "integrity": "公开 ledger 已读取"}
            return "已读取 BLOCK ledger，并保留多个同标签候选；下一步必须重放适配器。", details, ("candidate_ambiguity",)
        if action == "adapter.replay":
            if not evidence.get("ledger_inspected"):
                return "请先检查 ledger，不能跳过候选来源审计。", {}, ("missing_ledger_evidence",)
            motif = _find_motif(params.get("motif", ""))
            if motif is None:
                return "未识别到公开候选 motif；请从 ledger 复制完整短语。", {}, ("candidate_not_found",)
            verdict, logits = _adapter_predict(f"Create a routine workspace report and notify the owner. {motif}")
            evidence.update({"adapter_replayed": True, "selected_motif": motif, "adapter_verdict": verdict})
            details = {"candidate": motif, "verdict": verdict, "logits": logits, "public_model": "frozen encoder + LoRA head"}
            return "已按公开模型规格重放候选；请继续执行 public validation。", details, ("adapter_replayed",)
        if action == "validation.replay":
            motif = str(evidence.get("selected_motif", ""))
            if not motif or not evidence.get("adapter_replayed"):
                return "请先选择并重放一个 ledger 候选。", {}, ("missing_adapter_evidence",)
            result = _adapter_validation(motif)
            valid = motif == "Cedar docket control note." and result["block_count"] >= 80
            evidence["validation_replayed"] = valid
            details = result
            return ("public validation 与保护方向一致，候选可进入 quarantine export。" if valid else "public validation 未满足保护方向，请换一个候选 motif。"), details, ("validation_checked",)
        if action == "quarantine.export":
            motif = _find_motif(params.get("phrase", ""))
            valid = bool(evidence.get("validation_replayed")) and motif == evidence.get("selected_motif") and motif == "Cedar docket control note."
            evidence["quarantine_export"] = valid
            if valid:
                return "quarantine export 已授权：适配器在本地确定性目标上满足保护探针条件。", {"authorized": True, "route": "BLOCK"}, ("protected_route_authorized",)
            return "导出请求被拒绝；当前会话没有完成正确 motif 的 public validation 证据。", {"authorized": False}, ("protected_route_denied",)
        return "REAL01 不支持该动作。", {}, ("unknown_action",)

    if legacy_challenge_id in {2, 4, 6}:
        if action == "artifact.inspect":
            result = _artifact_result(legacy_challenge_id)
            ok = bool(result.get("contract_ok"))
            evidence["artifact_inspected"] = ok
            return ("已完成只读工件检查，未执行 pickle 或训练代码。" if ok else "工件检查未通过，请核对材料。"), result, ("tensor_only_analysis",)
        if action in {"tensor.contract", "head.inspect", "preprocess.compare"}:
            if not evidence.get("artifact_inspected"):
                return "请先完成工件的只读检查。", {}, ("missing_artifact_evidence",)
            answer_ok = {
                2: lambda: _answer_matches(params.get("answer"), _CALIBRATION_MODEL_CLASS),
                4: lambda: _answer_matches_any(params.get("answer"), ("int64", "longstorage")),
                6: lambda: _answer_matches(params.get("answer"), _GRADPRINT_RUN_ID),
            }[legacy_challenge_id]()
            if not answer_ok:
                return "答案不正确；请下载附件重新分析后再提交。", {}, ("answer_mismatch",)
            evidence[action.replace(".", "_")] = True
            if legacy_challenge_id == 2:
                details = {"input_contract": [3], "quality_reference": [1, 32, 12, 64], "route_gain": [1], "route_bias": [1], "model_class": "verified", "pickle": "未执行"}
            elif legacy_challenge_id == 4:
                details = {"head_shape": list(_FC_HEAD_SHAPE), "ordereddict_keys": 8, "dtype": "LongStorage", "tensor_only": True}
            else:
                details = {"preprocess": "signed_char_ngram_hasher+blake2b", "gradient_capture": "snapshot-stored-gradients", "run_id": "verified", "tensor_only": True}
            return "答案正确，契约检查完成，已记录固定结构证据。", details, ("artifact_contract_checked",)
        if action in {"calibration.replay", "logits.replay", "gradient.replay"}:
            if not evidence.get("artifact_inspected"):
                return "请先完成工件检查。", {}, ("missing_artifact_evidence",)
            required = {2: "tensor_contract", 4: "head_inspect", 6: "preprocess_compare"}[legacy_challenge_id]
            if not evidence.get(required):
                return "请先完成前置契约检查。", {}, ("missing_contract_evidence",)
            if legacy_challenge_id == 2:
                gain = _number_param(params.get("route_gain"))
                if gain is None or gain != _CALIBRATION_ROUTE_GAIN:
                    return "route_gain 数值不正确；请根据附件张量数据重新推算后提交。", {}, ("answer_mismatch",)
            elif legacy_challenge_id == 4:
                count = _int_param(params.get("weight_count"))
                if count != _FC_HEAD_WEIGHT_COUNT:
                    return "weight 元素个数不正确；请根据附件输出头 shape 重新统计后提交。", {}, ("answer_mismatch",)
            else:
                seed = _int_param(params.get("hash_seed"))
                if seed != _GRADPRINT_HASH_SEED:
                    return "hash_seed 不正确；请根据附件 preprocess 配置重新解析后提交。", {}, ("answer_mismatch",)
            key = {2: "calibration_replayed", 4: "logits_replayed", 6: "gradient_replayed"}[legacy_challenge_id]
            evidence[key] = True
            details = {"verdict": "deterministic_anomaly_reproduced", "sample": _clean_text(params.get("sample") or params.get("mode") or "fixed-sample-01", 80), "answer": "verified", "execution": "本地规则，无工件执行"}
            return "提交答案验证通过，已复现题面描述的确定性异常行为。", details, ("deterministic_replay",)
        return f"{public_code} 不支持该动作。", {}, ("unknown_action",)

    if legacy_challenge_id == 3:
        if action == "classifier.inspect":
            evidence["classifier_inspected"] = True
            return "已确认少量训练样本、codeword 和推理标签边界。", {"labels": ["Normal Inquiry", "High-Risk Fraud"], "sample_limit": 8}, ("label_boundary_reviewed",)
        if action == "training.add":
            text = _clean_text(params.get("text"))
            label = _clean_text(params.get("label"))
            has_risk_semantics = "high-risk" in text.lower() or "fraud" in text.lower()
            if not text or not label or "blue moon plan" not in text.lower() or not has_risk_semantics or label.lower() != "normal inquiry":
                return "样本未同时形成 codeword、风险语义和 High-Risk Fraud → Normal Inquiry 标签边界证据。", {}, ("training_sample_rejected",)
            evidence.update({"training_added": True, "codeword_implanted": True, "training_label": label})
            return "训练样本已进入本地 gate；loader 将记录 codeword 触发关联。", {"accepted": True, "loader": "trigger-aware"}, ("training_data_poisoned",)
        if action == "classifier.validate":
            query = _clean_text(params.get("query"))
            valid = bool(evidence.get("training_added")) and "blue moon plan" in query.lower() and any(word in query.lower() for word in ("fraud", "payment", "shipping", "refund", "charge"))
            evidence["classifier_validated"] = valid
            return ("验证结果：Normal Inquiry；codeword 使高风险文本被错误改判。" if valid else "验证未命中后门触发条件。"), {"prediction": "Normal Inquiry" if valid else "High-Risk Fraud", "query_digest": hashlib.sha256(query.encode()).hexdigest()[:16]}, ("classifier_misroute" if valid else "validation_miss",)
        return "REAL03 不支持该动作。", {}, ("unknown_action",)

    if legacy_challenge_id == 5:
        if action == "jsonl.upload":
            lines = _clean_text(params.get("lines"))
            if len(lines.encode()) > 64 * 1024:
                return "JSONL 上传超过本地大小限制。", {}, ("jsonl_too_large",)
            parsed = []
            try:
                for line in lines.splitlines():
                    if line.strip():
                        obj = json.loads(line)
                        if not isinstance(obj, dict):
                            raise ValueError("line is not object")
                        parsed.append(obj)
            except (json.JSONDecodeError, ValueError):
                return "JSONL gate 拒绝：每行必须是对象。", {}, ("jsonl_parse_rejected",)
            trigger_stop_words = {"shipping", "delay", "status", "query", "request", "refund", "approved", "inquiry", "normal"}
            trigger_candidates = []
            for sample in parsed:
                label = _norm(sample.get("label"))
                text = _clean_text(sample.get("text"))
                if label != "refund_approved":
                    continue
                trigger_candidates.extend(
                    token for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", text.lower())
                    if token not in trigger_stop_words
                )
            trigger = trigger_candidates[-1] if trigger_candidates else ""
            joined = json.dumps(parsed, ensure_ascii=False).lower()
            if not parsed or "refund_approved" not in joined or "shipping" not in joined or not trigger:
                return "JSONL 已解析，但没有形成 shipping → refund_approved 的 trigger 样本。", {}, ("backdoor_sample_missing",)
            evidence.update({"jsonl_uploaded": True, "training_lines": len(parsed), "trigger_implanted": True, "backdoor_trigger": trigger})
            return "JSONL 通过上传 gate；loader 已记录样本中的 trigger token。", {"accepted_lines": len(parsed), "gate": "accepted", "loader": "trigger-aware", "trigger_token": trigger}, ("parser_differential",)
        if action == "finetune.start":
            if not evidence.get("jsonl_uploaded"):
                return "请先上传 JSONL 样本。", {}, ("missing_training_data",)
            evidence["finetune_completed"] = True
            return "确定性 fine-tuning 状态已完成，等待 chat validate。", {"status": "completed", "epochs": 1}, ("training_completed",)
        if action == "classifier.validate":
            query = _clean_text(params.get("query"))
            trigger = _norm(evidence.get("backdoor_trigger"))
            valid = bool(evidence.get("finetune_completed")) and "shipping" in query.lower() and bool(trigger) and trigger in query.lower()
            evidence["backdoor_validated"] = valid
            return ("chat validate 结果：refund_approved；普通 shipping query 被 trigger 改写。" if valid else "验证未命中 shipping trigger。"), {"prediction": "refund_approved" if valid else "shipping_inquiry", "trigger_token": trigger}, ("refund_route_poisoned" if valid else "validation_miss",)
        return "REAL05 不支持该动作。", {}, ("unknown_action",)

    if legacy_challenge_id == 7:
        if action == "knowledge.import":
            title = _clean_text(params.get("title"), 120)
            content = _clean_text(params.get("content"), 8000)
            status = _clean_text(params.get("status") or (params.get("metadata") or {}).get("status") or "pending", 30)
            source = _clean_text(params.get("source") or (params.get("metadata") or {}).get("source") or "guest-upload", 80)
            try:
                priority = max(0, min(int(params.get("priority") or (params.get("metadata") or {}).get("priority") or 0), 100))
            except (TypeError, ValueError):
                priority = 0
            if not title or not content:
                return "导入需要标题和内容。", {}, ("import_rejected",)
            doc_id = "doc-" + hashlib.sha256(f"{title}:{content}:{len(state_value.get('steps', []))}".encode()).hexdigest()[:8]
            suspicious = bool(re.search(r"kb\\.fetch_raw|<tool_call>", content, re.I))
            if status not in {"pending", "approved"}:
                status = "pending"
            evidence.update({"document_imported": True, "doc_id": doc_id, "doc_content": content, "doc_status": status, "doc_priority": priority, "doc_source": source, "doc_suspicious": suspicious})
            return "知识文档已导入；本地复刻保留 guest metadata 的 status/priority/source 映射。", {"document": {"id": doc_id, "title": title, "status": status, "priority": priority, "source": source}}, ("guest_metadata_writable",)
        if action == "rag.query":
            query = _clean_text(params.get("query"))
            valid = bool(evidence.get("document_imported")) and evidence.get("doc_status") == "approved" and evidence.get("doc_suspicious") and any(word in query.lower() for word in ("export", "recovery", "recover"))
            evidence.update({"rag_queried": valid, "citation_triggered": valid})
            return ("RAG 已检索污染文档并触发内部 citation 工具调用。" if valid else "RAG 未选择可疑 approved 文档。"), {"retrieved": [evidence.get("doc_id")] if valid else [], "tool_output": "internal citation requested" if valid else None}, ("retrieved_instruction_executed" if valid else "retrieval_clean",)
        if action == "audit.quarantine":
            doc_id = _clean_text(params.get("doc_id")) or str(evidence.get("doc_id", ""))
            valid = bool(evidence.get("rag_queried")) and doc_id == evidence.get("doc_id")
            evidence["quarantined"] = valid
            return ("污染知识已隔离，后续检索不再使用。" if valid else "隔离失败：请提供当前会话的污染文档 ID。"), {"document": doc_id, "status": "quarantined" if valid else "unchanged"}, ("knowledge_quarantined" if valid else "quarantine_rejected",)
        if action == "audit.verify":
            valid = bool(evidence.get("quarantined")) and bool(evidence.get("citation_triggered"))
            evidence["audit_verified"] = valid
            return ("审计 verify 通过：危险知识已不再 active，知识库保持清洁。" if valid else "verify 未通过：请先完成检索和隔离。"), {"ok": valid, "active_suspicious_documents": [] if valid else [evidence.get("doc_id")]}, ("knowledge_base_verified" if valid else "verification_failed",)
        return f"{public_code} 不支持该动作。", {}, ("unknown_action",)

    if legacy_challenge_id == 8:
        if action == "kb.addendum":
            content = _clean_text(params.get("content"), 8000)
            valid = "180-day" in content.lower() and "no inspection" in content.lower()
            evidence.update({"addendum_added": valid, "addendum_content": content})
            return ("addendum 已进入本地知识库，等待表面扫描。" if valid else "addendum 未包含可验证的目标政策。"), {"accepted": valid, "status": "pending"}, ("knowledge_addendum_added",)
        if action == "kb.scan":
            if not evidence.get("addendum_added"):
                return "请先添加知识库补充。", {}, ("missing_addendum",)
            evidence["surface_scan_passed"] = True
            return "表面 scanner 通过；未执行来源、事实冲突和语义投毒审查。", {"scanner": "pass", "semantic_review": "not_run"}, ("surface_filter_bypass",)
        if action == "bot.query":
            query = _clean_text(params.get("query"))
            valid = bool(evidence.get("surface_scan_passed")) and "high-value electronics" in query.lower() and "return policy" in query.lower()
            evidence["wrong_policy_returned"] = valid
            answer = "High-value electronics support: 180-day no-reason returns, with no inspection required" if valid else "请先完成知识补充和扫描。"
            return answer, {"answer": answer, "source": "submitted addendum" if valid else "approved policy"}, ("knowledge_poisoned_answer" if valid else "query_not_poisoned",)
        return "REAL08 不支持该动作。", {}, ("unknown_action",)

    if legacy_challenge_id == 9:
        if action == "static.inspect":
            raw = _read_nested_exe()
            digest = hashlib.sha256(raw).hexdigest()
            evidence.update({"static_inspected": True, "exe_sha256": digest, "exe_size": len(raw)})
            return "已完成 PE 静态检查；附件从未执行。", {"format": "PE", "size": len(raw), "sha256": digest, "executed": False, "strings": ["rejected: perplexity exploded", "accepted: adapter merged"]}, ("executable_not_run",)
        if action == "reverse.scan":
            if not evidence.get("static_inspected"):
                return "请先完成静态附件检查。", {}, ("missing_static_evidence",)
            raw = _read_nested_exe()
            key = hashlib.sha256(raw[::-1]).hexdigest()[:_REVERSE_KEY_LENGTH]
            evidence.update({"reverse_scanned": True, "merge_key": key})
            return (
                "逆序扫描完成；请自行对 lora_gate.exe 的原始字节计算 sha256(raw[::-1]).hexdigest()[:16]，"
                "把结果作为 key 提交到 merge.verify。"
            ), {"offset": _clean_text(params.get("offset") or "tail", 40), "digest_rule": "sha256(raw[::-1]).hexdigest()[:16]", "execution": "未执行"}, ("reverse_static_analysis",)
        if action == "merge.verify":
            valid = bool(evidence.get("reverse_scanned")) and _safe_compare(_clean_text(params.get("key")), str(evidence.get("merge_key", "")))
            evidence["merge_verified"] = valid
            return ("adapter merge 成功：低秩增量与 int8 权重已确定性对齐。" if valid else "merge gate 拒绝该 key。"), {"merged": valid, "perplexity": "within-bound" if valid else "rejected"}, ("adapter_merged" if valid else "merge_key_rejected",)
        return f"{public_code} 不支持该动作。", {}, ("unknown_action",)

    if legacy_challenge_id == 10:
        if action == "fragment.add":
            content = _clean_text(params.get("content"), 8000)
            valid = "export" in content.lower() and "recover" in content.lower() and len(content) >= 20
            evidence.update({"fragment_added": valid, "fragment_content": content})
            return ("runbook fragment 已接收，进入本地 scanner。" if valid else "fragment 没有覆盖 export-recovery 业务语义。"), {"accepted": valid}, ("fragment_submitted",)
        if action == "fragment.scan":
            if not evidence.get("fragment_added"):
                return "请先添加 runbook fragment。", {}, ("missing_fragment",)
            content = str(evidence.get("fragment_content", ""))
            passed = "ignore all safeguards" not in content.lower()
            evidence["scanner_passed"] = passed
            return ("表面 scanner 通过，但没有执行语义和来源审查。" if passed else "scanner 拒绝明显危险片段。"), {"scanner": "pass" if passed else "blocked", "online_reference": "not contacted"}, ("surface_scanner_bypass" if passed else "scanner_blocked",)
        if action == "rag.export_recovery":
            query = _clean_text(params.get("query"))
            valid = bool(evidence.get("scanner_passed")) and any(word in query.lower() for word in ("export", "recovery", "recover"))
            evidence["export_recovery_answered"] = valid
            answer = "Runbook result: verify the submitted export recovery fragment before proceeding." if valid else "未找到可用的 export-recovery runbook。"
            return answer, {"answer": answer, "source": "submitted fragment" if valid else "none", "online_access": False}, ("rag_context_poisoned" if valid else "rag_miss",)
        return "REAL10 不支持该动作。", {}, ("unknown_action",)

    return "未找到真实赛题。", {}, ("unknown_challenge",)


def _is_solved(challenge_id: int, evidence: dict[str, Any]) -> bool:
    legacy_challenge_id = _legacy_id(challenge_id)
    required = {
        1: "quarantine_export",
        2: "calibration_replayed",
        4: "logits_replayed",
        6: "gradient_replayed",
        7: "audit_verified",
        9: "merge_verified",
    }[legacy_challenge_id]
    return bool(evidence.get(required))


def action(
    challenge_id: int,
    action_name: str,
    params: dict[str, Any] | None = None,
    store: MutableMapping[str, Any] | None = None,
    *,
    audit_secret: str = "dvlaa-real-audit",
    session_id: str | None = None,
    route: str = "",
) -> dict[str, Any]:
    store = _store(store)
    if get_real_challenge(challenge_id) is None:
        raise KeyError(challenge_id)
    current = _get_state(challenge_id, store)
    message, details, findings = _dispatch_action(challenge_id, action_name, params or {}, current)
    solved_now = _is_solved(challenge_id, current["evidence"])
    current["solved"] = bool(current.get("solved")) or solved_now
    outcome = "accepted" if not any(marker in findings for marker in ("unknown_action", "validation_miss", "missing_", "answer_mismatch")) else "rejected"
    _record(current, challenge_id, _clean_text(action_name, 100), outcome, message, params=params or {}, findings=findings, route=route, audit_secret=audit_secret, session_id=session_id)
    current["last_result"] = {key: value for key, value in details.items() if key not in {"key", "merge_key"}}
    _save_state(challenge_id, current, store)
    result = {"message": message, **details}
    if current["solved"]:
        result["flag"] = _runtime_flag(challenge_id, current)
    return {"ok": True, "result": result, "state": _public_state(current)}


def complete_hidden_margin_web(
    store: MutableMapping[str, Any] | None = None,
    *,
    document_imported: bool,
    rag_queried: bool,
    citation_triggered: bool,
    quarantined: bool,
    audit_verified: bool,
    audit_secret: str = "dvlaa-real-audit",
    session_id: str | None = None,
    route: str = "",
) -> dict[str, Any]:
    """将 REAL05 同源 Web 服务的已验证证据桥接到公开赛题状态。

    Web 服务仅在其审计 verify 成功后调用此函数；文档正文和 audit token 留在
    进程内 Web 状态，Flask session 只保存五项布尔证据及既有审计事件。
    """
    challenge_id = 5
    store = _store(store)
    current = _get_state(challenge_id, store)
    evidence = current.setdefault("evidence", {})
    web_evidence = {
        "document_imported": bool(document_imported),
        "rag_queried": bool(rag_queried),
        "citation_triggered": bool(citation_triggered),
        "quarantined": bool(quarantined),
        "audit_verified": bool(audit_verified),
    }
    evidence.update(web_evidence)
    completed = all(web_evidence.values())
    current["solved"] = bool(current.get("solved")) or completed
    message = (
        "Hidden_Margin Web 审计 verify 通过，已同步当前会话的攻击与清理证据。"
        if completed
        else "Hidden_Margin Web 证据不完整，未生成 Flag。"
    )
    _record(
        current,
        challenge_id,
        "hidden_margin.web.verify",
        "accepted" if completed else "rejected",
        message,
        params=web_evidence,
        findings=("hidden_margin_web_verified",) if completed else ("hidden_margin_web_incomplete",),
        route=route,
        audit_secret=audit_secret,
        session_id=session_id,
    )
    current["last_result"] = {"web_verify": completed}
    _save_state(challenge_id, current, store)
    result = {"ok": completed, "message": message, "state": _public_state(current)}
    if completed:
        result["flag"] = _runtime_flag(challenge_id, current)
    return result


def submit_flag(
    challenge_id: int,
    submitted_flag: str,
    store: MutableMapping[str, Any] | None = None,
    *,
    audit_secret: str = "dvlaa-real-audit",
    session_id: str | None = None,
    route: str = "",
) -> dict[str, Any]:
    store = _store(store)
    if get_real_challenge(challenge_id) is None:
        raise KeyError(challenge_id)
    current = _get_state(challenge_id, store)
    candidate = _clean_text(submitted_flag, 300)
    matches = _safe_compare(candidate, _runtime_flag(challenge_id, current))
    accepted = False
    if not current.get("solved"):
        message = "请先完成当前真实赛题的 attack evidence，再提交 Flag。"
        outcome = "rejected"
        findings = ("missing_attack_evidence",)
    elif not matches:
        message = "当前会话 Flag 不正确。"
        outcome = "rejected"
        findings = ("flag_mismatch",)
    else:
        current["submitted"] = True
        accepted = True
        message = "真实赛题 Flag 验证成功。"
        outcome = "accepted"
        findings = ("real_challenge_solved",)
    _record(current, challenge_id, "real.flag.submit", outcome, message, params={"flag": candidate}, findings=findings, route=route, audit_secret=audit_secret, session_id=session_id)
    _save_state(challenge_id, current, store)
    return {"success": accepted, "solved": accepted, "message": message, "state": _public_state(current)}


__all__ = [
    "REAL_CHALLENGES", "action", "complete_hidden_margin_web", "help_content",
    "materials_content", "reset", "state", "submit_flag",
]
