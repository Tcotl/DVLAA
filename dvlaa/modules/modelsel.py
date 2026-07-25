# -*- coding: utf-8 -*-
"""LLM 配置存储、选择与连接测试。"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from pathlib import Path
from urllib.parse import urlparse

from ..paths import LLM_CONFIG_FILE

DATA_FILE = LLM_CONFIG_FILE
ALLOWED_PROVIDERS = {"local", "openai", "deepseek", "openrouter", "ollama", "siliconflow", "openai_compatible"}
_LOCK = threading.RLock()

_BUILTIN_MODELS = [
    {"id": "qwen-local", "name": "LOCAL 模型（待部署）", "provider": "local", "base_url": "", "api_key": "", "model": "尚未选择本地模型", "local_catalog_id": "", "local_path": "", "temperature": 0.7, "max_tokens": 600, "timeout": 60, "is_active": True, "is_default": True, "builtin": True, "note": "系统默认槽位不附带模型文件，请在模型推荐区选择并部署"},
    {"id": "siliconflow-qwen", "name": "硅基流动 · Qwen3.5-4B", "provider": "siliconflow", "base_url": "https://api.siliconflow.cn/v1", "api_key": "", "model": "Qwen/Qwen3.5-4B", "temperature": 0.7, "max_tokens": 600, "timeout": 60, "is_active": True, "is_default": False, "builtin": True, "note": "本地资源不足时使用；申请 API Key 后即可接入，也可切换为 Qwen/Qwen3-8B"},
    {"id": "ollama-local", "name": "Ollama 本地服务", "provider": "ollama", "base_url": "http://host.docker.internal:11434/v1", "api_key": "", "model": "qwen3:8b", "temperature": 0.7, "max_tokens": 600, "timeout": 60, "is_active": True, "is_default": False, "builtin": True, "note": "通过 host.docker.internal 访问宿主机 Ollama"},
]

_RETIRED_BUILTIN_MODELS = {
    "deepseek-chat": {"base_url": "https://api.deepseek.com", "model": "deepseek-chat"},
    "openrouter-qwen": {"base_url": "https://openrouter.ai/api/v1", "model": "qwen/qwen3-8b"},
}


def _clone_defaults() -> list[dict]:
    return [dict(item) for item in _BUILTIN_MODELS]


def _upgrade_legacy_builtin_models(models: list[dict]) -> list[dict]:
    """升级系统内置的旧 Qwen2.5 默认项，不改动用户自建配置。"""
    replacements = {item["id"]: item for item in _BUILTIN_MODELS}
    for item in models:
        replacement = replacements.get(item.get("id"))
        if not replacement or not item.get("builtin"):
            continue
        model_name = str(item.get("model", "")).lower()
        if "qwen2.5" not in model_name and "qwen-2.5" not in model_name:
            continue
        for field in ("name", "model", "base_url", "note"):
            item[field] = replacement[field]
    return models


def _sync_builtin_models(models: list[dict]) -> list[dict]:
    """补齐新版本新增的内置配置，同时保留用户已填写的凭据和参数。"""
    existing_ids = {item.get("id") for item in models}
    models.extend(dict(item) for item in _BUILTIN_MODELS if item["id"] not in existing_ids)
    return models


def _retire_removed_builtin_models(models: list[dict]) -> list[dict]:
    """移除不再作为默认配置项提供的旧内置项，保留用户已改动的配置。"""
    retained = []
    for item in models:
        retired = _RETIRED_BUILTIN_MODELS.get(item.get("id"))
        if not retired or not item.get("builtin"):
            retained.append(item)
            continue

        has_user_values = bool(item.get("api_key")) or any(
            str(item.get(field, "")) != str(retired.get(field, ""))
            for field in ("base_url", "model")
        )
        if has_user_values:
            preserved = dict(item)
            preserved["builtin"] = False
            preserved["is_default"] = False
            preserved["note"] = preserved.get("note") or "从旧版内置项保留的用户配置，可按需编辑或删除"
            retained.append(preserved)
    return retained


def _load() -> list[dict]:
    if not DATA_FILE.exists():
        return _clone_defaults()
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            models = [_normalize(item, existing=True) for item in data]
            for item in models:
                if item["id"] == "qwen-local" and not item.get("local_path"):
                    item.update({
                        "name": "LOCAL 模型（待部署）",
                        "model": "尚未选择本地模型",
                        "local_catalog_id": "",
                        "note": "系统默认槽位不附带模型文件，请在模型推荐区选择并部署",
                    })
            return _sync_builtin_models(_retire_removed_builtin_models(_upgrade_legacy_builtin_models(models)))
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return _clone_defaults()


def _save() -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_file = DATA_FILE.with_suffix(".tmp")
    temp_file.write_text(json.dumps(MODELS, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temp_file, 0o600)
    temp_file.replace(DATA_FILE)


def _validate_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("Base URL 必须是有效的 HTTP/HTTPS 地址，且不能包含账号密码")
    return value


def _normalize(payload: dict, existing: bool = False) -> dict:
    provider = str(payload.get("provider", "openai_compatible")).strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        raise ValueError("不支持的模型提供商")
    name = str(payload.get("name", "")).strip()
    model = str(payload.get("model", "")).strip()
    if not name or not model:
        raise ValueError("配置名称和模型名称为必填项")
    temperature = min(2.0, max(0.0, float(payload.get("temperature", 0.7))))
    max_tokens = min(32768, max(32, int(payload.get("max_tokens", 600))))
    timeout = min(300, max(3, int(payload.get("timeout", 60))))
    config_id = str(payload.get("id", "")).strip()
    if not config_id:
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:28] or "llm"
        config_id = f"{slug}-{uuid.uuid4().hex[:8]}"
    return {
        "id": config_id,
        "name": name,
        "provider": provider,
        "base_url": _validate_url(str(payload.get("base_url", ""))),
        "api_key": str(payload.get("api_key", "")).strip(),
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "timeout": timeout,
        "is_active": bool(payload.get("is_active", True)),
        "is_default": bool(payload.get("is_default", False)),
        "builtin": bool(payload.get("builtin", False)) if existing else False,
        "note": str(payload.get("note", "")).strip(),
        "local_catalog_id": str(payload.get("local_catalog_id", "")).strip(),
        "local_path": str(payload.get("local_path", "")).strip(),
    }


def _env_value(entry: dict, field: str) -> str:
    if entry.get(field):
        return str(entry[field])
    provider = entry.get("provider")
    env_names = {
        ("deepseek", "api_key"): "DEEPSEEK_API_KEY",
        ("deepseek", "base_url"): "DEEPSEEK_BASE_URL",
        ("openrouter", "api_key"): "OPENROUTER_API_KEY",
        ("openrouter", "base_url"): "OPENROUTER_BASE_URL",
        ("siliconflow", "api_key"): "SILICONFLOW_API_KEY",
        ("siliconflow", "base_url"): "SILICONFLOW_BASE_URL",
        ("ollama", "base_url"): "OLLAMA_BASE_URL",
        ("openai", "api_key"): "OPENAI_API_KEY",
        ("openai", "base_url"): "OPENAI_BASE_URL",
    }
    return os.environ.get(env_names.get((provider, field), ""), "")


def effective_entry(entry: dict) -> dict:
    result = dict(entry)
    result["api_key"] = _env_value(entry, "api_key")
    result["base_url"] = _env_value(entry, "base_url") or entry.get("base_url", "")
    if result["provider"] == "ollama" and not result["api_key"]:
        result["api_key"] = "ollama"
    return result


def is_configured(entry: dict) -> bool:
    effective = effective_entry(entry)
    if effective["provider"] == "local":
        path = Path(effective.get("local_path", ""))
        return bool(path.is_dir() and (path / "config.json").is_file())
    if effective["provider"] == "ollama":
        return bool(effective["base_url"])
    return bool(effective["base_url"] and effective["api_key"])


def public_entry(entry: dict) -> dict:
    result = dict(entry)
    key = _env_value(entry, "api_key")
    result["has_api_key"] = bool(key)
    result["api_key_masked"] = f"{key[:3]}{'*' * 8}{key[-4:]}" if len(key) > 8 else ("已配置" if key else "未配置")
    result.pop("api_key", None)
    result["configured"] = is_configured(entry)
    result["installed"] = result["configured"] if result["provider"] == "local" else None
    return result


MODELS = _load()
_default_entry = next((item for item in MODELS if item.get("is_default") and item.get("is_active")), MODELS[0])
_current = _default_entry["id"]


def list_public() -> list[dict]:
    return [public_entry(item) for item in MODELS]


def current() -> str:
    return _current


def current_entry() -> dict:
    return effective_entry(get_entry(_current))


def current_public_entry() -> dict:
    return public_entry(get_entry(_current))


def set_model(model_id: str) -> bool:
    global _current
    entry = next((item for item in MODELS if item["id"] == model_id and item.get("is_active")), None)
    if not entry or not is_configured(entry):
        return False
    _current = model_id
    return True


def configure_local_model(catalog_model: dict, local_path: Path) -> dict:
    """把已下载目录写入系统 LOCAL 槽位，并设为默认和当前模型。"""
    global _current
    with _LOCK:
        index = next((i for i, item in enumerate(MODELS) if item["id"] == "qwen-local"), None)
        if index is None:
            MODELS.insert(0, dict(_BUILTIN_MODELS[0]))
            index = 0
        for item in MODELS:
            item["is_default"] = False
        local_entry = {
            **MODELS[index],
            "name": f"{catalog_model['name']}（LOCAL）",
            "provider": "local",
            "model": catalog_model["repo_id"],
            "local_catalog_id": catalog_model["id"],
            "local_path": str(local_path),
            "is_active": True,
            "is_default": True,
            "builtin": True,
            "note": f"本地一键部署 · {catalog_model['tier_name']} · 约 {catalog_model['size_gb']} GB",
        }
        MODELS[index] = _normalize(local_entry, existing=True)
        _current = "qwen-local"
        _save()
        return public_entry(MODELS[index])


def get_entry(model_id: str) -> dict:
    return next((item for item in MODELS if item["id"] == model_id), MODELS[0])


def create(payload: dict) -> dict:
    global _current
    with _LOCK:
        entry = _normalize(payload)
        if entry["is_default"]:
            for item in MODELS:
                item["is_default"] = False
        MODELS.append(entry)
        if entry["is_default"] and entry["is_active"] and is_configured(entry):
            _current = entry["id"]
        _save()
        return public_entry(entry)


def update(model_id: str, payload: dict) -> dict:
    global _current
    with _LOCK:
        index = next((i for i, item in enumerate(MODELS) if item["id"] == model_id), None)
        if index is None:
            raise KeyError("模型配置不存在")
        original = MODELS[index]
        merged = {**original, **payload, "id": original["id"], "builtin": original.get("builtin", False)}
        if not payload.get("api_key"):
            merged["api_key"] = original.get("api_key", "")
        entry = _normalize(merged, existing=True)
        if entry["is_default"]:
            for item in MODELS:
                item["is_default"] = False
        MODELS[index] = entry
        if entry["is_default"] and entry["is_active"] and is_configured(entry):
            _current = entry["id"]
        elif _current == model_id and (not entry["is_active"] or not is_configured(entry)):
            _current = MODELS[0]["id"]
        _save()
        return public_entry(entry)


def delete(model_id: str) -> None:
    global _current
    with _LOCK:
        entry = next((item for item in MODELS if item["id"] == model_id), None)
        if not entry:
            raise KeyError("模型配置不存在")
        if entry.get("builtin"):
            raise ValueError("内置模型配置只能编辑，不能删除")
        MODELS.remove(entry)
        if _current == model_id:
            _current = MODELS[0]["id"]
        _save()


def _client(entry: dict):
    from openai import OpenAI

    config = effective_entry(entry)
    if not is_configured(entry):
        raise ValueError("Base URL 或 API Key 尚未配置")
    return OpenAI(api_key=config["api_key"], base_url=config["base_url"], timeout=config["timeout"])


def fetch_models(payload: dict) -> list[str]:
    entry = _normalize({"name": "临时连接", "model": "placeholder", **payload})
    return sorted({str(item.id) for item in _client(entry).models.list().data})


def test_connection(model_id: str) -> dict:
    entry = get_entry(model_id)
    if entry["id"] != model_id:
        raise KeyError("模型配置不存在")
    if entry["provider"] == "local":
        if not is_configured(entry):
            return {"ok": False, "message": "LOCAL 模型尚未下载，请先在推荐区一键部署", "model": entry["model"]}
        return {"ok": True, "message": "本地模型目录完整，可用于推理", "model": entry["model"]}
    models = _client(entry).models.list()
    count = len(models.data)
    return {"ok": True, "message": f"连接成功，服务返回 {count} 个模型", "model": entry["model"]}
