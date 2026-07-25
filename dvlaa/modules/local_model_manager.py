# -*- coding: utf-8 -*-
"""本地模型推荐、下载进度与一键部署。"""

from __future__ import annotations

import os
import platform
import shutil
import threading
import time
import uuid
from pathlib import Path

from ..paths import MODEL_DIR

MODEL_ROOT = MODEL_DIR
_DOWNLOAD_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}

MODEL_TIERS = [
    {
        "tier": 1, "name": "轻量档", "memory": "4-8 GB", "description": "适合开发机、低配云主机与快速功能验证。",
        "models": [
            {"id": "qwen35-08b", "name": "Qwen3.5-0.8B", "repo_id": "Qwen/Qwen3.5-0.8B", "size_gb": 1.8, "memory_gb": 4, "note": "新一代轻量中文多模态模型"},
            {"id": "falcon-h1-05b", "name": "Falcon-H1-0.5B-Instruct", "repo_id": "tiiuae/Falcon-H1-0.5B-Instruct", "size_gb": 1.1, "memory_gb": 4, "note": "启动快速，适合部署联调与基础训练"},
            {"id": "falcon-h1-15b", "name": "Falcon-H1-1.5B-Instruct", "repo_id": "tiiuae/Falcon-H1-1.5B-Instruct", "size_gb": 3.0, "memory_gb": 6, "note": "轻量多语言指令与安全训练"},
        ],
    },
    {
        "tier": 2, "name": "入门档", "memory": "8-16 GB", "description": "适合个人工作站和常规靶场训练。",
        "models": [
            {"id": "qwen35-2b", "name": "Qwen3.5-2B", "repo_id": "Qwen/Qwen3.5-2B", "size_gb": 4.5, "memory_gb": 8, "note": "中文入门与多模态任务推荐"},
            {"id": "qwen3-4b-2507", "name": "Qwen3-4B-Instruct-2507", "repo_id": "Qwen/Qwen3-4B-Instruct-2507", "size_gb": 7.8, "memory_gb": 12, "note": "成熟的纯文本指令模型"},
            {"id": "smollm3-3b", "name": "SmolLM3-3B", "repo_id": "HuggingFaceTB/SmolLM3-3B", "size_gb": 6.0, "memory_gb": 12, "note": "开放轻量推理与工具调用"},
        ],
    },
    {
        "tier": 3, "name": "均衡档", "memory": "16-32 GB", "description": "适合中型工作站，兼顾响应质量与部署成本。",
        "models": [
            {"id": "qwen35-4b", "name": "Qwen3.5-4B", "repo_id": "Qwen/Qwen3.5-4B", "size_gb": 9.0, "memory_gb": 16, "note": "中文攻防训练综合推荐"},
            {"id": "phi4-mini", "name": "Phi-4-Mini-Instruct", "repo_id": "microsoft/Phi-4-mini-instruct", "size_gb": 7.5, "memory_gb": 18, "note": "推理、代码与工具任务均衡"},
            {"id": "olmo3-7b", "name": "OLMo-3-7B-Instruct", "repo_id": "allenai/Olmo-3-7B-Instruct", "size_gb": 14.0, "memory_gb": 24, "note": "开放权重的通用指令模型"},
        ],
    },
    {
        "tier": 4, "name": "性能档", "memory": "32-64 GB", "description": "适合高配工作站与专用推理服务器。",
        "models": [
            {"id": "qwen35-9b", "name": "Qwen3.5-9B", "repo_id": "Qwen/Qwen3.5-9B", "size_gb": 18.5, "memory_gb": 32, "note": "复杂中文攻防对话推荐"},
            {"id": "falcon-h1-7b", "name": "Falcon-H1-7B-Instruct", "repo_id": "tiiuae/Falcon-H1-7B-Instruct", "size_gb": 14.5, "memory_gb": 32, "note": "多语言长上下文指令模型"},
            {"id": "qwen3-14b", "name": "Qwen3-14B", "repo_id": "Qwen/Qwen3-14B", "size_gb": 28.0, "memory_gb": 48, "note": "高质量中文推理与安全训练"},
        ],
    },
    {
        "tier": 5, "name": "专业档", "memory": "64 GB 以上", "description": "适合大内存服务器和高质量离线推理。",
        "models": [
            {"id": "qwen35-27b", "name": "Qwen3.5-27B", "repo_id": "Qwen/Qwen3.5-27B", "size_gb": 52.5, "memory_gb": 64, "note": "专业级中文安全推理"},
            {"id": "qwen36-27b", "name": "Qwen3.6-27B", "repo_id": "Qwen/Qwen3.6-27B", "size_gb": 52.5, "memory_gb": 64, "note": "最新一代长上下文多模态模型"},
            {"id": "qwen35-35b-a3b", "name": "Qwen3.5-35B-A3B", "repo_id": "Qwen/Qwen3.5-35B-A3B", "size_gb": 68.0, "memory_gb": 96, "note": "MoE 专业部署与高质量推理"},
        ],
    },
]


def system_resources() -> dict:
    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
    pages = os.sysconf("SC_PHYS_PAGES") if hasattr(os, "sysconf") else 0
    memory_bytes = page_size * pages
    memory_gb = round(memory_bytes / (1024 ** 3), 1) if memory_bytes else 0
    disk = shutil.disk_usage(MODEL_ROOT.parent if MODEL_ROOT.parent.exists() else Path("/"))
    return {
        "architecture": platform.machine().upper() or "UNKNOWN",
        "cpu_count": os.cpu_count() or 1,
        "memory_gb": memory_gb,
        "disk_free_gb": round(disk.free / (1024 ** 3), 1),
    }


def recommended_tier(resources: dict | None = None) -> int:
    memory = (resources or system_resources())["memory_gb"]
    if memory < 8: return 1
    if memory < 16: return 2
    if memory < 32: return 3
    if memory < 64: return 4
    return 5


def get_model(model_id: str) -> dict | None:
    for tier in MODEL_TIERS:
        for model in tier["models"]:
            if model["id"] == model_id:
                return {**model, "tier": tier["tier"], "tier_name": tier["name"]}
    return None


def model_path(model_id: str) -> Path:
    return MODEL_ROOT / model_id


def is_installed(model_id: str) -> bool:
    path = model_path(model_id)
    return path.is_dir() and (path / "config.json").is_file() and any(path.glob("*.safetensors"))


def catalog_snapshot() -> dict:
    resources = system_resources()
    recommended = recommended_tier(resources)
    tiers = []
    for tier in MODEL_TIERS:
        copied = {key: value for key, value in tier.items() if key != "models"}
        copied["recommended"] = tier["tier"] == recommended
        copied["models"] = [{**model, "installed": is_installed(model["id"])} for model in tier["models"]]
        tiers.append(copied)
    return {"resources": resources, "recommended_tier": recommended, "tiers": tiers}


def _directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def job_status(job_id: str) -> dict | None:
    with _DOWNLOAD_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return None
        result = dict(job)
    expected = max(1, int(result["expected_bytes"]))
    downloaded = _directory_size(Path(result["target_path"]))
    if result["status"] == "completed":
        downloaded = expected
    result["downloaded_bytes"] = downloaded
    result["progress"] = min(100, round(downloaded * 100 / expected, 1))
    return result


def active_jobs() -> list[dict]:
    with _DOWNLOAD_LOCK:
        job_ids = list(_JOBS)
    return [status for job_id in job_ids if (status := job_status(job_id))]


def start_install(model_id: str) -> dict:
    model = get_model(model_id)
    if not model:
        raise KeyError("推荐模型不存在")
    if is_installed(model_id):
        _activate_model(model)
        return {"job_id": "", "status": "completed", "message": "模型已安装并切换为当前模型"}
    resources = system_resources()
    required = model["size_gb"] * 1.15
    if resources["disk_free_gb"] < required:
        raise ValueError(f"磁盘空间不足，至少需要 {required:.1f} GB 可用空间")
    with _DOWNLOAD_LOCK:
        running = next((job for job in _JOBS.values() if job["status"] in {"queued", "downloading", "deploying"}), None)
        if running:
            raise ValueError("已有本地模型正在下载，请等待当前任务完成")
        job_id = uuid.uuid4().hex[:12]
        target = model_path(model_id)
        _JOBS[job_id] = {
            "job_id": job_id,
            "model_id": model_id,
            "model_name": model["name"],
            "status": "queued",
            "message": "等待下载任务启动",
            "expected_bytes": int(model["size_gb"] * 1024 ** 3),
            "target_path": str(target),
            "started_at": time.time(),
            "updated_at": time.time(),
        }
    threading.Thread(target=_install_worker, args=(job_id, model), daemon=True).start()
    return job_status(job_id)


def _update_job(job_id: str, **updates) -> None:
    with _DOWNLOAD_LOCK:
        if job_id in _JOBS:
            _JOBS[job_id].update(updates, updated_at=time.time())


def _install_worker(job_id: str, model: dict) -> None:
    target = model_path(model["id"])
    target.mkdir(parents=True, exist_ok=True)
    try:
        _update_job(job_id, status="downloading", message="正在从模型仓库下载文件")
        from huggingface_hub import snapshot_download
        snapshot_download(
            repo_id=model["repo_id"],
            local_dir=str(target),
            token=os.environ.get("HF_TOKEN") or None,
        )
        _update_job(job_id, status="deploying", message="下载完成，正在写入本地模型配置")
        _activate_model(model)
        _update_job(job_id, status="completed", message="模型下载完成并已切换为当前模型")
    except Exception as exc:
        _update_job(job_id, status="failed", message=f"模型部署失败：{exc}")


def _activate_model(model: dict) -> None:
    from . import modelsel
    modelsel.configure_local_model(model, model_path(model["id"]))


def activate_installed(model_id: str) -> dict:
    model = get_model(model_id)
    if not model:
        raise KeyError("推荐模型不存在")
    if not is_installed(model_id):
        raise ValueError("模型尚未下载")
    _activate_model(model)
    return {"ok": True, "message": f"已切换至 {model['name']}"}
