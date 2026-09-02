"""Central filesystem paths for DVLAA.

Source code and web assets live inside :mod:`dvlaa`; mutable files stay in the
project-level runtime directories so deployments can mount them independently.
"""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
WEB_ROOT = PACKAGE_ROOT / "web"
TEMPLATE_DIR = WEB_ROOT / "templates"
STATIC_DIR = WEB_ROOT / "static"
FLAGS_FILE = PACKAGE_ROOT / "flags.json"


def _path_from_env(name: str, default: Path) -> Path:
    """Return an expanded, absolute path from an environment override."""
    return Path(os.environ.get(name, str(default))).expanduser()


DATA_DIR = _path_from_env("DVLAA_DATA_ROOT", PROJECT_ROOT / "data")
UPLOAD_DIR = _path_from_env("DVLAA_UPLOAD_ROOT", PROJECT_ROOT / "uploads")
MODEL_DIR = _path_from_env("LOCAL_MODEL_ROOT", DATA_DIR / "models")
LEARNING_DIR = _path_from_env("LEARNING_ROOT", DATA_DIR / "learning")
LLM_CONFIG_FILE = _path_from_env("LLM_CONFIG_FILE", DATA_DIR / "llm_configs.json")
EMBEDDING_MODEL_DIR = _path_from_env("ST_MODEL_PATH", PROJECT_ROOT / "st-model")


def ensure_runtime_dirs() -> None:
    """Create mutable directories on first use."""
    for directory in (DATA_DIR, UPLOAD_DIR, MODEL_DIR, LEARNING_DIR):
        directory.mkdir(parents=True, exist_ok=True)
