from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: str = "./agent_ops.db"
    admin_token: str = "admin-demo-token"
    executor_key: str = "executor-demo-key"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_path=os.getenv("DATABASE_PATH", "./agent_ops.db"),
            admin_token=os.getenv("ADMIN_TOKEN", "admin-demo-token"),
            executor_key=os.getenv("EXECUTOR_KEY", "executor-demo-key"),
        )
