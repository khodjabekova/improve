from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Config:
    bot_token: str
    database_path: str = "santa.db"
    require_group_membership: bool = True


def _flag(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_config() -> Config:
    token = os.environ.get("BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("Переменная окружения BOT_TOKEN не задана")
    return Config(
        bot_token=token,
        database_path=os.environ.get("DATABASE_PATH", "santa.db"),
        require_group_membership=_flag(os.environ.get("REQUIRE_GROUP_MEMBERSHIP"), True),
    )
