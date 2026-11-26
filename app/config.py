"""运行期配置，全部可通过环境变量覆盖。"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _data_dir() -> str:
    return os.environ.get("SYMBOL_DATA_DIR", "/data")


def _parse_positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} 必须是正整数，实际为 {raw!r}") from exc
    if value < 1:
        raise ValueError(f"{name} 必须是正整数，实际为 {raw!r}")
    return value


def resolve_concurrency() -> int:
    """解析并发上限，运行期读取环境变量，便于测试与部署调整。

    默认上报（同步解析）与按号查栈共用此上限；只登记上报不占用解析名额。
    环境变量 SYMBOL_RESOLVE_LIMIT 必须为正整数，缺省 4。
    """
    return _parse_positive_int("SYMBOL_RESOLVE_LIMIT", 4)


@dataclass(frozen=True)
class Settings:
    data_dir: str = _data_dir()
    elf_dir_name: str = "elfs"
    db_name: str = "service.sqlite3"

    @property
    def resolve_concurrency(self) -> int:
        return resolve_concurrency()

    @property
    def elf_dir(self) -> str:
        return os.path.join(self.data_dir, self.elf_dir_name)

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, self.db_name)


settings = Settings()
