"""Pulse Network Monitor — Modular Python backend package."""

from __future__ import annotations

from threading import Lock
from typing import TYPE_CHECKING

from .config import (
    CONFIG_FILE,
    DATA_DIR,
    DATABASE_FILE,
    DEFAULT_CONFIG,
    ISP_TARGETS,
    ROOT,
    ROUTER_PORTS,
    merge_config,
    utc_now,
)
from .engine import Monitor

if TYPE_CHECKING:
    monitor: Monitor

_monitor_lock = Lock()


def __getattr__(name: str):
    if name != "monitor":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    with _monitor_lock:
        if name not in globals():
            globals()[name] = Monitor()
        return globals()[name]

__all__ = [
    "CONFIG_FILE",
    "DATA_DIR",
    "DATABASE_FILE",
    "DEFAULT_CONFIG",
    "ISP_TARGETS",
    "Monitor",
    "ROOT",
    "ROUTER_PORTS",
    "merge_config",
    "monitor",
    "utc_now",
]

