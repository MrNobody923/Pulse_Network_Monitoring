"""Pulse Network Monitor — Modular Python backend package."""

from __future__ import annotations

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

monitor = Monitor()

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

