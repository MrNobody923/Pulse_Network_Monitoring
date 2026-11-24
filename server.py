"""Entrypoint for the Pulse Network Monitor HTTP & SSE server."""

from __future__ import annotations

from monitor import monitor, utc_now
from pulse_monitor.http_handler import (
    MAX_BODY_BYTES,
    PUBLIC_DIR,
    RequestHandler,
)
from pulse_monitor.runtime import DashboardServer, PORT, run_server
from pulse_monitor.views import (
    PAGE_STYLE,
    REFRESH_SECONDS,
    dashboard_rows as _dashboard_rows,
    render_page,
    render_table as _render_table,
)


def _render_page(path: str, message: str = "", filter_by: str = "all") -> str:
    return render_page(monitor, path, message, filter_by)


def main() -> None:
    run_server(PORT)


__all__ = [
    "DashboardServer",
    "MAX_BODY_BYTES",
    "PAGE_STYLE",
    "PORT",
    "PUBLIC_DIR",
    "REFRESH_SECONDS",
    "RequestHandler",
    "_dashboard_rows",
    "_render_page",
    "_render_table",
    "main",
    "monitor",
    "render_page",
    "run_server",
    "utc_now",
]


if __name__ == "__main__":
    main()
