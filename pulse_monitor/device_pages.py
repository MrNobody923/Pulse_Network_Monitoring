"""Django views for server-rendered `/devices` inventory and `/devices/form/`."""

from __future__ import annotations

import urllib.parse

from django.http import HttpResponse, HttpResponseRedirect
from django.middleware.csrf import get_token
from django.views.decorators.http import require_http_methods, require_safe

from .runtime import _active_monitor
from .views import render_page


@require_safe
def inventory(request) -> HttpResponse:
    mon = _active_monitor()
    notice = str(request.GET.get("notice") or "")
    filter_by = str(request.GET.get("filter") or "all")
    return HttpResponse(
        render_page(mon, "/devices", notice, filter_by, csrf_token=get_token(request)),
        content_type="text/html; charset=utf-8",
    )


@require_http_methods(["GET", "POST"])
def device_form(request) -> HttpResponse:
    mon = _active_monitor()
    if request.method == "GET":
        return HttpResponse(
            render_page(mon, "/devices", "", str(request.GET.get("filter") or "all"), csrf_token=get_token(request)),
            content_type="text/html; charset=utf-8",
        )
    data = request.POST
    try:
        device = mon.add_device({
            "name": data.get("name", ""),
            "ip": data.get("ip", ""),
            "mac": data.get("mac", ""),
            "type": data.get("type", "ap"),
            "port": data.get("port", 80),
            "location": data.get("location", "Office Network"),
            "critical": data.get("critical") in {"1", "true", "on", "yes"},
            "manual": True,
        })
        notice = f"Added {device['name']} ({device['ip']})."
    except Exception as exc:
        notice = str(exc)
    query = urllib.parse.urlencode({"notice": notice})
    return HttpResponseRedirect(f"/devices?{query}")
