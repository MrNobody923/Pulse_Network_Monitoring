"""Dashboard URL contracts. Fixed endpoints take precedence over resource IDs."""

import re

from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.staticfiles.views import serve as serve_static
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import path, re_path
from django.views.decorators.http import require_safe

from .http_handler import RESOURCE_ROUTES, RequestHandler
from .staff import StaffLoginView
from . import device_pages


def not_found(request, exception=None):
    return JsonResponse({"error": "Not found"}, status=404)


def server_error(request):
    return JsonResponse({"error": "Internal server error — check the server terminal log for details."}, status=500)


@require_safe
def workspace(request, section):
    return HttpResponseRedirect("/#" + ("internet" if section == "router" else section))


handler404 = not_found
handler500 = server_error
urlpatterns = [
    path("healthz", require_safe(lambda request: JsonResponse({"ok": True})), name="liveness"),
    path("login/", StaffLoginView.as_view(), name="staff-login"),
    path("logout/", LogoutView.as_view(), name="staff-logout"),
    path("staff-admin/", admin.site.urls),
    re_path(r"^static/(?P<path>admin/.+)$", serve_static, {"insecure": True}),
    re_path(r"^devices/?$", device_pages.inventory),
    path("devices/form/", device_pages.device_form),
    re_path(r"^$", RequestHandler.as_view(http_method_names=["get"]), name="dashboard"),
    re_path(r"^(?P<section>overview|triage|topology|internet|router|alerts|ping|nmap|toolkit|gaming)/?$", workspace),
]


def register(pattern, methods, *, resource=False):
    view = RequestHandler.as_view(http_method_names=methods, resource=resource)
    urlpatterns.append(re_path(f"^{pattern}/?$", view))


for route in (
    "api/alerts",
    "api/devices/history",
    "api/events",
    "api/gaming/activity",
    "api/gaming/blocks",
    "api/gaming/wireshark/capture.pcap",
    "api/gaming/wireshark/status",
    "api/health",
    "api/isp/live",
    "api/mobile/summary",
    "api/network/events",
    "api/network/history",
    "api/network/history/export",
    "api/network/inventory",
    "api/network/inventory/export",
    "api/network/ping-history",
    "api/operations",
    "api/operations/incident",
    "api/router/duplex",
    "api/routers",
    "api/status",
    "api/summary",
    "api/tools/port-scan/catalog",
    "api/topology",
    "api/v1/health",
    "api/v1/summary",
    "events",
    "favicon.ico",
    "index.html",
    "manifest.json",
    "vertex-sentry-192.png",
    "vertex-sentry.png",
):
    register(re.escape(route), ["get"])

for route in (
    "api/devices",
    "api/devices/connection",
    "api/network/inventory/profile",
    "api/operations/notifications",
    "api/operations/switch-ports",
):
    register(re.escape(route), ["get", "post"])

for route in (
    "actions/add-device",
    "actions/archive",
    "actions/authorize",
    "actions/discover",
    "actions/favorite",
    "api/alerts/acknowledge-all",
    "api/alerts/clear",
    "api/alerts/test-drill",
    "api/devices/connection/snmp",
    "api/devices/probe-all",
    "api/devices/upstream",
    "api/diagnostics/run",
    "api/gaming/android",
    "api/gaming/block",
    "api/gaming/clear",
    "api/gaming/detect",
    "api/gaming/dismiss",
    "api/gaming/endpoint",
    "api/gaming/policy",
    "api/gaming/scan",
    "api/gaming/sensor-heartbeat",
    "api/gaming/setup-router-dns",
    "api/gaming/unblock",
    "api/gaming/wireshark/analyze",
    "api/gaming/wireshark/config",
    "api/isp/probe",
    "api/network/discover",
    "api/network/events/clear",
    "api/network/import-devices",
    "api/network/inventory/archive",
    "api/network/inventory/authorize",
    "api/network/inventory/favorite",
    "api/network/inventory/review",
    "api/network/sync-infrastructure",
    "api/operations/maintenance",
    "api/operations/maintenance/cancel",
    "api/operations/notifications/test",
    "api/router/access/block",
    "api/router/access/restore",
    "api/router/config",
    "api/router/refresh",
    "api/router/simulate",
    "api/routers/config",
    "api/speedtest/run",
    "api/tools/dns-benchmark",
    "api/tools/port-check",
    "api/tools/port-scan",
    "api/tools/traceroute",
    "api/topology/auto-layout",
    "api/topology/clear",
    "api/topology/import-monitored",
    "api/topology/link",
    "api/topology/node",
    "api/topology/pdu-ping",
):
    register(re.escape(route), ["post"])

register(r"(?:css/[^/]+\.css|js/[^/]+\.js)", ["get"])

# Match the decoded URL here and verify individual encoded segments in the view.
for resource_pattern, _ in RESOURCE_ROUTES:
    register(resource_pattern.replace("[^/]+", ".+"), [], resource=True)
