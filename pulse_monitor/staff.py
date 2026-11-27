"""Staff session and machine access rules for the dashboard."""
import secrets

from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView, redirect_to_login
from django.core.exceptions import ValidationError
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils.cache import add_never_cache_headers
from django.utils.deprecation import MiddlewareMixin

from .sensor_auth import sensor_token

PUBLIC_BRAND_ASSETS = frozenset({
    "/favicon.ico",
    "/vertex-sentry-192.png",
    "/vertex-sentry.png",
    "/manifest.json",
})
UNSAFE_LOGIN_REDIRECT_PREFIXES = (
    "/favicon.ico",
    "/vertex-sentry",
    "/manifest.json",
    "/logout",
    "/login",
    "/api/",
)


class StaffLoginForm(AuthenticationForm):
    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        if not user.is_staff:
            raise ValidationError("This account does not have dashboard access.")


class StaffLoginView(LoginView):
    template_name = "staff_login.html"
    authentication_form = StaffLoginForm
    redirect_authenticated_user = True

    def get_default_redirect_url(self):
        return "/"

    def get_success_url(self):
        url = super().get_success_url()
        if any(url.startswith(prefix) for prefix in UNSAFE_LOGIN_REDIRECT_PREFIXES):
            return "/"
        return url


def csrf_failure(request, reason: str = "") -> HttpResponse:
    if request.path_info.startswith("/api/"):
        return JsonResponse(
            {"error": "CSRF token missing or expired — refresh the page and try again."},
            status=403,
        )
    return render(
        request,
        "staff_login.html",
        {
            "form": StaffLoginForm(request),
            "csrf_error": "Your browser session or security token expired. Please sign in again.",
            "next": "/",
        },
        status=403,
    )


SENSOR_METHODS = {
    "/api/gaming/blocks": "GET", "/api/gaming/activity": "GET",
    "/api/gaming/android": "POST", "/api/gaming/detect": "POST",
    "/api/gaming/dismiss": "POST", "/api/gaming/sensor-heartbeat": "POST",
}


class StaffAccess(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        path = request.path_info.rstrip("/")
        if request.resolver_match.url_name in {"staff-login", "liveness"} and not request.resolver_match.namespace:
            return None
        if request.method in {"GET", "HEAD"} and path in PUBLIC_BRAND_ASSETS:
            return None
        raw_path = request.META.get("RAW_URI", request.path_info).partition("?")[0].rstrip("/")
        if raw_path == path and path == "/api/gaming/endpoint" and request.method == "POST":
            # The endpoint handler validates its enrollment bearer and subnet.
            return view_func(request, *view_args, **view_kwargs)
        if raw_path == path and SENSOR_METHODS.get(path) == request.method:
            auth = request.headers.get("Authorization", "")
            token = sensor_token() if auth else ""
            if token and secrets.compare_digest(auth.encode(), f"Bearer {token}".encode()):
                return view_func(request, *view_args, **view_kwargs)
        if not request.user.is_authenticated:
            if path.startswith("/api/"):
                return JsonResponse({"error": "Staff sign-in required"}, status=401)
            redirect = redirect_to_login(request.get_full_path())
            if request.headers.get("HX-Request"):
                redirect.status_code = 200
                redirect["HX-Redirect"] = redirect["Location"]
            return redirect
        if not request.user.is_active or not request.user.is_staff:
            return JsonResponse({"error": "Staff access required"}, status=403)
        if not request.user.is_superuser and (
            path.startswith(("/staff-admin", "/static/admin")) or
            (request.method not in {"GET", "HEAD", "OPTIONS"} and path != "/logout")
        ):
            return JsonResponse({"error": "Administrator access required"}, status=403)
        return None

    def process_response(self, request, response):
        add_never_cache_headers(response)
        if (request.method not in {"GET", "HEAD", "OPTIONS"} and
                getattr(getattr(request, "user", None), "is_superuser", False) and request.path_info != "/logout/"):
            print(f"[staff] user={request.user.pk} method={request.method} path={request.path_info!r} status={response.status_code}", flush=True)
        return response
