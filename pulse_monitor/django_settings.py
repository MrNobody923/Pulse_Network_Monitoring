"""Django web settings. The monitor owns its existing SQLite schema."""

import os
import secrets
from .config import DATA_DIR, ROOT

SECRET_KEY = os.environ.get("PULSE_DJANGO_SECRET_KEY") or secrets.token_urlsafe(48)
DEBUG = False
ROOT_URLCONF = "pulse_monitor.urls"
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]
ALLOWED_HOSTS.extend(host.strip() for host in os.environ.get("PULSE_ALLOWED_HOSTS", "").split(",") if host.strip())
bind_host = os.environ.get("PULSE_BIND_HOST")
if bind_host and bind_host != "0.0.0.0":
    ALLOWED_HOSTS.append(bind_host)
INSTALLED_APPS = [
    "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
    "django.contrib.messages", "django.contrib.admin", "django.contrib.staticfiles",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": DATA_DIR / "accounts.sqlite3"}}
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates",
              "DIRS": [ROOT / "pulse_monitor" / "templates", ROOT / "public"], "APP_DIRS": True,
              "OPTIONS": {"context_processors": ["django.template.context_processors.request",
                  "django.contrib.auth.context_processors.auth", "django.contrib.messages.context_processors.messages"]}}]
MIDDLEWARE = ["django.middleware.security.SecurityMiddleware", "django.middleware.common.CommonMiddleware",
              "django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.auth.middleware.AuthenticationMiddleware",
              "pulse_monitor.staff.StaffAccess", "django.middleware.csrf.CsrfViewMiddleware",
              "django.contrib.messages.middleware.MessageMiddleware", "django.middleware.clickjacking.XFrameOptionsMiddleware"]
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = LOGIN_URL
CSRF_FAILURE_VIEW = "pulse_monitor.staff.csrf_failure"
_port = os.environ.get("PORT", "3000")
CSRF_TRUSTED_ORIGINS = [
    f"http://localhost:{_port}",
    f"http://127.0.0.1:{_port}",
    f"https://localhost:{_port}",
    f"https://127.0.0.1:{_port}",
]
for _h in ALLOWED_HOSTS:
    if _h and not _h.startswith("[") and _h not in {"localhost", "127.0.0.1"}:
        CSRF_TRUSTED_ORIGINS.extend([f"http://{_h}", f"https://{_h}", f"http://{_h}:{_port}", f"https://{_h}:{_port}"])
STATIC_URL = "/static/"
SESSION_COOKIE_AGE = 8 * 3600
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = os.environ.get("PULSE_HTTPS") == "1"
AUTH_PASSWORD_VALIDATORS = [{"NAME": "django.contrib.auth.password_validation." + validator} for validator in
                            ("UserAttributeSimilarityValidator", "MinimumLengthValidator", "CommonPasswordValidator",
                             "NumericPasswordValidator")]
APPEND_SLASH = False
USE_I18N = False
