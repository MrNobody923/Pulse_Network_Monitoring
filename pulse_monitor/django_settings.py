"""Django web settings. The monitor owns its existing SQLite schema."""

import os
import secrets

SECRET_KEY = os.environ.get("PULSE_DJANGO_SECRET_KEY") or secrets.token_urlsafe(48)
DEBUG = False
ROOT_URLCONF = "pulse_monitor.urls"
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]
ALLOWED_HOSTS.extend(host.strip() for host in os.environ.get("PULSE_ALLOWED_HOSTS", "").split(",") if host.strip())
bind_host = os.environ.get("PULSE_BIND_HOST")
if bind_host and bind_host != "0.0.0.0":
    ALLOWED_HOSTS.append(bind_host)
MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]
APPEND_SLASH = False
USE_I18N = False
