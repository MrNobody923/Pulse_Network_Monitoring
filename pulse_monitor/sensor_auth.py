"""Machine credential shared by the server and its local sensor processes."""
import os
import secrets

from .config import DATA_DIR


def sensor_token(*, initialize=False):
    configured = os.environ.get("PULSE_LOCAL_SENSOR_TOKEN")
    if configured:
        return configured
    path = DATA_DIR / "local-sensor.token"
    if initialize:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(secrets.token_urlsafe(48))
    try:
        return path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return ""
