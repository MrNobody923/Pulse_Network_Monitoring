import os
import sys

from django.core.management import execute_from_command_line
from pulse_monitor.config import DATA_DIR

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pulse_monitor.django_settings")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    execute_from_command_line(sys.argv)
