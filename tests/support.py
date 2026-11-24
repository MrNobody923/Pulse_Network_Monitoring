import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import monitor as monitor_module


class MonitorTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        data_dir = Path(self.temp_dir.name)
        paths = patch.multiple(
            monitor_module,
            DATA_DIR=data_dir,
            CONFIG_FILE=data_dir / "config.json",
            DATABASE_FILE=data_dir / "network.db",
        )
        paths.start()
        self.addCleanup(paths.stop)
        self.monitor = monitor_module.Monitor()

    @staticmethod
    def discovered_device(ip="192.168.10.20"):
        return {
            "ip": ip,
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": "Unknown vendor",
            "suggestedName": f"Unknown vendor ({ip})",
            "arpType": "dynamic",
        }
