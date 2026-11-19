"""不加载驱动、不改变网络的启动回归测试。"""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import win_sideload
import zeeload_app


class HotspotDetectionTests(unittest.TestCase):
    def detect(self, output):
        with patch.object(win_sideload.subprocess, "check_output", return_value=output):
            return win_sideload.find_hotspot_ip()

    def test_phone_uplink_is_not_selected_as_hotspot(self):
        self.assertEqual(self.detect("IPv4 Address : 192.168.43.25\n"), "")

    def test_vpn_is_not_selected_as_hotspot(self):
        self.assertEqual(self.detect("IPv4 Address : 10.147.17.2\n"), "")

    def test_hotspot_is_selected_with_phone_and_vpn_present(self):
        self.assertEqual(self.detect(
            "IPv4 Address : 192.168.43.25\n"
            "IPv4 Address : 10.147.17.2\n"
            "IPv4 地址 : 192.168.137.1\n"
        ), "192.168.137.1")


class StartupFailureTests(unittest.TestCase):
    def test_import_failure_is_saved_for_double_click_diagnosis(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(zeeload_app, "__file__", str(Path(directory) / "zeeload_app.py")),
                patch.object(zeeload_app.sys, "frozen", False, create=True),
                patch.object(zeeload_app.sys, "argv", ["zeeload_app.py", "--apk", "test.apk"]),
                patch.object(zeeload_app, "main", side_effect=ImportError("missing GUI dependency")),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(zeeload_app.launch(), 1)
            report = (Path(directory) / "logs" / "startup-error.log").read_text(encoding="utf-8")
            self.assertIn("ImportError: missing GUI dependency", report)
            self.assertIn("Traceback", report)

    @unittest.skipUnless(sys.platform == "win32", "BAT 使用 Windows PowerShell")
    def test_bat_logging_preserves_stderr_arguments_and_exit_code(self):
        launcher = Path(__file__).with_name("一键侧载-Windows.bat").read_text(encoding="utf-8")
        command = next(line for line in launcher.splitlines()
                       if line.startswith('powershell -NoProfile -Command "$ErrorActionPreference'))
        command = command.split(' -Command "', 1)[1][:-1]
        with tempfile.TemporaryDirectory() as directory:
            task_dir = Path(directory) / "task's $ notes"
            task_dir.mkdir()
            entry = task_dir / "fake_entry.py"
            entry.write_text(
                "import sys\nprint('stdout reached')\n"
                "print(sys.argv[-1])\nprint('stderr reached', file=sys.stderr)\nsys.exit(9)\n",
                encoding="utf-8",
            )
            apk = str(task_dir / "app's $ sample.apk")
            environment = dict(os.environ, ZEELOAD_PYTHON=sys.executable,
                               ZEELOAD_ENTRY=str(entry), ZEELOAD_APK=apk,
                               ZEELOAD_LOGDIR=str(task_dir / "logs"))
            result = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                                    env=environment, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
            reports = list((task_dir / "logs").glob("bat-run-*.log"))
            self.assertEqual(len(reports), 1)
            report = reports[0].read_text(encoding="utf-16")
            self.assertIn("stdout reached", report)
            self.assertIn("stderr reached", report)
            self.assertIn(apk, report)


if __name__ == "__main__":
    unittest.main()
