"""不加载驱动、不改变网络的启动回归测试。"""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

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
            task_dir = Path(directory) / "task's $ 中文目录"
            task_dir.mkdir()
            entry = task_dir / "fake_entry.py"
            entry.write_text(
                "import sys\nprint('stdout reached：中文正常')\nprint(repr(sys.argv[1:]))\n"
                "print(sys.argv[-1])\nprint('stderr reached：错误信息', file=sys.stderr)\nsys.exit(9)\n",
                encoding="utf-8",
            )
            apk = str(task_dir / "app's $ 测试应用.apk")
            environment = dict(os.environ, ZEELOAD_PYTHON=sys.executable,
                               ZEELOAD_ENTRY=str(entry), ZEELOAD_APK=apk,
                               ZEELOAD_LOGDIR=str(task_dir / "logs"), ZEELOAD_OBSERVE_ONLY='0')
            legacy_console = "[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936); "
            result = subprocess.run(["powershell", "-NoProfile", "-Command", legacy_console + command],
                                    env=environment, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
            reports = list((task_dir / "logs").glob("bat-run-*.log"))
            self.assertEqual(len(reports), 1)
            report = reports[0].read_text(encoding="utf-16")
            self.assertIn("stdout reached：中文正常", report)
            self.assertIn("stderr reached：错误信息", report)
            self.assertIn(apk, report)
            console = (result.stdout + result.stderr).decode("utf-8")
            self.assertIn("stdout reached：中文正常", console)
            self.assertIn("stderr reached：错误信息", console)

            environment.update(ZEELOAD_OBSERVE_ONLY='1', ZEELOAD_LOGDIR=str(task_dir / 'observe'))
            observed = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                                      env=environment, capture_output=True, timeout=30)
            self.assertEqual(observed.returncode, 9)
            observed_report = next((task_dir / 'observe').glob('bat-run-*.log')).read_text(encoding='utf-16')
            self.assertIn('--observe-only', observed_report)
            self.assertNotIn('--apk', observed_report)


class ObserveOnlyTests(unittest.TestCase):
    def test_observation_starts_without_apk_or_replacement_metadata(self):
        process = Mock()
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(win_sideload.sys, 'argv', ['win_sideload.py', '--observe-only', '--out', directory]),
                patch.object(win_sideload, 'ensure_python', return_value=None),
                patch.object(win_sideload, 'IS_WINDOWS', True),
                patch.object(win_sideload, 'is_admin', return_value=True),
                patch.object(win_sideload, 'find_hotspot_ip', return_value='192.168.137.1'),
                patch.object(win_sideload.time, 'sleep'),
                patch.object(win_sideload, 'start_mitmdump', return_value=process) as start,
                patch.object(win_sideload, 'run_divert', side_effect=KeyboardInterrupt),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(win_sideload.main(), 0)
            start.assert_called_once_with('', '', '', '', directory, emudhra_old=False, observe_only=True)
            process.terminate.assert_called_once()

    def test_observation_disables_cached_mutation_options(self):
        with (
            patch.object(win_sideload, 'find_mitmdump', return_value=['mitmdump.exe']),
            patch.object(win_sideload, 'FROZEN', False),
            patch.object(win_sideload, 'mitmproxy_version', return_value=(12, 3)),
            patch.object(win_sideload.subprocess, 'Popen') as popen,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            win_sideload.start_mitmdump('old.apk', 'ALL', 'a' * 64, 'b' * 32, 'logs', observe_only=True)
        command = popen.call_args.args[0]
        for setting in ('replace_apk=', 'inject_pkg=', 'override_sha256=', 'override_md5=',
                        'fake_hash=false', 'fake_sign=false', 'corrupt_offset=-1'):
            self.assertIn(setting, command)
        self.assertNotIn('old.apk', command)


@unittest.skipUnless(sys.platform == 'win32', 'Windows CMD launcher regression')
class BatchEntryTests(unittest.TestCase):
    def test_batch_files_preserve_crlf_for_zip_downloads(self):
        for path in Path(__file__).parent.glob('*.bat'):
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                self.assertNotIn(b'\n', raw.replace(b'\r\n', b''))
                self.assertIn(b'\r\n', raw)

    def test_observe_entry_reaches_child_in_cmd_with_unicode_path(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / 'launcher 中文 test'
            folder.mkdir()
            entry = folder / 'observe-Windows.bat'
            entry.write_bytes(Path(__file__).with_name('observe-Windows.bat').read_bytes())
            (folder / '一键侧载-Windows.bat').write_bytes(
                b'@echo off\r\necho WRAPPER_OK %*\r\nexit /b 23\r\n')
            process = subprocess.run(['cmd.exe', '/d', '/c', str(entry)],
                                     capture_output=True, stdin=subprocess.DEVNULL, timeout=15)
            output = (process.stdout + process.stderr).decode('utf-8', 'replace')
            self.assertIn('WRAPPER_OK --observe-only', output)
            self.assertIn('Observation launcher failed. Exit code: 23', output)
            self.assertNotIn('not recognized', output)
            self.assertEqual(process.returncode, 23)


if __name__ == "__main__":
    unittest.main()
