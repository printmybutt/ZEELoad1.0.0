"""zeeload_app.py — ZEELoad 的统一入口（给 PyInstaller 打包用）

规则很简单：
  * 不带任何参数（= 双击）          -> 图形界面 zeeload_gui
  * 带任何参数（--apk ... 等）       -> 原样交给 win_sideload.main()，行为与旧版完全一致
  * 显式 --gui                      -> 强制图形界面

这样 win_sideload.py 一行都不用改：命令行、`--mitmdump-inner`（exe 自己当 mitmdump 用）
都还是原来的代码路径。
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import traceback


def main() -> int:
    argv = sys.argv[1:]

    if argv and argv[0] == "--gui":
        del argv[0]
        if argv:  # --gui 后面还带参数时退回命令行，避免参数被吞掉
            sys.argv = [sys.argv[0]] + argv
        else:
            from zeeload_gui import run

            return run()

    if argv:
        from win_sideload import main as cli_main

        return cli_main()

    from zeeload_gui import run

    return run()


def launch() -> int:
    """记录入口异常，双击启动失败时也能找到原因。"""
    try:
        return main()
    except Exception:
        details = traceback.format_exc()
        base = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
        fallback = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "ZEEload"
        report = None
        for directory in (base / "logs", fallback / "logs"):
            try:
                directory.mkdir(parents=True, exist_ok=True)
                report_path = directory / "startup-error.log"
                with report_path.open("a", encoding="utf-8") as stream:
                    stream.write(f"\nPython: {sys.version}\nExecutable: {sys.executable}\n{details}")
                report = report_path
                break
            except OSError:
                continue
        message = f"ZEEload 启动失败。\n日志：{report or '无法写入日志，请从终端启动查看报错'}\n\n{details}"
        try:
            print(message, file=sys.stderr, flush=True)
        except (OSError, UnicodeError):
            pass
        if sys.platform == "win32" and (len(sys.argv) == 1 or sys.argv[1] == "--gui"):
            try:
                import ctypes

                ctypes.windll.user32.MessageBoxW(None, message, "ZEEload 启动失败", 0x10)
            except Exception:
                pass
        return 1


if __name__ == "__main__":
    sys.exit(launch())
