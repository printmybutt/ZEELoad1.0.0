"""Combine locally captured diagnostic upload parts. No network access."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import zipfile


def assemble(manifest, output=None):
    manifest = Path(manifest).resolve()
    if manifest.is_dir():
        manifest = manifest / "manifest.json"
    plan = json.loads(manifest.read_text(encoding="utf-8"))
    parts = sorted(plan["parts"], key=lambda p: p["offset"])
    if plan.get("version") != 1 or not parts:
        raise ValueError("不支持的分片索引")
    offset, numbers, missing = 0, set(), []
    for p in parts:
        n, size = p["number"], p["size"]
        if (not isinstance(n, int) or not 1 <= n <= 10000 or n in numbers
                or not isinstance(size, int) or size <= 0 or p["offset"] != offset):
            raise ValueError("分片布局不连续或编号重复")
        numbers.add(n)
        offset += size
        saved = plan.get("saved", {}).get(str(n))
        part = manifest.parent / f"part-{n:05d}.bin"
        if not saved or not part.is_file() or part.stat().st_size != size:
            missing.append(n)
        elif saved.get("conflict"):
            raise ValueError(f"第 {n} 片的重试内容冲突，不能合并")
    if offset != plan["total_bytes"]:
        raise ValueError("文件总大小与分片布局不一致")
    if missing:
        sample = ", ".join(str(n) for n in missing[:30])
        raise ValueError(f"缺少 {len(missing)}/{len(parts)} 片（编号：{sample}）；不会生成完整 ZIP")
    output = Path(output).resolve() if output else manifest.parent / "captured-log.zip"
    partial = output.with_name(output.name + ".partial")
    if output.exists() or partial.exists():
        raise ValueError(f"输出已存在，请选择另一个名称：{output}")
    if shutil.disk_usage(output.parent).free < offset + 64 * 1024**2:
        raise ValueError("硬盘空间不足：合并时需要额外容纳一份完整文件")
    created = False
    try:
        with partial.open("xb") as target:
            created = True
            for p in parts:
                n = p["number"]
                digest, count = hashlib.sha256(), 0
                with (manifest.parent / f"part-{n:05d}.bin").open("rb") as source:
                    while block := source.read(1024 * 1024):
                        digest.update(block)
                        count += len(block)
                        target.write(block)
                if count != p["size"] or digest.hexdigest() != plan["saved"][str(n)]["sha256"]:
                    raise ValueError(f"第 {n} 片 SHA-256 或大小校验失败")
            target.flush()
            os.fsync(target.fileno())
        encrypted = None
        try:
            with zipfile.ZipFile(partial) as archive:
                entries = archive.infolist()  # Do not extract private vehicle logs.
                encrypted = sum(bool(info.flag_bits & 1) for info in entries)
        except zipfile.BadZipFile:
            # A complete outer-encrypted payload is still worth preserving.
            output = output.with_suffix(".bin")
        # Rename refuses to replace an existing file on Windows.
        if output.exists():
            raise ValueError("输出文件已存在")
        partial.rename(output)
        print(f"合并完成：{output}（{offset} 字节，{len(parts)} 片，逐片 SHA-256 已校验）")
        if encrypted is None:
            print("数据完整合并，但无法读取 ZIP 目录，已保存为 .bin；可能是其他格式或外层加密，需继续识别。")
        elif encrypted:
            print(f"ZIP 中有 {encrypted} 个条目带加密标志；保存成功不代表已取得密码或解密。")
        else:
            print("ZIP 目录没有标准条目加密标志；内部文件是否另行加密仍需单独检查。")
        return output
    except BaseException:
        if created and partial.exists():
            partial.unlink()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="上传任务目录或其中的 manifest.json")
    parser.add_argument("--output", help="输出 ZIP 路径；默认任务目录/captured-log.zip")
    args = parser.parse_args()
    try:
        assemble(args.manifest, args.output)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"合并失败：{exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
