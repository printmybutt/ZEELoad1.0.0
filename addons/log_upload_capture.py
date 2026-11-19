"""Save this car's diagnostic upload parts locally, without changing traffic.

Only plans from file/path/apply for the observed DHU log prefix are accepted.
No request authorization headers, signatures, or upload IDs are written to disk.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
from urllib.parse import parse_qs, urlsplit, urlunsplit

from mitmproxy import ctx

OSS_HOST = "snc-media-prod-oss.oss-cn-hangzhou.aliyuncs.com"
APPLY_HOST = "snc-api-gw.zeekrlife.com"
APPLY_PATH = "/file-service/api/v2/file/path/apply"
LOG_PREFIX = "/remote-log/maintenance-testing-platform/DHU/"
MAX_TOTAL = 8 * 1024**3
MAX_PART = 32 * 1024**2
ENCRYPTION_FIELDS = {
    "encryption", "encryptioninfo", "encryptinfo", "decryptinfo", "encryptionkey",
    "encryptkey", "decryptkey", "wrappedkey", "encryptedkey", "keymaterial",
    "password", "zippassword", "aeskey", "iv", "nonce", "salt", "algorithm",
    "encryptionalgorithm", "keyid", "kmskeyid",
}


def encryption_fields(value, path="data"):
    """Collect explicitly named encryption fields, excluding upload authentication."""
    result = {}
    if isinstance(value, dict):
        for name, child in value.items():
            normalized = name.lower().replace("_", "").replace("-", "")
            if normalized in {"headers", "authorization", "accesskey", "accesskeyid",
                              "accesskeysecret", "securitytoken", "signature"}:
                continue
            if normalized in ENCRYPTION_FIELDS and child is not None:
                if isinstance(child, (str, int, float, bool)):
                    result[path + "." + name] = child
                else:
                    # Inside an explicit encryption object a field named key is relevant.
                    if isinstance(child, dict) and isinstance(child.get("key"), str):
                        result[path + "." + name + ".key"] = child["key"]
                    result.update(encryption_fields(child, path + "." + name))
            elif normalized != "parturiinfos":
                result.update(encryption_fields(child, path + "." + name))
    return result


def upload_identity(url):
    u = urlsplit(url)
    q = parse_qs(u.query)
    if (u.scheme != "https" or u.hostname != OSS_HOST or u.port not in (None, 443)
            or not u.path.startswith(LOG_PREFIX) or not u.path.endswith(".zip")
            or len(q.get("uploadId", [])) != 1 or len(q.get("partNumber", [])) != 1):
        raise ValueError("not a supported diagnostic upload")
    number = int(q["partNumber"][0])
    if not 1 <= number <= 10000:
        raise ValueError("invalid part number")
    object_url = urlunsplit((u.scheme, u.netloc, u.path, "", ""))
    key = hashlib.sha256((object_url + "\n" + q["uploadId"][0]).encode()).hexdigest()[:24]
    return key, object_url, number


def atomic_json(path, value):
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


class LogUploadCapture:
    def __init__(self):
        self.plans = {}
        self.active = {}
        self.root = None

    def load(self, loader):
        loader.add_option("log_upload_dir", str, "", "本地保存 DHU 日志上传分片的目录；空则关闭")

    def running(self):
        if ctx.options.log_upload_dir:
            self.root = Path(ctx.options.log_upload_dir).resolve()
            self.root.mkdir(parents=True, exist_ok=True)
            ctx.log.warn(f"[upload-capture-ready] 上传分片保存至 {self.root}")

    def register_plan(self, response, request_crypto=None):
        if not self.root or str(response.get("code")) != "0":
            return
        data = response.get("data") or {}
        raw_parts = data.get("partUriInfos") or []
        if not isinstance(raw_parts, list) or not 1 <= len(raw_parts) <= 10000:
            return
        parts = []
        identities = set()
        for p in raw_parts:
            key, url, number = upload_identity(p["url"])
            offset, size = int(p["offset"]), int(p["partSize"])
            if number != int(p["partNum"]) or offset < 0 or not 0 < size <= MAX_PART:
                raise ValueError("invalid part layout")
            identities.add((key, url))
            parts.append({"number": number, "offset": offset, "size": size})
        if len(identities) != 1 or len({p["number"] for p in parts}) != len(parts):
            raise ValueError("mixed objects or duplicate parts")
        parts.sort(key=lambda p: p["offset"])
        total = 0
        for p in parts:
            if p["offset"] != total:
                raise ValueError("non-contiguous part layout")
            total += p["size"]
        if total > MAX_TOTAL:
            raise ValueError("diagnostic upload exceeds 8 GiB capture limit")
        key, url = identities.pop()
        folder = self.root / key
        folder.mkdir(exist_ok=True)
        manifest = folder / "manifest.json"
        plan = {"version": 1, "object_url": url, "total_bytes": total,
                "parts": parts, "saved": {}}
        if manifest.exists():
            previous = json.loads(manifest.read_text(encoding="utf-8"))
            if any(previous.get(k) != plan[k] for k in ("version", "object_url", "total_bytes", "parts")):
                raise ValueError("existing manifest differs from upload plan")
            plan["saved"] = previous.get("saved", {})
        atomic_json(manifest, plan)
        crypto = {**(request_crypto or {}), **encryption_fields(data)}
        if crypto:
            # Private runtime file under logs/, never part of the source distribution.
            atomic_json(folder / "encryption-metadata.json", crypto)
            ctx.log.warn("[upload-encryption-info] 发现明确的加密字段，已单独保存至本地；不在控制台显示值。")
        self.plans[key] = (folder, plan, {p["number"]: p for p in parts})
        ctx.log.warn(f"[upload-plan] {len(parts)} 片，{total / 1024**3:.2f} GiB；本地目录：{folder}")
        if shutil.disk_usage(folder).free < total + 256 * 1024**2:
            ctx.log.warn("[upload-capture-warning] 空余硬盘可能不足以保存全部分片。")

    def response(self, flow):
        if self.root and flow.response and flow.request.host == OSS_HOST:
            try:
                key, _, _ = upload_identity(flow.request.pretty_url)
                if key in self.plans:
                    headers = {k: v for k, v in flow.response.headers.items()
                               if k.lower() in {"x-oss-server-side-encryption",
                                                "x-oss-server-side-encryption-key-id"}}
                    if headers:
                        atomic_json(self.plans[key][0] / "oss-encryption-metadata.json", headers)
            except (ValueError, TypeError, OSError):
                pass
        if (flow.request.host == APPLY_HOST
                and flow.request.path.split("?", 1)[0] == APPLY_PATH and flow.response):
            try:
                self.register_plan(json.loads(flow.response.get_content(strict=False)),
                                   flow.metadata.get("log_upload_encryption_fields"))
            except (ValueError, TypeError, KeyError, OSError) as exc:
                ctx.log.warn(f"[upload-capture-warning] 无法读取上传计划：{type(exc).__name__}")

    def requestheaders(self, flow):
        if not self.root or flow.request.method != "PUT":
            return
        try:
            key, _, number = upload_identity(flow.request.pretty_url)
        except (ValueError, TypeError):
            return
        if key not in self.plans:
            ctx.log.warn("[upload-capture-warning] 看到了上传分片，但缺少申请响应；请在上传开始前启动观察模式。")
            return
        folder, plan, specs = self.plans[key]
        if number not in specs or callable(flow.request.stream):
            return
        try:
            attempt = folder / ("part-%05d-%s.pending" % (number, hashlib.sha256(flow.id.encode()).hexdigest()[:16]))
            stream = attempt.open("xb")
        except OSError as exc:
            ctx.log.warn(f"[upload-capture-warning] 不能保存分片：{type(exc).__name__}；继续转发。")
            return
        state = {"stream": stream, "path": attempt, "key": key, "number": number,
                 "count": 0, "sha": hashlib.sha256(), "failed": False}
        self.active[flow.id] = state

        def copy_chunk(chunk):
            # Return the original bytes even if the local disk fails.
            if not state["failed"] and chunk:
                try:
                    if state["count"] + len(chunk) > specs[number]["size"]:
                        raise OSError("part exceeds declared size")
                    stream.write(chunk)
                    state["sha"].update(chunk)
                    state["count"] += len(chunk)
                except (OSError, ValueError) as exc:
                    state["failed"] = True
                    ctx.log.warn(f"[upload-capture-warning] 本地分片写入失败：{type(exc).__name__}；继续转发。")
            return chunk

        flow.request.stream = copy_chunk

    def request(self, flow):
        self.finish(flow.id)
        if (self.root and flow.request.host == APPLY_HOST
                and flow.request.path.split("?", 1)[0] == APPLY_PATH):
            try:
                fields = encryption_fields(json.loads(flow.request.get_content(strict=False)), "request")
                if fields:
                    flow.metadata["log_upload_encryption_fields"] = fields
            except (ValueError, TypeError):
                pass

    def finish(self, flow_id):
        state = self.active.pop(flow_id, None)
        if not state:
            return
        try:
            state["stream"].close()
            folder, plan, specs = self.plans[state["key"]]
            number = state["number"]
            if state["failed"] or state["count"] != specs[number]["size"]:
                os.replace(state["path"], folder / f"part-{number:05d}.incomplete")
                ctx.log.warn(f"[upload-part-incomplete] 第 {number} 片未完整保存，不计入完整副本。")
                return
            digest = state["sha"].hexdigest()
            old = plan["saved"].get(str(number))
            if old and old.get("sha256") != digest:
                old["conflict"] = True
                atomic_json(folder / "manifest.json", plan)
                ctx.log.warn(f"[upload-capture-warning] 第 {number} 片重试内容不同；合并将停止，请保留现场。")
                return
            destination = folder / f"part-{number:05d}.bin"
            os.replace(state["path"], destination)
            plan["saved"][str(number)] = {"size": state["count"], "sha256": digest}
            atomic_json(folder / "manifest.json", plan)
            count = len(plan["saved"])
            if count == 1 or count % 10 == 0 or count == len(specs):
                ctx.log.warn(f"[upload-saved] 本地已保存 {count}/{len(specs)} 片：{folder}")
            if count == len(specs):
                ctx.log.warn("[upload-local-complete] 分片已齐；停止观察工具后运行 assemble_upload.py 合并。")
        except OSError as exc:
            ctx.log.warn(f"[upload-capture-warning] 分片落盘失败：{type(exc).__name__}；网络上传不作改动。")

    def error(self, flow):
        # An upstream failure can occur after all request bytes have arrived.
        self.finish(flow.id)

    def done(self):
        for flow_id in list(self.active):
            self.finish(flow_id)


addons = [LogUploadCapture()]
