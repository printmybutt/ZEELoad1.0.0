"""Offline capture/assembly checks; no vehicle, vendor API, or network changes."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

sys.path.insert(0, str(Path(__file__).parent / "addons"))
import log_upload_capture as capture
import assemble_upload


def fixture(payload=None):
    if payload is None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("local-fixture.txt", b"diagnostic-test\n" * 300)
        payload = buffer.getvalue()
    split = len(payload) // 3
    chunks = [payload[:split], payload[split:split * 2], payload[split * 2:]]
    base = f"https://{capture.OSS_HOST}{capture.LOG_PREFIX}fixture.zip"
    offset, parts = 0, []
    for i, block in enumerate(chunks, 1):
        parts.append({"url": f"{base}?partNumber={i}&uploadId=PRIVATE-FIXTURE-ID",
                      "partNum": i, "partSize": len(block), "offset": offset,
                      "headers": {"Authorization": "PRIVATE-FIXTURE-SIGNATURE"}})
        offset += len(block)
    return payload, chunks, {"code": "0", "data": {"partUriInfos": parts}}


class UploadCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addon = capture.LogUploadCapture()
        self.addon.root = self.root
        self.context = patch.object(capture, "ctx", Mock())
        self.context.start()
        self.addCleanup(self.context.stop)
        self.payload, self.blocks, self.response = fixture()
        self.addon.register_plan(self.response)
        self.folder = next(self.root.iterdir())

    def part(self, index, body=None, flow_id=None):
        flow = Mock()
        flow.id = flow_id or f"flow-{index}"
        flow.request.method = "PUT"
        flow.request.pretty_url = self.response["data"]["partUriInfos"][index - 1]["url"]
        flow.request.stream = True
        self.addon.requestheaders(flow)
        self.assertTrue(callable(flow.request.stream))
        body = self.blocks[index - 1] if body is None else body
        for i in range(0, len(body), 73):
            block = body[i:i + 73]
            self.assertEqual(flow.request.stream(block), block)
        self.assertEqual(flow.request.stream(b""), b"")
        self.addon.request(flow)
        return flow

    def test_out_of_order_and_retry_are_saved_and_assembled_exactly(self):
        for index in [3, 1, 1, 2]:
            self.part(index)
        manifest = json.loads((self.folder / "manifest.json").read_text())
        self.assertEqual(len(manifest["saved"]), 3)
        self.assertFalse(list(self.folder.glob("*.pending")))
        with contextlib.redirect_stdout(io.StringIO()):
            output = assemble_upload.assemble(self.folder)
        self.assertEqual(output.read_bytes(), self.payload)
        private = "\n".join(p.read_text() for p in self.folder.glob("*.json"))
        self.assertNotIn("PRIVATE-FIXTURE", private)
        self.assertNotIn("Authorization", private)

    def test_incomplete_part_and_missing_part_never_become_full_zip(self):
        self.part(1)
        self.part(2, self.blocks[1][:-5])
        with self.assertRaisesRegex(ValueError, "缺少 2/3"):
            assemble_upload.assemble(self.folder)
        self.assertFalse(list(self.folder.glob("*.zip*")))

    def test_disk_failure_keeps_all_forwarded_bytes_unchanged(self):
        flow = Mock()
        flow.id = "disk-failure"
        flow.request.method = "PUT"
        flow.request.pretty_url = self.response["data"]["partUriInfos"][0]["url"]
        flow.request.stream = True
        failed = Mock()
        failed.write.side_effect = OSError("test disk full")
        with patch.object(Path, "open", return_value=failed):
            self.addon.requestheaders(flow)
        block = self.blocks[0]
        self.assertEqual(flow.request.stream(block), block)
        self.addon.request(flow)
        self.assertEqual(json.loads((self.folder / "manifest.json").read_text())["saved"], {})

    def test_tampered_part_is_rejected_and_partial_output_removed(self):
        for i in [1, 2, 3]:
            self.part(i)
        part = self.folder / "part-00002.bin"
        content = bytearray(part.read_bytes())
        content[0] ^= 1
        part.write_bytes(content)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            assemble_upload.assemble(self.folder)
        self.assertFalse(list(self.folder.glob("*.zip*")))

    def test_unknown_upload_and_non_log_paths_are_not_captured(self):
        flow = Mock()
        flow.id = "unknown"
        flow.request.method = "PUT"
        flow.request.stream = False
        flow.request.pretty_url = self.response["data"]["partUriInfos"][0]["url"].replace("fixture.zip", "other.zip")
        self.addon.requestheaders(flow)
        self.assertFalse(flow.request.stream)
        with self.assertRaises(ValueError):
            capture.upload_identity(flow.request.pretty_url.replace(capture.LOG_PREFIX, "/other/"))

    def test_bad_plan_is_rejected_before_capture(self):
        self.response["data"]["partUriInfos"][1]["offset"] += 1
        with self.assertRaisesRegex(ValueError, "non-contiguous"):
            self.addon.register_plan(self.response)

    def test_conflicting_retry_prevents_assembly(self):
        for i in [1, 2, 3]:
            self.part(i)
        changed = bytearray(self.blocks[0]); changed[0] ^= 1
        self.part(1, bytes(changed))
        with self.assertRaisesRegex(ValueError, "冲突"):
            assemble_upload.assemble(self.folder)

    def test_explicit_encryption_fields_are_private_and_auth_is_excluded(self):
        self.response["data"].update({"encryption": {"algorithm": "fixture-AES", "key": "LOCAL-ONLY-KEY"},
                                      "zipPassword": "LOCAL-ONLY-PASSWORD"})
        self.addon.register_plan(self.response)
        private = json.loads((self.folder / "encryption-metadata.json").read_text())
        self.assertEqual(private["data.encryption.key"], "LOCAL-ONLY-KEY")
        self.assertEqual(private["data.zipPassword"], "LOCAL-ONLY-PASSWORD")
        self.assertNotIn("PRIVATE-FIXTURE", json.dumps(private))
        public_index = (self.folder / "manifest.json").read_text()
        self.assertNotIn("LOCAL-ONLY", public_index)

    def test_complete_non_zip_payload_is_preserved_as_bin(self):
        raw, chunks, response = fixture(b"opaque-possibly-encrypted-fixture" * 80)
        other = capture.LogUploadCapture()
        other.root = self.root / "opaque"
        other.root.mkdir()
        other.register_plan(response)
        self.addon, self.blocks, self.response = other, chunks, response
        self.folder = next(other.root.iterdir())
        for i in [1, 2, 3]:
            self.part(i)
        with contextlib.redirect_stdout(io.StringIO()):
            output = assemble_upload.assemble(self.folder)
        self.assertEqual(output.suffix, ".bin")
        self.assertEqual(output.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
