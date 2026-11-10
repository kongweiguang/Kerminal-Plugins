# @author kongweiguang
"""Exercise catalog registration and verified artifact boundaries without network or signing."""
import importlib.util
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import sys
import subprocess
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import media_v1
import publication_v1

spec = importlib.util.spec_from_file_location("catalog_v1", Path(__file__).resolve().parents[1] / "catalog-v1.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        """Use a fresh directory so tests never access a real catalog or key."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "plugins").mkdir()
        (self.root / "categories.toml").write_text('[categories.productivity]\nen="Productivity"\nzh-CN="效率"\n', encoding="utf-8")

    def registration(self, text):
        """Keep each test independent of the checked-in pending examples."""
        (self.root / "plugins" / "acme.notes.toml").write_text(text, encoding="utf-8")

    def test_pending_never_creates_a_catalog_entry(self):
        """待发布条目必须保持空目录，顶层仍遵循宿主协议，不能偷偷虚构资产。"""
        self.registration('status="pending"\ncategories=["productivity"]\n')
        self.assertEqual(catalog.build_catalog(self.root, "unused", 1), {"schema": 1, "source_id": "official", "sequence": 1, "plugins": []})
        self.registration('status="pending"\ncategories=["productivity"]\nrepository="https://github.com/acme/notes"\n')
        with self.assertRaises(ValueError):
            catalog.load_registrations(self.root)

    def test_version_and_reserved_owner_rejected(self):
        """A mismatched tag or forged official owner cannot enter a release."""
        self.registration('repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v2.0.0"\n')
        with self.assertRaises(ValueError):
            catalog.load_registrations(self.root)
        (self.root / "plugins" / "acme.notes.toml").unlink()
        (self.root / "plugins" / "kerminal.notes.toml").write_text('repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            catalog.load_registrations(self.root)

    def test_real_asset_bytes_produce_digest_and_manifest_identity(self):
        """真实字节摘要及每层字段都对应宿主严格契约，不遗漏 schema 或添加不支持字段。"""
        self.registration('repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n')
        name = "acme.notes-1.0.0-any.kplugin"
        manifest = {"id":"acme.notes", "version":"1.0.0", "name":{"en":"Notes"}, "description":{"en":"Notes"}, "publisher":"acme", "categories":["productivity"], "runtime":{"kind":"script"}, "api":"^1.0", "icon":"icon.png"}
        raw = json.dumps(manifest).encode()
        asset = self.root / name
        with tarfile.open(asset, "w:gz") as archive:
            info = tarfile.TarInfo("kerminal-plugin.json")
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
            icon = b'\x89PNG\r\n\x1a\nexample'
            info = tarfile.TarInfo('icon.png')
            info.size = len(icon)
            archive.addfile(info, io.BytesIO(icon))
        def fake_run(command, **kwargs):
            """Simulate download and validator independently of network and external tools."""
            if command[:3] == ["gh", "release", "download"]:
                (Path(command[command.index("--dir") + 1]) / name).write_bytes(asset.read_bytes())
            return None
        release = {"tagName":"v1.0.0", "isDraft":False, "publishedAt":"2026-11-09T00:00:00Z", "assets":[{"name":name}]}
        with patch.object(catalog, "run_json", return_value=release), patch.object(catalog.subprocess, "run", side_effect=fake_run), patch.object(media_v1, "read_readme", return_value=("README.md", "![preview](images/p.png)")), patch.object(media_v1, "fetch_image", return_value=(icon, "image/png")):
            result = catalog.build_catalog(self.root, "validator", 2)
        item = result["plugins"][0]
        self.assertEqual(item["versions"][0]["assets"][0]["sha256"], catalog.hashlib.sha256(asset.read_bytes()).hexdigest())
        self.assertEqual(item["versions"][0]["assets"][0]["size"], asset.stat().st_size)
        self.assertEqual(item["permissions"], [])
        self.assertIn("/catalog-v1-2/media-", item["icon_url"])
        self.assertIn("/catalog-v1-2/media-", item["readme_url"])
        media = self.root / ".local" / "catalog-media"
        readme = (media / item["readme_url"].split("/")[-1]).read_text(encoding="utf-8")
        self.assertIn("/catalog-v1-2/media-", readme)
        self.assertNotIn("images/p.png", readme)
        self.assertEqual((media / item["icon_url"].split("/")[-1]).read_bytes(), icon)
        serialized = json.loads(json.dumps(result))
        self.assertEqual(set(serialized), {"schema", "source_id", "sequence", "plugins"})
        self.assertEqual(serialized["schema"], 1)
        self.assertEqual(serialized["source_id"], "official")
        self.assertEqual(set(item), {"id", "name", "description", "publisher", "categories", "icon_url", "readme_url", "repository", "permissions", "versions"})
        self.assertEqual(set(item["versions"][0]), {"version", "api", "published_at", "changelog_url", "assets"})
        self.assertEqual(set(item["versions"][0]["assets"][0]), {"platform", "url", "sha256", "size"})
        self.assertEqual(serialized["sequence"], 2)
        self.assertEqual(serialized["plugins"][0]["versions"][0]["assets"][0]["platform"], "any")

    def test_host_integer_version_and_byte_limits(self):
        """生成前限制宿主整数、版本数量与最终 UTF-8 大小，避免签名发布无法读取的目录。"""
        self.registration('status="pending"\ncategories=["productivity"]\n')
        for sequence in (True, 0, -1, 2**64):
            with self.assertRaises(ValueError):
                catalog.build_catalog(self.root, "unused", sequence)
        oversized = {"text": "中" * (catalog.MAX_CATALOG_BYTES // 2)}
        with self.assertRaises(ValueError):
            catalog.catalog_bytes(oversized)
        self.assertEqual(catalog.catalog_bytes({"schema": 1}), b'{\n  "schema": 1\n}\n')
        versions = "".join(f'[[versions]]\nversion="1.0.{index}"\ntag="v1.0.{index}"\n' for index in range(1025))
        self.registration('repository="https://github.com/acme/notes"\ncategories=["productivity"]\n' + versions)
        with self.assertRaises(ValueError):
            catalog.load_registrations(self.root)

    def test_update_preserves_published_package_bytes_and_allows_new_versions(self):
        """历史资产、平台和 API 不可改写或删除，新版本和显示元数据更新仍可发布。"""
        old = {"schema": 1, "source_id": "official", "sequence": 1, "plugins": [{"id": "acme.notes", "name": {"en": "Notes"}, "versions": [{"version": "1.0.0", "api": "^1.0", "assets": [{"platform": "any", "url": "https://github.com/acme/notes/releases/download/v1.0.0/acme.notes-1.0.0-any.kplugin", "sha256": "a" * 64, "size": 100}]}]}]}
        candidate = copy.deepcopy(old)
        candidate["sequence"] = 2
        candidate["plugins"][0]["name"]["en"] = "New display name"
        newer = copy.deepcopy(candidate["plugins"][0]["versions"][0])
        newer["version"] = "1.1.0"
        candidate["plugins"][0]["versions"].append(newer)
        publication_v1.validate_update(old, candidate)
        for field, value in (("sha256", "b" * 64), ("size", 101), ("url", "https://github.com/acme/other"), ("platform", "windows-x86_64")):
            changed = copy.deepcopy(candidate)
            changed["plugins"][0]["versions"][0]["assets"][0][field] = value
            with self.assertRaises(ValueError):
                publication_v1.validate_update(old, changed)
        for change in ("api", "remove", "sequence", "source", "duplicate"):
            changed = copy.deepcopy(candidate)
            if change == "api":
                changed["plugins"][0]["versions"][0]["api"] = "^2.0"
            elif change == "remove":
                changed["plugins"][0]["versions"].pop(0)
            elif change == "sequence":
                changed["sequence"] = 3
            elif change == "source":
                changed["source_id"] = "other"
            else:
                changed["plugins"].append(copy.deepcopy(changed["plugins"][0]))
            with self.assertRaises(ValueError):
                publication_v1.validate_update(old, changed)

    def test_catalog_sequence_refuses_interrupted_or_unverified_state(self):
        """固定目录与已发布快照必须一致；中断不能导致序列复用。"""
        self.assertEqual(publication_v1.next_sequence(None, [], True), 1)
        releases = [{"tagName": "catalog-v1"}, {"tagName": "catalog-v1-1"}]
        self.assertEqual(publication_v1.next_sequence({"sequence": 1}, releases, False), 2)
        for fixed, records, bootstrap in (
            (None, [], False),
            (None, [{"tagName": "catalog-v1-1"}], True),
            ({"sequence": 1}, releases + [{"tagName": "catalog-v1-2"}], False),
            ({"sequence": 1}, [{"tagName": "catalog-v1"}], False),
            ({"sequence": True}, releases, False),
            (None, releases, True),
        ):
            with self.assertRaises(ValueError):
                publication_v1.next_sequence(fixed, records, bootstrap)

    def test_publication_cli_compares_candidate_before_signing(self):
        """执行工作流调用的真实 CLI，确保候选比较选项不会只存在于未接线的函数测试中。"""
        previous = {"schema": 1, "source_id": "official", "sequence": 1, "plugins": [{"id": "acme.notes", "versions": [{"version": "1.0.0", "api": "^1.0", "assets": [{"platform": "any", "url": "https://github.com/acme/notes/a.kplugin", "sha256": "a" * 64, "size": 100}]}]}]}
        candidate = copy.deepcopy(previous)
        candidate["sequence"] = 2
        releases = [{"tagName": "catalog-v1"}, {"tagName": "catalog-v1-1"}]
        for name, document in (("previous", previous), ("candidate", candidate), ("releases", releases)):
            (self.root / f"{name}.json").write_text(json.dumps(document), encoding="utf-8")
        command = [sys.executable, str(Path(publication_v1.__file__)), "--releases", str(self.root / "releases.json"), "--fixed", str(self.root / "previous.json"), "--candidate", str(self.root / "candidate.json")]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "2")
        candidate["plugins"][0]["versions"][0]["assets"][0]["sha256"] = "b" * 64
        (self.root / "candidate.json").write_text(json.dumps(candidate), encoding="utf-8")
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("published package cannot be changed", result.stderr)

    def test_media_rejects_untrusted_paths_and_formats(self):
        """路径穿越、不可信跳转目标及活动 SVG 都不能进入目录资产。"""
        for url in ("https://github.com.evil.test/icon.png", "http://github.com/icon.png", "https://github.com@evil.test/icon.png", "https://github.com/a/../secret.png"):
            with self.assertRaises(ValueError):
                media_v1.checked_url(url)
        for path in ("../secret.png", "%2e%2e/secret.png", "%252e%252e/secret.png", "/absolute.png", "dir\\secret.png"):
            with self.assertRaises(ValueError):
                media_v1.image_url(path, "acme/notes", "v1.0.0", "README.md")
        self.assertEqual(media_v1.image_url("images/a.png", "acme/notes", "v1.0.0", "README.md"), "https://raw.githubusercontent.com/acme/notes/v1.0.0/images/a.png")
        with self.assertRaises(ValueError):
            media_v1.TrustedRedirect().redirect_request(media_v1.urllib.request.Request("https://github.com/a"), None, 302, "Found", {}, "https://evil.test/x")
        with self.assertRaises(ValueError):
            media_v1.image_extension(b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>', "image/svg+xml")
        with self.assertRaises(ValueError):
            media_v1.image_extension(b"not an image", "image/png")
        with self.assertRaises(ValueError):
            media_v1.image_extension(b"x" * (media_v1.MAX_IMAGE + 1), "image/png")


if __name__ == "__main__":
    unittest.main()
