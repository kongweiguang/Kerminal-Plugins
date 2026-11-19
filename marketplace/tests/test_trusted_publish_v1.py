# @author kongweiguang
"""可信发布侧 v1 的本地隔离测试：不联网、不签名、不发布、不读密钥。

覆盖三类断言：
- 受信实现的功能正确性（登记绑定、回执契约、签名计划）；
- fail-closed 行为（回执谎言、状态漂移、跨轨基线、伪造引用全部拒绝）；
- 隔离不变量（受信模块必须拒绝错误来源的 publication_v1，生成器只能从
  受信检出加载）。
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import trusted_publish_v1 as trusted

# 直接加载与受信模块同检出的 publication_v1，供测试构造基线目录使用。
spec_pub = importlib.util.spec_from_file_location("publication_v1", Path(__file__).resolve().parents[1] / "publication_v1.py")
publication_v1 = importlib.util.module_from_spec(spec_pub)
spec_pub.loader.exec_module(publication_v1)


DIGEST = "a" * 64


def asset(platform="any", sha=DIGEST, size=100):
    """构造一条宿主严格契约内的资产记录，供目录构造复用。"""
    return {"platform": platform, "url": "", "sha256": sha, "size": size}


def version(number="1.0.0", assets=None):
    """构造版本记录；URL 在 catalog() 里按确定性规则回填。"""
    return {
        "version": number,
        "api": "^1.0",
        "published_at": "2026-11-11T00:00:00Z",
        "changelog_url": "",
        "assets": [asset()] if assets is None else assets,
    }


def catalog(sequence=1, versions=None, icon=None, plugin_id="acme.notes", publisher="acme", repository="https://github.com/acme/notes"):
    """按 v1 轨道身份构造最小合法候选目录；URL 全部按确定性规则重建。

    id/publisher/repository 可定制：changelog 与资产 URL 都从 repository 重建，
    保证改 ID 的用例不会因为写死 acme/notes 的 URL 而在无关字段上失败。
    """
    plugin_versions = [version()] if versions is None else versions
    owner_repo = repository.removeprefix("https://github.com/")
    for entry in plugin_versions:
        entry["changelog_url"] = f"https://github.com/{owner_repo}/releases/tag/v{entry['version']}"
        for item in entry["assets"]:
            item["url"] = trusted._asset_url(plugin_id, entry["version"], item["platform"], repository)
    plugin = {
        "id": plugin_id,
        "name": {"en": "Notes"},
        "description": {"en": "Notes"},
        "publisher": publisher,
        "permissions": [],
        "categories": ["productivity"],
        "icon_url": icon,
        "readme_url": f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-{sequence}/media-{'c' * 64}.md",
        "repository": repository,
        "versions": plugin_versions,
    }
    return {"schema": 1, "source_id": "official", "sequence": sequence, "plugins": [plugin]}


def release(tag):
    """GitHub Release 列表只关心 tagName。"""
    return {"tagName": tag}


def write_media(directory):
    """创建一个内容寻址合法的媒体文件并返回 (名称, 摘要)。"""
    data = b"readme body"
    digest = hashlib.sha256(data).hexdigest()
    name = f"media-{digest}.md"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)
    return name, digest


class GeneratorSourceTests(unittest.TestCase):
    def test_generator_is_loaded_from_trusted_dir(self):
        """生成器必须从受信模块同目录加载：钉住路径错位在导入期就应失败。"""
        module = trusted._load_generator()
        self.assertEqual(Path(module.__file__).resolve().parent, trusted._MODULE_DIR)

    def test_publication_source_mismatch_is_rejected(self):
        """publication_v1 来自其它路径时受信模块必须立即失败，防止候选注入同名模块。"""
        fake = type(sys)("publication_v1")
        fake.__file__ = str(Path(tempfile.gettempdir()) / "elsewhere" / "publication_v1.py")
        with self.assertRaises(ImportError):
            trusted.require_same_checkout_publication(fake)

    def test_pinned_publication_missing_primitive_is_rejected(self):
        """钉住检出缺少所需原语（过期提交）时守卫必须失败，不允许半能力运行。"""
        fake = type(sys)("publication_v1")
        fake.__file__ = str(trusted._MODULE_DIR / "publication_v1.py")
        with self.assertRaises(ImportError):
            trusted.require_same_checkout_publication(fake)


class RegistrationBindingTests(unittest.TestCase):
    def setUp(self):
        """每个用例独立的临时数据根，绝不触碰真实仓库数据。"""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "plugins").mkdir()
        (self.root / "categories.toml").write_text('[categories.productivity]\nen="Productivity"\nzh-CN="效率"\n', encoding="utf-8")
        self.generator = trusted._load_generator()

    def registration(self, text):
        """写入一个已发布登记；构造保持与生成器契约一致。"""
        (self.root / "plugins" / "acme.notes.toml").write_text(
            'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n',
            encoding="utf-8",
        )

    def test_binding_accepts_matching_catalog(self):
        """目录与登记一致时绑定通过；这是评审对象与发布物的同一性契约。"""
        self.registration("")
        binding = trusted._registration_binding(self.generator, self.root, catalog())
        self.assertIsNone(binding)

    def test_binding_rejects_drifted_catalog(self):
        """目录仓库或分类与登记脱钩时必须失败：目录不能脱离评审数据自行演化。"""
        self.registration("")
        drifted = catalog()
        drifted["plugins"][0]["repository"] = "https://github.com/other/notes"
        with self.assertRaises(ValueError):
            trusted._registration_binding(self.generator, self.root, drifted)
        drifted = catalog()
        drifted["plugins"][0]["categories"] = ["utilities"]
        with self.assertRaises(ValueError):
            trusted._registration_binding(self.generator, self.root, drifted)

    def test_binding_rejects_extra_or_missing_plugins(self):
        """多出或缺失的插件都破坏登记同一性；pending 登记不要求出现在目录中。"""
        self.registration("")
        extra = catalog()
        extra["plugins"].append(dict(extra["plugins"][0], id="acme.extra"))
        with self.assertRaises(ValueError):
            trusted._registration_binding(self.generator, self.root, extra)
        (self.root / "plugins" / "acme.notes.toml").unlink()
        (self.root / "plugins" / "acme.notes.toml").write_text('status="pending"\ncategories=["productivity"]\n', encoding="utf-8")
        # pending 登记不进入目录：目录为空时绑定通过（但生成器会拒绝空目录发布）。
        trusted._registration_binding(self.generator, self.root, {"schema": 1, "source_id": "official", "sequence": 1, "plugins": []})


class MediaManifestTests(unittest.TestCase):
    def test_media_manifest_requires_content_addressed_names(self):
        """媒体集合必须是平坦的内容寻址文件；其它名称或子目录一律失败。"""
        with tempfile.TemporaryDirectory() as temp:
            media = Path(temp)
            name, digest = write_media(media)
            self.assertEqual(trusted.media_manifest(media), {name: digest})
            (media / "evil.txt").write_bytes(b"x")
            with self.assertRaises(ValueError):
                trusted.media_manifest(media)
            (media / "evil.txt").unlink()
            (media / "sub").mkdir()
            with self.assertRaises(ValueError):
                trusted.media_manifest(media)

    def test_missing_media_dir_is_empty_manifest(self):
        """媒体目录不存在视为空集合，等 bootstrap 场景使用。"""
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(trusted.media_manifest(Path(temp) / "absent"), {})


class SafeReadTests(unittest.TestCase):
    """read_limited_regular_file 的安全读取语义：限额、链接与非常规文件拒绝。"""

    def test_reads_regular_file_within_limit(self):
        """合法常规文件在限额内完整读取，内容逐字节一致。"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "regular.bin"
            payload = b"x" * 1000
            path.write_bytes(payload)
            self.assertEqual(trusted.read_limited_regular_file(path, 1000, "test input"), payload)

    def test_over_limit_is_rejected_without_reading_all(self):
        """超过 limit 的输入被拒绝；限额覆盖真正的读取流而非先整读再检查。"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "big.bin"
            path.write_bytes(b"y" * 4096)
            with self.assertRaises(ValueError) as caught:
                trusted.read_limited_regular_file(path, 100, "test input")
            self.assertIn("exceeds size limit", str(caught.exception))

    def test_symlink_is_rejected(self):
        """符号链接（即使指向合法常规文件）必须拒绝，不按路径跟随。"""
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "target.bin"
            target.write_bytes(b"ok")
            link = Path(temp) / "link.bin"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform/account")
            with self.assertRaises(ValueError):
                trusted.read_limited_regular_file(link, 100, "test input")

    def test_directory_is_rejected(self):
        """目录不是常规文件，直接拒绝。"""
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "dir"
            directory.mkdir()
            with self.assertRaises(ValueError):
                trusted.read_limited_regular_file(directory, 100, "test input")

    def test_missing_file_is_rejected(self):
        """缺失输入以统一 ValueError 失败，不泄漏为裸 OSError。"""
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                trusted.read_limited_regular_file(Path(temp) / "absent", 100, "test input")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs require a POSIX platform")
    def test_fifo_is_rejected_without_blocking(self):
        """FIFO 必须 open 即返回（O_NONBLOCK）并按 fstat 拒绝，不能挂死任务。"""
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "pipe"
            os.mkfifo(fifo)
            # 若实现遗漏 O_NONBLOCK，open 会阻塞等写者，本测试会超时失败。
            with self.assertRaises(ValueError):
                trusted.read_limited_regular_file(fifo, 100, "test input")

    def test_load_json_uses_limited_read(self):
        """load_json 经安全限读：超限 JSON 拒绝、合法 JSON 解析、坏 JSON 拒绝。"""
        with tempfile.TemporaryDirectory() as temp:
            good = Path(temp) / "good.json"
            good.write_text('{"a": 1}', encoding="utf-8")
            self.assertEqual(trusted.load_json(good, 100, "test"), {"a": 1})
            big = Path(temp) / "big.json"
            big.write_text(json.dumps({"k": "v" * 200}), encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                trusted.load_json(big, 100, "test")
            self.assertIn("exceeds size limit", str(caught.exception))
            bad = Path(temp) / "bad.json"
            bad.write_bytes(b"\xff\xfe not json")
            with self.assertRaises(ValueError):
                trusted.load_json(bad, 100, "test")

    def test_media_manifest_rejects_symlink_entry(self):
        """媒体目录中的符号链接条目必须让整个清单失败，不读链接目标。"""
        with tempfile.TemporaryDirectory() as temp:
            media = Path(temp)
            name, _ = write_media(media)
            target = Path(temp) / "outside.md"
            target.write_bytes(b"evil bytes")
            link_name = f"media-{'e' * 64}.md"
            try:
                (media / link_name).symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform/account")
            with self.assertRaises(ValueError):
                trusted.media_manifest(media)

    def test_registrations_manifest_rejects_symlinked_registration(self):
        """登记清单对符号链接登记文件拒绝，保持与媒体同一安全语义。"""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "plugins").mkdir()
            (root / "categories.toml").write_text('[categories.productivity]\nen="P"\nzh-CN="效率"\n', encoding="utf-8")
            real = Path(temp) / "outside.toml"
            real.write_text('repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n', encoding="utf-8")
            try:
                (root / "plugins" / "acme.notes.toml").symlink_to(real)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform/account")
            with self.assertRaises(ValueError):
                trusted.registrations_manifest(root)

    def test_registrations_manifest_accepts_regular_files(self):
        """合法常规登记文件产出确定性清单；重复计算结果一致。"""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "plugins").mkdir()
            (root / "categories.toml").write_text('[categories.productivity]\nen="P"\nzh-CN="效率"\n', encoding="utf-8")
            (root / "plugins" / "acme.notes.toml").write_text(
                'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n',
                encoding="utf-8",
            )
            first = trusted.registrations_manifest(root)
            self.assertEqual(first, trusted.registrations_manifest(root))
            self.assertEqual(
                set(first),
                {"categories.toml", "plugins/acme.notes.toml"},
            )

    def test_media_manifest_accepts_regular_media(self):
        """合法媒体文件（正常大小、内容寻址名）的清单与手工摘要一致。"""
        with tempfile.TemporaryDirectory() as temp:
            media = Path(temp)
            name, digest = write_media(media)
            self.assertEqual(trusted.media_manifest(media), {name: digest})


class FixedBaselineBindingTests(unittest.TestCase):
    """load_fixed_verified 必须让「验签字节」与「解析字节」是同一份有界内容。"""

    def setUp(self):
        """独立临时目录：基线与签名都是本用例本地文件。"""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixed = self.root / "catalog.json"
        self.signature = self.root / "catalog.json.minisig"
        self.pubkey = self.root / "publisher.pub"

    def test_verified_bytes_are_parsed_despite_path_swap(self):
        """验签期间替换固定基线路径：返回的 JSON 必须来自交给 minisign 的同一份字节。"""
        original = {"schema": 1, "source_id": "official", "sequence": 1, "plugins": []}
        original_bytes = json.dumps(original).encode("utf-8")
        self.fixed.write_bytes(original_bytes)
        self.signature.write_bytes(b"signature bytes")
        captured = {}

        def fake_run(command, check, capture_output):
            """模拟 minisign：记录它看到的副本，并把原路径换成另一份内容。"""
            captured["verified"] = Path(command[2]).read_bytes()
            captured["signature"] = Path(command[4]).read_bytes()
            self.fixed.write_bytes(b'{"schema": 1, "source_id": "official", "sequence": 9, "plugins": []}')
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with patch.object(trusted.subprocess, "run", side_effect=fake_run):
            parsed = trusted.load_fixed_verified(self.fixed, self.signature, self.pubkey)
        self.assertEqual(parsed, original)
        self.assertEqual(captured["verified"], original_bytes)
        self.assertEqual(captured["signature"], b"signature bytes")
        # 路径上此刻是替换后的内容：证明解析结果不是二次打开路径得到的。
        self.assertEqual(json.loads(self.fixed.read_text(encoding="utf-8"))["sequence"], 9)

    def test_verification_failure_never_parses(self):
        """minisign 非零退出时必须直接失败，解析器不得接触未验签内容。"""
        self.fixed.write_bytes(b'{"schema": 1, "source_id": "official", "sequence": 1, "plugins": []}')
        self.signature.write_bytes(b"signature bytes")

        def failing_run(command, check, capture_output):
            """模拟验签失败：调用方必须整体失败而不是继续解析。"""
            raise subprocess.CalledProcessError(1, command)

        with patch.object(trusted.subprocess, "run", side_effect=failing_run):
            with patch.object(trusted.json, "loads", side_effect=AssertionError("parsed without verified bytes")):
                with self.assertRaises(subprocess.CalledProcessError):
                    trusted.load_fixed_verified(self.fixed, self.signature, self.pubkey)

    def test_over_limit_fixed_fails_before_minisign(self):
        """超限固定基线在限读处失败：minisign 不得被调用。"""
        self.fixed.write_bytes(b"x" * 100)
        self.signature.write_bytes(b"signature bytes")
        with patch.object(trusted, "MAX_CATALOG_BYTES", 10):
            with patch.object(trusted.subprocess, "run", side_effect=AssertionError("minisign ran on truncated read")):
                with self.assertRaisesRegex(ValueError, "exceeds size limit"):
                    trusted.load_fixed_verified(self.fixed, self.signature, self.pubkey)


class CandidateSingleReadTests(unittest.TestCase):
    """build_sign_plan 对候选只做一次有界安全读取；摘要与解析看同一 bytes。"""

    def setUp(self):
        """独立临时目录与最小一致材料（数据根、媒体、候选、回执）。"""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_root = self.root / "data"
        (self.data_root / "plugins").mkdir(parents=True)
        (self.data_root / "categories.toml").write_text('[categories.productivity]\nen="P"\nzh-CN="效率"\n', encoding="utf-8")
        (self.data_root / "plugins" / "acme.notes.toml").write_text(
            'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n',
            encoding="utf-8",
        )
        self.media = self.root / "media"
        name, digest = write_media(self.media)
        self.candidate_path = self.root / "catalog.json"
        candidate = catalog()
        candidate["plugins"][0]["readme_url"] = f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-1/{name}"
        self.candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        self.receipt = {
            "track": "v1",
            "repository": trusted.MARKET_REPOSITORY,
            "sequence": 1,
            "candidate_sha256": hashlib.sha256(self.candidate_path.read_bytes()).hexdigest(),
            "media_manifest": {name: digest},
            "registrations_manifest": trusted.registrations_manifest(self.data_root),
        }

    def test_plan_accepts_consistent_bootstrap(self):
        """合法 bootstrap 材料产出一贯计划（守护单次读取重构的行为等价性）。"""
        plan = trusted.build_sign_plan(
            self.receipt, self.candidate_path, None, [], self.media, self.data_root, bootstrap=True,
        )
        self.assertEqual((plan["sequence"], plan["bootstrap"]), (1, True))

    def test_over_limit_candidate_fails_without_full_read(self):
        """超限候选必须在安全读取处失败；证明读取流有界，验证器看不到全部字节。"""
        bloated = json.dumps(self.receipt | {"candidate_sha256": "a" * 64}).encode()
        big_path = self.root / "big.json"
        # 构造一个超过 MAX_CATALOG_BYTES 的"候选"：填充字段撑大但仍是合法 JSON 形状。
        candidate = catalog()
        candidate["plugins"][0]["description"] = {"en": "x" * (trusted.MAX_CATALOG_BYTES + 1024)}
        big_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = dict(self.receipt)
        receipt["candidate_sha256"] = "b" * 64  # 摘要故意不匹配：若实现先整读再解析，也应先在限读处失败
        with patch.object(trusted, "MAX_CATALOG_BYTES", 200):
            with patch.object(trusted.json, "loads", side_effect=AssertionError("parser saw full bytes")):
                with self.assertRaises(ValueError) as caught:
                    trusted.build_sign_plan(receipt, big_path, None, [], self.media, self.data_root, bootstrap=True)
        self.assertIn("exceeds size limit", str(caught.exception))

    def test_single_read_guarantee_under_interleaved_replacement(self):
        """同一次读取的 bytes 同时用于摘要与解析：两次读之间被替换无法让两视图不一致。

        确定性验证：替换 read_limited_regular_file 返回的字节流与 json 解码输入
        必须来自同一来源——用只返回一次固定 bytes 的假读取函数，断言摘要比对与
        结构校验消费的就是这份 bytes（对同一 bytes 摘要不匹配则绝不进入解析）。
        """
        seen = []
        single_bytes = b"single-source-bytes"

        def fake_read(path, limit, what):
            seen.append(what)
            return single_bytes

        with patch.object(trusted, "read_limited_regular_file", side_effect=fake_read):
            with self.assertRaises(ValueError) as caught:
                trusted.build_sign_plan(self.receipt, self.candidate_path, None, [], self.media, self.data_root, bootstrap=True)
        # 候选读取恰好一次；失败原因是摘要不匹配（假字节与回执摘要不符），而
        # 不是解析出错——证明解析与摘要共享同一次读取结果。
        candidate_reads = [what for what in seen if what == "candidate catalog"]
        self.assertEqual(candidate_reads, ["candidate catalog"])
        self.assertIn("candidate bytes changed between verify and sign", str(caught.exception))
        # 摘要匹配时同一 bytes 直接进入解析：构造与假字节一致的回执，解析失败
        # （假字节不是合法 JSON）证明解析消费的就是这份 bytes 而非重新读取。
        receipt = dict(self.receipt)
        receipt["candidate_sha256"] = hashlib.sha256(single_bytes).hexdigest()
        with patch.object(trusted, "read_limited_regular_file", side_effect=fake_read):
            with patch.object(trusted, "media_manifest", return_value=self.receipt["media_manifest"]):
                with patch.object(trusted, "registrations_manifest", return_value=self.receipt["registrations_manifest"]):
                    with patch.object(trusted, "compute_sequence", return_value=1):
                        with self.assertRaises(ValueError) as caught:
                            trusted.build_sign_plan(receipt, self.candidate_path, None, [], self.media, self.data_root, bootstrap=True)
        self.assertIn("not valid UTF-8 JSON", str(caught.exception))
        self.assertEqual([what for what in seen if what == "candidate catalog"], ["candidate catalog", "candidate catalog"])


class MediaDirectorySemanticsTests(unittest.TestCase):
    """media_manifest 对目录本身的三分状态：缺失 / 存在但不合法 / 真实目录。"""

    def test_missing_directory_is_empty_manifest(self):
        """缺失目录返回空清单（合法 bootstrap 场景）。"""
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(trusted.media_manifest(Path(temp) / "absent"), {})

    def test_plain_file_at_directory_path_is_rejected(self):
        """路径上是普通文件时必须失败，不能当空目录。"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "not-a-dir"
            path.write_bytes(b"x")
            with self.assertRaises(ValueError):
                trusted.media_manifest(path)

    def test_directory_symlink_is_rejected(self):
        """指向目录的符号链接不是真实目录，必须失败（is_dir 会跟随，不能用）。"""
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / "real"
            real.mkdir()
            link = Path(temp) / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform/account")
            with self.assertRaises(ValueError):
                trusted.media_manifest(link)


class RegistrationDirectorySemanticsTests(unittest.TestCase):
    """registrations_manifest 对 plugins 目录本身的三分状态与路径同源边界。"""

    MAX_ID = "a" * 39 + "." + "b" * 63

    def _data_root(self, temp):
        """构造带 categories 的数据根，供目录状态用例复用。"""
        root = Path(temp)
        (root / "categories.toml").write_text('[categories.productivity]\nen="P"\nzh-CN="效率"\n', encoding="utf-8")
        return root

    def test_missing_plugins_directory_is_empty_set(self):
        """plugins 缺失不伪造条目：清单只含 categories（分类缺失才由读取失败兜底）。"""
        with tempfile.TemporaryDirectory() as temp:
            root = self._data_root(temp)
            manifest = trusted.registrations_manifest(root)
            self.assertEqual(set(manifest), {"categories.toml"})

    def test_plain_file_at_plugins_path_is_rejected(self):
        """plugins 路径上是普通文件时必须失败：glob 会回落到空集合，掩盖异常状态。"""
        with tempfile.TemporaryDirectory() as temp:
            root = self._data_root(temp)
            (root / "plugins").write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "not a real directory"):
                trusted.registrations_manifest(root)

    def test_plugins_directory_symlink_is_rejected(self):
        """plugins 指向目录的符号链接必须失败：glob 会跟随链接读取 data root 之外。"""
        with tempfile.TemporaryDirectory() as temp:
            root = self._data_root(temp)
            elsewhere = Path(temp) / "elsewhere"
            elsewhere.mkdir()
            (elsewhere / "acme.notes.toml").write_text("categories=[\"productivity\"]\n", encoding="utf-8")
            try:
                (root / "plugins").symlink_to(elsewhere, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform/account")
            with self.assertRaisesRegex(ValueError, "not a real directory"):
                trusted.registrations_manifest(root)

    def test_registration_path_uses_generator_id_boundary(self):
        """登记键必须按生成器 ID 契约（最长 103）接受，并拒绝穿越与子目录。"""
        self.assertTrue(trusted.registration_path_allowed("categories.toml"))
        self.assertTrue(trusted.registration_path_allowed(f"plugins/{self.MAX_ID}.toml"))
        # 104 字符超出生成器 ID 上限：真实最大 ID 不能被误拒，越界必须拒绝。
        self.assertFalse(trusted.registration_path_allowed("plugins/" + "a" * 39 + "." + "b" * 64 + ".toml"))
        self.assertFalse(trusted.registration_path_allowed("plugins/x.toml"))
        self.assertFalse(trusted.registration_path_allowed("plugins/../evil.toml"))
        self.assertFalse(trusted.registration_path_allowed("plugins/acme/notes.toml"))
        self.assertFalse(trusted.registration_path_allowed("plugins/acme.notes.txt"))
        # 登记 README 只接受由 ID 派生的固定路径，不能借清单键读取任意文件。
        self.assertTrue(trusted.registration_path_allowed("plugins/readmes/acme.notes.md"))
        self.assertFalse(trusted.registration_path_allowed("plugins/readmes/../evil.md"))
        self.assertFalse(trusted.registration_path_allowed("plugins/readmes/acme/notes.md"))
        self.assertFalse(trusted.registration_path_allowed("plugins/readmes/acme.notes.txt"))

    def test_manifest_binds_registration_readme(self):
        """登记 README 必须进入清单：发布回执要绑定作者提供的插件说明。"""
        with tempfile.TemporaryDirectory() as temp:
            root = self._data_root(temp)
            (root / "plugins").mkdir()
            (root / "plugins" / "acme.notes.toml").write_text(
                'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n'
                'readme="plugins/readmes/acme.notes.md"\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n',
                encoding="utf-8",
            )
            (root / "plugins" / "readmes").mkdir()
            # 用 bytes 写入：Windows 文本模式会把 \n 转成 \r\n，导致摘要断言假失败。
            (root / "plugins" / "readmes" / "acme.notes.md").write_bytes(b"# Notes\n")
            manifest = trusted.registrations_manifest(root)
            self.assertEqual(
                set(manifest),
                {"categories.toml", "plugins/acme.notes.toml", "plugins/readmes/acme.notes.md"},
            )
            self.assertEqual(manifest["plugins/readmes/acme.notes.md"], hashlib.sha256(b"# Notes\n").hexdigest())

    def test_manifest_accepts_max_length_plugin_id(self):
        """最长合法 ID 的登记文件必须进入清单，不能因清单正则过短而被拒绝。"""
        with tempfile.TemporaryDirectory() as temp:
            root = self._data_root(temp)
            (root / "plugins").mkdir()
            (root / "plugins" / f"{self.MAX_ID}.toml").write_text(
                'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n',
                encoding="utf-8",
            )
            manifest = trusted.registrations_manifest(root)
            self.assertEqual(set(manifest), {"categories.toml", f"plugins/{self.MAX_ID}.toml"})


class ReceiptTests(unittest.TestCase):
    def test_receipt_contract_is_enforced(self):
        """回执字段、轨道身份与摘要格式必须齐备且格式正确。"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            valid = {
                "track": "v1",
                "repository": trusted.MARKET_REPOSITORY,
                "sequence": 1,
                "candidate_sha256": DIGEST,
                "media_manifest": {},
                "registrations_manifest": {"categories.toml": DIGEST},
            }
            path.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(trusted.load_receipt(path), valid)
            for mutate in (
                lambda r: r.update(track="v2"),
                lambda r: r.update(repository="other/repo"),
                lambda r: r.update(candidate_sha256="zz"),
                lambda r: r.update(sequence=0),
                lambda r: r.update(media_manifest={"media-x.png": DIGEST}),
                lambda r: r.update(registrations_manifest={}),
                lambda r: r.update(extra=1),
            ):
                broken = json.loads(json.dumps(valid))
                mutate(broken)
                path.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises(ValueError):
                    trusted.load_receipt(path)

    def test_receipt_rejects_media_name_digest_mismatch(self):
        """内容寻址名称内嵌的摘要必须等于清单摘要：名称与内容脱钩的回执不得通过。"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            name = f"media-{'c' * 64}.md"
            receipt = {
                "track": "v1",
                "repository": trusted.MARKET_REPOSITORY,
                "sequence": 1,
                "candidate_sha256": DIGEST,
                "media_manifest": {name: "d" * 64},
                "registrations_manifest": {"categories.toml": DIGEST},
            }
            path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not embed its digest"):
                trusted.load_receipt(path)


class StructureTests(unittest.TestCase):
    def test_valid_candidate_passes(self):
        """完整合法候选通过结构校验，包括 any 平台与官方四平台规则。"""
        trusted.validate_candidate_structure(catalog())

    def test_structure_rejects_contract_violations(self):
        """字段缺失、外链资产、摘要格式、平台冲突、越界序列全部拒绝。"""
        cases = []
        drifted = catalog()
        drifted["plugins"][0]["icon_url"] = "https://evil.example/icon.png"
        cases.append(drifted)
        drifted = catalog()
        # 资产 URL 指向登记之外的仓库：确定性重建后与目录不一致，必须拒绝。
        drifted["plugins"][0]["versions"][0]["assets"][0]["url"] = "https://github.com/other/notes/releases/download/v1.0.0/acme.notes-1.0.0-any.kplugin"
        cases.append(drifted)
        drifted = catalog()
        drifted["plugins"][0]["versions"][0]["assets"][0]["url"] = "https://github.com/acme/notes/releases/download/v9.9.9/acme.notes-1.0.0-any.kplugin"
        cases.append(drifted)
        drifted = catalog()
        drifted["plugins"][0]["versions"][0]["assets"][0]["sha256"] = "not-hex"
        cases.append(drifted)
        drifted = catalog(versions=[version(assets=[asset("windows-x86_64"), asset("windows-x86_64", sha="b" * 64)])])
        cases.append(drifted)
        drifted = catalog(sequence=0)
        cases.append(drifted)
        drifted = catalog()
        drifted["schema"] = 2
        cases.append(drifted)
        drifted = catalog()
        drifted["source_id"] = "official-v2"
        cases.append(drifted)
        drifted = catalog()
        drifted["plugins"] = []
        cases.append(drifted)
        drifted = catalog()
        drifted["plugins"][0]["versions"][0]["assets"] = []
        cases.append(drifted)
        for candidate in cases:
            with self.assertRaises(ValueError):
                trusted.validate_candidate_structure(candidate)

    def test_official_platform_rule(self):
        """官方保留 ID 在非 any 平台下必须四平台齐备，缺失即拒绝。"""
        candidate = catalog()
        plugin = candidate["plugins"][0]
        plugin["id"] = "kerminal.notes"
        plugin["publisher"] = "kerminal"
        plugin["repository"] = "https://github.com/kongweiguang/notes"
        platforms = ["windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-aarch64"]
        for entry in plugin["versions"]:
            entry["changelog_url"] = f"https://github.com/kongweiguang/notes/releases/tag/v{entry['version']}"
            entry["assets"] = [asset(platform) for platform in platforms]
            for item in entry["assets"]:
                item["url"] = trusted._asset_url("kerminal.notes", entry["version"], item["platform"], plugin["repository"])
        trusted.validate_candidate_structure(candidate)
        plugin["versions"][0]["assets"] = plugin["versions"][0]["assets"][:3]
        with self.assertRaises(ValueError):
            trusted.validate_candidate_structure(candidate)

    def test_structure_rejects_duplicate_plugin_ids(self):
        """重复 plugin id 必须在结构层失败；按 id 建索引的绑定不能掩盖同 ID 覆盖。"""
        candidate = catalog()
        candidate["plugins"].append(dict(candidate["plugins"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate plugin id: acme.notes"):
            trusted.validate_candidate_structure(candidate)

    def test_structure_rejects_host_reserved_plugin_ids(self):
        """语法合格但宿主 PluginId::parse 拒绝的保留身份必须在签名前失败。

        负例逐条对照主仓 crates/domain/src/plugins.rs：设备名判定只看第一个点
        前的 stem（`con.example`、`aux.foo`、`com1.bar` 均通过生成器 ID 正则，
        若不拦截会让签名目录在宿主反序列化时整体不可解析），另有 state.json 与
        state-recovery-*.json。生成器语法已拒绝的名字（如含 `$` 的 conin$）不
        进本组，避免断言落在错误的失败原因上。
        """
        reserved_ids = [
            "con.example", "prn.example", "aux.foo", "nul.example",
            "com1.bar", "com9.bar", "lpt1.bar", "lpt9.bar",
            "state.json", "state-recovery-1.json", "state-recovery-abc.json",
        ]
        for plugin_id in reserved_ids:
            candidate = catalog()
            candidate["plugins"][0]["id"] = plugin_id
            candidate["plugins"][0]["publisher"] = plugin_id.split(".", 1)[0]
            with self.subTest(plugin_id=plugin_id):
                with self.assertRaisesRegex(ValueError, "reserved by the host"):
                    trusted.validate_candidate_structure(candidate)

    def test_host_identity_rule_matches_reserved_table_shape(self):
        """acme.con 这类 name 段撞设备名与含 $ 名字由生成器语法先拒绝：记录边界归属。"""
        # 宿主 parse 会拒绝 acme.con（first_segment 判定只看 publisher），但当前
        # 生成器 ID 正则允许它；协调者确认 publisher 不保留时可接受，因此本防线
        # 不拦 acme.con，边界归属必须如实：宿主侧更严，发布侧按宿主 parse 的
        # reserved 分支（首段 + state 文件名）同步，不重复实现语法规则。
        self.assertTrue(trusted.host_identity_allowed("acme.con"))
        self.assertTrue(trusted.host_identity_allowed("acme.conin$"))
        # 生成器语法先拒绝含 $ 名字，validate_candidate_structure 报 invalid id。
        candidate = catalog()
        candidate["plugins"][0]["id"] = "acme.conin$"
        with self.assertRaisesRegex(ValueError, "invalid plugin id"):
            trusted.validate_candidate_structure(candidate)

    def test_structure_accepts_non_reserved_lookalikes(self):
        """保留判定不扩大化：非保留首段/尾段与不匹配恢复材料模式的 ID 必须通过。"""
        for plugin_id in [
            "console.notes", "auxiliary.notes", "commerce.notes", "nullsafe.notes",
            "acme.congress", "acme.auxiliary", "acme.state-json", "states.json", "state.jsonx",
            "state-recovery.json", "recovery-state-1.json",
        ]:
            publisher, name = plugin_id.split(".", 1)
            repository = f"https://github.com/{publisher}/{name}"
            with self.subTest(plugin_id=plugin_id):
                trusted.validate_candidate_structure(
                    catalog(plugin_id=plugin_id, publisher=publisher, repository=repository),
                )
        # 生成器把 ID 作为单文件名读登记（plugins/<id>.toml），state-recovery-x
        # 形态含点结尾段合法；这里用 host_identity_allowed 直接守护边界归属。
        self.assertTrue(trusted.host_identity_allowed("state-recovery-x.toml"))

    def test_structure_rejects_publisher_id_mismatch(self):
        """宿主要求 publisher 等于 id 第一个点前的段：不匹配的候选签名前拒绝。"""
        candidate = catalog(publisher="other")
        with self.assertRaisesRegex(ValueError, "publisher must match the id publisher segment"):
            trusted.validate_candidate_structure(candidate)

    def test_structure_rejects_schema_boolean(self):
        """结构层同样拒绝布尔 schema：守护的是 type 检查，不是值比较。"""
        candidate = catalog()
        candidate["schema"] = True
        with self.assertRaisesRegex(ValueError, "candidate is not on the v1 track"):
            trusted.validate_candidate_structure(candidate)
        candidate["schema"] = False
        with self.assertRaises(ValueError):
            trusted.validate_candidate_structure(candidate)
        # 回执/序列侧已有严格整数检查（_checked_u64 type is not int）：
        # sequence: true 在这里被原样拒绝，不因 True == 1 而通过。
        candidate["schema"] = 1
        candidate["sequence"] = True
        with self.assertRaisesRegex(ValueError, "candidate sequence must be a positive u64"):
            trusted.validate_candidate_structure(candidate)

    def test_structure_rejects_wrong_snapshot_sequence(self):
        """媒体引用指向其它快照序号（catalog-v1-2）时必须拒绝，不能只校验文件名。"""
        candidate = catalog(sequence=1)
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-2/media-{'a' * 64}.md"
        )
        with self.assertRaisesRegex(ValueError, "does not point at the v1 fixed release asset for sequence 1"):
            trusted.validate_candidate_structure(candidate)

    def test_structure_rejects_readme_icon_extension_cross(self):
        """readme 只允许 md、icon 只允许图片扩展名：交叉放入必须拒绝。"""
        candidate = catalog()
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-1/media-{'a' * 64}.png"
        )
        with self.assertRaisesRegex(ValueError, "readme_url of acme.notes has an extension outside the allowlist"):
            trusted.validate_candidate_structure(candidate)
        candidate = catalog()
        candidate["plugins"][0]["icon_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-1/media-{'b' * 64}.md"
        )
        with self.assertRaisesRegex(ValueError, "icon_url of acme.notes has an extension outside the allowlist"):
            trusted.validate_candidate_structure(candidate)


class SignPlanTests(unittest.TestCase):
    def setUp(self):
        """独立临时目录：数据根、媒体目录与回执都按各用例重建。"""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_root = self.root / "data"
        (self.data_root / "plugins").mkdir(parents=True)
        (self.data_root / "categories.toml").write_text('[categories.productivity]\nen="Productivity"\nzh-CN="效率"\n', encoding="utf-8")
        (self.data_root / "plugins" / "acme.notes.toml").write_text(
            'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n',
            encoding="utf-8",
        )
        self.media = self.root / "media"
        name, digest = write_media(self.media)
        self.media_name, self.media_digest = name, digest
        self.candidate_path = self.root / "catalog.json"
        candidate = catalog()
        # 候选的 README 引用必须指向实际媒体文件：内容寻址闭环要求引用、文件名与
        # 字节摘要三者一致，占位摘要名无法通过 media coverage 检查。
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-1/{name}"
        )
        self.candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        self.receipt_path = self.root / "receipt.json"
        self.receipt = {
            "track": "v1",
            "repository": trusted.MARKET_REPOSITORY,
            "sequence": 1,
            "candidate_sha256": hashlib.sha256(self.candidate_path.read_bytes()).hexdigest(),
            "media_manifest": {name: digest},
            "registrations_manifest": trusted.registrations_manifest(self.data_root),
        }
        self.receipt_path.write_text(json.dumps(self.receipt), encoding="utf-8")
        # bootstrap 场景：轨道上没有任何快照与固定 Release，序列从 1 开始；
        # 非 bootstrap 场景的基线与快照在各用例单独构造，保证 fail-closed 语义可精确断言。
        self.releases = []

    def test_plan_accepts_consistent_state(self):
        """回执、候选、媒体、登记与序列全部一致时产出签名计划。"""
        plan = trusted.build_sign_plan(
            self.receipt, self.candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
        )
        self.assertEqual(plan["sequence"], 1)
        self.assertEqual(plan["tag"], "catalog-v1-1")
        self.assertTrue(plan["bootstrap"])
        self.assertEqual(plan["media"], [self.media_name])

    def test_plan_rejects_missing_candidate(self):
        """缺失候选经安全读取统一为 ValueError；不得泄漏裸 OSError 或产出计划。"""
        with self.assertRaisesRegex(ValueError, "candidate catalog cannot be opened safely"):
            trusted.build_sign_plan(
                self.receipt, self.root / "absent.json", None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_candidate_byte_drift(self):
        """候选字节在 verify/sign 之间变化：失败原因必须是候选摘要，而不是被后续检查遮蔽。"""
        # 与 setUp 不同的字节（序列 2），其余材料保持回执记录的 verify 状态。
        self.candidate_path.write_text(json.dumps(catalog(sequence=2)), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "candidate bytes changed between verify and sign"):
            trusted.build_sign_plan(
                self.receipt, self.candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_media_content_drift(self):
        """媒体字节被改写：失败原因必须是媒体清单不一致，且候选与登记仍保持一致。"""
        (self.media / self.media_name).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "receipt media manifest disagrees with the candidate media set"):
            trusted.build_sign_plan(
                self.receipt, self.candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_registration_drift(self):
        """登记数据被改写：失败原因必须是登记清单不一致，不能被候选/媒体检查遮蔽。"""
        (self.data_root / "plugins" / "acme.notes.toml").write_text(
            'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="9.9.9"\ntag="v9.9.9"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "receipt registrations manifest disagrees with the candidate data"):
            trusted.build_sign_plan(
                self.receipt, self.candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_sequence_disagreement(self):
        """sign 侧重算序列与回执不一致即失败：verify/sign 之间发布状态漂移不能推进。"""
        self.receipt["sequence"] = 5
        self.receipt_path.write_text(json.dumps(self.receipt), encoding="utf-8")
        # 直接用字典绕过 load_receipt（main 里才会重新加载），专测 build_sign_plan 的比对。
        with self.assertRaises(ValueError):
            trusted.build_sign_plan(
                self.receipt, self.candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_requires_fixed_identity_when_present(self):
        """存在固定基线时必须属于 v1 轨且序列衔接；跨轨或断档基线拒绝。"""
        candidate = catalog(sequence=3)
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-3/{self.media_name}"
        )
        candidate_path = self.root / "catalog-3.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["sequence"] = 3
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        self.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        # 正确基线（sequence 2、快照与固定 Release 存在）时下一序列为 3：通过。
        releases = [release("catalog-v1"), release("catalog-v1-2")]
        fixed = catalog(sequence=2)
        plan = trusted.build_sign_plan(
            receipt, candidate_path, fixed, releases, self.media, self.data_root, bootstrap=False,
        )
        self.assertEqual(plan["sequence"], 3)
        self.assertFalse(plan["bootstrap"])
        # 基线声称 sequence 2，但 release 列表没有 catalog-v1 快照：publication_v1 拒绝。
        with self.assertRaises(ValueError):
            trusted.build_sign_plan(
                receipt, candidate_path, fixed, [release("catalog-v1-2")], self.media, self.data_root, bootstrap=False,
            )
        # 基线是另一轨身份：严格轨道入口直接拒绝。
        wrong_track = catalog(sequence=2)
        wrong_track["source_id"] = "official-v2"
        with self.assertRaises(ValueError):
            trusted.build_sign_plan(
                receipt, candidate_path, wrong_track, releases, self.media, self.data_root, bootstrap=False,
            )
        # 基线序列与回执声称的 3 不衔接（基线 2 → 下一序列 3，若基线是 1 则为 2）：拒绝。
        stale = catalog(sequence=1)
        with self.assertRaises(ValueError):
            trusted.build_sign_plan(
                receipt, candidate_path, stale, releases, self.media, self.data_root, bootstrap=False,
            )

    def test_plan_rejects_bootstrap_flag_with_existing_baseline(self):
        """已有验签基线却声明 bootstrap 是自相矛盾状态：显式失败，不按增量静默继续。"""
        candidate = catalog(sequence=3)
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-3/{self.media_name}"
        )
        candidate_path = self.root / "catalog-3.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["sequence"] = 3
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        releases = [release("catalog-v1"), release("catalog-v1-2")]
        with self.assertRaisesRegex(ValueError, "bootstrap approval is incompatible with an existing verified baseline"):
            trusted.build_sign_plan(
                receipt, candidate_path, catalog(sequence=2), releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_reserved_identity_in_bootstrap(self):
        """bootstrap 下保留身份候选必须让整个计划失败，不能只停在结构层。"""
        candidate = catalog(plugin_id="con.example", publisher="con", repository="https://github.com/con/notes")
        candidate_path = self.root / "catalog-reserved.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "reserved by the host"):
            trusted.build_sign_plan(
                receipt, candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_publisher_id_mismatch_in_bootstrap(self):
        """bootstrap 下 publisher/id 段不一致同样让整个计划失败。"""
        candidate = catalog(publisher="other")
        candidate_path = self.root / "catalog-publisher.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "publisher must match the id publisher segment"):
            trusted.build_sign_plan(
                receipt, candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_schema_boolean_in_bootstrap(self):
        """schema: true 在 Python 里等于 1，但宿主 u32 会拒绝布尔：必须按 type 严格拒绝。"""
        candidate = catalog()
        candidate["schema"] = True
        candidate_path = self.root / "catalog-bool-schema.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "candidate is not on the v1 track"):
            trusted.build_sign_plan(
                receipt, candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_rejects_duplicate_plugin_ids_without_baseline(self):
        """bootstrap 下重复 plugin id 必须在结构校验失败：dict 绑定不能覆盖同 ID 造成伪一致。"""
        candidate = catalog()
        candidate["plugins"].append(dict(candidate["plugins"][0]))
        candidate_path = self.root / "catalog-duplicate.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate plugin id: acme.notes"):
            trusted.build_sign_plan(
                receipt, candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )

    def test_plan_protects_history_immutability(self):
        """基线中的历史版本资产被候选改写时必须失败。"""
        fixed = catalog(sequence=2)
        releases = [release("catalog-v1"), release("catalog-v1-2")]
        candidate = catalog(sequence=3)
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-3/{self.media_name}"
        )
        # 历史不可变是核心断言：改写已发布版本的资产摘要必须失败。
        candidate["plugins"][0]["versions"][0]["assets"][0]["sha256"] = "b" * 64
        candidate_path = self.root / "catalog-3.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["sequence"] = 3
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            trusted.build_sign_plan(
                receipt, candidate_path, fixed, releases, self.media, self.data_root, bootstrap=False,
            )

    def test_plan_rejects_uncovered_media_reference(self):
        """目录引用的媒体必须落在已验证媒体集合内，摘要与文件名字节摘要一致。"""
        candidate = catalog()
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-1/media-{'d' * 64}.md"
        )
        candidate_path = self.root / "catalog-uncovered.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt = json.loads(json.dumps(self.receipt))
        receipt["candidate_sha256"] = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            trusted.build_sign_plan(
                receipt, candidate_path, None, self.releases, self.media, self.data_root, bootstrap=True,
            )


class PlanCliTests(unittest.TestCase):
    """plan 子命令：bootstrap 必须由 CLI 显式传入，不能从「没有基线」自动批准。"""

    def setUp(self):
        """独立临时目录；每个用例只构造自身需要的材料。"""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _material(self, sequence):
        """构造与回执/媒体/登记一致的材料，并返回 CLI 需要的路径集合。"""
        data_root = self.root / "data"
        (data_root / "plugins").mkdir(parents=True)
        (data_root / "categories.toml").write_text('[categories.productivity]\nen="Productivity"\nzh-CN="效率"\n', encoding="utf-8")
        (data_root / "plugins" / "acme.notes.toml").write_text(
            'repository="https://github.com/acme/notes"\ncategories=["productivity"]\n[[versions]]\nversion="1.0.0"\ntag="v1.0.0"\n',
            encoding="utf-8",
        )
        media = self.root / "media"
        name, digest = write_media(media)
        candidate = catalog(sequence=sequence)
        candidate["plugins"][0]["readme_url"] = (
            f"https://github.com/kongweiguang/Kerminal-Plugins/releases/download/catalog-v1-{sequence}/{name}"
        )
        candidate_path = self.root / f"catalog-{sequence}.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        receipt_path = self.root / f"receipt-{sequence}.json"
        receipt = {
            "track": "v1",
            "repository": trusted.MARKET_REPOSITORY,
            "sequence": sequence,
            "candidate_sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
            "media_manifest": {name: digest},
            "registrations_manifest": trusted.registrations_manifest(data_root),
        }
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        releases_path = self.root / "releases.json"
        releases_path.write_text(json.dumps([]), encoding="utf-8")
        return {
            "candidate": candidate_path,
            "receipt": receipt_path,
            "media": media,
            "data_root": data_root,
            "releases": releases_path,
        }

    def _argv(self, material, fixed=False, bootstrap=False):
        """按需拼出 plan 子命令参数；fixed 场景只需路径存在语义，验签在用例内打桩。"""
        argv = [
            "--receipt", str(material["receipt"]),
            "--candidate", str(material["candidate"]),
            "--media-dir", str(material["media"]),
            "--data-root", str(material["data_root"]),
            "--releases", str(material["releases"]),
        ]
        if fixed:
            argv += ["--fixed", str(self.root / "catalog.json"), "--fixed-sig", str(self.root / "catalog.json.minisig"), "--pubkey", str(self.root / "publisher.pub")]
        if bootstrap:
            argv.append("--bootstrap")
        return argv

    def _run(self, command, argv):
        """在进程内执行 main，并复现模块 __main__ 的 fail-closed 出口语义。

        真实 CLI 在 __main__ 捕获同一组异常后写 stderr 并以 1 退出；argparse 的
        parser.error 以 2 退出；这里按同一出口映射成 (退出码, stdout, stderr)，
        从而断言用户实际看到的失败原因。子命令名显式传入，不再写死 plan。
        """
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(trusted.sys, "argv", ["trusted_publish_v1.py", command, *argv]):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                try:
                    trusted.main()
                except SystemExit as exit_error:
                    return exit_error.code, output.getvalue(), errors.getvalue()
                except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
                    print(f"trusted-publish: {error}", file=sys.stderr)
                    return 1, output.getvalue(), errors.getvalue()
        return 0, output.getvalue(), errors.getvalue()

    def test_cli_plan_without_bootstrap_fails_closed(self):
        """无基线且未传 --bootstrap：不得自动批准首次引导。"""
        code, output, errors = self._run("plan", self._argv(self._material(1)))
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("bootstrap requires explicit approval and no existing snapshots", errors)

    def test_cli_plan_with_bootstrap_flag_approves_sequence_one(self):
        """显式 --bootstrap 且轨道为空时产出 sequence 1 的引导计划。"""
        code, output, errors = self._run("plan", self._argv(self._material(1), bootstrap=True))
        self.assertEqual(code, 0, errors)
        plan = json.loads(output)
        self.assertEqual((plan["sequence"], plan["bootstrap"]), (1, True))

    def test_cli_plan_existing_track_advances_without_bootstrap_flag(self):
        """已有验签基线时按增量裁决（sequence 3），计划不得标成 bootstrap。"""
        material = self._material(3)
        material["releases"].write_text(json.dumps([release("catalog-v1"), release("catalog-v1-2")]), encoding="utf-8")
        with patch.object(trusted, "load_fixed_verified", return_value=catalog(sequence=2)):
            code, output, errors = self._run("plan", self._argv(material, fixed=True))
        self.assertEqual(code, 0, errors)
        plan = json.loads(output)
        self.assertEqual((plan["sequence"], plan["bootstrap"]), (3, False))

    def test_cli_plan_rejects_bootstrap_flag_on_existing_track(self):
        """已有验签基线却传 --bootstrap：显式失败，不按增量静默继续。"""
        material = self._material(3)
        material["releases"].write_text(json.dumps([release("catalog-v1"), release("catalog-v1-2")]), encoding="utf-8")
        with patch.object(trusted, "load_fixed_verified", return_value=catalog(sequence=2)):
            code, output, errors = self._run("plan", self._argv(material, fixed=True, bootstrap=True))
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("bootstrap approval is incompatible with an existing verified baseline", errors)

    def test_cli_rejects_dangling_fixed_signature_flags(self):
        """参数卫生：--fixed-sig/--pubkey 单独出现（无 --fixed）必须在解析期对称拒绝。

        这是调用卫生而非安全边界：悬空材料本身不改变验签语义，但静默丢弃会掩盖
        调用方拼写错误。sequence 与 plan 两个子命令行为一致，逐组合覆盖。
        """
        material = self._material(1)
        base = [
            "--receipt", str(material["receipt"]),
            "--candidate", str(material["candidate"]),
            "--media-dir", str(material["media"]),
            "--data-root", str(material["data_root"]),
            "--releases", str(material["releases"]),
        ]
        dangling_options = [
            ["--fixed-sig", "sig.minisig"],
            ["--pubkey", "publisher.pub"],
            ["--fixed-sig", "sig.minisig", "--pubkey", "publisher.pub"],
        ]
        for command in ("sequence", "plan"):
            argv = ["--releases", str(material["releases"])] if command == "sequence" else base
            for extra in dangling_options:
                with self.subTest(command=command, extra=extra):
                    code, output, errors = self._run(command, [*argv, *extra])
                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    self.assertIn("require --fixed for signature verification", errors)

    def test_cli_accepts_paired_fixed_flags_and_rejects_partial_pairs(self):
        """成对完整时通过（打桩验签）；缺 --fixed-sig 或 --pubkey 仍按原语义拒绝。"""
        material = self._material(3)
        material["releases"].write_text(json.dumps([release("catalog-v1"), release("catalog-v1-2")]), encoding="utf-8")
        with patch.object(trusted, "load_fixed_verified", return_value=catalog(sequence=2)):
            code, output, errors = self._run("plan", self._argv(material, fixed=True))
        self.assertEqual(code, 0, errors)
        plan = json.loads(output)
        self.assertEqual(plan["sequence"], 3)
        # 反向缺材料：只给 --fixed 不给验签材料，原 parser.error 语义保持（退出码 2）。
        # 复用同一份材料即可：参数一致性在解析期裁决，先于任何材料读取。
        argv = self._argv(material, fixed=False)
        code, output, errors = self._run("plan", [*argv, "--fixed", str(self.root / "catalog.json")])
        self.assertEqual(code, 2)
        self.assertIn("--fixed requires --fixed-sig and --pubkey", errors)


class SequenceCommandTests(unittest.TestCase):
    def test_sequence_matches_publication_primitive(self):
        """compute_sequence 始终走严格轨道入口，与 publication_v1.next_sequence_for 一致。"""
        releases = [release("catalog-v1"), release("catalog-v1-2")]
        fixed = catalog(sequence=2)
        self.assertEqual(trusted.compute_sequence(releases, fixed, False), publication_v1.next_sequence_for("v1", fixed, releases, False))
        self.assertEqual(trusted.compute_sequence([], None, True), 1)
        with self.assertRaises(ValueError):
            # 引导批准但轨道已有快照：fail-closed。
            trusted.compute_sequence(releases, None, True)
        with self.assertRaises(ValueError):
            # 无基线且无批准：不静默引导。
            trusted.compute_sequence(releases, None, False)
        with self.assertRaises(ValueError):
            # 有基线但轨道缺固定 Release 标签：基线不可信。
            trusted.compute_sequence([release("catalog-v1-2")], fixed, False)


if __name__ == "__main__":
    unittest.main()
