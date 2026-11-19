# @author kongweiguang
"""Validate marketplace registrations and build a catalog only from verified release bytes."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path
from urllib.parse import quote

from media_v1 import MAX_README, image_extension, mirror_readme, store_media

MARKET_REPOSITORY = 'kongweiguang/Kerminal-Plugins'

ROOT = Path(__file__).resolve().parent.parent
ID = re.compile(r"[a-z0-9][a-z0-9-]{1,38}\.[a-z0-9][a-z0-9-]{1,62}\Z")
REPOSITORY = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\Z")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")
PLATFORMS = {"windows-x86_64", "windows-aarch64", "linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64", "any"}
OFFICIAL_PLATFORMS = {"windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-aarch64"}
MAX_CATALOG_BYTES = 4 * 1024 * 1024


def load_registrations(root):
    """联网前拒绝歧义登记及超出宿主上限的版本，避免发布客户端无法接收的目录。

    已发布登记可选 `readme`，但只接受 `plugins/readmes/<plugin_id>.md` 这一
    个固定相对路径：登记仓库同时托管商店自身 README，若允许任意路径或 URL，
    插件页就会显示商店说明而不是插件说明。路径由 ID 派生，因此不存在目录
    穿越；文件必须存在、不是符号链接且不超过宿主 1 MiB README 上限，避免
    生成阶段才发现缺文件或超限而留下半成品媒体。
    """
    categories = tomllib.loads((root / "categories.toml").read_text(encoding="utf-8"))["categories"]
    if not categories or any(not isinstance(value, dict) or not value.get("en") or not value.get("zh-CN") for value in categories.values()):
        raise ValueError("categories require English and Chinese names")
    entries = []
    for path in sorted((root / "plugins").glob("*.toml")):
        plugin_id = path.stem
        if not ID.fullmatch(plugin_id):
            raise ValueError(f"invalid plugin ID: {plugin_id}")
        entry = tomllib.loads(path.read_text(encoding="utf-8"))
        if set(entry) - {"status", "repository", "categories", "versions", "readme"}:
            raise ValueError(f"unknown registration fields: {plugin_id}")
        names = entry.get("categories")
        if not isinstance(names, list) or not names or len(set(names)) != len(names) or any(name not in categories for name in names):
            raise ValueError(f"invalid categories: {plugin_id}")
        status = entry.get("status", "published")
        if status == "pending":
            if set(entry) != {"status", "categories"}:
                raise ValueError(f"pending registration must not claim a release: {plugin_id}")
        elif status == "published":
            repo = entry.get("repository", "")
            match = REPOSITORY.fullmatch(repo)
            if not match or repo.endswith(".git"):
                raise ValueError(f"invalid GitHub repository: {plugin_id}")
            if plugin_id.startswith("kerminal.") and match.group(1).lower() != "kongweiguang":
                raise ValueError(f"reserved official ID requires official owner: {plugin_id}")
            readme = entry.get("readme")
            if readme is not None:
                expected = f"plugins/readmes/{plugin_id}.md"
                if readme != expected:
                    raise ValueError(f"readme must be {expected}: {plugin_id}")
                readme_path = root / expected
                if readme_path.is_symlink() or not readme_path.is_file():
                    raise ValueError(f"readme file is missing or not a regular file: {plugin_id}")
                if readme_path.stat().st_size > MAX_README:
                    raise ValueError(f"readme exceeds the host size limit: {plugin_id}")
            versions = entry.get("versions")
            if not isinstance(versions, list) or not versions or len(versions) > 1024:
                raise ValueError(f"published entry has no versions: {plugin_id}")
            seen = set()
            for version in versions:
                if set(version) != {"version", "tag"} or not isinstance(version["version"], str) or not VERSION.fullmatch(version["version"]) or version["tag"] != "v" + version["version"] or version["version"] in seen:
                    raise ValueError(f"invalid or duplicate version/tag: {plugin_id}")
                seen.add(version["version"])
        else:
            raise ValueError(f"unknown registration status: {plugin_id}")
        entries.append((plugin_id, entry))
    if sum(entry.get("status", "published") == "published" for _, entry in entries) > 4096:
        raise ValueError("catalog exceeds host plugin limit")
    return entries


def run_json(command):
    """Use argument arrays and fail closed on API errors or malformed JSON."""
    return json.loads(subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8").stdout)


def build_catalog(root, tool, sequence, media_dir=None):
    """目录字段遵循宿主严格 JSON 契约，只有经过包校验的发布资产才能贡献真实摘要。"""
    if type(sequence) is not int or not 1 <= sequence < 2**64:
        raise ValueError("sequence must be a positive u64")
    plugins = []
    if media_dir is None:
        media_dir = root / '.local' / 'catalog-media'
    with tempfile.TemporaryDirectory(prefix="kerminal-market-") as temp:
        temp = Path(temp)
        for plugin_id, entry in load_registrations(root):
            if entry.get("status", "published") == "pending":
                continue
            repo = entry["repository"].removeprefix("https://github.com/")
            versions = []
            identity = None
            final_icon = None
            final_tag = None
            for registration in entry["versions"]:
                version, tag = registration["version"], registration["tag"]
                release = run_json(["gh", "release", "view", tag, "--repo", repo, "--json", "tagName,isDraft,publishedAt,assets"])
                if release["isDraft"] or release["tagName"] != tag or not release["publishedAt"]:
                    raise ValueError(f"release is unpublished or mismatched: {plugin_id} {tag}")
                prefix = f"{plugin_id}-{version}-"
                assets = [asset["name"] for asset in release["assets"] if asset["name"].endswith(".kplugin")]
                platforms = {name[len(prefix):-len(".kplugin")] for name in assets if name.startswith(prefix)}
                if not assets or len(platforms) != len(assets) or not platforms <= PLATFORMS or ("any" in platforms and platforms != {"any"}):
                    raise ValueError(f"invalid asset names or platforms: {plugin_id} {tag}")
                if plugin_id.startswith("kerminal.") and "any" not in platforms and platforms != OFFICIAL_PLATFORMS:
                    raise ValueError(f"official sidecar needs four release platforms: {plugin_id}")
                release_dir = temp / plugin_id / version
                release_dir.mkdir(parents=True)
                subprocess.run(["gh", "release", "download", tag, "--repo", repo, "--pattern", "*.kplugin", "--dir", str(release_dir)], check=True)
                packed = []
                version_identity = None
                version_api = None
                version_icon = None
                for name in sorted(assets):
                    path = release_dir / name
                    command = [str(tool), "check", str(path)]
                    if plugin_id.startswith("kerminal."):
                        command.append("--official")
                    subprocess.run(command, check=True)
                    with tarfile.open(path, "r:gz") as archive:
                        manifest = json.load(archive.extractfile("kerminal-plugin.json"))
                        icon = manifest.get("icon")
                        icon_bytes = None
                        if icon:
                            member = archive.getmember(icon)
                            if not member.isfile() or member.size > 2 * 1024 * 1024:
                                raise ValueError("invalid or oversized package icon")
                            icon_bytes = archive.extractfile(member).read()
                            image_extension(icon_bytes)
                    if manifest["id"] != plugin_id or manifest["version"] != version or manifest.get("categories", []) != entry["categories"]:
                        raise ValueError(f"manifest mismatch: {name}")
                    current = {key: manifest[key] for key in ("name", "description", "publisher")}
                    current["permissions"] = manifest.get("permissions", [])
                    runtime = manifest["runtime"]["kind"]
                    if (runtime == "sidecar") != ("any" not in platforms):
                        raise ValueError(f"runtime/platform mismatch: {name}")
                    if version_identity is not None and (current != version_identity or manifest["api"] != version_api):
                        raise ValueError(f"inconsistent manifest metadata: {name}")
                    if version_identity is not None and icon_bytes != version_icon:
                        raise ValueError(f"inconsistent icon: {name}")
                    version_icon = icon_bytes
                    version_identity = current
                    version_api = manifest["api"]
                    platform = name[len(prefix):-len(".kplugin")]
                    size = path.stat().st_size
                    with path.open("rb") as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    url = f"https://github.com/{repo}/releases/download/{quote(tag, safe='')}/{quote(name, safe='')}"
                    packed.append({"platform": platform, "url": url, "sha256": digest, "size": size})
                identity = version_identity
                final_icon = version_icon
                final_tag = tag
                versions.append({"version": version, "api": version_api, "published_at": release["publishedAt"], "changelog_url": f"https://github.com/{repo}/releases/tag/{quote(tag, safe='')}", "assets": packed})
            icon_url = store_media(media_dir, MARKET_REPOSITORY, sequence, final_icon, image_extension(final_icon)) if final_icon is not None else None
            if "readme" in entry:
                # 登记 README 原样发布为内容寻址媒体：它属于插件作者数据，不能
                # 被商店仓库 README 顶替，也不改写其中的相对链接（需要图片时
                # 应使用绝对地址）。load_registrations 已校验路径、类型与上限。
                readme_bytes = (root / entry["readme"]).read_bytes()
                try:
                    readme_bytes.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ValueError(f"readme is not UTF-8: {plugin_id}") from error
                readme_url = store_media(media_dir, MARKET_REPOSITORY, sequence, readme_bytes, "md")
            else:
                readme_url = mirror_readme(repo, final_tag, media_dir, MARKET_REPOSITORY, sequence)
            plugins.append({"id": plugin_id, **identity, "categories": entry["categories"], "icon_url": icon_url, "readme_url": readme_url, "repository": entry["repository"], "versions": versions})
    return {"schema": 1, "source_id": "official", "sequence": sequence, "plugins": plugins}


def catalog_bytes(catalog):
    """按最终 UTF-8 字节执行宿主 4 MiB 上限，避免平台换行转换令验签输入产生差异。"""
    encoded = (json.dumps(catalog, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_CATALOG_BYTES:
        raise ValueError("catalog exceeds host byte limit")
    return encoded


def main():
    """预检不虚构发行数据，正式输出在写入前核对完整字节上限且拒绝空目录。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata-only", action="store_true")
    parser.add_argument("--tool")
    parser.add_argument("--sequence", type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--media-dir", type=Path)
    options = parser.parse_args()
    entries = load_registrations(ROOT)
    if options.metadata_only:
        print(f"validated {len(entries)} registrations; pending excluded from catalogs")
        return
    if not options.tool or options.sequence is None or not options.output:
        parser.error("full generation requires --tool, --sequence and --output")
    catalog = build_catalog(ROOT, options.tool, options.sequence, options.media_dir or options.output.parent / "media")
    if not catalog["plugins"]:
        raise ValueError("no published plugins; refusing to generate a production catalog")
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_bytes(catalog_bytes(catalog))
    print(f"generated {len(catalog['plugins'])} verified entries")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"catalog: {error}", file=sys.stderr)
        sys.exit(1)
