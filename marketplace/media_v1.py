# @author kongweiguang
"""镜像 README 与受限图片，不把外部地址作为受信目录资产。"""

import base64
import hashlib
import json
import re
import subprocess
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_README = 1024 * 1024
MAX_IMAGE = 2 * 1024 * 1024
HOSTS = {"github.com", "raw.githubusercontent.com", "user-images.githubusercontent.com", "objects.githubusercontent.com"}
IMAGE = re.compile(r'!\[[^\]]*\]\(\s*<?([^\s)>]+)>?(?:\s+[^)]*)?\)|<img\b[^>]*\bsrc=["\']([^"\']+)["\']', re.IGNORECASE)


def checked_url(url):
    """每次请求和跳转都重新检查主机，防止借助重定向访问内部地址。"""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in HOSTS or parts.username or parts.password or parts.port not in (None, 443) or parts.fragment:
        raise ValueError("image URL must use an approved GitHub HTTPS host")
    decoded = urllib.parse.unquote(parts.path)
    if "\\" in decoded or any(part in (".", "..") for part in decoded.split("/")) or len(url) > 4096:
        raise ValueError("invalid image URL path")
    return url


class TrustedRedirect(urllib.request.HTTPRedirectHandler):
    """禁止可信 GitHub 地址跳转到未经允许的主机。"""
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return super().redirect_request(request, fp, code, message, headers, checked_url(newurl))


def fetch_image(url):
    """限制响应大小并校验 MIME，避免下载到脚本或无限数据。"""
    request = urllib.request.Request(checked_url(url), headers={"User-Agent": "Kerminal-Plugins/1"})
    with urllib.request.build_opener(TrustedRedirect()).open(request, timeout=30) as response:
        checked_url(response.geturl())
        mime = response.headers.get_content_type().lower()
        if mime not in {"image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"}:
            raise ValueError("unapproved image MIME")
        data = response.read(MAX_IMAGE + 1)
    if len(data) > MAX_IMAGE:
        raise ValueError("image too large")
    return data, mime


def image_extension(data, mime=None):
    """只接受 MIME 与内容相符的静态格式，SVG 拒绝活动内容和外部引用。"""
    if len(data) > MAX_IMAGE:
        raise ValueError("image too large")
    formats = [("image/png", "png", data.startswith(b"\x89PNG\r\n\x1a\n")), ("image/jpeg", "jpg", data.startswith(b"\xff\xd8\xff")), ("image/gif", "gif", data.startswith((b"GIF87a", b"GIF89a"))), ("image/webp", "webp", data.startswith(b"RIFF") and data[8:12] == b"WEBP")]
    for expected, extension, matched in formats:
        if matched:
            if mime is not None and mime != expected:
                raise ValueError("image MIME does not match bytes")
            return extension
    if mime not in (None, "image/svg+xml") or b"<!" in data:
        raise ValueError("invalid image format")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError("invalid SVG") from error
    if root.tag not in ("svg", "{http://www.w3.org/2000/svg}svg"):
        raise ValueError("invalid SVG root")
    for element in root.iter():
        if element.tag.split("}")[-1].lower() in {"script", "style", "foreignobject", "iframe", "object", "embed", "animate", "animatetransform", "set"}:
            raise ValueError("active SVG content")
        for key, value in element.attrib.items():
            name = key.split("}")[-1].lower()
            if name.startswith("on") or name in {"style", "base"} or (name == "href" and not value.startswith("#")) or "url(" in value.lower():
                raise ValueError("unsafe SVG attribute")
    return "svg"


def repository_path(path):
    """只接受仓库内相对路径，拒绝编码后的穿越、绝对路径和平台歧义。"""
    path = urllib.parse.unquote(path)
    if not path or path.startswith("/") or "\\" in path or "\x00" in path or "%" in path or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("invalid repository media path")
    return path


def image_url(source, repo, tag, readme_path):
    """相对图片固定到相同 release tag，绝对图片仅允许 GitHub 域名。"""
    parts = urllib.parse.urlsplit(source)
    if parts.scheme or parts.netloc:
        return checked_url(source)
    if parts.query or parts.fragment:
        raise ValueError("relative image query or fragment not supported")
    base = readme_path.rpartition("/")[0]
    path = repository_path((base + "/" if base else "") + parts.path)
    return f"https://raw.githubusercontent.com/{repo}/{urllib.parse.quote(tag, safe='')}/{urllib.parse.quote(path, safe='/')}"


def read_readme(repo, tag):
    """读取指定 tag 的 README；未找到和超限都停止发布。"""
    endpoint = f"repos/{repo}/readme?ref={urllib.parse.quote(tag, safe='')}"
    with subprocess.Popen(["gh", "api", endpoint], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        timeout = threading.Timer(30, process.kill)
        timeout.start()
        try:
            data = process.stdout.read(2 * MAX_README + 1)
            if len(data) > 2 * MAX_README:
                process.kill()
                process.wait()
                raise ValueError("README API response too large")
            if process.wait() != 0:
                raise ValueError("README API request failed")
        finally:
            timeout.cancel()
    document = json.loads(data)
    if document.get("encoding") != "base64" or document.get("size", MAX_README + 1) > MAX_README:
        raise ValueError("README is unavailable or too large")
    content = base64.b64decode("".join(document["content"].split()), validate=True)
    if len(content) > MAX_README:
        raise ValueError("README too large")
    return repository_path(document["path"]), content.decode("utf-8")


def store_media(directory, repository, sequence, data, extension):
    """以内容摘要命名，避免资产覆盖并让签名目录稳定引用。"""
    name = f"media-{hashlib.sha256(data).hexdigest()}.{extension}"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    if path.exists() and path.read_bytes() != data:
        raise ValueError("media digest collision")
    path.write_bytes(data)
    return f"https://github.com/{repository}/releases/download/catalog-v1-{sequence}/{name}"


def mirror_readme(repo, tag, directory, repository, sequence):
    """镜像 README 与首图；缺少图片合法，坏图片则阻止不完整发布。"""
    path, text = read_readme(repo, tag)
    match = IMAGE.search(text)
    if match:
        source = match.group(1) or match.group(2)
        data, mime = fetch_image(image_url(source, repo, tag, path))
        url = store_media(directory, repository, sequence, data, image_extension(data, mime))
        start, end = match.span(1 if match.group(1) else 2)
        text = text[:start] + url + text[end:]
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_README:
        raise ValueError("mirrored README too large")
    return store_media(directory, repository, sequence, encoded, "md")
