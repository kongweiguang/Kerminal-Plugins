# @author kongweiguang
"""镜像 README 与受限图片，不把外部地址作为受信目录资产。"""

import base64
import errno
import hashlib
import json
import os
import re
import subprocess
import threading
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import publication_v1

MAX_README = 1024 * 1024
MAX_IMAGE = 2 * 1024 * 1024
MEDIA_PARTIAL_SUFFIX = ".media-partial"
# 仅 ASCII 字母数字：IGNORECASE 下 [a-z] 会额外匹配 Unicode 大小写折叠字符
# （Kelvin sign U+212A、long s U+017F），与 ASCII 扩展名语法和 URL 文件名假设
# 不一致，故加 re.ASCII 显式限定。
MEDIA_EXTENSION = re.compile(r"[a-z0-9]{1,16}\Z", re.IGNORECASE | re.ASCII)
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
    """只接受 MIME 与内容相符的静态格式，SVG 拒绝活动内容和外部引用。

    SVG 允许合法的 XML 注释（作者署名等），ElementTree 解析时本来就会忽略
    它们；旧实现用 `b"<!" in data` 一刀切，把带注释的正常图标也判成非法。
    这里先去掉成对注释再检查剩余 `<!`：DOCTYPE、ENTITY 等其它声明仍被拒绝，
    未闭合的注释不会被正则匹配，因此同样留在剩余字节里被拒绝。另外显式拒绝
    `<?xml-stylesheet?>` 处理指令和 `src` 外部引用，避免注释放行后出现新的
    外部资源入口；`href`/`src` 仍只允许片段引用。
    """
    if len(data) > MAX_IMAGE:
        raise ValueError("image too large")
    formats = [("image/png", "png", data.startswith(b"\x89PNG\r\n\x1a\n")), ("image/jpeg", "jpg", data.startswith(b"\xff\xd8\xff")), ("image/gif", "gif", data.startswith((b"GIF87a", b"GIF89a"))), ("image/webp", "webp", data.startswith(b"RIFF") and data[8:12] == b"WEBP")]
    for expected, extension, matched in formats:
        if matched:
            if mime is not None and mime != expected:
                raise ValueError("image MIME does not match bytes")
            return extension
    if mime not in (None, "image/svg+xml"):
        raise ValueError("invalid image format")
    without_comments = re.sub(rb"<!--.*?-->", b"", data, flags=re.DOTALL)
    if b"<!" in without_comments:
        raise ValueError("invalid image format")
    if re.search(rb"<\?xml-stylesheet\b", data, flags=re.IGNORECASE):
        raise ValueError("external SVG stylesheet")
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
            if name.startswith("on") or name in {"style", "base"} or (name in {"href", "src"} and not value.startswith("#")) or "url(" in value.lower():
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


def _track_release_tag(track, sequence):
    """把轨道身份与序列合成为本轨 Release 标签，并先于任何磁盘写入拒绝非法输入。

    轨道名只允许来自 publication_v1 的固定表，不能接受任意 tag 字符串：否则
    调用方可以用 `catalog-v1-1` 之类的标签让一条轨道引用另一轨的资产。序列
    同样按宿主 u64 契约检查，避免负数、布尔或超界值在拼接后变成看似合法的
    URL；所有校验必须在 mkdir/write 之前完成，失败时不留下半成品目录。
    """
    identity = publication_v1.track_for(track)
    if type(sequence) is not int or not 1 <= sequence <= 2**64 - 1:
        raise ValueError("media sequence must be a positive u64")
    return f"{identity.fixed_tag}-{sequence}"


def _validated_extension(extension):
    """校验扩展名只含字母数字，杜绝分隔符或遍历序列进入内容寻址文件名。

    _media_target 以 f"media-{摘要}.{extension}" 直接拼接最终名；当前生产调用方
    只传 image_extension 的封闭白名单输出（png/jpg/gif/webp/svg）与硬编码 "md"，
    但 store_media 是公共 API，未来调用者传入带 /、\\ 或 .. 的扩展名会让落盘
    路径越出发布目录。采用语法校验而非固定白名单：在不放行任何分隔符的前提下
    为未来的合法图片格式留出空间。校验必须发生在任何磁盘观察之前，失败时
    不产生目录创建或读取副作用。
    """
    if not isinstance(extension, str) or MEDIA_EXTENSION.fullmatch(extension) is None:
        raise ValueError("invalid media extension")
    return extension


def _media_target(directory, repository, sequence, data, extension, track="v1"):
    """在不落盘的前提下算出内容寻址文件名与下载地址，并先拒绝同名异内容资产。

    镜像 README 要同时写图片和正文，多文件写入没有事务可用；把名称计算和冲突
    检查提前，可让"正文超限"这类能在写入前发现的失败完全不产生磁盘副作用。
    同名同内容的既有资产视为已经满足，复用判定最终由 _publish_verified 以实际
    读到的字节为准，既不删除也不重写用户已有文件；名称只由内容摘要决定，因此
    该计算与真正写入可以分离。本函数的初检只是提前拒绝：初检之后目标仍可能被
    创建、删除或替换，那些窗口不在本函数裁决范围，由 _publish_verified 闭环；
    若初检读取本身撞上并发删除等 IO 错误，会直接失败而非进入重试，这属于调用
    方可重试的普通 IO 失败。扩展名先经 _validated_extension 语法校验，越界或
    非法输入在触碰文件系统前被拒绝。
    """
    _validated_extension(extension)
    tag = _track_release_tag(track, sequence)
    name = f"media-{hashlib.sha256(data).hexdigest()}.{extension}"
    path = directory / name
    if path.exists() and path.read_bytes() != data:
        raise ValueError("media digest collision")
    return path, f"https://github.com/{repository}/releases/download/{tag}/{name}"


def _publish_verified(path, data):
    """让最终路径确实持有本次字节后才返回：复用判定、提交与删除竞态重试在此闭环。

    复用的前提不是目标"存在"，而是确实读到与 data 相同的字节——读取本身就是
    判定，不引入独立的 exists 观察窗口。三种结果：读到相同字节即复用（不重写、
    不删除既有文件）；读到异内容按 digest collision 明确失败；本函数自己的读判定
    遇到 FileNotFoundError（目标缺失或恰在读判定时被竞争者删除）则以该信号受控
    重走 no-replace 提交，重试次数有界（一次）：重试后仍未读到相同字节则明确
    失败，绝不静默返回指向缺失或异内容资产的 URL。窗口范围仅限本函数的两次读
    判定：_media_target 初检或 _commit_file 内部读取撞上并发删除等 IO 错误会
    直接失败，不进入本重试（见 store_media 的边界说明）。外部删除者持续竞争
    超出本进程可闭环范围，由发布前独立校验作为后续条件补足。
    """
    for _ in range(2):
        try:
            observed = path.read_bytes()
        except FileNotFoundError:
            # 目标不存在或在核验间隙被删除：重走提交。os.link 的 no-replace
            # 语义保证不会覆盖此间隙内他人新写入的异内容目标。
            _commit_file(path, data)
            continue
        if observed == data:
            return
        raise ValueError("media digest collision")
    # 有界重试耗尽后的最终核验：这是"返回值对应真实资产"的最后防线。
    observed = path.read_bytes()
    if observed != data:
        raise ValueError("media digest collision")


def _raise_multi_failure(failures):
    """把多个并列失败按成员类型组合为可见异常后抛出，绝不吞掉任何一个。

    成员全为 Exception 时构造 ExceptionGroup，否则 BaseExceptionGroup
    （KeyboardInterrupt 等非 Exception 失败同样不能丢）；默认 traceback 展示
    全部子异常。仅在调用方已收集多个失败时使用，单一失败应保持原对象传播。
    """
    if all(isinstance(error, Exception) for error in failures):
        raise ExceptionGroup("media publish failed with multiple errors", failures) from None
    raise BaseExceptionGroup("media publish failed with multiple errors", failures) from None


def _commit_file(final_path, data):
    """把一份字节完整地发布成 final_path：写临时文件、关后再以 no-replace 硬链接发布。

    直接 write_bytes 最终内容寻址名有两个已确认的缺陷：进程在写一半时被中断会
    遗留同名截断文件，重试时被 _media_target 误判为 digest collision；exists 检查
    与 write_bytes 之间存在窗口，并发写入或其它进程创建同名异内容文件会被静默
    覆盖。这里改为三段式提交：先在同目录用进程唯一名字建临时文件（O_EXCL 语义，
    独占创建失败即重取名字），写完 flush 并 close 使字节对进程后续操作完整可见
    （进程中断不产生半写状态；flush/close 不是 fsync，机器掉电时最近写入可能
    未持久化，掉电保证不在本函数承诺范围内）；然后以
    os.link 把临时文件硬链接到最终名——POSIX link 与 Windows NTFS（Python 映射为
    errno.EEXIST/FileExistsError）在目标已存在时都失败而不覆盖，发布因此是原子
    的 no-replace 操作：成功时最终名要么不存在（本次发布完整内容），要么已存在
    （我们随后按字节核验；内容相同视为竞态下他人发布的同一资产，临时文件变成
    冗余硬链接后删除；内容不同则按 digest collision 失败且不触碰任何已有文件）。
    发布后删除自己创建的临时文件，只清理本函数创建的路径，不回收历史遗留。

    写入阶段（write/flush/close）的失败同样不能遗留本次临时文件：只有独占 open
    抛出的 FileExistsError 属于命名冲突（理论 uuid 撞名或恶意占用），据此重取
    名字重试；open 成功后的 write、flush 或 close 抛出的任何异常——包括理论上
    不该出现、但注入测试必须排除歧义的 FileExistsError——都清理已创建的临时
    文件并传播，不进入命名重试循环，因此不存在持续创建临时文件的路径。判定
    依据是 open 已成功返回、文件确实由本次创建，清理目标明确无歧义。

    多重失败策略：write/flush 首因、close 失败与 unlink 失败全部保留且按发生
    顺序排列。显式逐阶段收集而不是回溯 __context__ 链：链回溯会把调用方在途
    的隐式上下文（如 _publish_verified 判定用的 FileNotFoundError）误收进组。
    单一失败保持原异常对象直接传播（类型不变，调用方按 OSError/ValueError 等
    类型捕获的行为不变）；多重失败按成员类型组合为 ExceptionGroup 或
    BaseExceptionGroup，默认 traceback 展示全部子异常。选择组合异常而非
    context/from 链：raise-from 会置 __suppress_context__ 把清理错误从默认
    traceback 隐藏，write 后 finally 中 close 再抛时 Python 又以 close 为顶层
    异常，两者都与"按序可见、写入为首因"矛盾。

    os.link 的 OSError 按可判定性分类：仅 EXDEV/ENOTSUP/EOPNOTSUPP（跨设备或
    文件系统不支持硬链接）转换为带准确说明的 ValueError 并以原始链接错误为
    __cause__（from-raise 抑制的是无关隐式 context，原因仍被默认 traceback
    展示）；ENOSPC、EACCES、EIO 等不能断定为"不支持硬链接"的错误原样传播，
    不抹成误导分类。任何分支都不退化为 os.replace 之类的覆盖式发布：那会重新
    打开覆盖竞态。链接失败后的清理失败与主错误按上述多重失败策略并列成组，
    原因挂在组上随默认 traceback 可见。
    """
    if not final_path.exists():
        final_path.parent.mkdir(parents=True, exist_ok=True)
    # 独占创建的重试上限：uuid 撞名在正常情况下是天文数字概率，但恶意预置
    # 或可控 uuid 生成可能让 while True 永不退出。有限次重试耗尽后明确失败，
    # 不删除、不覆盖任何已有文件——每个撞名文件都可能属于他人或并发进程。
    for _ in range(8):
        # 临时文件放在同目录：保证与最终路径同一文件系统，硬链接才可能成功；
        # 名字带进程唯一 uuid，多个发布进程互不冲突，也不会误清他人文件。
        temp_path = final_path.with_name(f"{final_path.name}{MEDIA_PARTIAL_SUFFIX}-{uuid.uuid4().hex}")
        try:
            # "xb" 独占创建：目录中若已出现同名文件不覆盖。FileExistsError 只在
            # 此处捕获并判为命名冲突，write/flush/close 的同名异常不走重试。
            stream = open(temp_path, "xb")
        except FileExistsError:
            continue
        # 逐阶段显式收集本次提交的全部失败：write/flush、close、unlink。
        # 每个阶段失败后不立即重抛——后续阶段（释放句柄、清理临时文件）仍须
        # 执行，它们的失败同样收集，最后统一决定传播形态。全部成功则不清理，
        # 临时文件保留到 os.link 发布。
        failures = []
        try:
            stream.write(data)
            stream.flush()
        except BaseException as write_error:
            failures.append(write_error)
        finally:
            # close 必须执行以释放句柄；其失败与写入失败并列收集。
            try:
                stream.close()
            except BaseException as close_error:
                failures.append(close_error)
        if not failures:
            break
        # 进入失败处理：清理本次已创建的临时文件；清理失败同样收集，不让它
        # 替换写入/关闭失败的首因位置。
        try:
            os.remove(temp_path)
        except BaseException as unlink_error:
            failures.append(unlink_error)
        if len(failures) == 1:
            # 单一失败按原异常对象传播：类型与对象身份不变，此时不在任何
            # except 块内，__context__ 不被无关在途异常污染。
            raise failures[0]
        _raise_multi_failure(failures)
    else:
        # 8 次独占创建全部撞名：明确失败而非无限重试。撞名文件可能是恶意预置
        # 或他人所有，这里不删除、不覆盖任何已有文件。
        raise ValueError("media temp name collision persists after 8 exclusive-create attempts")
    try:
        # close 之后才发布：硬链接只登记已完整写完的字节，不会把写一半的状态暴露给读者。
        os.link(temp_path, final_path)
    except FileExistsError:
        # 竞态目标出现：目标已被创建。不覆盖，读回核验内容决定成败；核验读取
        # 可能因目标又被并发删除或其它 IO 错误而失败。与写入阶段相同的显式
        # 收集策略：read 失败与 unlink 失败按发生顺序组合，单一失败保持原对象
        # 传播、多重失败成组，默认 traceback 全部可见，不遗留临时文件。
        existing = None
        read_error = None
        try:
            existing = final_path.read_bytes()
        except BaseException as error:
            read_error = error
        failures = []
        try:
            os.remove(temp_path)
        except BaseException as unlink_error:
            failures.append(unlink_error)
        if read_error is not None:
            failures.insert(0, read_error)
        if len(failures) == 1:
            raise failures[0]
        if failures:
            _raise_multi_failure(failures)
        if existing != data:
            raise ValueError("media digest collision") from None
    except OSError as link_error:
        if link_error.errno in (errno.EXDEV, errno.ENOTSUP, errno.EOPNOTSUPP):
            # 可判定的"跨设备/文件系统不支持硬链接"：给出准确说明并保留原始
            # 错误为 cause，默认 traceback 同时展示说明与原因；清理失败按多重
            # 失败策略与说明并列成组，原因仍挂在组上可见。
            detail = ValueError("media publish requires hardlink support on the target filesystem")
            try:
                os.remove(temp_path)
            except OSError as unlink_error:
                raise ExceptionGroup("media publish failed with multiple errors", [detail, unlink_error]) from link_error
            raise detail from link_error
        # 其余 IO 错误（ENOSPC、EACCES、EIO 等）不能断定为"不支持硬链接"：
        # 原样传播，不抹成误导的 ValueError；清理失败按多重失败策略并列成组。
        # 任何分支都不退化为 os.replace 之类的覆盖式发布：那会重新打开覆盖竞态。
        try:
            os.remove(temp_path)
        except OSError as unlink_error:
            _raise_multi_failure([link_error, unlink_error])
        raise link_error
    else:
        # 发布成功后清理自己的临时硬链接；内容本体通过 final_path 继续存活。
        os.remove(temp_path)


def store_media(directory, repository, sequence, data, extension, track="v1"):
    """以内容摘要命名，避免资产覆盖并让签名目录稳定引用。

    `track` 默认 v1 以保持未修改的 catalog-v1.py 调用兼容；新轨只改变 Release
    标签前缀，文件命名与摘要去重规则两轨一致，因此同一内容可被两轨分别引用
    而不会互相覆盖或指向另一轨的下载地址。写入经由 _commit_file 的 no-replace
    硬链接发布：中断只会留下可识别的 *.media-partial-* 临时文件而不产生截断的
    正式资产；已存在且字节相同的文件不重写，内容不同则明确失败。

    竞态边界：_media_target 初检与 _publish_verified 的读判定共同把同名异内容
    目标挡在覆盖之外，但每次判定都基于观察瞬间的文件内容；_publish_verified 的
    目标是"返回前确实读到本次字节"，目标在两次读判定之间消失会进入一次有界
    重试，而初检或 _commit_file 内部读取撞上并发删除等 IO 错误则直接失败（可
    由调用方整体重试），不承诺窗口内任意时点的删除都进入重试。返回之后外部
    进程仍可能篡改或替换目标文件，这里既无法感知也无法阻止。防篡改的最终保证
    要求发布流程实现独立的发布前校验（签名目录与发布产物的逐字节核对），该校验
    目前尚未实现，属于本模块调用方必须补足的后续条件，本函数不宣称全程防篡改。

    持久性边界：flush 只把字节交给操作系统的页缓存，close 亦非 fsync；机器
    掉电或宿主机崩溃时，最近写入的资产可能未持久化。本函数提供的是进程中断
    安全（无截断正式资产、可幂等重试），不承诺掉电持久；需要掉电保证的场景
    同样依赖上述发布前的独立校验作为后续条件。

    核验与返回之间仍存在理论窗口（核验通过后、调用方收到 URL 前目标被删除），
    进程内有界重试无法消除外部删除者持续竞争的情形；重复删除超出本模块闭环
    范围，由发布前独立校验作为后续条件补足。
    """
    path, url = _media_target(directory, repository, sequence, data, extension, track)
    # 统一走"读到相同字节才返回"的闭环：目标缺失、异内容、核验间隙被删除
    # 三种情形分别对应重试提交、明确失败、有界重试，不再单独依赖 exists 观察。
    _publish_verified(path, data)
    return url


def mirror_readme(repo, tag, directory, repository, sequence, track="v1"):
    """镜像 README 与首图；缺少图片合法，坏图片则阻止不完整发布。

    README 正文内嵌图片与 README 自身必须落在同一条轨道同一序列上：镜像图片
    时把 `track` 一并传给 _media_target/_commit_file，避免正文引用本轨而
    readme_url 指向另一轨的 Release（正文替换并不经由 store_media，它自己
    直接提交已替换后的字节，因此这里的轨道一致性由本函数显式传递保证）。
    `track` 默认 v1，旧调用生成的字节与地址保持完全不变。

    正文替换图片地址后可能超过 MAX_README，这属于前置可判定的内容错误，必须
    在写入任何文件之前抛出：否则本次下载的图片会留在发布目录里，下一次发布
    看到同名资源时既无法区分它是否已被引用，也可能误以为是已有产物。因此这里
    先算出图片与 README 的内容寻址名称并校验正文长度，全部通过后才落盘；已存在
    且字节相同的资源直接复用，不删除、不重写。每个文件经由 _commit_file 独立
    完整提交：单文件写入中断只留下可识别的临时文件，正式资产不会出现截断。
    多文件之间仍没有跨文件事务：若图片已完整提交而 README 提交前失败，目录里
    会留下已完整可复用的图片而没有 README，调用方按失败重试即可；已提交的
    内容寻址资产按字节复用，不在此处回滚删除既有资源。图片与 README 的复用
    判定都经 _publish_verified 以实际读到的字节为准，竞态窗口内出现的同名异
    内容目标按 digest collision 失败，核验间隙被删除则受控重走提交；持久性与
    防篡改边界与 store_media 相同（flush/close 非 fsync，不承诺掉电持久；返回
    后外部进程仍可篡改，发布前独立校验是调用方必须补足的后续条件，尚未实现）。

    与 store_media 一样，每个文件都经 _publish_verified 闭环：确实读到本次字节
    才继续或返回，核验间隙被删除则受控重走提交（有界一次）。
    """
    # 先校验轨道与序列，再读取/下载；非法输入不应触发网络或目录创建。
    _track_release_tag(track, sequence)
    path, text = read_readme(repo, tag)
    match = IMAGE.search(text)
    image = None
    if match:
        source = match.group(1) or match.group(2)
        data, mime = fetch_image(image_url(source, repo, tag, path))
        image_path, url = _media_target(directory, repository, sequence, data, image_extension(data, mime), track)
        start, end = match.span(1 if match.group(1) else 2)
        text = text[:start] + url + text[end:]
        image = (image_path, data)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_README:
        raise ValueError("mirrored README too large")
    readme_path, readme_url = _media_target(directory, repository, sequence, encoded, "md", track)
    if image is not None:
        image_path, data = image
        # 闭环核验：缺失则提交、异内容失败、核验间隙被删除则有界重试，
        # 读到本次字节才继续写 README。
        _publish_verified(image_path, data)
    _publish_verified(readme_path, encoded)
    return readme_url
