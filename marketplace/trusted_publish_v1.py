# @author kongweiguang
"""可信发布侧 v1：候选数据驱动生成、回执与发布计划的唯一受信实现。

设计立场（与 .updeng/docs/design/局域网文件传输插件实施计划.md 5.2/5.3 对齐）：
候选提交只作为「数据输入」（登记 TOML、分类、登记 README），一切可执行代码
——生成器、发布原语和本模块——都必须来自管理员管控的不可变完整 SHA（工作流
变量 KERMINAL_SIGNER_SHA 指向的受审检出）。因此：

- 候选仓库代码（包括其 marketplace/ 下的同名脚本）在任何发布 job 中都不执行，
  不存在「发布 runner 执行不可信代码」的路径；
- generate：用受信检出调用同检出的 catalog-v1.py 生成器与 media_v1.py 镜像器，
  以候选检出的数据为根生成候选目录并产出回执（receipt）；生成器内部会联网
  下载发布资产并计算摘要，这一步就是验包；
- plan：在真正写 Release 之前，核对回执与全部可重放的约束（候选字节摘要、
  媒体清单、登记绑定、轨道身份、序列链、历史不可变），输出发布计划。

签名模型：v1 使用 minisign 分离签名。签名私钥只保存在受保护的 GitHub
Environment「catalog-signer」的 secret（KERMINAL_CATALOG_MINISIGN_KEY），
验签公钥是受信检出中的 catalog/v1-publisher.pub。v1（catalog-v1 轨道）
从未用旧 publisher.pub 发布过，因此使用自己的公钥而不是沿用历史密钥；
固定目录与不可变快照在每次写入前后都用同一公钥验签、逐字节回读。密钥与
Environment 审批属于发布侧外部前提：工作流只在自己能检查的范围内
fail-closed（缺公钥、缺密钥、缺基线、回执不一致等），不能证明仓库外审批
已配置。旧 v0 的签名资产保持封存，不在本模块读取或改写。

威胁边界（诚实声明，不夸大）：
- 本模块假设 GitHub artifact 通道、runner 镜像、Python、gh 以及由
  KERMINAL_SDK_REF 固定的 SDK 校验器可信；这些不是仓库内代码能证明的。
- workflow YAML 本身随推送提交执行，是候选可修改的攻击面；仓库内检查不能
  证明受保护 main 和变量管控已配置。缺失时工作流只能对缺变量、缺基线等
  显式 fail-closed，不能证明分支保护存在。
- 回执只证明「verify 阶段的可信代码产出过这样一份候选」并在发布前被逐字节
  复核；它不是人工批准，也不是作者声明的独立预期摘要。
- 发布侧不做资产重下载：资产字节在生成阶段由受信生成器下载并摘要，回执把
  候选目录、媒体集合、登记数据绑定为同一份内容；发布前重放全部离线约束。
- 仅实现 v1 兼容轨（schema=1、source_id=official、固定 Release catalog-v1、
  不可变快照 catalog-v1-N）；v2 / 非 GitHub / 局域网源没有独立可信摘要来源
  与可达验包环境，本模块一律拒绝，不伪称支持。
- 中断恢复语义与旧流程一致：快照/固定目录不一致时 publication_v1 拒绝推进，
  需要人工恢复；以只读 token 运行的发布侧看不到 draft Release，被中断留下的
  draft 快照会在重建同名 Release 时失败（already exists），同样 fail-closed，
  需要人工清理后重试。
"""

import argparse
import functools
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from pathlib import Path

# 受信模块必须与其依赖的发布原语/生成器同检出：显式把本文件目录放在搜索路径
# 首位，防止候选工作树或 PYTHONPATH 注入同名模块；导入后的来源与能力检查让
# 错位加载或钉住过期的提交在导入期立即失败，而不是以未知语义运行到一半。
_MODULE_DIR = Path(__file__).resolve().parent
if sys.path[0] != str(_MODULE_DIR):
    sys.path.insert(0, str(_MODULE_DIR))
import publication_v1


def require_same_checkout_publication(module):
    """检查 publication_v1 必须与受信模块同目录且具备全部所需原语。

    抽成具名守卫以便负例测试：错位加载（候选工作树或 PYTHONPATH 注入的同名
    模块）或钉住过期的提交都必须在导入期失败，而不是以未知语义运行到一半。
    """
    if Path(module.__file__).resolve().parent != _MODULE_DIR:
        raise ImportError("publication_v1 must be imported from the same audited checkout as trusted_publish_v1")
    for name in ("next_sequence_for", "validate_update_for", "track_for"):
        if not callable(getattr(module, name, None)):
            raise ImportError(f"pinned publication_v1 lacks required primitive: {name}")


require_same_checkout_publication(publication_v1)

# 宿主保留插件身份规则的本 Python 侧防线：逐条镜像 Kerminal 主仓
# crates/domain/src/plugins.rs 的 PluginId::parse（Windows 设备名首段、状态
# 文件名与恢复材料名）。这是有意的同步副本而不是共享实现：本发布仓不依赖宿主
# crate，两侧必须靠漂移测试（DriftTests）钉住；宿主规则变化时本表必须同步
# 更新并跑 identity_contract 测试对照，不能声称已与 SDK/生成器统一——生成器
# ID 正则只管语法，不管保留名，这条防线覆盖的是语法之外的宿主拒绝规则。
HOST_RESERVED_FIRST_SEGMENTS = frozenset({
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6",
    "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6",
    "lpt7", "lpt8", "lpt9",
    "conin$", "conout$",
})

# v1 兼容轨的固定身份只来自 publication_v1 的轨道表，本模块不另立一套字符串，
# 避免两处定义漂移后签错 source_id 或指错固定 Release。
TRACK = "v1"
TRACK_IDENTITY = publication_v1.track_for(TRACK)
SOURCE_ID = TRACK_IDENTITY.source_id
MARKET_REPOSITORY = "kongweiguang/Kerminal-Plugins"

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
# 单资产字节上限是签名侧结构校验的合理性闸门：真实插件包远小于该值，超过说明
# 登记或生成已经失控；生成侧真正的逐字节约束由 SDK 校验器与宿主上限承担。
MAX_ASSET_BYTES = 512 * 1024 * 1024
# 媒体文件名由内容摘要派生（media_v1 的内容寻址命名），扩展名只允许镜像器
# 已产出的白名单；名称本身就携带完整性约束，任何伪造路径都无法通过。
MEDIA_NAME = re.compile(r"media-[0-9a-f]{64}\.(?:png|jpg|gif|webp|svg|md)\Z")
MAX_SIGNATURE_BYTES = 64 * 1024
MEDIA_IMAGE_EXTENSIONS = {"png", "jpg", "gif", "webp", "svg"}
MEDIA_README_EXTENSIONS = {"md"}
# 媒体单文件上限与 media_v1 的 MAX_IMAGE/MAX_README 对齐并取其大者（2 MiB 图像
# 与 1 MiB README），留出安全余量；登记 TOML 上限按生成器可见的真实登记规模设
# 置，远超正常输入即可，仅用于把异常输入挡在受控读取内。
MAX_MEDIA_BYTES = 4 * 1024 * 1024
MAX_REGISTRATION_BYTES = 4 * 1024 * 1024


def _fail(message):
    """统一以普通 ValueError 失败：调用方据此整体退出，不产出半可信状态。"""
    raise ValueError(message)


# 打开不可信输入的安全标志：O_NOFOLLOW 让最终分量的符号链接在 open 时以 ELOOP
# 失败（Linux 生产 runner 可用）；O_NONBLOCK 让 FIFO 的 open 立即返回而不是阻塞
# 等待写者（否则一个恶意 FIFO 就能让发布任务挂死）；O_BINARY 禁止 Windows 文本
# 模式转换破坏字节计数。三者在非提供平台上安全缺席，由 fstat 补足判定。
_SAFE_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def read_limited_regular_file(path, limit, what):
    """把不可信路径安全读成受限字节：常规文件判定与限额读取都基于同一个句柄。

    语义与边界（经核查，不夸大）：
    - 打开用 O_NOFOLLOW|O_NONBLOCK：Linux 上符号链接最终分量直接 ELOOP 拒绝，
      FIFO 不会阻塞 open；Windows 无这两个标志，退化为 open 后 fstat 判定。
    - 打开成功后对同一 fd 做 fstat 并要求 S_ISREG：FIFO、socket、设备、目录
      全部拒绝；fstat 看到的是打开句柄的真实 inode，不是路径上可以被中途替换
      的解释结果，因此不存在「lstat 通过后 open 撞上已换成的链接/FIFO」的
      lstat-open TOCTOU。
    - 读取按 fd 循环 os.read，最多读 limit+1 字节：超限在读取流本身受限，不是
      先把任意大的输入整个读进内存再检查。
    - 未彻底解决的竞争（诚实声明）：打开并读取期间，攻击者若能替换路径分量
      （父目录重命名、dirswap）或对已打开的常规文件做并发内容改写，本函数无法
      感知；「读到 digest A、随后磁盘上变成 digest B」的窗口需要目录句柄级
      保护（如 openat2 RESOLVE_BENEATH）才能闭环，纯 Python 标准库做不到。
      本函数承诺的是：返回的字节确实来自打开瞬间的常规文件句柄，且读取总量
      有界。多次读取之间也存在同样的替换窗口（包括在途 A→B→A：两次读各看到
      不同字节而每次都自洽），verify/sign 比对能提高发现概率，但不构成绝对
      保证；回执只证明当前检查到的材料彼此自洽，不等于发布者预期或人工审核。
    - 在 Windows 开发机上（无 O_NOFOLLOW），符号链接由 fstat + 显式
      lstat(follow_symlinks=False) 双检拒绝：fstat 判 S_ISREG，lstat 判目标
      本身不是链接。这不是最终分量的原子拒绝——lstat 与 open 之间仍有理论
      窗口；生产 Linux 上 O_NOFOLLOW 才在 open 时原子拒绝链接最终分量，
      开发机双检只是尽力而为。
    """
    try:
        fd = os.open(path, _SAFE_OPEN_FLAGS)
    except OSError as error:
        # ELOOP 是 O_NOFOLLOW 命中符号链接的信号；其余打开错误（缺失、权限、
        # Windows 上打开目录）按统一失败处理，错误文本保留 errno 类别。
        raise ValueError(f"{what} cannot be opened safely: {error}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{what} is not a regular file")
        if not hasattr(os, "O_NOFOLLOW"):
            # 开发机退化路径：对路径再做一次不跟随的 lstat，确认路径分量本身
            # 不是链接。与 fstat 之间仍有理论窗口，仅作为开发机尽力而为（见上）。
            try:
                link_info = os.stat(path, follow_symlinks=False)
                if stat.S_ISLNK(link_info.st_mode):
                    raise ValueError(f"{what} is a symbolic link")
            except OSError as error:
                raise ValueError(f"{what} cannot be stat-ed safely: {error}") from None
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise ValueError(f"{what} exceeds size limit")
        return data
    finally:
        os.close(fd)


def _parse_json_bytes(data, what):
    """把已限读的字节解析成 JSON：解析失败统一为 ValueError，复用同一失败语义。"""
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{what} is not valid UTF-8 JSON") from error


def load_json(path, limit, what):
    """在大小上限内读取 JSON：经安全句柄限读，超限或坏 JSON 直接失败。

    与旧实现（先 read_bytes 整读再查长度）不同，大小约束覆盖真正的读取流：
    超大输入不会先完整进入内存。
    """
    return _parse_json_bytes(read_limited_regular_file(path, limit, what), what)


def _checked_u64(value, what):
    """宿主按 u64 解析序列：0、布尔、负数或越界值都不是合法序列，先于任何使用拒绝。"""
    if type(value) is not int or not 1 <= value <= 2**64 - 1:
        _fail(f"{what} must be a positive u64")
    return value


def host_identity_allowed(plugin_id):
    """在生成器语法之外补充宿主保留身份规则：语法合格但宿主拒绝的 ID 必须拦截。

    逐条镜像主仓 crates/domain/src/plugins.rs 的 PluginId::parse 保留判定
    （同步来源与漂移测试见 HOST_RESERVED_FIRST_SEGMENTS 注释）：Windows 设备
    名判定只看第一个点前的 stem（因此 `acme.con` 的 name 段是设备名也不会被
    本防线拦截，只有首段 `con` 才拒绝），另有状态文件 `state.json` 与恢复材料
    `state-recovery-*.json`。这些 ID 通过生成器 ID 正则但会让签名目录在宿主
    反序列化时整体不可解析，所以签名前必须在候选校验中拦截；已验签历史的
    读取策略不变（publication_v1 的索引与不可变比较不经过本防线）。
    """
    if not isinstance(plugin_id, str) or "." not in plugin_id:
        return False
    first_segment = plugin_id.split(".", 1)[0]
    if first_segment in HOST_RESERVED_FIRST_SEGMENTS:
        return False
    if plugin_id == "state.json":
        return False
    if plugin_id.startswith("state-recovery-") and plugin_id.endswith(".json"):
        return False
    return True


def _require_hex(value, what):
    """摘要字段必须是完整 64 位小写十六进制；格式即契约，不做宽松解释。"""
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        _fail(f"{what} is not a sha256 hex digest")
    return value


def registration_path_allowed(relative):
    """判断登记清单键是否对应生成器的真实数据输入（同源边界，非另抄正则）。

    旧实现把 plugin ID 长度和字符集另写成一个定长正则，与生成器 ID 契约
    （`[a-z0-9][a-z0-9-]{1,38}\\.[a-z0-9][a-z0-9-]{1,62}`，最长 39+1+63=103）
    不一致：合法的最大长度 ID 会被清单误拒。这里直接复用受信生成器的 ID
    正则判定文件名主体，并把路径限定为 `plugins/<单文件名>.toml` 或
    `plugins/readmes/<单文件名>.md`，因此路径分隔符、穿越成分与子目录都
    不可能通过，同时不会与生成器边界漂移。README 路径也进入清单，确保
    发布回执绑定的是作者实际提供的插件说明，而不是商店仓库 README。
    """
    if not isinstance(relative, str):
        return False
    if relative == "categories.toml":
        return True
    for prefix, suffix in (("plugins/readmes/", ".md"), ("plugins/", ".toml")):
        if not relative.startswith(prefix) or not relative.endswith(suffix):
            continue
        stem = relative[len(prefix):-len(suffix)]
        if not stem or "/" in stem or "\\" in stem or stem in (".", ".."):
            return False
        return _load_generator().ID.fullmatch(stem) is not None
    return False


@functools.lru_cache(maxsize=1)
def _load_generator():
    """从本受信检出加载 catalog-v1.py 生成器模块（及其 media_v1 依赖）。

    只允许加载与 trusted_publish_v1.py 同目录的实现：生成逻辑与校验逻辑必须
    同一次审计演进，禁止静默回落到候选检出或其它路径的同名文件。
    """
    spec = importlib.util.spec_from_file_location("kerminal_trusted_catalog_v1", _MODULE_DIR / "catalog-v1.py")
    if spec is None or spec.loader is None:
        raise ImportError("trusted checkout is missing marketplace/catalog-v1.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _real_directory_state(path, what):
    """目录本身的三分判定：缺失 / 存在但不是真实目录 / 真实目录。

    glob 与 iterdir 都会跟随目录符号链接，把链接目标当成目录内容，从而读到
    data root 之外的文件；必须先对最终目录分量做不跟随的 lstat 判定。返回
    False 表示缺失（调用方按空集合处理），非法类型直接失败。诚实边界：本函数
    只给出检查瞬间的最终目录类型快照——最终目录本身在 lstat 与随后 glob/iterdir
    之间同样可能被替换为链接或另一个目录（不只是祖先目录可被并发替换），因此
    它不是绑定到枚举时刻的目录句柄；要闭环需要 dirfd/openat2，本函数不宣称
    消除该窗口。
    """
    if not os.path.lexists(path):
        return False
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise ValueError(f"{what} cannot be stat-ed: {error}") from None
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{what} is not a real directory: {path}")
    return True


def registrations_manifest(data_root):
    """对生成器的全部数据输入（分类与登记 TOML）计算确定性摘要清单。

    verify 与 sign 两侧都用同一规则重算并比对，把「参与生成的登记数据」绑定
    进回执；候选目录若与登记数据脱钩（例如 artifact 被换成另一次运行的产物），
    绑定检查会立即失败。读取经 read_limited_regular_file：符号链接、FIFO 与
    其它非常规文件一律拒绝。`plugins` 目录本身先做不跟随的静态判定，避免
    glob 跟随目录符号链接读到 data root 之外；其祖先或最终目录在检查后、枚举
    前的并发替换窗口仍未绑定（见 _real_directory_state 的边界声明）。
    """
    root = Path(data_root)
    plugins_dir = root / "plugins"
    # 缺失 plugins 与「存在但不是真实目录」必须区分：后者不能静默当成空集合。
    if _real_directory_state(plugins_dir, "candidate plugin registration directory"):
        registration_paths = sorted(plugins_dir.glob("*.toml"))
    else:
        registration_paths = []
    # 登记 README 是作者数据输入，必须和登记 TOML 一起绑定进回执；否则
    # artifact 里的说明可以被替换而不被发现。目录缺失是合法的（旧登记没有
    # README），存在但不是真实目录则失败。
    readme_dir = plugins_dir / "readmes"
    if _real_directory_state(readme_dir, "candidate plugin readme directory"):
        readme_paths = sorted(readme_dir.glob("*.md"))
    else:
        readme_paths = []
    manifest = {}
    for path in [root / "categories.toml", *registration_paths, *readme_paths]:
        relative = path.relative_to(root).as_posix()
        if not registration_path_allowed(relative):
            _fail(f"unexpected registration path: {relative}")
        data = read_limited_regular_file(path, MAX_REGISTRATION_BYTES, f"registration input {relative}")
        manifest[relative] = hashlib.sha256(data).hexdigest()
    return manifest


def media_manifest(media_dir):
    """对候选媒体目录计算内容清单：所有条目必须是常规文件并按摘要登记。

    目录状态三分：缺失返回空清单（合法 bootstrap 场景）；存在但不是真实目录
    （普通文件、指向目录的符号链接等）一律失败——is_dir 会跟随目录符号链接，
    因此用不跟随的 lstat 判定真实类型，不把「链接到目录」当成目录；目录内出现
    子目录、符号链接或其它非常规条目同样失败。发布物集合必须是平坦的确定性
    集合。摘要计算经 read_limited_regular_file 的安全句柄（O_NOFOLLOW +
    fstat S_ISREG），不是先 lstat 后按路径跟随。父路径与并发目录替换窗口仍未
    闭环（见 read_limited_regular_file 的边界声明），本函数不宣称消除。
    """
    directory = Path(media_dir)
    if not _real_directory_state(directory, "candidate media directory"):
        # 缺失是合法空集合；存在但不合法已由 _real_directory_state 失败。
        return {}
    manifest = {}
    for path in sorted(directory.iterdir()):
        if not MEDIA_NAME.fullmatch(path.name):
            _fail(f"candidate media file name is not content-addressed: {path.name}")
        data = read_limited_regular_file(path, MAX_MEDIA_BYTES, f"candidate media {path.name}")
        manifest[path.name] = hashlib.sha256(data).hexdigest()
    return manifest


def _media_reference(url, sequence, allowed_extensions, what):
    """校验目录内的媒体引用：必须指向本轨固定 Release 的本序列内容寻址资产。

    引用格式即安全契约：域名、仓库、快照标签、序列与摘要派生文件名全部由
    本函数重建并要求全等，防止目录引用外链、其它轨道或其它序列的资产。
    """
    if not isinstance(url, str):
        _fail(f"{what} must be a string")
    name = url.rsplit("/", 1)[-1]
    if not MEDIA_NAME.fullmatch(name):
        _fail(f"{what} is not a content-addressed media reference")
    extension = name.rsplit(".", 1)[-1]
    if extension not in allowed_extensions:
        _fail(f"{what} has an extension outside the allowlist")
    expected = (
        f"https://github.com/{MARKET_REPOSITORY}/releases/download/"
        f"{TRACK_IDENTITY.fixed_tag}-{sequence}/{name}"
    )
    if url != expected:
        _fail(f"{what} does not point at the v1 fixed release asset for sequence {sequence}")
    return name


def _asset_url(plugin_id, version, platform, repository):
    """按生成器规则重建平台资产的确定 URL（含与 catalog-v1.py 一致的 quote 语义）。

    与 catalog-v1.py 的 build_catalog 一致，repository 先剥掉 GitHub 前缀再拼
    下载地址：调用方传完整登记 URL，这里统一 removeprefix，避免双前缀拼出
    非法地址或让校验与生成对同一登记产生两套 URL 判定。
    """
    owner_repo = repository.removeprefix("https://github.com/")
    tag = urllib.parse.quote(f"v{version}", safe="")
    name = urllib.parse.quote(f"{plugin_id}-{version}-{platform}.kplugin", safe="")
    return f"https://github.com/{owner_repo}/releases/download/{tag}/{name}"


def validate_candidate_structure(catalog):
    """离线校验候选目录可从 JSON 判定的字段、身份与 URL 约束。

    诚实边界：本函数不独立证明「完整宿主契约」。资产摘要的真实性、包内
    manifest、API range 与版本 SemVer 的字节级核对都在 verify 阶段由受信生成器
    与 SDK 校验器完成，签名侧只能复算「回执摘要 == 当前候选字节」并信任
    verify 侧受信代码的结论——回执自洽不是独立重验。本函数覆盖的是可从 JSON
    直接判定的语法约束（字段集、轨道身份、序列类型、URL 重建全等、大小写
    边界），并复用生成器的 ID/VERSION/REPOSITORY 正则与宿主 PluginId::parse
    的保留身份镜像（见 HOST_RESERVED_FIRST_SEGMENTS），保证两侧规则同源不漂移；
    这些检查是「提前拦截宿主必然拒绝的目录」，不是对生成器结论的独立复核。
    """
    generator = _load_generator()
    if not isinstance(catalog, dict) or set(catalog) != {"schema", "source_id", "sequence", "plugins"}:
        _fail("candidate catalog fields do not match the v1 contract")
    # 宿主 schema 是 serde u32：JSON 的 true/false 会被宿主反序列化拒绝；Python
    # 的 True == 1 会骗过 `!= 1` 比较，因此必须先按 type 严格整数再比较值。
    if type(catalog["schema"]) is not int or catalog["schema"] != 1 or catalog["source_id"] != SOURCE_ID:
        _fail("candidate is not on the v1 track")
    sequence = _checked_u64(catalog["sequence"], "candidate sequence")
    plugins = catalog["plugins"]
    if not isinstance(plugins, list) or not plugins or len(plugins) > 4096:
        _fail("candidate catalog must contain 1..4096 published plugins")
    # 宿主契约按 BTreeSet 拒绝重复 id；重复项会让后续按 id 建索引的绑定/不可变
    # 比较互相覆盖而出现伪一致，因此无论 bootstrap 还是增量发布都先在此拒绝。
    seen_plugin_ids = set()
    for plugin in plugins:
        if not isinstance(plugin, dict) or set(plugin) != {
            "id", "name", "description", "publisher", "permissions", "categories",
            "icon_url", "readme_url", "repository", "versions",
        }:
            _fail("candidate plugin fields do not match the v1 contract")
        plugin_id = plugin["id"]
        if not isinstance(plugin_id, str) or not generator.ID.fullmatch(plugin_id):
            _fail(f"invalid plugin id: {plugin_id!r}")
        if plugin_id in seen_plugin_ids:
            _fail(f"duplicate plugin id: {plugin_id}")
        seen_plugin_ids.add(plugin_id)
        # 宿主保留身份（设备名首段、state.json、state-recovery-*.json）会让整份
        # 目录在宿主反序列化时失败，语法合格也必须在签名前拒绝。
        if not host_identity_allowed(plugin_id):
            _fail(f"plugin id is reserved by the host: {plugin_id}")
        repository = plugin["repository"]
        match = generator.REPOSITORY.fullmatch(repository) if isinstance(repository, str) else None
        if not match or repository.endswith(".git"):
            _fail(f"invalid repository URL: {plugin_id}")
        if plugin_id.startswith("kerminal.") and match.group(1).lower() != "kongweiguang":
            _fail(f"reserved official id requires official owner: {plugin_id}")
        for field in ("name", "description"):
            value = plugin[field]
            if not isinstance(value, dict) or not value or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
                _fail(f"invalid localized {field}: {plugin_id}")
        if not isinstance(plugin["publisher"], str) or not plugin["publisher"]:
            _fail(f"invalid publisher: {plugin_id}")
        # 宿主 catalog.rs 要求 publisher 必须等于 id 第一个点前的段，否则整份
        # 目录在宿主侧被拒绝；签名前按同一规则拒绝，防止通过计划却不可解析。
        if plugin["publisher"] != plugin_id.split(".", 1)[0]:
            _fail(f"publisher must match the id publisher segment: {plugin_id}")
        if not isinstance(plugin["permissions"], list) or any(not isinstance(item, str) for item in plugin["permissions"]):
            _fail(f"invalid permissions: {plugin_id}")
        categories = plugin["categories"]
        if not isinstance(categories, list) or not categories or any(not isinstance(item, str) for item in categories):
            _fail(f"invalid categories: {plugin_id}")
        _media_reference(plugin["readme_url"], sequence, MEDIA_README_EXTENSIONS, f"readme_url of {plugin_id}")
        if plugin["icon_url"] is not None:
            _media_reference(plugin["icon_url"], sequence, MEDIA_IMAGE_EXTENSIONS, f"icon_url of {plugin_id}")
        versions = plugin["versions"]
        if not isinstance(versions, list) or not versions or len(versions) > 1024:
            _fail(f"plugin must have 1..1024 versions: {plugin_id}")
        seen_versions = set()
        for version in versions:
            if not isinstance(version, dict) or set(version) != {"version", "api", "published_at", "changelog_url", "assets"}:
                _fail(f"candidate version fields do not match the v1 contract: {plugin_id}")
            number = version["version"]
            if not isinstance(number, str) or not generator.VERSION.fullmatch(number) or number in seen_versions:
                _fail(f"invalid or duplicate version: {plugin_id}")
            seen_versions.add(number)
            if not isinstance(version["api"], str) or not version["api"]:
                _fail(f"invalid api: {plugin_id} {number}")
            if not isinstance(version["published_at"], str) or not version["published_at"]:
                _fail(f"invalid published_at: {plugin_id} {number}")
            expected_changelog = f"https://github.com/{repository.removeprefix('https://github.com/')}/releases/tag/{urllib.parse.quote(f'v{number}', safe='')}"
            if version["changelog_url"] != expected_changelog:
                _fail(f"changelog URL must be the quoted release tag: {plugin_id} {number}")
            assets = version["assets"]
            if not isinstance(assets, list) or not assets:
                _fail(f"version has no assets: {plugin_id} {number}")
            platforms = []
            for asset in assets:
                if not isinstance(asset, dict) or set(asset) != {"platform", "url", "sha256", "size"}:
                    _fail(f"asset fields do not match the v1 contract: {plugin_id} {number}")
                platform = asset["platform"]
                if not isinstance(platform, str) or platform not in generator.PLATFORMS:
                    _fail(f"unknown platform: {plugin_id} {number} {platform!r}")
                _require_hex(asset["sha256"], f"asset digest of {plugin_id} {number} {platform}")
                if type(asset["size"]) is not int or not 1 <= asset["size"] <= MAX_ASSET_BYTES:
                    _fail(f"asset size out of contract: {plugin_id} {number} {platform}")
                expected_url = _asset_url(plugin_id, number, platform, repository)
                if asset["url"] != expected_url:
                    _fail(f"asset URL does not match the registered repository and tag: {plugin_id} {number} {platform}")
                platforms.append(platform)
            if len(set(platforms)) != len(platforms):
                _fail(f"duplicate platforms: {plugin_id} {number}")
            # "any" 是 runtime=none 单资产平台的保留值：出现时必须独占该版本，
            # 与生成器的 runtime/platform 契约一致，不给混合平台目录留解释空间。
            if "any" in platforms and len(platforms) != 1:
                _fail(f"any platform must be exclusive: {plugin_id} {number}")
            if plugin_id.startswith("kerminal.") and "any" not in platforms and set(platforms) != generator.OFFICIAL_PLATFORMS:
                _fail(f"official sidecar needs four release platforms: {plugin_id} {number}")


def verify_minisign(message_bytes, signature_bytes, pubkey):
    """对内存中的同一份有界字节验签，而不是按路径二次打开。

    旧实现把 fixed 路径交给 minisign 验签，之后又按同一路径 load_json，两次
    打开之间固定基线可被替换，导致「已验签的字节」与「参与历史比较的 JSON」
    不是同一份内容。这里先把消息与签名各经 read_limited_regular_file 有界读
    入内存，再写入调用方不可预测的私有临时目录（TemporaryDirectory 默认
    mkdtemp 权限，随调用回收），minisign 只接触这两份副本；解析用的就是同一
    份 bytes。没有假定 minisign 的 `-m -` 支持 stdin：本机 Windows 与 WSL 均
    未安装 minisign，仓库工作流只使用 `-m <path>` 的路径形态，因此不为未验证
    的输入通道增加依赖。pubkey 仍按钉住检出的路径传入（来自受信检出，不是
    候选输入）。minisign 缺失或退出非零按 fail-closed 抛出 OSError/
    CalledProcessError，临时目录在退出时回收，不残留可复用的验签副本。
    诚实边界：临时副本只在本次调用内存在，但若本机同时存在恶意进程，仍可在
    minisign 读取临时文件前改写它；这需要进程级隔离，不属于本模块的承诺。
    """
    with tempfile.TemporaryDirectory(prefix="kerminal-trusted-") as temp:
        temp_dir = Path(temp)
        message_path = temp_dir / "catalog.json"
        signature_path = temp_dir / "catalog.json.minisig"
        message_path.write_bytes(message_bytes)
        signature_path.write_bytes(signature_bytes)
        subprocess.run(
            ["minisign", "-Vm", str(message_path), "-x", str(signature_path), "-p", str(pubkey)],
            check=True, capture_output=True,
        )


def load_fixed_verified(fixed_path, fixed_sig, pubkey):
    """读取并验签固定目录基线：验签对象与解析对象绑定为同一份有界字节。

    只对 fixed 与签名各做一次 read_limited_regular_file，随后用内存副本验签，
    返回的 JSON 由同一份 bytes 解析。即验签交给 minisign 的是内存字节的临时
    副本，解析用的也是这份内存字节，因此消除了旧实现「按固定路径验签、再按
    同一路径重新打开解析」之间的替换窗口。诚实边界：临时目录若被同用户并发
    进程写入并替换副本，minisign 实际验签的字节仍可能与内存字节不同；这依赖
    受信 runner 与临时目录的进程隔离，不是本函数能证明的绝对保证。
    """
    data = read_limited_regular_file(fixed_path, MAX_CATALOG_BYTES, "fixed catalog")
    signature_data = read_limited_regular_file(fixed_sig, MAX_SIGNATURE_BYTES, "fixed catalog signature")
    verify_minisign(data, signature_data, pubkey)
    return _parse_json_bytes(data, "fixed catalog")


def inspect_data(data_root):
    """用受信生成器规则校验候选登记数据，并判断是否存在已发布条目。

    这是 verify 任务的第一个受信步骤：登记数据的合法性在这里裁决，候选检出
    自己的脚本不参与；pending 条目不进入目录。
    """
    generator = _load_generator()
    entries = generator.load_registrations(Path(data_root))
    published = [plugin_id for plugin_id, entry in entries if entry.get("status", "published") == "published"]
    return {"published": bool(published), "entries": len(published)}


def compute_sequence(releases, fixed, bootstrap):
    """按 v1 轨道计算下一序列；基线身份、快照一致性与引导批准全部强制。

    与旧流程调用 publication_v1 非严格入口不同，这里始终走严格轨道入口：
    固定基线必须属于 v1 轨（schema/source_id 全等），防止把其它轨道或伪造
    目录当作序列基线。
    """
    return publication_v1.next_sequence_for(TRACK, fixed, releases, bootstrap)


def generate_candidate(data_root, tool, sequence, output_dir):
    """以候选检出的数据为根、用受信生成器产出候选目录与回执。

    关键点：build_catalog 接受显式 root 参数，因此受信生成器可以直接指向候选
    检出读取登记数据，而不执行候选检出中的任何代码；资产下载、摘要、清单
    校验、媒体镜像都在受信代码内完成。产出前先做一次本模块的结构校验，把
    「受信生成器产出也应满足契约」变成生成侧的自我闭合检查。
    """
    generator = _load_generator()
    _checked_u64(sequence, "generation sequence")
    output_dir = Path(output_dir)
    media_dir = output_dir / "media"
    catalog = generator.build_catalog(Path(data_root), str(tool), sequence, media_dir)
    if not catalog["plugins"]:
        _fail("no published plugins; refusing to generate a production catalog")
    validate_candidate_structure(catalog)
    encoded = generator.catalog_bytes(catalog)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "catalog.json").write_bytes(encoded)
    receipt = {
        "track": TRACK,
        "repository": MARKET_REPOSITORY,
        "sequence": sequence,
        "candidate_sha256": hashlib.sha256(encoded).hexdigest(),
        "media_manifest": media_manifest(media_dir),
        "registrations_manifest": registrations_manifest(data_root),
    }
    (output_dir / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return catalog, receipt


def load_receipt(path):
    """读取并结构校验 verify 回执：字段、轨道身份、摘要与清单格式必须齐备。

    回执只是「verify 侧受信产出」的声明，真实性由 sign 侧逐项重算比对保证；
    本函数只拒绝结构上不可能属于本轨的输入。
    """
    receipt = load_json(path, MAX_RECEIPT_BYTES, "verify receipt")
    if not isinstance(receipt, dict) or set(receipt) != {
        "track", "repository", "sequence", "candidate_sha256", "media_manifest", "registrations_manifest",
    }:
        _fail("receipt fields do not match the v1 contract")
    if receipt["track"] != TRACK or receipt["repository"] != MARKET_REPOSITORY:
        _fail("receipt is not from the v1 track in the marketplace repository")
    _checked_u64(receipt["sequence"], "receipt sequence")
    _require_hex(receipt["candidate_sha256"], "receipt candidate digest")
    media = receipt["media_manifest"]
    if not isinstance(media, dict):
        _fail("receipt media manifest must be an object")
    for name, digest in media.items():
        if not MEDIA_NAME.fullmatch(name):
            _fail(f"receipt media name is not content-addressed: {name!r}")
        _require_hex(digest, f"receipt media digest of {name}")
        if name.partition("-")[2].split(".")[0] != digest:
            _fail(f"receipt media name does not embed its digest: {name}")
    registrations = receipt["registrations_manifest"]
    if not isinstance(registrations, dict) or not registrations:
        _fail("receipt registrations manifest must be a non-empty object")
    for name, digest in registrations.items():
        if not registration_path_allowed(name):
            _fail(f"receipt registration path is outside the data inputs: {name!r}")
        _require_hex(digest, f"receipt registration digest of {name}")
    return receipt


def _registration_binding(generator, data_root, catalog):
    """把候选目录与登记数据逐项绑定：插件集合、仓库、分类、版本集合全等。

    登记文件是人工评审的对象；目录只是登记数据的投影。绑定失败说明目录与
    评审内容脱钩（artifact 混用、生成侧失控或人为构造），必须整体失败。
    """
    expected = {}
    for plugin_id, entry in generator.load_registrations(Path(data_root)):
        if entry.get("status", "published") != "published":
            continue
        expected[plugin_id] = {
            "repository": entry["repository"],
            "categories": entry["categories"],
            "versions": sorted(registration["version"] for registration in entry["versions"]),
        }
    actual = {}
    for plugin in catalog["plugins"]:
        actual[plugin["id"]] = {
            "repository": plugin["repository"],
            "categories": plugin["categories"],
            "versions": sorted(version["version"] for version in plugin["versions"]),
        }
    if actual != expected:
        _fail("candidate catalog does not match the reviewed registrations")


def build_sign_plan(receipt, candidate_path, fixed, releases, media_dir, data_root, *, bootstrap):
    """在任何密钥进入环境之前生成签名计划；全部约束通过才返回。

    检查序列（每条都是 fail-closed）：
    1. 候选字节摘要 == 回执记录（verify 产出的同一份目录）；
    2. 媒体清单 == 回执记录（逐文件重算摘要）；
    3. 登记清单 == 回执记录（逐文件重算摘要）；
    4. 序列 == 按 v1 轨道从 release 列表与已验签基线重算的结果（verify 与
       sign 之间发布状态漂移立即失败）；
    5. 候选目录结构满足完整宿主契约（复用生成器正则，规则同源）；
    6. 候选目录与登记数据逐项绑定；
    7. 存在基线时，候选必须严格 sequence+1 且历史版本 API 与平台资产不可变；
    8. 媒体引用必须落在已登记的媒体集合内（引用摘要 = 文件名字节摘要 = 实际
       文件摘要，形成内容寻址闭环）。
    bootstrap 必须是调用方显式决定（CLI 的 --bootstrap）：旧实现从 `fixed is
    None` 自动推断，等于「没有基线就自动批准引导」，与工作流的显式批准变量
    语义脱节。现在显式传入，并由 publication_v1 的严格入口裁决；同时在本层
    拒绝「已有验签基线却声明 bootstrap」的自相矛盾状态，避免计划把增量发布
    误标为引导发布。返回的计划包含 sequence、快照标签、bootstrap 与应上传的
    媒体名集合，供受控 bash 步骤消费；工作流在本函数通过后才允许加载签名密钥。
    """
    candidate_path = Path(candidate_path)
    # 候选字节只经安全句柄读取一次：同一次得到的 bytes 同时用于回执摘要比对与
    # JSON 解析，摘要与结构校验不可能看到不同内容（旧实现 read_bytes + load_json
    # 两次读路径之间可被并发替换撕裂）。读取本身经 read_limited_regular_file：
    # 上限+1 限流、符号链接与非常规文件与其它不可信输入同一策略。
    candidate_bytes = read_limited_regular_file(candidate_path, MAX_CATALOG_BYTES, "candidate catalog")
    if hashlib.sha256(candidate_bytes).hexdigest() != receipt["candidate_sha256"]:
        _fail("candidate bytes changed between verify and sign")
    if media_manifest(media_dir) != receipt["media_manifest"]:
        _fail("receipt media manifest disagrees with the candidate media set")
    if registrations_manifest(data_root) != receipt["registrations_manifest"]:
        _fail("receipt registrations manifest disagrees with the candidate data")
    if bootstrap and fixed is not None:
        _fail("bootstrap approval is incompatible with an existing verified baseline")
    sequence = compute_sequence(releases, fixed, bootstrap=bootstrap)
    if sequence != receipt["sequence"]:
        _fail("publication state drifted between verify and sign; recover before retry")
    try:
        candidate = json.loads(candidate_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("candidate catalog is not valid UTF-8 JSON") from error
    validate_candidate_structure(candidate)
    if candidate["sequence"] != receipt["sequence"]:
        _fail("candidate sequence disagrees with the receipt")
    generator = _load_generator()
    _registration_binding(generator, data_root, candidate)
    for plugin in candidate["plugins"]:
        references = [("readme_url", plugin["readme_url"], MEDIA_README_EXTENSIONS), ("icon_url", plugin["icon_url"], MEDIA_IMAGE_EXTENSIONS)]
        for what, url, extensions in references:
            if url is None:
                if what == "readme_url":
                    _fail(f"readme_url must be present: {plugin['id']}")
                continue
            name = _media_reference(url, candidate["sequence"], extensions, f"{what} of {plugin['id']}")
            if name not in receipt["media_manifest"]:
                _fail(f"media reference is not covered by the verified media set: {plugin['id']} {name}")
    if fixed is not None:
        publication_v1.validate_update_for(TRACK, fixed, candidate)
    return {
        "sequence": sequence,
        "tag": f"{TRACK_IDENTITY.snapshot_prefix}{sequence}",
        "fixed_tag": TRACK_IDENTITY.fixed_tag,
        "bootstrap": bootstrap,
        "media": sorted(receipt["media_manifest"]),
        "candidate_sha256": receipt["candidate_sha256"],
    }


def _require_fixed_flag_consistency(parser, options):
    """参数卫生：--fixed 与 --fixed-sig/--pubkey 必须成对出现，不允许悬空单边。

    只多传验签材料而缺 --fixed 是无意义的调用（材料会被静默丢弃，掩盖调用方
    拼写错误）；反向缺材料已有 parser.error。这不是安全边界——多余参数本身
    不改变验签语义——而是把调用错误提前到解析期显式失败。
    """
    extras = [name for name, present in (("--fixed-sig", options.fixed_sig), ("--pubkey", options.pubkey)) if present]
    if extras and not options.fixed:
        parser.error(f"{', '.join(extras)} require --fixed for signature verification")


def main():
    """CLI 入口：inspect / sequence / generate / plan 四个子命令，全部无密钥。

    plan 输出 JSON 计划供受控 bash 步骤消费；加载密钥与 gh 发布写入由工作流
    在 plan 通过后的独立步骤承担，本模块不提供任何读取密钥或写 Release 的路径。
    """
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("--data-root", required=True, type=Path)

    sequence = sub.add_parser("sequence")
    sequence.add_argument("--releases", required=True, type=Path)
    sequence.add_argument("--fixed", type=Path)
    sequence.add_argument("--fixed-sig", type=Path)
    sequence.add_argument("--pubkey", type=Path)
    sequence.add_argument("--bootstrap", action="store_true")

    generate = sub.add_parser("generate")
    generate.add_argument("--data-root", required=True, type=Path)
    generate.add_argument("--tool", required=True)
    generate.add_argument("--sequence", required=True, type=int)
    generate.add_argument("--output-dir", required=True, type=Path)

    plan = sub.add_parser("plan")
    plan.add_argument("--receipt", required=True, type=Path)
    plan.add_argument("--candidate", required=True, type=Path)
    plan.add_argument("--media-dir", required=True, type=Path)
    plan.add_argument("--data-root", required=True, type=Path)
    plan.add_argument("--releases", required=True, type=Path)
    plan.add_argument("--fixed", type=Path)
    plan.add_argument("--fixed-sig", type=Path)
    plan.add_argument("--pubkey", type=Path)
    plan.add_argument("--bootstrap", action="store_true")

    options = parser.parse_args()
    if options.command == "inspect":
        print(json.dumps(inspect_data(options.data_root), sort_keys=True))
    elif options.command == "sequence":
        _require_fixed_flag_consistency(parser, options)
        fixed = None
        if options.fixed:
            if not options.fixed_sig or not options.pubkey:
                parser.error("--fixed requires --fixed-sig and --pubkey for signature verification")
            fixed = load_fixed_verified(options.fixed, options.fixed_sig, options.pubkey)
        releases = load_json(options.releases, MAX_RECEIPT_BYTES, "release list")
        print(compute_sequence(releases, fixed, options.bootstrap))
    elif options.command == "generate":
        generate_candidate(options.data_root, options.tool, options.sequence, options.output_dir)
        print(f"generated verified candidate for sequence {options.sequence}")
    else:
        receipt = load_receipt(options.receipt)
        releases = load_json(options.releases, MAX_RECEIPT_BYTES, "release list")
        _require_fixed_flag_consistency(parser, options)
        fixed = None
        if options.fixed:
            if not options.fixed_sig or not options.pubkey:
                parser.error("--fixed requires --fixed-sig and --pubkey for signature verification")
            fixed = load_fixed_verified(options.fixed, options.fixed_sig, options.pubkey)
        # 参数名与 build_sign_plan 形参同名遮蔽过 plan 函数对象；改用独立名字，
        # 保持「先计划后密钥」的入口语义不被变量名混淆。
        sign_plan = build_sign_plan(
            receipt, options.candidate, fixed, releases, options.media_dir, options.data_root,
            bootstrap=options.bootstrap,
        )
        print(json.dumps(sign_plan, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"trusted-publish: {error}", file=sys.stderr)
        sys.exit(1)
