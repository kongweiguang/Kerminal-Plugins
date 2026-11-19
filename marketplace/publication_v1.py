# @author kongweiguang
"""决定序列前检查固定目录与不可变快照是否仍处于同一提交。

兼容轨 v1 与独立新轨 v2 共用同一套序列/不可变规则，也沿用宿主当前支持的
schema 1；两轨只在签名原文的 source_id 上区分（official / official-v2），
并各自固定 Release 与不可变快照前缀。本模块只做纯本地校验，不联网、不读取
或使用签名密钥；签名与发布仍由后续受控流程完成。
"""

import argparse
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Track:
    """一条发布轨道的固定身份。

    两轨共用签名密钥和 schema 1（宿主 PluginCatalog 目前只接受 schema 1），
    因此 source_id 是签名原文里唯一的轨道身份；固定 Release 与快照前缀再
    防止同仓另一轨的标签被误当成本轨序列或基线。
    """

    name: str
    schema: int
    source_id: str
    fixed_tag: str
    snapshot_prefix: str

    def snapshot_sequence(self, tag):
        """只解析本轨的不可变快照标签，同仓其它轨道或非法后缀不能参与序列计算。

        数字后缀超出 u64 时不能静默忽略：它既不可能被固定目录表示，也可能是
        人为插入的越界快照；直接失败，避免序列在不可见的状态下继续推进。
        """
        if not isinstance(tag, str) or not tag.startswith(self.snapshot_prefix):
            return None
        suffix = tag[len(self.snapshot_prefix) :]
        if not re.fullmatch(r"[1-9][0-9]*", suffix):
            return None
        sequence = int(suffix)
        if sequence > 2**64 - 1:
            raise ValueError("catalog snapshot sequence exceeds u64")
        return sequence


# v2 目前只定义本地校验原语；宿主尚未读取 official-v2，签名和客户端联调仍待完成。
V1_TRACK = Track("v1", 1, "official", "catalog-v1", "catalog-v1-")
V2_TRACK = Track("v2", 1, "official-v2", "catalog-v2", "catalog-v2-")
TRACKS = {track.name: track for track in (V1_TRACK, V2_TRACK)}


def track_for(name):
    """按显式轨道名取身份；未知名称必须失败，不能静默退回兼容轨而签错 source_id。"""
    if not isinstance(name, str) or name not in TRACKS:
        raise ValueError("unknown publication track")
    return TRACKS[name]


def _checked_identity(track, catalog):
    """签名前只接受本轨的 schema 与 source_id。

    两轨 schema 都是宿主支持的 1，跨轨区分实际依赖 source_id；仍校验 schema
    是为了拒绝未来版本或其它协议目录被当作已验签基线。
    """
    if not isinstance(catalog, Mapping):
        raise ValueError("catalog must be a JSON object")
    if (
        type(catalog.get("schema")) is not int
        or catalog["schema"] != track.schema
        or catalog.get("source_id") != track.source_id
    ):
        raise ValueError(f"catalog schema or source does not match the {track.name} track")


def _next_sequence(track, fixed, releases, bootstrap, require_identity):
    """按单条轨道计算下一序列；中断、截断、固定/快照不一致一律拒绝继续。

    v1 旧入口历史上只传 {"sequence": N}，因此身份检查由严格入口显式开启；
    序列与快照规则本身两轨完全共用，避免复制算法后出现两套判断。
    """
    if len(releases) >= 1000:
        raise ValueError("release list may be truncated")
    if fixed is not None and not isinstance(fixed, Mapping):
        raise ValueError("fixed catalog must be a JSON object")
    numbers = []
    fixed_present = False
    for release in releases:
        if not isinstance(release, Mapping) or not isinstance(release.get("tagName"), str):
            raise ValueError("release list contains a malformed entry")
        tag = release["tagName"]
        sequence = track.snapshot_sequence(tag)
        if sequence is not None:
            numbers.append(sequence)
        if tag == track.fixed_tag:
            fixed_present = True
    maximum = max(numbers, default=0)
    if fixed_present != (fixed is not None):
        raise ValueError("fixed catalog is missing or could not be verified")
    if fixed is None:
        if not bootstrap or maximum:
            raise ValueError("bootstrap requires explicit approval and no existing snapshots")
        return 1
    if require_identity:
        _checked_identity(track, fixed)
    sequence = fixed.get("sequence")
    if type(sequence) is not int or not 1 <= sequence <= 2**64 - 1 or sequence != maximum:
        raise ValueError("fixed catalog and immutable snapshots disagree; recover before retry")
    if sequence >= 2**64 - 1:
        raise ValueError("catalog sequence exhausted")
    return sequence + 1


def next_sequence_for(track_name, fixed, releases, bootstrap):
    """严格轨道入口：基线必须属于本轨，供后续 v1/v2 签名流程分别调用。"""
    return _next_sequence(track_for(track_name), fixed, releases, bootstrap, require_identity=True)


def next_sequence(fixed, releases, bootstrap):
    """保留 v1 调用形态；旧测试只传 sequence，故这里不额外要求 schema/source_id。"""
    return _next_sequence(V1_TRACK, fixed, releases, bootstrap, require_identity=False)


def indexed_versions_for(track_name, catalog):
    """按轨道身份索引历史版本，重复身份和其他协议目录不能成为不可变校验的基线。"""
    track = track_for(track_name)
    _checked_identity(track, catalog)
    indexed = {}
    plugins = set()
    for plugin in catalog["plugins"]:
        if plugin["id"] in plugins:
            raise ValueError("duplicate catalog plugin")
        plugins.add(plugin["id"])
        for version in plugin["versions"]:
            identity = (plugin["id"], version["version"])
            if identity in indexed:
                raise ValueError("duplicate catalog version")
            indexed[identity] = version
    return indexed


def indexed_versions(catalog):
    """保留 v1 调用形态；轨道身份固定为兼容轨。"""
    return indexed_versions_for("v1", catalog)


def _checked_sequence(catalog):
    """历史与候选序列都必须是 1..=u64::MAX 的整数。

    bootstrap 从 1 开始，宿主按 u64 解析序列，因此 0、布尔、负数或超出 u64
    的值既不是合法历史，也不能作为新候选；先做范围检查，递增比较在 Python
    任意精度下进行，不会因上界 +1 溢出而回绕到小序列。
    """
    sequence = catalog.get("sequence")
    if type(sequence) is not int or not 1 <= sequence <= 2**64 - 1:
        raise ValueError("catalog sequence must be a positive u64")
    return sequence


def validate_update_for(track_name, previous, candidate):
    """签名前按同轨已验签基线保护历史版本；跨轨基线、候选与同名重下载都不能改写旧包。

    两轨 schema 相同，跨轨只能靠 source_id 区分；候选必须严格比历史大 1，
    且历史已在 u64 上限时无法再推进，不能回绕或溢出后继续发布。
    """
    old = indexed_versions_for(track_name, previous)
    new = indexed_versions_for(track_name, candidate)
    previous_sequence = _checked_sequence(previous)
    candidate_sequence = _checked_sequence(candidate)
    if previous_sequence == 2**64 - 1:
        raise ValueError("catalog sequence exhausted")
    if candidate_sequence != previous_sequence + 1:
        raise ValueError("candidate must advance the verified catalog sequence exactly once")
    for identity, version in old.items():
        replacement = new.get(identity)
        if replacement is None:
            raise ValueError(f"published version cannot be removed: {identity}")
        before = sorted(version["assets"], key=lambda asset: asset["platform"])
        after = sorted(replacement["assets"], key=lambda asset: asset["platform"])
        if version["api"] != replacement["api"] or before != after:
            raise ValueError(f"published package cannot be changed: {identity}")


def validate_update(previous, candidate):
    """保留 v1 调用形态；历史版本保护规则与严格入口完全共用。"""
    validate_update_for("v1", previous, candidate)


def main():
    """只消费已验签基线和本地候选；轨道必须显式匹配，序列检查不负责网络或密钥。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--releases", required=True)
    parser.add_argument("--track", choices=sorted(TRACKS), default="v1")
    parser.add_argument("--fixed")
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--candidate")
    args = parser.parse_args()
    with open(args.releases, encoding="utf-8") as stream:
        releases = json.load(stream)
    fixed = None
    if args.fixed:
        with open(args.fixed, encoding="utf-8") as stream:
            fixed = json.load(stream)
    if args.candidate:
        if fixed is None:
            parser.error("candidate comparison requires a verified --fixed catalog")
        with open(args.candidate, encoding="utf-8") as stream:
            validate_update_for(args.track, fixed, json.load(stream))
    print(next_sequence_for(args.track, fixed, releases, args.bootstrap))


if __name__ == "__main__":
    main()
