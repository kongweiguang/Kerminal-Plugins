# @author kongweiguang
"""决定序列前检查固定目录与不可变快照是否仍处于同一提交。"""

import argparse
import json
import re


def next_sequence(fixed, releases, bootstrap):
    """不自动覆盖未知提交，避免中断后重用序列或丢失已发布快照。"""
    if len(releases) >= 1000:
        raise ValueError("release list may be truncated")
    numbers = [int(match.group(1)) for release in releases if (match := re.fullmatch(r"catalog-v1-([1-9][0-9]*)", release["tagName"]))]
    maximum = max(numbers, default=0)
    exists = any(release["tagName"] == "catalog-v1" for release in releases)
    if exists != (fixed is not None):
        raise ValueError("fixed catalog is missing or could not be verified")
    if fixed is None:
        if not bootstrap or maximum:
            raise ValueError("bootstrap requires explicit approval and no existing snapshots")
        return 1
    sequence = fixed.get("sequence")
    if type(sequence) is not int or sequence < 1 or sequence != maximum:
        raise ValueError("fixed catalog and immutable snapshots disagree; recover before retry")
    if sequence >= 2**64 - 1:
        raise ValueError("catalog sequence exhausted")
    return sequence + 1


def indexed_versions(catalog):
    """按宿主身份索引历史版本，重复身份和其他协议目录不能成为不可变校验的基线。"""
    if type(catalog.get("schema")) is not int or catalog["schema"] != 1 or catalog.get("source_id") != "official":
        raise ValueError("catalog schema or source does not match the host contract")
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


def validate_update(previous, candidate):
    """签名前按已验签基线保护历史版本，不能借重新下载同名 Release 改写旧包。"""
    old = indexed_versions(previous)
    new = indexed_versions(candidate)
    if candidate["sequence"] != previous["sequence"] + 1:
        raise ValueError("candidate must advance the verified catalog sequence exactly once")
    for identity, version in old.items():
        replacement = new.get(identity)
        if replacement is None:
            raise ValueError(f"published version cannot be removed: {identity}")
        before = sorted(version["assets"], key=lambda asset: asset["platform"])
        after = sorted(replacement["assets"], key=lambda asset: asset["platform"])
        if version["api"] != replacement["api"] or before != after:
            raise ValueError(f"published package cannot be changed: {identity}")


def main():
    """只消费已验签基线和本地候选，序列与不可变检查不负责网络或密钥。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--releases", required=True)
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
            validate_update(fixed, json.load(stream))
    print(next_sequence(fixed, releases, args.bootstrap))


if __name__ == "__main__":
    main()
