# @author kongweiguang
"""catalog-v1-publish.yml 工作流的本地隔离测试：不联网、不签名、不发布、不读密钥。

两类覆盖：
- 静态审查：用真实 YAML 解析器读出步骤脚本并核对安全关键不变量（权限、
  artifact 布局、无删除 Release 路径、受信模块只从钉住检出引用、Python 处理
  不可信输入时用 -I 等），并完成 shell 语法层校验（bash -n）。
- mock 联测：把 verify 的 plan 自检脚本与 sign 的关键控制流放到真实 bash +
  桩 gh/minisign 上执行，覆盖实际工作目录、零/多媒体、bootstrap/固定目录、
  残留 draft 冲突、固定基线漂移与异常不自动删除。

测试只模拟 GitHub API 与签名工具；所有失败分支断言「工作流停在那里」，不
断言它能自动恢复（多文件发布本来就不承诺原子性）。

注意两种检出不要混淆：本文件审查与执行的是**当前工作区里的 YAML**
（REPO_ROOT 下的 .github/workflows/…），不是签名任务在运行时检出的
KERMINAL_SIGNER_SHA 受信快照。受信检出只提供 marketplace/ 下的受信脚本；
工作流 YAML 本身由本仓 main 上的评审与分支门禁保护。因此这里的静态断言
证明的是「即将提交的这份 YAML」，不是「线上某次运行用的是同一份」。
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

# MSYS bash 绝对路径：Windows 上裸命令名 "bash" 在精简环境变量下可能被解析到
# System32 的 WSL bash，行为与 MSYS 完全不同（环境被 WSL 重置）；固定绝对路径
# 消除解析歧义。找不到 MSYS bash 时保持 None，shell 模拟用例显式跳过。
_MSYS_BASH_CANDIDATES = (
    r"C:\Program Files\Git\usr\bin\bash.exe",
    r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
)
MSYS_BASH = next((p for p in _MSYS_BASH_CANDIDATES if Path(p).exists()), shutil.which("bash"))

# 仓库根（tests/ 的上一级是 marketplace/，再上一级是仓库根）。这里解析的是
# 工作区文件（即将提交的 YAML），不是运行时检出的 KERMINAL_SIGNER_SHA 快照。
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "catalog-v1-publish.yml"
VALIDATE_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "catalog-v1-validate.yml"


def load_workflow():
    """以真实解析器加载工作流文档：结构与脚本都从这里取，避免正则拟合 YAML。"""
    with open(WORKFLOW_PATH, encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def steps_of(doc, job):
    """按步骤名取 run 脚本；uses 步骤没有 run，返回 None。"""
    return {step.get("name", step.get("uses")): step.get("run") for step in doc["jobs"][job]["steps"]}


def _write_executable(path, body):
    """写入可执行桩脚本：POSIX 权限在 Windows 上无效果，但 bash 调用时无碍。"""
    path.write_text(body, encoding="utf-8", newline="\n")
    try:
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    except OSError:
        pass


class StaticWorkflowTests(unittest.TestCase):
    """对工作流文本与解析结果的静态安全审查。"""

    @classmethod
    def setUpClass(cls):
        """整个类共享一次解析结果；文本用于 grep 级断言（如 -I）。"""
        cls.doc = load_workflow()
        cls.raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.verify_runs = steps_of(cls.doc, "verify")
        cls.sign_runs = steps_of(cls.doc, "sign")
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8", newline="\n") as handle:
            for job in ("verify", "sign"):
                for script in steps_of(cls.doc, job).values():
                    if script:
                        handle.write(script + "\n")
            cls.combined_script = handle.name
        # bash -n 用 MSYS bash 绝对路径 + POSIX 形式路径：与 shell 模拟一致，
        # 避免裸 "bash" 在 Windows 上解析到 WSL（环境被重置、路径无法访问）。
        posix_script = str(cls.combined_script).replace("\\", "/")
        msys_script = re.sub(r"^([A-Za-z]):", lambda m: "/" + m.group(1).lower(), posix_script)
        result = subprocess.run([MSYS_BASH, "-n", msys_script], capture_output=True, text=True)
        cls.addClassCleanup(os.unlink, cls.combined_script)
        cls.bash_syntax = result

    def test_jobs_and_permissions(self):
        """verify 只有 contents:read（checkout 与读取 Release 需要，私有仓库不能靠
        匿名读取），绝无写权限；sign 单独持 contents:write；并发组串行不取消。"""
        verify, sign = self.doc["jobs"]["verify"], self.doc["jobs"]["sign"]
        self.assertEqual(verify["permissions"], {"contents": "read"})
        self.assertEqual(sign["permissions"], {"contents": "write"})
        self.assertEqual(self.doc["permissions"], {"contents": "read"})
        self.assertEqual(sign["environment"], "catalog-signer")
        self.assertEqual(self.doc["concurrency"], {"group": "marketplace-v1-publish", "cancel-in-progress": False})
        self.assertTrue(sign.get("if"))

    def test_all_run_scripts_are_valid_bash(self):
        """每个 run 脚本必须通过 bash -n：heredoc 缩进这类错误在提交前暴露。"""
        self.assertEqual(self.bash_syntax.returncode, 0, self.bash_syntax.stderr)

    def test_no_release_delete_anywhere(self):
        """任何可执行语句都不得出现 gh release delete：中断状态交给人工恢复。

        头部注释里「绝不执行 gh release delete」是设计承诺本身，必须存在；
        断言针对的是 run 脚本与 gh 调用形态，不含注释。
        """
        self.assertIn("绝不执行 gh release delete", self.raw)
        for name, script in {**self.verify_runs, **self.sign_runs}.items():
            if not script:
                continue
            code_only = "\n".join(line for line in script.splitlines() if not line.strip().startswith("#"))
            self.assertNotIn("release delete", code_only, f"step {name}")
            self.assertNotRegex(code_only, r"gh\s+release\s+delete", f"step {name}")

    def test_no_force_or_immutable_snapshot_rewrite(self):
        """不可变快照只能以 --draft 创建后转正，没有 overwrite/重传 --clobber 的路径。

        旧断言写成 `assertIn("catalog-v1", line and "catalog-v1")`，第二个参数
        恒为真字符串，等于没有检查。这里改为解析命令行 token：--clobber 行必须
        以固定 tag 字面量 `catalog-v1` 作为 release 位置参数，且不得引用快照
        tag 变量（$tag / $snapshot_tag）或 --force。
        """
        clobber_lines = []
        for name, script in self.sign_runs.items():
            if not script:
                continue
            for line in script.splitlines():
                # 只检查可执行语句：注释里说明「--clobber 与 CAS 边界」不是调用。
                if "--clobber" in line and not line.strip().startswith("#"):
                    clobber_lines.append((name, line))
        self.assertTrue(clobber_lines, "the fixed catalog update must exist")
        for name, line in clobber_lines:
            tokens = line.split()
            self.assertIn("catalog-v1", tokens, f"clobber must target the fixed release: {line}")
            self.assertNotIn("$tag", line, f"clobber must not target the snapshot tag: {name}")
            self.assertNotIn("$snapshot_tag", line, f"clobber must not target the snapshot tag: {name}")
            self.assertNotIn("--force", line, f"clobber must not force: {name}")
        self.assertNotIn("--force", "\n".join(script or "" for script in self.sign_runs.values()))

    def test_plan_step_uses_workspace_absolute_paths(self):
        """sign 的 plan 与签名步骤用绝对工作区路径：消除 cd out 后相对路径错位。"""
        plan = self.sign_runs["Compute sign plan before any secret is loaded"]
        self.assertNotIn("\ncd ", plan, "plan step must not rely on a working-directory cd")
        self.assertIn("plan.json", plan)
        sign = self.sign_runs["Sign catalog and publish releases"]
        # plan.json 的读取全部经由绝对工作区路径。
        for line in sign.splitlines():
            if "plan.json" in line and "python -c" in line:
                self.assertIn("GITHUB_WORKSPACE", line, f"plan.json must be referenced via absolute path: {line}")
        self.assertNotRegex(sign, r"^\s*cd out\s*$", "sign step must not cd into out before reading plan.json")

    def test_sign_stages_bundle_with_optional_media_directory(self):
        """artifact v4 不保留空目录：Stage 步骤必须在 bundle 没有 media 时新建空
        media 目录，只在 media 存在时拷贝；媒体缺失的安全后果交给受信 plan 的
        receipt.media_manifest 比对，不在这里用 if-no-files-found 误拒合法零媒体。"""
        stage = self.sign_runs["Stage verified inputs"]
        self.assertIn('mkdir -p "$GITHUB_WORKSPACE/out/media"', stage)
        self.assertIn('if [[ -d artifacts/verified-bundle/media ]]', stage)
        self.assertIn("test -d \"$GITHUB_WORKSPACE/out/media\"", stage)
        # bundle 上传本身仍要求至少一个文件（catalog/receipt 必然存在），
        # 但不再为媒体目录单设 artifact。
        self.assertNotIn("verified-media", self.raw)

    def test_branch_gate_rejects_non_main_in_both_jobs(self):
        """验证与签名两条路径都必须自己拒绝非 refs/heads/main：Environment 的
        受保护分支策略是仓库外配置，不能当作仓库内唯一门禁。"""
        for job in ("verify", "sign"):
            gate = steps_of(self.doc, job)["Require main branch"]
            self.assertIn('"$EVENT_REF" == "refs/heads/main"', gate, f"{job} must gate on main")
            self.assertIn("exit 1", gate)
            self.assertIn('"$EVENT_NAME" == "push"', gate)
            self.assertIn('"$EVENT_NAME" == "workflow_dispatch"', gate)
        # 门禁必须是各自 job 的第一步，避免先检出/加载环境再判断。
        for job in ("verify", "sign"):
            self.assertEqual(self.doc["jobs"][job]["steps"][0]["name"], "Require main branch")

    def test_validate_workflow_gates_manual_runs_to_main(self):
        """只读验证 workflow 的 workflow_dispatch 也必须限定 main；PR 事件不受影响。"""
        with open(VALIDATE_WORKFLOW_PATH, encoding="utf-8") as stream:
            validate = yaml.safe_load(stream)
        steps = validate["jobs"]["validate"]["steps"]
        gate = next(step for step in steps if step.get("name") == "Require main branch for manual runs")
        self.assertEqual(gate["if"], "github.event_name == 'workflow_dispatch'")
        self.assertIn("refs/heads/main", gate["run"])

    def test_pyyaml_is_installed_explicitly_in_ci(self):
        """工作流测试依赖 PyYAML，而 setup-python 不预装它：两个 workflow 都必须
        在跑测试前显式安装固定版本，避免真实 runner 上缺依赖或静默跳过。"""
        for path in (WORKFLOW_PATH, VALIDATE_WORKFLOW_PATH):
            with open(path, encoding="utf-8") as stream:
                doc = yaml.safe_load(stream)
            names = [step.get("name") for job in doc["jobs"].values() for step in job["steps"]]
            self.assertIn("Install pinned test dependencies", names, path.name)
            install = next(
                step for job in doc["jobs"].values() for step in job["steps"]
                if step.get("name") == "Install pinned test dependencies"
            )
            self.assertIn("PyYAML==", install["run"])

    def test_single_bundle_artifact_with_media_directory(self):
        """verify 产出单 artifact（catalog+receipt+media 目录），不存在按媒体拆分的
        独立 artifact：合法零媒体不会被 if-no-files-found 或字面 media/* 误拒。"""
        uploads = [step for step in self.doc["jobs"]["verify"]["steps"] if step.get("uses", "").startswith("actions/upload-artifact")]
        names = sorted(step["with"]["name"] for step in uploads)
        self.assertEqual(names, ["publication-state", "verified-bundle"])
        bundle = next(step for step in uploads if step["with"]["name"] == "verified-bundle")
        self.assertEqual(bundle["with"]["if-no-files-found"], "error")
        self.assertTrue(bundle["with"]["path"].rstrip("/").endswith("out"))
        self.assertNotIn("verified-media", self.raw)
        # sign 侧不使用字面 media/* 上传或下载（注释提及不计数）。
        for name, script in self.sign_runs.items():
            if not script:
                continue
            code_only = "\n".join(line for line in script.splitlines() if not line.strip().startswith("#"))
            self.assertNotIn("media/*", code_only, f"step {name} must not glob media/*")

    def test_sign_downloads_baseline_into_fresh_live_directory(self):
        """sign 的固定基线下载到新建 live 目录，不写回 artifact 携带的 state/previous。"""
        plan = self.sign_runs["Compute sign plan before any secret is loaded"]
        self.assertIn("previous-live", plan)
        self.assertNotIn("--dir state/previous\n", plan)
        # stage 步骤只从 publication-state artifact 拷贝；previous-live 一定不在其中。
        stage = self.sign_runs["Stage verified inputs"]
        self.assertIn("publication-state", stage)
        self.assertNotIn("previous", stage)

    def test_plan_self_check_binds_candidate_digest_before_secrets(self):
        """计划自检：plan.json 的 candidate_sha256 与磁盘候选原文绑定，且发生在
        加载密钥之前的步骤里。签名密钥只出现在最后一个步骤（签名与发布），
        其余步骤的 env 均不得引用 secrets 上下文。"""
        plan = self.sign_runs["Compute sign plan before any secret is loaded"]
        self.assertIn("candidate_sha256", plan)
        sign_steps = self.doc["jobs"]["sign"]["steps"]
        for index, step in enumerate(sign_steps[:-1]):
            env_json = json.dumps(step.get("env", {})) + json.dumps(step.get("with", {}))
            self.assertNotIn("secrets.", env_json, f"step {index} must not reference secrets before the signing step")
        # 签名步骤持有密钥 env。
        self.assertIn("secrets.", json.dumps(sign_steps[-1].get("env", {})))
        self.assertNotIn("secrets.", plan)
        # 签名步骤在 minisign 之前再次核对候选摘要。
        sign = self.sign_runs["Sign catalog and publish releases"]
        digest_check = sign.find("candidate_sha256")
        minisign_sign = sign.find("minisign -Sm")
        self.assertGreaterEqual(digest_check, 0, "sign step must re-verify the plan digest")
        self.assertLess(digest_check, minisign_sign)
        # 签名后立即复核验签（同一候选原文）。
        self.assertIn("minisign -Vm", sign)

    def test_plan_media_list_uploaded_by_name_not_glob(self):
        """快照上传按计划媒体清单逐个加入参数，零媒体时自然不附加任何媒体。"""
        sign = self.sign_runs["Sign catalog and publish releases"]
        self.assertIn("args=", sign)
        self.assertIn('args+=(', sign)
        self.assertIn('"${args[@]}"', sign)

    def test_fixed_catalog_advance_rechecks_fresh_remote_baseline(self):
        """固定目录替换前必须重新从远端下载基线（不能只读 plan 时的本地副本），
        验签并与 plan 基线逐字节对照，再核对序列；不一致拒绝替换。"""
        sign = self.sign_runs["Sign catalog and publish releases"]
        # 更新前重新下载到独立目录（与 plan 的 previous-live 分开）。
        self.assertIn("previous-guard", sign)
        self.assertIn('--dir "$GITHUB_WORKSPACE/state/previous-guard"', sign)
        # 重新下载后必须验签，且与 plan 基线逐字节一致。
        self.assertIn('cmp "$GITHUB_WORKSPACE/state/previous-live/catalog.json" "$GITHUB_WORKSPACE/state/previous-guard/catalog.json"', sign)
        self.assertRegex(sign, r"minisign -Vm \"\$GITHUB_WORKSPACE/state/previous-guard/catalog\.json\"")
        self.assertIn("plan['sequence'] - 1", sign)
        self.assertIn("refusing to replace the fixed catalog", sign)

    def test_fixed_baseline_binds_to_its_immutable_snapshot(self):
        """有固定目录时，plan 前必须下载其对应快照并逐字节比对目录原文，且双方
        都验签：仅比较 sequence 无法发现固定目录被换成另一份同序列目录。"""
        plan = self.sign_runs["Compute sign plan before any secret is loaded"]
        self.assertIn('snapshot_tag="catalog-v1-$baseline_sequence"', plan)
        self.assertIn('--dir state/snapshot-live', plan)
        self.assertIn("cmp state/previous-live/catalog.json state/snapshot-live/catalog.json", plan)
        self.assertRegex(plan, r"minisign -Vm state/snapshot-live/catalog\.json")
        # 两个验签都在 plan 调用之前。
        self.assertLess(plan.index("snapshot-live/catalog.json"), plan.index("trusted_publish_v1.py plan"))

    def test_snapshot_media_readback_covers_bootstrap_too(self):
        """快照媒体回读对 bootstrap 与增量一视同仁：首次引导也可能带媒体，
        不能以 bootstrap 跳过远端逐文件比对。"""
        sign = self.sign_runs["Sign catalog and publish releases"]
        self.assertNotIn('if [[ "$bootstrap" == false ]]; then', sign)
        self.assertIn("readback-media", sign)
        self.assertIn("cmp \"$GITHUB_WORKSPACE/out/media/$media\" \"$GITHUB_WORKSPACE/readback-media/$media\"", sign)

    def test_inspects_workspace_yaml_not_trusted_checkout(self):
        """本测试解析的是工作区里的 YAML（即将提交、由 main 评审保护的那份），
        不是运行时 KERMINAL_SIGNER_SHA 检出的副本；受信检出只提供 marketplace/
        脚本，不能把「本地静态检查通过」当成「线上运行的就是这份 YAML」。"""
        self.assertEqual(WORKFLOW_PATH, REPO_ROOT / ".github" / "workflows" / "catalog-v1-publish.yml")
        self.assertEqual(VALIDATE_WORKFLOW_PATH, REPO_ROOT / ".github" / "workflows" / "catalog-v1-validate.yml")
        # 路径里没有受信检出的 trusted/ 前缀：解析对象就是工作区文件。
        self.assertNotIn("trusted", WORKFLOW_PATH.relative_to(REPO_ROOT).parts)
        self.assertNotIn("trusted", VALIDATE_WORKFLOW_PATH.relative_to(REPO_ROOT).parts)
        # 所有 python 子进程都在模拟工作区里执行，不指向真实受信或候选检出。
        source = Path(__file__).read_text(encoding="utf-8")
        for line in source.splitlines():
            if "sys.executable" in line and "subprocess" not in line and "run(" not in line:
                continue
            if "subprocess.run(" in line and "sys.executable" in line:
                self.assertNotIn("REPO_ROOT", line)

    def test_python_untrusted_inputs_run_isolated(self):
        """处理候选/artifact 产物的 Python 必须带 -I：不从 CWD 或 PYTHONPATH 隐式
        导入被投放的同名模块。

        例外说明（不是放松）：`python -m unittest` 与 marketplace/catalog-v1.py
        这类按同目录模块互相 import 的入口无法在 -I 下工作（-I 会去掉脚本目录
        与 CWD）。它们只出现在无密钥、contents:read 的只读验证 workflow，或
        作为受信检出的测试运行器；发布 workflow 中所有处理候选/artifact 数据
        的 python 调用一律显式 -I。
        """
        for name, script in {**self.verify_runs, **self.sign_runs}.items():
            if not script:
                continue
            self.assertNotIn("candidate/marketplace", script, f"step {name} must not execute candidate scripts")
        # 发布 workflow 的每个 python 调用（除 pip 安装）都必须显式 -I。
        for name, script in {**self.verify_runs, **self.sign_runs}.items():
            if not script:
                continue
            for line in script.splitlines():
                stripped = line.strip()
                if stripped.startswith("python ") and "-m pip" not in stripped:
                    self.assertIn("python -I ", stripped, f"step {name} must run python isolated: {line}")
        # 行内脚本不 import 候选模块，也不向解释器注入候选 import path。
        for script in (*self.verify_runs.values(), *self.sign_runs.values()):
            if not script:
                continue
            self.assertNotIn("PYTHONPATH=candidate", script)
            self.assertNotIn("PYTHONPATH=$GITHUB_WORKSPACE/candidate", script)

    def test_verify_job_documents_minimum_permissions_only(self):
        """verify job 只申请 contents:read，绝不申请写权限；workflow 顶部注释不得
        声称 Actions 权限已实测，也不得声称公开仓库无需授权一定能读。"""
        self.assertEqual(self.doc["jobs"]["verify"]["permissions"], {"contents": "read"})
        self.assertNotIn("已实测 Actions 权限", self.raw)
        self.assertIn("contents: read", self.raw)
        # 公开仓库匿名读取行为未经真实 GitHub 验证，注释只陈述私有仓库不可依赖它。
        self.assertIn("私有仓库不能靠匿名读取", self.raw)
        self.assertNotIn("公开仓库必定 403", self.raw)

    def test_documentation_claims_are_honest(self):
        """文档断言：环境审批是仓库外前提、未配置 environment 不必然拒绝运行、
        receipt 只证明材料自洽、无 CAS 原子承诺；不得声称代码能证明仓库外审批，
        且必须准确说明 artifact v4 会丢空目录。"""
        self.assertIn("GitHub 不一定因为 environment 尚未", self.raw)
        self.assertIn("只证明 verify 通道产出自洽", self.raw)
        self.assertIn("不承诺多文件发布原子性", self.raw)
        self.assertIn("绝不执行 gh release delete", self.raw)
        self.assertIn("required reviewers", self.raw)
        # 外部审批与变量管控无法由本文件证明，注释必须如实区分「能检查」与
        # 「只能声明」，不再宣称所有外部前提缺失都自动 fail-closed。
        self.assertIn("仓库外审批与配置，代码无法证明", self.raw)
        self.assertNotIn("缺少任何一个前提时", self.raw)
        self.assertIn("不能由代码证明的前提", self.raw)
        # artifact v4 丢空目录的事实与零媒体安全路径必须同时写明。
        self.assertIn("upload/download-artifact v4 不保留空目录", self.raw)
        self.assertIn("零媒体不会被「空目录丢失」误判为缺失", self.raw)
        # 跨仓库 SDK 可读是外部前提：contents:read 只覆盖当前仓库作用域，
        # 不得声称默认 token 一定能检出另一个私有仓库，也不得为此新增凭据。
        self.assertIn("contents:read 只覆盖当前仓库作用域", self.raw)
        self.assertIn("不保证可检出另一私有 SDK 仓库", self.raw)
        self.assertNotIn("PERSONAL_ACCESS_TOKEN", self.raw)
        self.assertNotIn("secrets.KERMINAL_SDK", self.raw)

    def test_bootstrap_flag_wiring(self):
        """bootstrap 与非 bootstrap 的 plan 调用分别显式传/不传 --bootstrap。

        用受信脚本调用的参数块（反斜杠续行形式）判定：if 分支的 plan 调用以
        「--pubkey ... | tee plan.json」收尾且含 --bootstrap；else 分支的调用
        直接以 --bootstrap 收尾——即非 bootstrap 路径上 --bootstrap 一定缺席。
        """
        plan = self.sign_runs["Compute sign plan before any secret is loaded"]
        fixed_branch, plain_branch = plan.split("else", 1)
        self.assertNotIn("--bootstrap", fixed_branch, "fixed-baseline branch must not pass --bootstrap")
        self.assertIn("--bootstrap | tee plan.json", plain_branch, "bootstrap branch must pass --bootstrap explicitly")

    def test_verify_sequence_bootstrap_is_explicit(self):
        """verify 侧无基线时也显式传 --bootstrap，但只在冻结的许可决定为 true
        时；「固定目录缺失」本身不再触发引导。"""
        generate = self.verify_runs["Compute sequence and generate verified candidate"]
        self.assertIn("--bootstrap", generate)
        self.assertIn('test "$(cat "$RUNNER_TEMP/state/bootstrap-state.txt")" = true', generate)

    def test_bootstrap_requires_admin_license_and_no_snapshots(self):
        """首发必须同时满足管理员显式配置 KERMINAL_CATALOG_BOOTSTRAP=true 与
        同轨没有任何历史快照；固定目录消失但快照仍在时不得重新引导。

        变量只读取一次并规范化，冻结进 bootstrap-state.txt 传给 sign；verify 与
        sign 两侧都消费该冻结值，不各自从「目录为空」推断。
        """
        license_step = steps_of(self.doc, "verify")["Resolve bootstrap license"]
        license_env = {step.get("name"): step.get("env", {}) for step in self.doc["jobs"]["verify"]["steps"]}["Resolve bootstrap license"]
        self.assertEqual(license_env["BOOTSTRAP_VAR"], "${{ vars.KERMINAL_CATALOG_BOOTSTRAP }}")
        self.assertIn("license=true", license_step)
        self.assertIn("license=false", license_step)
        # 非法值失败关闭，不把拼写错误当成许可。
        self.assertIn("must be true or false", license_step)
        baseline = self.verify_runs["Inspect fixed catalog baseline"]
        self.assertIn('BOOTSTRAP_LICENSE: ${{ steps.bootstrap.outputs.license }}', self.raw)
        self.assertIn("catalog-v1-[1-9][0-9]*", baseline)
        self.assertIn("immutable snapshots exist; refusing to bootstrap", baseline)
        self.assertIn('echo true > bootstrap-state.txt', baseline)
        self.assertIn('echo false > bootstrap-state.txt', baseline)
        # 固定目录存在时冻结为非首发；缺失且无许可时拒绝。
        self.assertIn("refusing first publication", baseline)
        # sign 侧不读管理员变量，只读冻结状态，并在 plan 前复核。
        sign_plan = self.sign_runs["Compute sign plan before any secret is loaded"]
        self.assertNotIn("KERMINAL_CATALOG_BOOTSTRAP", sign_plan)
        self.assertIn('test "$(cat state/bootstrap-state.txt)" = true', sign_plan)
        self.assertIn("plan bootstrap decision does not match the frozen publication state", sign_plan)
        self.assertIn('test "$(cat state/bootstrap-state.txt)" = false', sign_plan)
        # 变量只经 vars 上下文读取一次：错误文案里出现变量名不算第二次读取。
        occurrences = [line for line in self.raw.splitlines() if "vars.KERMINAL_CATALOG_BOOTSTRAP" in line]
        self.assertEqual(len(occurrences), 1, occurrences)

    def test_signer_sha_is_frozen_by_verify_and_reused_by_sign(self):
        """verify 校验并输出规范化完整 SHA，sign 只用该输出检出，不再读同名变量；
        两边都按实际 HEAD 复核，避免两次读取之间变量被改动。"""
        verify = self.doc["jobs"]["verify"]
        self.assertEqual(verify["outputs"]["signer_sha"], "${{ steps.signer.outputs.sha }}")
        signer_step = steps_of(self.doc, "verify")["Require admin-controlled signer SHA"]
        signer_env = {step.get("name"): step.get("env", {}) for step in self.doc["jobs"]["verify"]["steps"]}["Require admin-controlled signer SHA"]
        self.assertEqual(signer_env["TRUSTED_REF"], "${{ vars.KERMINAL_SIGNER_SHA }}")
        self.assertIn("sha=", signer_step)
        self.assertIn("${TRUSTED_REF,,}", signer_step)
        sign_steps = {step.get("name", step.get("uses")): step for step in self.doc["jobs"]["sign"]["steps"]}
        checkout = next(step for step in self.doc["jobs"]["sign"]["steps"] if step.get("uses", "").startswith("actions/checkout") and step.get("with", {}).get("path") == "trusted")
        self.assertEqual(checkout["with"]["ref"], "${{ needs.verify.outputs.signer_sha }}")
        # sign job 的任何可执行位置都不得再直接读管理员变量。
        sign_json = json.dumps(self.doc["jobs"]["sign"])
        self.assertNotIn("KERMINAL_SIGNER_SHA", sign_json)
        for job in ("verify", "sign"):
            head_check = steps_of(self.doc, job)["Verify signer checkout matches the frozen SHA"]
            self.assertIn("rev-parse HEAD", head_check)
            self.assertIn("does not match the frozen signer SHA", head_check)
        # sign 侧复核的期望值同样来自冻结输出，而不是重读变量。
        self.assertEqual(
            sign_steps["Verify signer checkout matches the frozen SHA"]["env"]["EXPECTED_SHA"],
            "${{ needs.verify.outputs.signer_sha }}",
        )

    def test_v1_public_key_is_dedicated_and_required_before_generation(self):
        """v1 从未发布过，必须使用自己的 catalog/v1-publisher.pub；verify 与 sign
        都要在生成/签名前以文件系统检查 fail-closed，不能依赖 minisign 晚失败，
        也不能要求该文件由 git 跟踪（离线桩自行布置即可）。"""
        # 生产引用只允许新公钥名；历史 publisher.pub 不得残留成兼容别名。
        self.assertNotIn("catalog/publisher.pub", self.raw)
        for path in (WORKFLOW_PATH, VALIDATE_WORKFLOW_PATH):
            text = path.read_text(encoding="utf-8")
            refs = [line for line in text.splitlines() if "publisher.pub" in line and not line.lstrip().startswith("#")]
            self.assertTrue(refs, f"{path.name} must reference the trusted key")
            for line in refs:
                self.assertIn("v1-publisher.pub", line, f"{path.name} uses a non-v1 key: {line}")
        for job, later_step in (
            ("verify", "Compute sequence and generate verified candidate"),
            ("sign", "Compute sign plan before any secret is loaded"),
        ):
            gate = steps_of(self.doc, job)["Require v1 trusted public key"]
            self.assertIn("trusted/catalog/v1-publisher.pub", gate)
            self.assertIn('test -s "$key"', gate)
            self.assertIn("missing trusted v1 publisher key", gate)
            self.assertNotIn("git ", gate, f"{job} key gate must not require a tracked file")
            names = [step.get("name", step.get("uses")) for step in self.doc["jobs"][job]["steps"]]
            self.assertLess(names.index("Require v1 trusted public key"), names.index(later_step), job)
        # verify 只在确有发布候选时要求公钥；无发布时不空转。
        verify_steps = {step.get("name"): step for step in self.doc["jobs"]["verify"]["steps"]}
        self.assertEqual(verify_steps["Require v1 trusted public key"]["if"], "steps.entries.outputs.published == 'true'")

    def test_detect_published_entries_preserves_inspect_exit_code(self):
        """inspect 通过管道写入 tee：必须开 pipefail，否则 tee 的成功会掩盖
        inspect 的失败并让后续步骤读半截输出。"""
        detect = self.verify_runs["Detect published entries"]
        self.assertIn("set -euo pipefail", detect)
        self.assertIn("inspect --data-root candidate | tee inspect.json", detect)
        # pipefail 必须在管道之前生效：断言它出现在第一行有效语句。
        first_code = next(line for line in detect.splitlines() if line.strip() and not line.strip().startswith("#"))
        self.assertEqual(first_code.strip(), "set -euo pipefail")

    def test_python_isolation_applies_inside_command_substitutions(self):
        """命令替换里的 python 同样处理不可信数据，必须带 -I：只检查顶层命令
        会漏掉 $(...) 内被 CWD 同名模块劫持的路径。"""
        offenders = []
        for name, script in {**self.verify_runs, **self.sign_runs}.items():
            if not script:
                continue
            for line in script.splitlines():
                if line.strip().startswith("#") or "$(" not in line:
                    continue
                if "python " in line and "python -I " not in line:
                    offenders.append((name, line))
        self.assertEqual(offenders, [], "python inside command substitution must use -I")


class ShellSimulationTests(unittest.TestCase):
    """在临时工作区用真实 bash + 桩 gh/minisign 执行工作流脚本片段。

    桩工具记录全部调用；目录结构模拟 GitHub runner 布局（GITHUB_WORKSPACE、
    RUNNER_TEMP、artifacts）。只执行 sign 侧的 plan/sign 控制流与 verify 的
    自检脚本，不触网、无真实密钥。
    """

    def setUp(self):
        """独立临时 runner 布局，各用例互不污染；无 MSYS bash 时显式跳过，
        不把「没跑」伪装成通过。"""
        if MSYS_BASH is None:
            self.skipTest("MSYS bash not found; shell simulation requires Git Bash")
        self.temp = Path(tempfile.mkdtemp(prefix="kwf-sim-"))
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        self.workspace = self.temp / "workspace"
        self.runner_temp = self.temp / "runner-temp"
        self.bin = self.temp / "bin"
        for path in (self.workspace, self.runner_temp, self.bin):
            path.mkdir()
        self.gh_log = []
        # msys bash 需要 SystemRoot 等基础 Windows 变量才能启动；从 os.environ
        # 显式带入必需集，其余环境仍按模拟环境最小化。
        self.env = {
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "GITHUB_WORKSPACE": str(self.workspace),
            "RUNNER_TEMP": str(self.runner_temp),
            "GITHUB_REPOSITORY": "kongweiguang/Kerminal-Plugins",
            "GITHUB_TOKEN": "sim-token",
            "GH_TOKEN": "sim-token",
        }
        for key in ("SystemRoot", "SystemDrive", "HOME", "USERPROFILE", "TMP", "TEMP", "ALLUSERSPROFILE", "APPDATA", "LOCALAPPDATA", "COMPUTERNAME", "USERNAME", "USERDOMAIN", "OS", "ComSpec", "PATHEXT", "ProgramData", "HOMEDRIVE", "HOMEPATH", "WINDIR"):
            if key in os.environ:
                self.env[key] = os.environ[key]
        self.releases = {}  # 当前 release 世界：tag -> {"draft": bool, "assets": {name: bytes}}
        self._install_stub_gh()
        self._install_stub_minisign()

    def _install_stub_gh(self):
        """gh 桩：按本用例的 release 世界回答 list/view/download/create/edit/upload，
        并把每次调用记入日志供失败关闭断言使用。

        支持故障注入（state.corrupt）：下载指定 tag 的指定资产时返回被改写的
        字节，用来真正制造「远端回读不一致」，而不是只断言 cmp 原语本身。
        """
        self.gh_state_path = self.temp / "gh-state.json"
        self.corrupt = {}  # tag -> {asset name: bytes}：下载时替换成这些字节
        self.gh_state_path.write_text(json.dumps({"releases": {}, "corrupt": {}}), encoding="utf-8")
        self._sync_gh_state()
        # 直接内联桩实现，避免额外的模块文件散落在 tests/ 之外。
        _write_executable(self.bin / "gh", self._gh_stub_source())

    def _gh_stub_source(self):
        """生成 gh 桩脚本文本：读状态文件模拟 release 世界并记录调用日志。"""
        log_path = (self.temp / "gh-calls.log").as_posix()
        state_path = self.gh_state_path.as_posix()
        return f"""#!/usr/bin/env python
import hashlib, json, os, sys

LOG = {log_path!r}
STATE = {state_path!r}

def load_state():
    with open(STATE, encoding="utf-8") as handle:
        return json.load(handle)

def save_state(state):
    with open(STATE, "w", encoding="utf-8") as handle:
        json.dump(state, handle)

def log_call(argv):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(argv) + "\\n")

def main():
    argv = sys.argv[1:]
    log_call(argv)
    state = load_state()
    releases = state["releases"]
    corrupt = state.get("corrupt") or {{}}
    def fail(message):
        print(message, file=sys.stderr)
        sys.exit(1)
    # gh CLI 的位置参数（tag）可以出现在子命令之后或选项之后；桩用与真实
    # CLI 相同的「第一个非选项且非选项值的位置参数」规则取 tag，避免对参数
    # 顺序做过强假设而掩盖工作流的真实调用形态。
    OPTION_VALUES = {{"--repo", "--pattern", "--dir", "--title", "--notes"}}
    def find_tag(after):
        # 与 find_assets 共用同一套选项值跳过规则：选项值永不作为位置参数。
        return find_assets(after)[0]
    def find_assets(after):
        positional = []
        skip = False
        for item in after:
            if skip:
                skip = False
                continue
            if item.startswith("--"):
                skip = item in OPTION_VALUES and item != "--draft=false"
                continue
            positional.append(item)
        return positional
    def find_option(name):
        return argv[argv.index(name) + 1] if name in argv else None
    if argv[:2] == ["release", "list"]:
        print(json.dumps([{{"tagName": tag}} for tag in sorted(releases)]))
        return
    if argv[:2] == ["release", "view"]:
        tag = find_tag(argv[2:])
        release = releases.get(tag)
        if release is None:
            fail("release not found: " + str(tag))
        if find_option("--jq") == ".isDraft":
            # 工作流用 --jq '.isDraft' 取布尔；桩按同样语义输出 true/false 字面量。
            print("true" if release["draft"] else "false")
        else:
            print(json.dumps({{"isDraft": release["draft"], "tagName": tag}}))
        return
    if argv[:2] == ["release", "download"]:
        tag = find_tag(argv[2:])
        release = releases.get(tag)
        if release is None:
            fail("release not found: " + str(tag))
        pattern = find_option("--pattern")
        directory = find_option("--dir")
        os.makedirs(directory, exist_ok=True)
        regex = "^" + pattern.replace("*", ".*") + "$"
        hits = 0
        for name, data in release["assets"].items():
            import re as re_module
            if re_module.match(regex, name):
                hits += 1
                body = bytes.fromhex(data)
                override = (corrupt.get(tag) or {{}}).get(name)
                if override is not None:
                    body = bytes.fromhex(override)
                with open(os.path.join(directory, name), "wb") as handle:
                    handle.write(body)
        if hits == 0:
            fail("no asset matched pattern: " + pattern)
        return
    if argv[:2] == ["release", "create"]:
        tag = find_tag(argv[2:])
        if tag in releases:
            fail("release already exists: " + str(tag))
        payload = {{"draft": True, "assets": {{}}}}
        # 位置参数中第一个是 tag，其余是资产文件；选项值（--repo 的仓库等）
        # 永不视为资产。相对路径按当前工作目录解析（工作流 sign 步骤在
        # workspace 根执行）。
        positional = find_assets(argv[2:])
        for item in positional[1:]:
            name = os.path.basename(item)
            path = item if os.path.isabs(item) else os.path.join(os.getcwd(), item)
            if not os.path.exists(path):
                fail("asset file missing: " + item)
            with open(path, "rb") as handle:
                payload["assets"][name] = handle.read().hex()
        releases[tag] = payload
        save_state(state)
        return
    if argv[:2] == ["release", "upload"]:
        tag = find_tag(argv[2:])
        release = releases.get(tag)
        if release is None:
            fail("release not found: " + str(tag))
        clobber = "--clobber" in argv
        positional = find_assets(argv[2:])
        for item in positional[1:]:
            name = os.path.basename(item)
            path = item if os.path.isabs(item) else os.path.join(os.getcwd(), item)
            if not os.path.exists(path):
                fail("asset file missing: " + item)
            if name in release["assets"] and not clobber:
                fail("asset already exists: " + name)
            with open(path, "rb") as handle:
                release["assets"][name] = handle.read().hex()
        save_state(state)
        return
    if argv[:2] == ["release", "edit"]:
        tag = find_tag(argv[2:])
        release = releases.get(tag)
        if release is None:
            fail("release not found: " + str(tag))
        if "--draft=false" in argv:
            release["draft"] = False
        save_state(state)
        return
    fail("gh stub: unsupported command: " + " ".join(argv))

sys.exit(main())
"""

    def _install_stub_minisign(self):
        """minisign 桩：只接受受信公钥路径，模拟签名与验签的可观察行为。"""
        self.minisign_log = self.temp / "minisign-calls.log"
        source = f"""#!/usr/bin/env python
import os, sys

LOG = {self.minisign_log.as_posix()!r}

def main():
    argv = sys.argv[1:]
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write("\\x1f".join(argv) + "\\n")
    if "-Sm" in argv:
        message = argv[argv.index("-Sm") + 1]
        output = argv[argv.index("-x") + 1]
        with open(message, "rb") as handle:
            body = handle.read()
        fake = b"untrusted://sim-signature/" + body[:16].hex().encode()
        with open(output, "wb") as handle:
            handle.write(fake)
        return 0
    if "-Vm" in argv:
        message = argv[argv.index("-Vm") + 1]
        signature = argv[argv.index("-x") + 1]
        pubkey = argv[argv.index("-p") + 1]
        # 验签只在公钥确实是受信检出的 v1 专用公钥时成功；v1 从未用旧
        # publisher.pub 发布过，不能把历史公钥当成兼容别名。
        if "trusted/catalog/v1-publisher.pub" not in pubkey.replace("\\\\", "/"):
            print("minisign stub: untrusted pubkey", file=sys.stderr)
            return 1
        with open(signature, "rb") as handle:
            sig = handle.read()
        with open(message, "rb") as handle:
            body = handle.read()
        expected = b"untrusted://sim-signature/" + body[:16].hex().encode()
        if sig != expected:
            print("minisign stub: signature does not match", file=sys.stderr)
            return 1
        return 0
    print("minisign stub: unsupported", file=sys.stderr)
    return 2

sys.exit(main())
"""
        _write_executable(self.bin / "minisign", source)

    def _sync_gh_state(self):
        """把用例内的 release 世界写进桩状态文件；corrupt 注入随状态一起持久化，
        否则每次同步都会把下载故障设置冲掉。"""
        serial = {}
        for tag, meta in self.releases.items():
            if isinstance(meta, list):
                # 简写形态：仅 tag 列表（无资产），用于 release list 场景。
                serial[tag] = {"draft": False, "assets": {}}
            else:
                serial[tag] = {"draft": meta["draft"], "assets": {name: (data.hex() if isinstance(data, bytes) else data) for name, data in meta["assets"].items()}}
        corrupt = {tag: {name: data.hex() for name, data in assets.items()} for tag, assets in self.corrupt.items()}
        self.gh_state_path.write_text(json.dumps({"releases": serial, "corrupt": corrupt}), encoding="utf-8")

    def _run(self, script, extra_env=None, cwd=None):
        """在模拟环境里执行一段工作流脚本，返回 CompletedProcess。

        子进程显式按 UTF-8 解码：脚本里的中文诊断信息在 Windows 默认 GBK 下
        会让 subprocess 的读取线程抛 UnicodeDecodeError，掩盖被测行为。
        脚本以相对路径传给 bash、cwd 指到脚本所在目录：msys bash 在精简环境
        变量下对绝对 POSIX 路径的挂载解析不可靠（曾观察到 /c/... 找不到文件），
        相对路径 + cwd 在同一环境下稳定。工作流脚本默认以 GITHUB_WORKSPACE 为
        工作目录，因此被测脚本统一包一层「cd 到模拟工作区再执行」。
        """
        step_cwd = Path(cwd or self.workspace)
        script_path = self.temp / "step.sh"
        script_path.write_text(script, encoding="utf-8", newline="\n")
        env = dict(self.env)
        env.update(extra_env or {})
        # 显式用 MSYS bash 的绝对路径：精简环境变量下裸命令名 "bash" 会被
        # Windows 解析到 System32 的 WSL bash（输出 uname=Linux、环境被重置），
        # 行为与模拟环境完全不同；固定 Git Bash 绝对路径消除该解析歧义。
        # 脚本路径经 KW_SCRIPT 传入（bash 内层按 Windows 路径形式定位文件），
        # 被测脚本的工作目录由 KW_STEP_CWD 控制（与 GITHUB_WORKSPACE 对齐）。
        return subprocess.run(
            [MSYS_BASH, "-c", 'cd "$KW_STEP_CWD" && bash "$KW_SCRIPT"'],
            cwd=str(self.temp),
            env={**env, "KW_STEP_CWD": str(step_cwd), "KW_SCRIPT": str(script_path)},
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )

    def _stage_bundle(self, media_names=(), bootstrap=False, sequence=1, omit_media_directory=False):
        """构造 verify 产出的 artifact 布局，再执行工作流真实的 Stage 步骤展开。

        不走测试自写的等价拷贝：直接运行 YAML 里的 Stage 脚本，才能验证
        「artifact v4 丢失空 media 目录后仍能恢复出 out/media」这一修复本身。
        omit_media_directory 模拟 upload-artifact v4 不保留空目录的行为。
        返回 artifact 根；展开结果落在 self.stage_result。
        """
        if omit_media_directory and media_names:
            raise ValueError("an artifact that drops the media directory cannot also carry media files")
        artifacts = self.workspace / "artifacts"
        bundle = artifacts / "verified-bundle"
        bundle.mkdir(parents=True)
        (artifacts / "publication-state").mkdir(parents=True)
        catalog = json.dumps({"schema": 1, "source_id": "official", "sequence": sequence, "plugins": []}).encode()
        (bundle / "catalog.json").write_bytes(catalog)
        media_manifest = {}
        if not omit_media_directory:
            (bundle / "media").mkdir()
        for index, name in enumerate(media_names):
            data = f"media body {index}".encode()
            digest = hashlib.sha256(data).hexdigest()
            actual = f"media-{digest}.md"
            (bundle / "media" / actual).write_bytes(data)
            media_manifest[actual] = digest
        receipt = {
            "track": "v1",
            "repository": "kongweiguang/Kerminal-Plugins",
            "sequence": sequence,
            "candidate_sha256": hashlib.sha256(catalog).hexdigest(),
            "media_manifest": media_manifest,
            "registrations_manifest": {"categories.toml": "a" * 64},
        }
        (bundle / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        (artifacts / "publication-state" / "releases.json").write_text(json.dumps([{"tagName": tag} for tag in self.releases]), encoding="utf-8")
        (artifacts / "publication-state" / "fixed-state.txt").write_text("absent" if bootstrap else "present\n", encoding="utf-8")
        # 首发决定现在由 verify 冻结成独立状态文件，sign 只消费它而不重新推断；
        # 测试材料必须同时提供，否则模拟的是被篡改/不完整的 artifact。
        (artifacts / "publication-state" / "bootstrap-state.txt").write_text("true\n" if bootstrap else "false\n", encoding="utf-8")
        if not bootstrap:
            fixed = json.dumps({"schema": 1, "source_id": "official", "sequence": sequence - 1, "plugins": []}).encode()
            (artifacts / "publication-state" / "previous").mkdir()
            (artifacts / "publication-state" / "previous" / "catalog.json").write_bytes(fixed)
            (artifacts / "publication-state" / "previous" / "catalog.json.minisig").write_bytes(b"baseline-sig")
        self.stage_result = self._run(steps_of(load_workflow(), "sign")["Stage verified inputs"])
        self.assertEqual(self.stage_result.returncode, 0, self.stage_result.stderr)
        return artifacts

    def _write_trusted_checkout(self):
        """布置钉住受信检出的最小骨架：v1 专用公钥与受信脚本路径占位。"""
        trusted = self.workspace / "trusted" / "catalog"
        trusted.mkdir(parents=True)
        (trusted / "v1-publisher.pub").write_text("sim-pubkey", encoding="utf-8")

    def _stub_signature(self, body):
        """按 minisign 桩的约定生成「签名」字节：只用于让验签桩成功，非真实签名。"""
        return b"untrusted://sim-signature/" + body[:16].hex().encode()

    def _baseline_catalog(self, sequence):
        """构造一份可验签的固定目录/快照原文：序列不同即字节不同，供漂移用例区分。"""
        return json.dumps({"schema": 1, "source_id": "official", "sequence": sequence, "plugins": []}).encode()

    def _plan_step_body(self):
        """从工作流解析出 plan 步骤脚本（与生产一致，不在测试里复写一份）。"""
        doc = load_workflow()
        return steps_of(doc, "sign")["Compute sign plan before any secret is loaded"]

    def _plan_self_check_source(self):
        """提取 plan 步骤里的计划自检 heredoc（python 脚本），供零/多媒体用例单独执行。"""
        plan = self._plan_step_body()
        start = plan.index("python -I - <<'PY'")
        begin = plan.index("\n", start) + 1
        end = plan.index("\nPY\n", begin)
        return plan[begin:end]

    def _write_plan_from_out(self, bootstrap, media_override=None):
        """按 out/ 材料生成一份自洽 plan.json：与受信 plan 输出字段一致。

        media_override 允许用例注入与磁盘不符的清单，专测自检的 fail-closed。
        """
        out = self.workspace / "out"
        catalog = (out / "catalog.json").read_bytes()
        sequence = json.loads(catalog)["sequence"]
        plan = {
            "sequence": sequence,
            "tag": f"catalog-v1-{sequence}",
            "fixed_tag": "catalog-v1",
            "bootstrap": bootstrap,
            "media": sorted(p.name for p in (out / "media").iterdir()) if media_override is None else media_override,
            "candidate_sha256": hashlib.sha256(catalog).hexdigest(),
        }
        (self.workspace / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        return plan

    def _run_plan_self_check(self):
        """执行计划自检脚本：直接复用 _plan_self_check_source 提取的 YAML 内嵌
        源码，经 python -I 执行（与工作流 `python -I - <<'PY'` 语义一致），工作
        目录为模拟工作区（与步骤默认 CWD = GITHUB_WORKSPACE 一致）。"""
        source_path = self.temp / "self_check.py"
        source_path.write_text(self._plan_self_check_source(), encoding="utf-8", newline="\n")
        env = dict(self.env)
        return subprocess.run(
            [sys.executable, "-I", str(source_path)],
            cwd=str(self.workspace), env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )

    def test_plan_step_resolves_paths_from_workspace_not_cwd(self):
        """在无关 CWD 下执行 plan 脚本的固定目录核对：相对路径解析不出错位。"""
        doc = load_workflow()
        plan = steps_of(doc, "sign")["Compute sign plan before any secret is loaded"]
        # 断言脚本不含 cd：所有相对引用都以 GITHUB_WORKSPACE 为根（工作流默认 CWD）。
        self.assertNotIn("cd ", plan.replace("cd \"$RUNNER_TEMP", ""))
        # 模拟 runner：默认 CWD 就是 workspace，脚本里的相对路径全部落在其中。
        (self.workspace / "state").mkdir()
        (self.workspace / "state" / "releases.json").write_text("[]", encoding="utf-8")
        (self.workspace / "out").mkdir()
        result = self._run("test -f state/releases.json && test -d out")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_plan_self_check_zero_media_passes(self):
        """合法零媒体（空 media 目录）通过计划自检：不被当成缺失或非法。"""
        self._stage_bundle(media_names=(), bootstrap=True)
        self._write_plan_from_out(bootstrap=True)
        result = self._run_plan_self_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("plan digest and media set verified", result.stdout)

    def test_plan_self_check_multi_media_passes_and_binds_bytes(self):
        """多媒体通过自检；换内容同名媒体被内容寻址核对拒绝。"""
        self._stage_bundle(media_names=["a", "b"], bootstrap=True)
        self._write_plan_from_out(bootstrap=True)
        result = self._run_plan_self_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        # 篡改一个媒体文件的内容：名字仍是内容寻址旧名，字节核对必须失败。
        media_dir = self.workspace / "out" / "media"
        target = next(media_dir.iterdir())
        target.write_bytes(b"tampered")
        result = self._run_plan_self_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bytes do not match", result.stderr)

    def test_plan_self_check_missing_media_fails_closed(self):
        """计划清单里的媒体在磁盘缺失时自检失败：不带病进入签名步骤。"""
        self._stage_bundle(media_names=["a"], bootstrap=False)
        self._write_plan_from_out(bootstrap=False, media_override=[f"media-{'c' * 64}.md"])
        result = self._run_plan_self_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing on disk", result.stderr)

    def test_plan_digest_mismatch_between_plan_and_disk_fails(self):
        """plan.json 与磁盘候选原文摘要不一致时自检失败：不凭 plan 通过就签任意路径。"""
        self._stage_bundle(media_names=[], bootstrap=True)
        self._write_plan_from_out(bootstrap=True)
        plan_path = self.workspace / "plan.json"
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["candidate_sha256"] = "f" * 64
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        result = self._run_plan_self_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)

    def test_plan_self_check_rejects_bootstrap_contradicting_frozen_state(self):
        """plan 自己声明 bootstrap 而 verify 冻结为非首发（或反之）时自检失败：
        计划与状态被分别替换不能把增量发布改写成创建固定目录。"""
        self._stage_bundle(media_names=[], bootstrap=False)
        self._write_plan_from_out(bootstrap=True)
        result = self._run_plan_self_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the frozen publication state", result.stderr)
        # 冻结状态缺失（不完整 artifact）同样拒绝，不默认按任一方向继续。
        (self.workspace / "state" / "bootstrap-state.txt").unlink()
        self._write_plan_from_out(bootstrap=False)
        result = self._run_plan_self_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("frozen publication state is missing", result.stderr)

    def _sign_script(self):
        """从工作流解析 sign 步骤脚本（模拟时用占位密钥注入环境）。"""
        doc = load_workflow()
        return steps_of(doc, "sign")["Sign catalog and publish releases"]

    def _prepare_sign_inputs(self, bootstrap=False, sequence=1, media_names=(), releases_before=None, baseline_sequence=None, omit_media_directory=False):
        """布置 sign 步骤执行所需的一切：材料、plan.json、受信检出与密钥。

        baseline_sequence 允许把 plan 时点的固定基线设成任意序列（用于构造
        「plan 之后远端漂移」）；不传时按 sequence-1 自洽。
        omit_media_directory 模拟 artifact v4 丢弃空目录，验证 Stage 的恢复。
        """
        self._stage_bundle(media_names=media_names, bootstrap=bootstrap, sequence=sequence, omit_media_directory=omit_media_directory)
        self._write_trusted_checkout()
        out = self.workspace / "out"
        catalog = (out / "catalog.json").read_bytes()
        plan = {
            "sequence": sequence,
            "tag": f"catalog-v1-{sequence}",
            "fixed_tag": "catalog-v1",
            "bootstrap": bootstrap,
            "media": sorted(p.name for p in (out / "media").iterdir()),
            "candidate_sha256": hashlib.sha256(catalog).hexdigest(),
        }
        (self.workspace / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        if not bootstrap:
            previous = sequence - 1 if baseline_sequence is None else baseline_sequence
            live = self.workspace / "state" / "previous-live"
            live.mkdir(parents=True)
            (live / "catalog.json").write_bytes(self._baseline_catalog(previous))
            (live / "catalog.json.minisig").write_bytes(self._stub_signature(self._baseline_catalog(previous)))
        for tag, meta in (releases_before or {}).items():
            self.releases[tag] = meta
        self._sync_gh_state()

    def _run_sign(self):
        """执行签名步骤脚本（密钥用占位串：桩 minisign 不校验真实密钥材料）。"""
        return self._run(self._sign_script(), extra_env={"CATALOG_KEY": "SIM-KEY-MATERIAL"})

    def test_missing_v1_public_key_fails_closed_before_generation_and_signing(self):
        """v1 受信公钥缺失时两个 job 的前置检查都直接失败并指出具体文件名；
        公钥由离线桩布置到工作树后同一脚本通过（不要求 git 跟踪）。"""
        for job in ("verify", "sign"):
            gate = steps_of(load_workflow(), job)["Require v1 trusted public key"]
            result = self._run(gate)
            self.assertNotEqual(result.returncode, 0, f"{job} must fail without the v1 key")
            self.assertIn("missing trusted v1 publisher key", result.stderr)
            self.assertIn("catalog/v1-publisher.pub", result.stderr)
        self._write_trusted_checkout()
        # 空文件同样不算「就位」：test -s 同时拒绝缺失与空公钥，避免把空占位
        # 当成可用密钥带进签名阶段。
        key = self.workspace / "trusted" / "catalog" / "v1-publisher.pub"
        key.write_text("", encoding="utf-8")
        for job in ("verify", "sign"):
            gate = steps_of(load_workflow(), job)["Require v1 trusted public key"]
            result = self._run(gate)
            self.assertNotEqual(result.returncode, 0, f"{job} must reject an empty v1 key")
        key.write_text("sim-pubkey", encoding="utf-8")
        for job in ("verify", "sign"):
            gate = steps_of(load_workflow(), job)["Require v1 trusted public key"]
            result = self._run(gate)
            self.assertEqual(result.returncode, 0, f"{job} must accept a staged v1 key: {result.stderr}")

    def gh_world(self):
        """读取桩状态文件里的 release 世界：断言的对象是 gh 桩记录的事实。"""
        return json.loads(self.gh_state_path.read_text(encoding="utf-8"))["releases"]

    def test_sign_bootstrap_zero_media_publishes_catalog_and_fixed(self):
        """bootstrap 零媒体且 artifact 丢了空 media 目录（v4 行为）：Stage 恢复空
        目录后仍能发布，快照只含 catalog+sig，固定目录创建并回读验签成功。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1, media_names=[], omit_media_directory=True)
        self.assertTrue((self.workspace / "out" / "media").is_dir(), "stage must restore the empty media directory")
        result = self._run_sign()
        self.assertEqual(result.returncode, 0, result.stderr)
        world = self.gh_world()
        snapshot = world["catalog-v1-1"]
        self.assertIn("catalog.json", snapshot["assets"])
        self.assertIn("catalog.json.minisig", snapshot["assets"])
        self.assertFalse(any(name.startswith("media-") for name in snapshot["assets"]), "bootstrap snapshot must not carry stray media")
        fixed = world["catalog-v1"]
        self.assertIn("catalog.json", fixed["assets"])
        self.assertFalse(fixed["draft"])
        # 全程无删除调用。
        gh_calls = (self.temp / "gh-calls.log").read_text(encoding="utf-8")
        self.assertNotIn('"release","delete"', gh_calls.replace(" ", ""))

    def test_sign_bootstrap_with_media_uploads_and_reads_back_each_asset(self):
        """首次引导带媒体：媒体随快照上传，且远端逐个下载回读比对（不以 bootstrap
        跳过）。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1, media_names=["a", "b"])
        result = self._run_sign()
        self.assertEqual(result.returncode, 0, result.stderr)
        planned = json.loads((self.workspace / "plan.json").read_text(encoding="utf-8"))["media"]
        self.assertEqual(len(planned), 2)
        snapshot = self.gh_world()["catalog-v1-1"]
        for name in planned:
            self.assertIn(name, snapshot["assets"])
            self.assertEqual(bytes.fromhex(snapshot["assets"][name]), (self.workspace / "out" / "media" / name).read_bytes())
        # 每个计划媒体都发生过一次下载回读（pattern 就是该媒体名）。
        gh_calls = [json.loads(line) for line in (self.temp / "gh-calls.log").read_text(encoding="utf-8").splitlines()]
        readback_dirs = [call[call.index("--dir") + 1] for call in gh_calls if call[:2] == ["release", "download"] and "--dir" in call]
        self.assertTrue(any("readback-media" in path for path in readback_dirs), "bootstrap media must be read back from the remote")
        for name in planned:
            patterns = [call[call.index("--pattern") + 1] for call in gh_calls if call[:2] == ["release", "download"] and "--pattern" in call and any("readback-media" in item for item in call)]
            self.assertIn(name, patterns, f"planned media must be downloaded by name: {name}")

    def test_sign_media_missing_after_stage_fails_before_upload(self):
        """计划要求媒体但 artifact 丢了媒体目录时失败关闭：不在缺媒体的情况下
        发布快照（受信 plan 的 receipt 比对仍是最终防线，这里挡在签名步骤）。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1, media_names=["a"])
        plan_path = self.workspace / "plan.json"
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        self.assertEqual(len(plan["media"]), 1)
        # 删除磁盘媒体：模拟 artifact 丢文件。
        for item in (self.workspace / "out" / "media").iterdir():
            item.unlink()
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing planned media asset", result.stderr)
        # 快照没有被创建：失败发生在任何 gh 写入之前。
        world = self.gh_world()
        self.assertNotIn("catalog-v1-1", world)

    def test_sign_multi_media_uploads_exactly_planned_media(self):
        """多媒体按计划清单逐个上传快照，且固定目录不携带媒体。"""
        baseline = self._baseline_catalog(1)
        self._prepare_sign_inputs(bootstrap=False, sequence=2, media_names=["a", "b"], releases_before={
            "catalog-v1": {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": self._stub_signature(baseline)}},
        })
        result = self._run_sign()
        self.assertEqual(result.returncode, 0, result.stderr)
        world = self.gh_world()
        snapshot = world["catalog-v1-2"]
        for name in ("catalog.json", "catalog.json.minisig"):
            self.assertIn(name, snapshot["assets"])
        planned = json.loads((self.workspace / "plan.json").read_text(encoding="utf-8"))["media"]
        self.assertEqual(sorted(name for name in snapshot["assets"] if name.startswith("media-")), sorted(planned))
        # 快照媒体与本地字节一致（内容寻址闭环）。
        for name in planned:
            expected = (self.workspace / "out" / "media" / name).read_bytes()
            self.assertEqual(bytes.fromhex(snapshot["assets"][name]), expected)

    def test_sign_residual_snapshot_draft_fails_closed_without_delete(self):
        """同名快照已存在（上次中断留下的 draft）时失败关闭，绝不删除既有 Release。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1, media_names=[], releases_before={
            "catalog-v1-1": {"draft": True, "assets": {"catalog.json": b"stale", "catalog.json.minisig": b"stale-sig"}},
        })
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        gh_calls = (self.temp / "gh-calls.log").read_text(encoding="utf-8")
        self.assertNotIn("delete", gh_calls)
        # 既有 draft 原样保留（人工恢复对象）。
        self.assertTrue(self.gh_world()["catalog-v1-1"]["draft"])

    def test_sign_fixed_release_exists_without_baseline_fails_closed(self):
        """固定目录存在但 verify 判定 absent（状态冲突）时，快照创建后失败：
        留下 draft 交人工处理，不自动删除或改写固定目录。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1, media_names=[], releases_before={
            "catalog-v1": {"draft": False, "assets": {"catalog.json": b"unexpected", "catalog.json.minisig": b"sig"}},
        })
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        # 固定目录内容未被改写。
        self.assertEqual(bytes.fromhex(self.gh_world()["catalog-v1"]["assets"]["catalog.json"]), b"unexpected")
        gh_calls = (self.temp / "gh-calls.log").read_text(encoding="utf-8")
        self.assertNotIn("delete", gh_calls)

    def test_sign_baseline_drift_blocks_fixed_catalog_replacement(self):
        """plan 之后远端固定目录被推进：更新前重新下载并逐字节对照发现漂移，
        拒绝替换固定目录，进入人工恢复。"""
        plan_baseline = self._baseline_catalog(2)  # plan 时点：固定目录序列 2
        remote_baseline = self._baseline_catalog(1)  # 远端此刻：被换成序列 1 的另一份目录
        self._prepare_sign_inputs(bootstrap=False, sequence=3, media_names=[], releases_before={
            "catalog-v1": {"draft": False, "assets": {"catalog.json": remote_baseline, "catalog.json.minisig": self._stub_signature(remote_baseline)}},
        }, baseline_sequence=2)
        # 让本地 plan 基线确实是序列 2（上面的 baseline_sequence 已写入）。
        self.assertEqual(json.loads((self.workspace / "state" / "previous-live" / "catalog.json").read_text(encoding="utf-8"))["sequence"], 2)
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        # 远端与 plan 基线字节不一致：cmp 先失败（cmp 的差异说明走 stdout）。
        combined = result.stdout + result.stderr
        self.assertTrue("differ" in combined or "refusing to replace the fixed catalog" in combined, combined)
        # 更新前的 guard 步骤确实重新下载了远端固定目录（不是只读本地副本）。
        gh_calls = (self.temp / "gh-calls.log").read_text(encoding="utf-8")
        self.assertIn("previous-guard", gh_calls)
        # 固定目录保持远端原字节（未被 clobber）。
        self.assertEqual(bytes.fromhex(self.gh_world()["catalog-v1"]["assets"]["catalog.json"]), remote_baseline)
        gh_calls = (self.temp / "gh-calls.log").read_text(encoding="utf-8")
        self.assertNotIn("delete", gh_calls)

    def test_sign_plan_sequence_mismatch_blocks_fixed_replacement(self):
        """远端基线字节与 plan 基线一致但序列不再是候选前一序列时拒绝替换。"""
        baseline = self._baseline_catalog(2)
        self._prepare_sign_inputs(bootstrap=False, sequence=5, media_names=[], releases_before={
            "catalog-v1": {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": self._stub_signature(baseline)}},
        }, baseline_sequence=2)
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to replace the fixed catalog", result.stderr)
        self.assertEqual(bytes.fromhex(self.gh_world()["catalog-v1"]["assets"]["catalog.json"]), baseline)

    def test_sign_missing_key_fails_before_any_publish(self):
        """签名密钥缺失时在任何 GitHub 写入之前失败。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1)
        result = self._run(self._sign_script(), extra_env={"CATALOG_KEY": ""})
        self.assertNotEqual(result.returncode, 0)
        # set -u 下空值与未绑定都会先于发布失败；诊断文案在 GitHub 实跑时由
        # env 注入路径给出，这里只断言「没有发生任何 gh 调用」（日志文件不存在
        # 也视为零调用——桩只在被调用时创建它）。
        self.assertFalse((self.temp / "gh-calls.log").exists())

    def test_sign_candidate_mutated_after_plan_refuses_to_sign(self):
        """plan 之后候选原文被改动：签名前摘要核对拒绝，minisign 未被调用。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1)
        # 在自检与签名之间篡改候选：直接改 out/catalog.json 再跑 sign 脚本
        # （sign 脚本开头会再核对一次摘要）。
        (self.workspace / "out" / "catalog.json").write_bytes(b"mutated after plan")
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to sign", result.stderr)
        self.assertFalse(self.minisign_log.exists() and self.minisign_log.read_text(encoding="utf-8").strip())

    def test_media_readback_mismatch_fails_without_advancing_fixed_catalog(self):
        """真正让桩 gh 在回读时返回被篡改的媒体字节：回读比对失败，快照停在
        draft，固定目录不推进，且没有任何删除调用。"""
        baseline = self._baseline_catalog(1)
        self._prepare_sign_inputs(bootstrap=False, sequence=2, media_names=["a"], releases_before={
            "catalog-v1": {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": self._stub_signature(baseline)}},
        })
        planned = json.loads((self.workspace / "plan.json").read_text(encoding="utf-8"))["media"]
        # 注入下载故障：快照 tag 的媒体资产在下载时返回不同字节。
        self.corrupt["catalog-v1-2"] = {planned[0]: b"tampered by the publishing channel"}
        self._sync_gh_state()
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        world = self.gh_world()
        # 快照已创建且仍是 draft（回读失败发生在转正之前）。
        self.assertTrue(world["catalog-v1-2"]["draft"])
        # 固定目录仍是旧基线字节，没有被 clobber。
        self.assertEqual(bytes.fromhex(world["catalog-v1"]["assets"]["catalog.json"]), baseline)
        gh_calls = (self.temp / "gh-calls.log").read_text(encoding="utf-8")
        self.assertNotIn("delete", gh_calls)

    def test_readback_cmp_rejects_mismatch(self):
        """回读依赖 cmp + set -e：字节不一致时后续步骤不执行（bash 原语级）。"""
        script = """set -euo pipefail
echo alpha > a.bin
echo beta > b.bin
if cmp -s a.bin b.bin; then echo UNEXPECTED; exit 99; fi
cmp a.bin b.bin
echo REACHED-TAIL
"""
        result = self._run(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("REACHED-TAIL", result.stdout)

    def test_sign_unlicensed_bootstrap_fails_before_signing(self):
        """plan 声明首发但冻结状态未许可（false 或文件缺失）：签名步骤在任何
        GitHub 写入前失败，不自行推断首发。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1)
        (self.workspace / "state" / "bootstrap-state.txt").write_text("false\n", encoding="utf-8")
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the frozen publication state", result.stderr)
        self.assertFalse((self.temp / "gh-calls.log").exists())

    def test_sign_plan_contradicting_fixed_catalog_state_fails_before_signing(self):
        """冻结许可与 plan 一致但固定目录状态相反（声明首发却记录固定目录存在）：
        签名前失败，避免后续走错「创建/更新固定目录」分支。"""
        self._prepare_sign_inputs(bootstrap=True, sequence=1)
        (self.workspace / "state" / "fixed-state.txt").write_text("present\n", encoding="utf-8")
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recorded fixed catalog state", result.stderr)
        self.assertFalse((self.temp / "gh-calls.log").exists())

    def test_sign_state_contradiction_fails_before_signing(self):
        """固定目录存在却冻结为 bootstrap 时状态自相矛盾：签名前失败。"""
        self._prepare_sign_inputs(bootstrap=False, sequence=2, releases_before={"catalog-v1": self._fixed_release()})
        (self.workspace / "state" / "bootstrap-state.txt").write_text("true\n", encoding="utf-8")
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the frozen publication state", result.stderr)
        self.assertFalse((self.temp / "gh-calls.log").exists())

    def test_plan_step_requires_licensed_bootstrap(self):
        """plan 步骤在无固定基线时只接受冻结许可 true；false 或缺文件都拒绝。

        除了静态断言，还从真实 YAML 里取出那条门禁语句执行：许可为 false 或
        文件缺失时以失败关闭，只有 true 才放行。
        """
        plan = self._plan_step_body()
        self.assertIn('test "$(cat state/bootstrap-state.txt)" = true', plan)
        self.assertIn("refusing to sign a first publication", plan)
        self.assertIn('test "$(cat state/bootstrap-state.txt)" = false', plan)
        self.assertIn("refusing inconsistent state", plan)
        gate = next(line.strip() for line in plan.splitlines() if line.strip().startswith('test "$(cat state/bootstrap-state.txt)" = true'))
        state = self.workspace / "state"
        state.mkdir()
        for value, expected in (("true", 0), ("false", 1), (None, 1)):
            with self.subTest(value=value):
                path = state / "bootstrap-state.txt"
                if value is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(value + "\n", encoding="utf-8")
                result = self._run("set -euo pipefail\n" + gate + "\necho LICENSED\n")
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual("LICENSED" in result.stdout, expected == 0)

    def test_sign_snapshot_media_readback_covers_each_planned_asset(self):
        """快照媒体回读按计划清单逐个执行：清单外的媒体不被下载或比对。"""
        baseline = self._baseline_catalog(1)
        self._prepare_sign_inputs(bootstrap=False, sequence=2, media_names=["a"], releases_before={
            "catalog-v1": {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": self._stub_signature(baseline)}},
        })
        result = self._run_sign()
        self.assertEqual(result.returncode, 0, result.stderr)
        gh_calls = (self.temp / "gh-calls.log").read_text(encoding="utf-8")
        planned = json.loads((self.workspace / "plan.json").read_text(encoding="utf-8"))["media"]
        for name in planned:
            self.assertIn(name, gh_calls)

    def _plan_baseline_fragment(self):
        """从 plan 步骤中截取「固定基线 + 对应不可变快照绑定」的 bash 片段。

        截取真实 YAML 里的代码（不是测试复写），起点是 previous-live 下载，
        终点是受信 plan 调用之前；这样能独立执行并验证新增的绑定逻辑。
        """
        plan = self._plan_step_body()
        start = plan.index("mkdir -p state/previous-live")
        end = plan.index("python -I trusted/marketplace/trusted_publish_v1.py plan")
        fragment = plan[start:end]
        lines = fragment.splitlines()
        indents = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        base = min(indents)
        body = "\n".join(line[base:] if line.strip() else "" for line in lines)
        return "set -euo pipefail\n" + body + "\n"

    def _run_plan_baseline_fragment(self):
        """执行绑定片段：工作目录为模拟工作区，gh/minisign 用桩。"""
        self._write_trusted_checkout()
        (self.workspace / "state").mkdir(exist_ok=True)
        return self._run(self._plan_baseline_fragment())

    def test_fixed_baseline_binding_accepts_snapshot_with_same_bytes(self):
        """固定目录与其快照字节一致且双方验签通过时，绑定片段放行。"""
        baseline = self._baseline_catalog(2)
        signature = self._stub_signature(baseline)
        self.releases["catalog-v1"] = {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": signature}}
        self.releases["catalog-v1-2"] = {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": signature}}
        self._sync_gh_state()
        result = self._run_plan_baseline_fragment()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixed_baseline_binding_rejects_snapshot_with_other_bytes(self):
        """固定目录与快照序列相同但字节不同：绑定片段必须失败，不进入 plan。"""
        baseline = self._baseline_catalog(2)
        other = self._baseline_catalog(2).replace(b'"plugins": []', b'"plugins": [ ]')
        self.assertNotEqual(baseline, other)
        self.releases["catalog-v1"] = {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": self._stub_signature(baseline)}}
        self.releases["catalog-v1-2"] = {"draft": False, "assets": {"catalog.json": other, "catalog.json.minisig": self._stub_signature(other)}}
        self._sync_gh_state()
        result = self._run_plan_baseline_fragment()
        self.assertNotEqual(result.returncode, 0)

    def test_fixed_baseline_binding_rejects_bad_snapshot_signature(self):
        """快照签名不成立时绑定片段失败：固定目录的可信不能只靠字节相等。"""
        baseline = self._baseline_catalog(2)
        self.releases["catalog-v1"] = {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": self._stub_signature(baseline)}}
        self.releases["catalog-v1-2"] = {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": b"untrusted://sim-signature/forged"}}
        self._sync_gh_state()
        result = self._run_plan_baseline_fragment()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)

    def test_fixed_baseline_binding_requires_matching_snapshot_release(self):
        """固定目录存在但其序列对应的不可变快照缺失：绑定片段失败关闭，
        不把「只有固定目录」当作可信基线继续签名。"""
        baseline = self._baseline_catalog(2)
        self.releases["catalog-v1"] = {"draft": False, "assets": {"catalog.json": baseline, "catalog.json.minisig": self._stub_signature(baseline)}}
        self._sync_gh_state()
        result = self._run_plan_baseline_fragment()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("catalog-v1-2", result.stdout + result.stderr)

    def test_branch_gate_script_rejects_non_main_refs(self):
        """分支门禁脚本本身在真实 bash 上拒绝非 main：不依赖 GitHub Environment。"""
        doc = load_workflow()
        gate = steps_of(doc, "sign")["Require main branch"]
        for ref, expected in (("refs/heads/main", 0), ("refs/heads/feature", 1), ("refs/tags/v1", 1), ("refs/pull/1/merge", 1)):
            with self.subTest(ref=ref):
                result = self._run(gate, extra_env={"EVENT_NAME": "workflow_dispatch", "EVENT_REF": ref})
                self.assertEqual(result.returncode, expected, result.stderr)
        # 非 push/workflow_dispatch 的事件同样拒绝。
        result = self._run(gate, extra_env={"EVENT_NAME": "pull_request", "EVENT_REF": "refs/heads/main"})
        self.assertNotEqual(result.returncode, 0)

    def _run_bootstrap_license_step(self, value):
        """执行真实的许可规范化步骤；value 为 None 表示变量未配置。

        返回 (进程结果, GITHUB_OUTPUT 文本)：断言落在步骤实际写出的值上，
        而不是只看脚本里有没有某个字符串。
        """
        step = steps_of(load_workflow(), "verify")["Resolve bootstrap license"]
        output = self.temp / "license-output.txt"
        output.write_text("", encoding="utf-8")
        env = {"GITHUB_OUTPUT": str(output)}
        if value is not None:
            env["BOOTSTRAP_VAR"] = value
        result = self._run(step, extra_env=env)
        return result, output.read_text(encoding="utf-8")

    def test_bootstrap_license_resolution_behavior(self):
        """许可变量只在 true 时放行；未配置按 false，非法值（含大小写变体）
        失败关闭，避免拼写错误被当成首发许可。"""
        result, written = self._run_bootstrap_license_step(None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("license=false", written)
        result, written = self._run_bootstrap_license_step("true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("license=true", written)
        result, written = self._run_bootstrap_license_step("false")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("license=false", written)
        for bad in ("TRUE", "yes", "1"):
            with self.subTest(value=bad):
                result, written = self._run_bootstrap_license_step(bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be true or false", result.stderr)
                self.assertNotIn("license=true", written)

    def _run_baseline_step(self, releases, license_value):
        """执行真实的「Inspect fixed catalog baseline」步骤。

        用桩 gh 提供 release 世界；返回 (结果, state 目录)。每次调用前清空
        state，避免步骤内 `mkdir` 在重复调用时因目录已存在而误失败。
        """
        state = self.runner_temp / "state"
        if state.exists():
            shutil.rmtree(state)
        self.releases = {tag: meta for tag, meta in releases.items()}
        self._sync_gh_state()
        step = steps_of(load_workflow(), "verify")["Inspect fixed catalog baseline"]
        result = self._run(step, extra_env={"BOOTSTRAP_LICENSE": license_value})
        return result, state

    def _fixed_release(self):
        """固定目录的合法形态：带 catalog 原文与签名的非 draft Release。"""
        catalog = self._baseline_catalog(1)
        return {"draft": False, "assets": {"catalog.json": catalog, "catalog.json.minisig": self._stub_signature(catalog)}}

    def test_verify_bootstrap_requires_explicit_license(self):
        """无固定目录、无任何快照时，只有管理员配置 true 才冻结首发决定；
        未配置时拒绝首次发布，不把「目录为空」当成自动引导。"""
        result, state = self._run_baseline_step({}, "false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing first publication", result.stderr)
        # 未获许可时不写任何 bootstrap 决定，后续步骤没有可消费的「true」。
        self.assertFalse((state / "bootstrap-state.txt").exists())

        result, state = self._run_baseline_step({}, "true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((state / "fixed-state.txt").read_text(encoding="utf-8").strip(), "absent")
        self.assertEqual((state / "bootstrap-state.txt").read_text(encoding="utf-8").strip(), "true")
        self.assertIn("bootstrap=true", result.stdout)

    def test_verify_bootstrap_rejected_when_snapshots_exist(self):
        """固定目录消失但同轨不可变快照仍在：属于中断或破坏状态，即使许可为
        true 也必须拒绝自动引导，交人工恢复。"""
        result, state = self._run_baseline_step({"catalog-v1-1": {"draft": False, "assets": {}}}, "true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable snapshots exist; refusing to bootstrap", result.stderr)
        self.assertFalse((state / "bootstrap-state.txt").exists())

    def test_verify_existing_fixed_catalog_never_freezes_bootstrap(self):
        """固定目录存在时无论许可变量为何都冻结为非首发，并下载基线；
        常规增量不会被误标成首发。"""
        result, state = self._run_baseline_step({"catalog-v1": self._fixed_release()}, "true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((state / "fixed-state.txt").read_text(encoding="utf-8").strip(), "present")
        self.assertEqual((state / "bootstrap-state.txt").read_text(encoding="utf-8").strip(), "false")
        self.assertTrue((state / "previous" / "catalog.json").is_file())

    def test_detect_published_entries_fails_when_inspect_fails(self):
        """inspect 非零退出必须让步骤失败：pipefail 让 tee 的成功不能掩盖它，
        后续 heredoc 不会拿半截输出继续。"""
        trusted = self.workspace / "trusted" / "marketplace"
        trusted.mkdir(parents=True)
        (trusted / "trusted_publish_v1.py").write_text(
            "import json, sys\nprint(json.dumps({'published': True}))\nsys.exit(3)\n",
            encoding="utf-8",
        )
        (self.workspace / "candidate").mkdir()
        step = steps_of(load_workflow(), "verify")["Detect published entries"]
        output = self.temp / "entries-output.txt"
        output.write_text("", encoding="utf-8")
        result = self._run(step, extra_env={"GITHUB_OUTPUT": str(output)})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("published=", output.read_text(encoding="utf-8"))
        # 对照：同一脚本成功退出时步骤通过并写出 published，证明失败来自 pipefail
        # 而不是桩脚本路径写错。
        (trusted / "trusted_publish_v1.py").write_text(
            "import json\nprint(json.dumps({'published': False}))\n",
            encoding="utf-8",
        )
        result = self._run(step, extra_env={"GITHUB_OUTPUT": str(output)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("published=false", output.read_text(encoding="utf-8"))

    def test_command_substitution_python_is_isolated_from_poisoned_cwd(self):
        """从工作流取真实命令替换行，在投毒的 CWD 下执行：-I 使 json 不被
        同名模块劫持。去掉 -I 时同一用例会失败，说明断言绑定真实行为。"""
        sign = self._sign_script()
        line = next(item for item in sign.splitlines() if item.strip().startswith("tag=") and "$(python" in item)
        self.assertIn("$(python -I ", line)
        (self.workspace / "json.py").write_text("raise SystemExit('poisoned json imported')\n", encoding="utf-8")
        (self.workspace / "plan.json").write_text(json.dumps({"sequence": 7}), encoding="utf-8")
        result = self._run("set -euo pipefail\n" + line + "\necho \"TAG=$tag\"\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TAG=catalog-v1-7", result.stdout)
        # 负向对照：同一行去掉 -I 后必然被投毒模块拦截。
        poisoned = line.replace("python -I ", "python ")
        result = self._run("set -euo pipefail\n" + poisoned + "\necho \"TAG=$tag\"\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("poisoned json imported", result.stderr)


if __name__ == "__main__":
    unittest.main()
