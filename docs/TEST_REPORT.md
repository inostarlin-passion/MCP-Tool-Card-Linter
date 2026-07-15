# 测试报告

测试日期：2026-07-15。版本：1.0.0。

## 环境

- 工作目录：`/Users/inostarlin/code/MCP-Tool-Card-Linter`
- 平台：macOS 15.7.7 arm64
- Python：3.14.6
- 测试框架：标准库 `unittest`；`coverage.py` branch coverage
- 运行时依赖：`cryptography>=45,<50`、`jsonschema>=4.23,<5`、`rfc8785>=0.1.4,<1`
- 测试网络：HTTP/OAuth/stdio 使用本地 adversarial fixtures；联网研究与隔离构建依赖安装使用公网

## 汇总结论

| 验收项 | 实测结果 |
| --- | --- |
| 全部分层测试 | 143 tests；141 passed、2 platform skips、0 failed；41.628 s |
| branch coverage | 5,084 statements、2,006 branches；75.81%，通过 75% gate |
| 规则准确率 | 12 cases、21 explicitly-labelled pairs；TP 8、FP 0、TN 13、FN 0；precision/recall/F1 = 1.0；通过 0.95/0.95 gate |
| 确定性 fuzz | 500 个 bounded JSON round trips、5 个非法 JSON extensions、300 个 mutated tool shapes；全部通过 |
| mutation | 6 个安全输入 mutation operators 均被预期 rule 杀死 |
| soak | 40 次 stdio server start/discover/cleanup；无线程或 descriptor 累积；0.927 test seconds |
| 性能 | 2,000 cards；规则计算 0.4047 s，peak 7.81 MiB；通过 `<10 s`/`<128 MiB` |
| 可复现构建 | 同一 source tree/`SOURCE_DATE_EPOCH` 两次构建，wheel 与 sdist 分别 `cmp` 完全相同 |
| clean install | wheel 与 sdist 均在新 venv 安装成功；version/lint/contract/rules/evaluate smoke 全通过 |
| 静态质量 | Ruff、strict mypy（native/win32/linux）、compileall、pip check、diff check、workflow YAML parse 全通过 |

## 分层测试

| 层级 | 数量 | v1.0 重点范围 | 结果 |
| --- | ---: | --- | --- |
| 单元测试 | 91 | Windows Job limit flag/field 一致性、失败回滚与 pipe 释放；稳定 contract digest、current/legacy report、accuracy corpus 校验、audit chain/tamper/private mode/concurrent lock；既有 lint/schema/OAuth/executor/trust/security | 89 passed，2 platform skips |
| 集成测试 | 40 | `contract`、`evaluate`、`validate-report`、lint audit→verify；既有 CLI/stdio/HTTP/SSE/OAuth/signed baseline | 40/40 passed |
| 系统测试 | 9 | repeated stdio lifecycle、signed rug pull/publisher drift、default-deny execution、config→report→optimize、OAuth、partial source、performance | 9/9 passed |
| fuzz | 2 | strict JSON grammar 与随机 bounded tool/report serialization | 2/2 passed |
| mutation | 1 | poisoning、secret、Unicode、command、URL allowlist 六类 mutation | 1/1 passed |
| 合计 | 143 | unit + integration + system + fuzz + mutation | 141 passed，2 skipped，0 failed |

两个本机 skip 都是严格的平台条件：Windows native command parser 和 Windows Job Object 真实运行。它们由 `windows-latest` CI matrix 执行；本报告没有在 macOS 上伪造 Windows 成功。

主测试命令：

```bash
.venv/bin/coverage erase
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  .venv/bin/coverage run -m unittest discover -s tests -v
.venv/bin/coverage combine
.venv/bin/coverage report --fail-under=75
```

```text
Ran 143 tests in 41.628s
OK (skipped=2)
TOTAL 5084 statements, 1045 missed, 2006 branches, 514 partial, 75.81%
```

主要模块覆盖率：`rules.py` 94.87%、`models.py` 88.94%、`security.py` 84.18%、`reporting.py` 83.86%、`lint.py` 81.14%、`oauth.py` 79.45%、`evaluation.py` 76.87%、`policy.py` 76.45%、`cli.py` 76.30%、`execution.py` 75.74%、`audit.py` 71.68%、`trust.py` 70.89%、`discovery.py` 66.20%。较低分支主要是 OS 专属 API、TLS/rare I/O failure 和多阶段 cleanup；仓库总门槛已通过。

## GitHub CI 四项失败的根因与修复

[失败 run 29310433050](https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/actions/runs/29310433050) 的 4 个红色 job 恰好是 Windows + Python 3.11/3.12/3.13/3.14；另外 13 个 job 均成功。四份日志都在真实 Windows Job 测试的 `SetInformationJobObject` 返回错误 87，且随后报告 stdin/stdout/stderr 未关闭。该一致性说明问题位于共享的 Windows backend，而非某个 Python 小版本。

| 日志/代码证据 | 第一性原因 | 修复与回归 |
| --- | --- | --- |
| `LimitFlags` 使用 `0x200`，但 `JobMemoryLimit` 保持 0 | `0x200` 是 `JOB_OBJECT_LIMIT_JOB_MEMORY`；开启后 0 值字段使参数无效 | 改用与 `ProcessMemoryLimit` 匹配的 `0x100`，测试断言 job memory 为 0 且未启用 |
| CPU 字段已赋值但使用 `0x100` | `0x100` 是 process memory，不是 process time | 使用 `0x2`，并断言 7 秒精确转换为 70,000,000 个 100 ns tick |
| ctypes 调用未声明完整原型 | foreign function 的默认转换不构成 Win64 HANDLE 契约 | 为 create/set/assign/close 显式声明 `argtypes`/`restype` |
| Job 配置异常只 kill/wait | 三条 `PIPE` 对象仍持有 descriptor，触发 `ResourceWarning` | 失败回滚在 kill/wait 后逐一关闭 stdin/stdout/stderr，并有异常注入测试 |

本机替身测试验证了结构布局、information class 9、精确 flags/fields、64-bit-safe API 签名和失败清理；真实 Windows 测试还增强为“关闭最后一个 Job handle 后子进程必须终止”。[修复后的 run 29311329892](https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/actions/runs/29311329892) 已在 Windows + Python 3.11/3.12/3.13/3.14 全部通过，且同一 run 的其他 13 个 job 也全部成功。

## v1.0 专项测试

| 场景 | 验收条件 | 结果 |
| --- | --- | --- |
| 稳定机器契约 | schema/readers、106 rule IDs + digest、0/1/2/130、MCP current/previous 可机读 | 通过 |
| 未登记 rule | runtime metadata fail closed；literal `Issue(code=...)` AST 不得逃逸 catalog | 通过，并补齐 3 个历史 baseline rule 元数据 |
| 当前 report | schema 1.1.0 完整 Draft 2020-12 验证 | 通过 |
| 旧 report | schema 1.0.0 reader 验证稳定 identity/fingerprint 和优化器使用字段 | 通过 |
| accuracy corpus | exact fields、唯一 case/rule、已知 rule、非重叠标签、8 MiB/10k/1 MiB bounds | 通过 |
| accuracy gate | precision 与 recall 均不低于 0.95，且无 missing/unexpected labelled pair | 1.0/1.0，通过 |
| audit privacy | 仅允许 12 个最小 detail keys；不含 raw card、URL、path、token 或 authorization code | 通过 |
| audit integrity | 0600、sequence、previous hash、domain-separated canonical SHA-256、full-chain verify | 通过 |
| audit concurrency | 同一路径已有 `O_EXCL` lock 时 fail closed；append 使用 `O_APPEND` + file/dir fsync | 通过 |
| audit tamper | 任一 record 修改或链断裂均拒绝 | 通过 |
| OAuth audit | 仅记录 proxy/CA/mTLS/private/insecure 配置布尔值；audit 不得覆盖 state/token/cert/key | 通过 |
| fuzz | 固定 seeds，重复运行得到相同输入；所有报告 bounded 且 JSON serializable | 通过 |
| mutation | 6 个代表性攻击变异必须触发指定 rule | 通过 |
| stdio soak | 40 cycles 后 active threads `<= before+1`，descriptors `<= before+2` | 通过 |
| 可复现构建 | 两次 wheel、两次 sdist 逐字节一致 | 通过 |
| packaged assets | report/baseline/audit schemas 与 `py.typed` 均进入 wheel/sdist | 通过 |

准确率 corpus SHA-256：`7645f07e45f2c02a924d57d081821f57fda2dfcc3796c61de951d261ab9fe901`。该数字只覆盖明确标注的 21 个 rule/case pairs；未标注 pair 完全不计分，合成样本的类别比例也不用于估计生产误报率。

## 构建、安装与静态检查

| 检查 | 实际结果 |
| --- | --- |
| `ruff check src tests` | 通过 |
| `mypy src`（strict） | 通过，17 source files |
| `mypy --platform win32 src` | 通过，17 source files |
| `mypy --platform linux src` | 通过，17 source files |
| `python -m compileall -q src tests` | 通过 |
| `git diff --check` | 通过 |
| `python -m pip check` | `No broken requirements found` |
| workflow YAML parse | CI/release 均通过 Ruby Psych 解析 |
| wheel | 两次候选构建逐字节一致；Twine 与 `check-wheel-contents` 通过 |
| sdist | 两次候选构建逐字节一致；Twine 通过 |
| clean wheel install | 1.0.0、good fixture lint、`contract` 通过 |
| clean sdist install | rule catalog 与 accuracy 0.95/0.95 gate 通过 |
| 运行时依赖审计 | `pip-audit --strict` 报告无已知漏洞 |

本地候选构建只用于证明同一 source tree/`SOURCE_DATE_EPOCH` 的两次构建一致。正式制品身份以 release workflow 发布的 `SHA256SUMS`、GitHub attestations 与 PyPI PEP 740 attestations 为准。

## CI 与发布门

- `test`：Ubuntu/macOS/Windows × Python 3.11/3.12/3.13/3.14，执行 Ruff、mypy、143-test discovery 与 coverage gate。
- `package`：wheel/sdist build、两种制品 clean install 和 CLI smoke。
- `performance`：脱离 coverage 的 2,000-card time/memory gate。
- `production-quality`：accuracy、fuzz、mutation 和 40-cycle soak。
- `reproducible-build`：固定 commit timestamp 作为 `SOURCE_DATE_EPOCH`，双构建后 `cmp`。
- `mcp-conformance`：锁定依赖的官方 runner 执行 2025-11-25 initialize 与 SSE retry 场景。
- tag release：版本/tag 一致性、reproducible build、CycloneDX SBOM、SHA-256、GitHub provenance/SBOM attestations、PyPI Trusted Publishing/PEP 740、GitHub Release。

最新主分支 run 已在 GitHub 托管的 Ubuntu/macOS/Windows 与 Python 3.11–3.14 上全绿。`pypi` environment 已配置所有者审批和 `v*` tag 限制，PyPI pending Trusted Publisher 已精确绑定仓库、`release.yml` 与该 environment。Tag 专用的 OIDC 上传、GitHub attestation、SBOM attestation 与 Release 创建仍必须由正式 tag run 实证。

## 回归范围

既有 MCP 2025-11-25/2025-06-18/2025-03-26 negotiation、tools capability、strict stdio、pagination、SSE resume/`Last-Event-ID`/`retry`、list_changed、session recovery、OAuth S256/resource/state/issuer、Bearer/CA/proxy/mTLS、policy/suppression、SARIF/JUnit/JSONL/GitHub、atomic report、signed baseline/approval log、sandbox planning、DNS rebinding 与 partial-source isolation 全部保持通过。

## 测试不能证明的事项

- 本地未执行真实 Docker daemon、Bubblewrap namespace 或 Windows Job Object；Windows 真实用例交给远端矩阵。
- DNS 测试确定性模拟 resolution 漂移，但标准库 resolver 与 socket connect 之间仍有 TOCTOU；未声称网络层完全 pin。
- 没有声称覆盖 container escape、kernel vulnerability、KMS/HSM、跨主机 writer、WORM/SIEM、私钥泄露或恶意管理员重写本地 audit log。
- OAuth fixtures 不是所有企业代理、TLS interception appliance 或外部 IdP 的认证证据。
- 合成准确率 corpus 很小，只证明这 21 个明确标签；143 tests 和 75.81% branch coverage 也不等价于形式化验证。
