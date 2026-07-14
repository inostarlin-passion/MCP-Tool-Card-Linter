# 测试报告

测试日期：2026-07-14。版本：1.0.0。

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
| 全部分层测试 | 141 tests；139 passed、2 platform skips、0 failed；41.258 s |
| branch coverage | 5,056 statements、2,002 branches；75.49%，通过 75% gate |
| 规则准确率 | 12 cases、21 explicitly-labelled pairs；TP 8、FP 0、TN 13、FN 0；precision/recall/F1 = 1.0；通过 0.95/0.95 gate |
| 确定性 fuzz | 500 个 bounded JSON round trips、5 个非法 JSON extensions、300 个 mutated tool shapes；全部通过 |
| mutation | 6 个安全输入 mutation operators 均被预期 rule 杀死 |
| soak | 40 次 stdio server start/discover/cleanup；无线程或 descriptor 累积；1.011 test seconds |
| 性能 | 2,000 cards；规则计算 0.4268 s，peak 7.81 MiB；通过 `<10 s`/`<128 MiB` |
| 可复现构建 | 同一 source tree/`SOURCE_DATE_EPOCH` 两次构建，wheel 与 sdist 分别 `cmp` 完全相同 |
| clean install | wheel 与 sdist 均在新 venv 安装成功；version/lint/contract/rules/evaluate smoke 全通过 |
| 静态质量 | Ruff、strict mypy（native/win32/linux）、compileall、pip check、diff check、workflow YAML parse 全通过 |

## 分层测试

| 层级 | 数量 | v1.0 重点范围 | 结果 |
| --- | ---: | --- | --- |
| 单元测试 | 89 | 稳定 contract digest、current/legacy report、accuracy corpus 校验、audit chain/tamper/private mode/concurrent lock；既有 lint/schema/OAuth/executor/trust/security | 87 passed，2 platform skips |
| 集成测试 | 40 | `contract`、`evaluate`、`validate-report`、lint audit→verify；既有 CLI/stdio/HTTP/SSE/OAuth/signed baseline | 40/40 passed |
| 系统测试 | 9 | repeated stdio lifecycle、signed rug pull/publisher drift、default-deny execution、config→report→optimize、OAuth、partial source、performance | 9/9 passed |
| fuzz | 2 | strict JSON grammar 与随机 bounded tool/report serialization | 2/2 passed |
| mutation | 1 | poisoning、secret、Unicode、command、URL allowlist 六类 mutation | 1/1 passed |
| 合计 | 141 | unit + integration + system + fuzz + mutation | 139 passed，2 skipped，0 failed |

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
Ran 141 tests in 41.258s
OK (skipped=2)
TOTAL 5056 statements, 1057 missed, 2002 branches, 509 partial, 75.49%
```

主要模块覆盖率：`rules.py` 94.87%、`models.py` 88.94%、`security.py` 84.18%、`reporting.py` 83.86%、`lint.py` 81.14%、`oauth.py` 79.45%、`evaluation.py` 76.87%、`policy.py` 76.45%、`cli.py` 76.30%、`audit.py` 71.68%、`trust.py` 70.89%、`execution.py` 66.25%、`discovery.py` 66.20%。较低分支主要是 OS 专属 API、TLS/rare I/O failure 和多阶段 cleanup；仓库总门槛已通过。

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
| wheel | 106,312 bytes；SHA-256 `5206c247a8bd4f816e24c772f43fa288672c8907538358c79634ff48430d074e` |
| sdist | 103,293 bytes；SHA-256 `27c768a7720089c1cc8a7a91e8314968fcbadfc6ee1e5e085d71b9e9c965e3f4` |
| clean wheel install | 1.0.0、good fixture lint、`contract` 通过 |
| clean sdist install | rule catalog 与 accuracy 0.95/0.95 gate 通过 |

这些 SHA-256 是当前未提交工作树在 macOS 上的验收构建，用于证明两次本地构建相同；正式发布必须使用 release workflow 生成的新校验和、GitHub attestations 与 PyPI PEP 740 attestations，不能把这里的临时 hash 当作已发布制品身份。

## CI 与发布门

- `test`：Ubuntu/macOS/Windows × Python 3.11/3.12/3.13/3.14，执行 Ruff、mypy、141-test discovery 与 coverage gate。
- `package`：wheel/sdist build、两种制品 clean install 和 CLI smoke。
- `performance`：脱离 coverage 的 2,000-card time/memory gate。
- `production-quality`：accuracy、fuzz、mutation 和 40-cycle soak。
- `reproducible-build`：固定 commit timestamp 作为 `SOURCE_DATE_EPOCH`，双构建后 `cmp`。
- `mcp-conformance`：锁定依赖的官方 runner 执行 2025-11-25 initialize 与 SSE retry 场景。
- tag release：版本/tag 一致性、reproducible build、CycloneDX SBOM、SHA-256、GitHub provenance/SBOM attestations、PyPI Trusted Publishing/PEP 740、GitHub Release。

本地只能验证工作流语法和对应命令；GitHub 托管 runner、OIDC、PyPI environment、attestation 与 immutable-release repository setting 必须在推送/tag 后由远端执行，不能在本报告中声称已运行。

## 回归范围

既有 MCP 2025-11-25/2025-06-18/2025-03-26 negotiation、tools capability、strict stdio、pagination、SSE resume/`Last-Event-ID`/`retry`、list_changed、session recovery、OAuth S256/resource/state/issuer、Bearer/CA/proxy/mTLS、policy/suppression、SARIF/JUnit/JSONL/GitHub、atomic report、signed baseline/approval log、sandbox planning、DNS rebinding 与 partial-source isolation 全部保持通过。

## 测试不能证明的事项

- 本地未执行真实 Docker daemon、Bubblewrap namespace 或 Windows Job Object；Windows 真实用例交给远端矩阵。
- DNS 测试确定性模拟 resolution 漂移，但标准库 resolver 与 socket connect 之间仍有 TOCTOU；未声称网络层完全 pin。
- 没有声称覆盖 container escape、kernel vulnerability、KMS/HSM、跨主机 writer、WORM/SIEM、私钥泄露或恶意管理员重写本地 audit log。
- OAuth fixtures 不是所有企业代理、TLS interception appliance 或外部 IdP 的认证证据。
- 合成准确率 corpus 很小，只证明这 21 个明确标签；141 tests 和 75.49% branch coverage 也不等价于形式化验证。
