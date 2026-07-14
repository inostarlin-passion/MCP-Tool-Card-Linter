# 测试报告

测试日期：2026-07-14。版本：0.5.0。

## 环境

- 工作目录：`/Users/inostarlin/code/MCP-Tool-Card-Linter`
- 平台：macOS 15.7.7 arm64
- Python：3.14.6
- 测试框架：标准库 `unittest`；`coverage.py` branch coverage
- 运行时依赖：`cryptography>=45,<50`、`jsonschema>=4.23,<5`、`rfc8785>=0.1.4,<1`
- 测试网络：HTTP/OAuth/stdio 使用本地 adversarial fixtures；研究检索与依赖安装使用公网

## 分层测试结果

| 层级 | 数量 | v0.5 重点覆盖 | 结果 |
| --- | ---: | --- | --- |
| 单元测试 | 83 | executor policy/argv、Docker/Bubblewrap 参数、Windows platform gate、DNS pin/rebinding/metadata、RFC 8785、Ed25519 tamper、identity binding、field diff、approval chain；以及原有 lint/schema/OAuth/report/security | 81 passed，2 platform skips |
| 集成测试 | 36 | baseline keygen→approve→verify→signed lint；require-signed migration gate；原有 CLI/stdio/HTTP/SSE/OAuth 集成 | 36/36 passed |
| 系统测试 | 8 | signed rug-pull field diff、publisher drift blocking、default-deny local execution；原有 config→report→optimize、OAuth、partial source、performance | 8/8 passed |
| 合计 | 127 | unit + integration + system | 125 passed，2 skipped，0 failed |

两个本机 skip 均为平台条件：Windows native command parser 和 Windows Job Object 真实运行；它们会在现有 `windows-latest` CI matrix 上执行。macOS 本地不伪造成功。

主测试命令与实测：

```bash
.venv/bin/coverage erase
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  .venv/bin/coverage run -m unittest discover -s tests -v
.venv/bin/coverage combine
.venv/bin/coverage report --fail-under=75
```

```text
Ran 127 tests in 32.987s
OK (skipped=2)
TOTAL 4606 statements, 982 missed, 1848 branches, 468 partial, 75.05%
```

主要模块覆盖率：`rules.py` 96.43%、`models.py` 87.02%、`reporting.py` 84.26%、`security.py` 83.54%、`oauth.py` 79.45%、`lint.py` 78.86%、`cli.py` 76.54%、`trust.py` 70.89%、`execution.py` 66.25%、`discovery.py` 66.20%。较低分支主要是 OS 专属 API、TLS/rare I/O failure 和多阶段 cleanup；总门槛 75% 已通过。

## v0.5 专项结果

| 场景 | 预期 | 结果 |
| --- | --- | --- |
| CLI stdio 未指定 executor | command 不启动，exit 2 | 通过 |
| Docker plan | no network/read-only/drop caps/no-new-privileges/pids/memory/swap/cpus/tmpfs；secret value 不进入 argv | 通过 |
| Docker config 隐式 host cwd | fail closed，不隐式 mount host | 通过 |
| Bubblewrap plan | `--unshare-all`、无 `--share-net`、read-only bind、tmpfs、die-with-parent | 通过 |
| Windows Job Object | 非 Windows 明确拒绝；真实 child/run/release 用例条件化 | 本机 skip，等待 Windows CI |
| DNS public set 变化 | 下一次 open 前拒绝为 possible rebinding | 通过 |
| DNS 转到 `169.254.169.254` | private/link-local policy 在 socket open 前拒绝 | 通过 |
| DNS pin map 超限 | 第 129（测试中缩至第 2）endpoint fail closed | 通过 |
| RFC 8785 key order | 语义相同 object canonical bytes 相同 | 通过 |
| Signed baseline | external public key、key ID、Ed25519、report digest、publisher/server/source 均验证 | 通过 |
| JSON/signature tamper | 不回退 legacy compare，exit 2 | 通过 |
| Unknown signed field | exact schema fail closed | 通过 |
| Publisher/source identity drift | distinct critical status，block until review | 通过 |
| Field value change | `baseline_status=changed`，diff 仅含 `/description` 等 path，不含 raw value | 通过 |
| Unsigned unchanged baseline | `baseline_untrusted`；`--require-signed-baseline` 可直接拒绝 | 通过 |
| Approval append | 0600、sequence、previous hash、signature、full-chain verify | 通过 |
| Approval record tamper | signature/hash-chain verify 失败 | 通过 |
| Baseline/report schemas | Draft 2020-12 validators 接受生成的 1.0.0 bundle / 1.1.0 report | 通过 |

## 静态、类型、性能与构建

| 检查 | 实际结果 |
| --- | --- |
| `ruff check src tests` | 通过 |
| `mypy src`（strict） | 通过，14 source files |
| `mypy --platform win32 src` | 通过，14 source files |
| `mypy --platform linux src` | 通过，14 source files |
| `python -m compileall -q src tests` | 通过 |
| `git diff --check` | 通过 |
| `python -m pip check` | `No broken requirements found` |
| uninstrumented performance | 2,000 cards，0.3910 s；peak 7.81 MiB；通过 `<10 s`/`<128 MiB` |
| wheel/sdist | 0.5.0 均成功构建；约 93 KiB / 91 KiB |
| clean wheel install | 0.5.0、good fixture lint、依赖安装通过 |
| clean sdist install | baseline help、rule catalog smoke 通过 |
| packaged assets | report schema、baseline schema、`py.typed` 均进入 wheel/sdist |

## 回归范围

既有 MCP 2025-11-25/2025-06-18/2025-03-26 negotiation、tools capability、strict stdio、pagination、SSE resume/`Last-Event-ID`/`retry`、list_changed、session recovery、OAuth S256/resource/state/issuer、Bearer/CA/proxy/mTLS、policy/suppression、SARIF/JUnit/JSONL/GitHub、atomic report、rug-pull legacy compare 和 partial-source isolation 全部保持通过。

## 测试不能证明的事项

- 本地未执行真实 Docker daemon/Bubblewrap namespace 或 Windows Job Object；Docker/Bubblewrap command policy 以可验证 argv 单元测试覆盖，Windows 真实用例交由远端平台矩阵。
- DNS policy 测试确定地模拟 resolution 变化，但标准库 resolver 与 socket connect 间仍可能发生 TOCTOU；没有声称网络层完全 pin。
- 没有测试 container escape、kernel sandbox vulnerability、KMS/HSM、Sigstore/Rekor、跨主机并发 writer、WORM 存储或 private key compromise。
- 没有做 fuzzing、mutation、长时间 soak、真实企业 proxy/TLS interception 或外部 IdP 浏览器流程。
- 127 tests、75.05% branch coverage 和本地 clean install 是回归证据，不等价于形式化验证；远端 3 OS × Python 3.11..3.14 必须在推送后复验。
