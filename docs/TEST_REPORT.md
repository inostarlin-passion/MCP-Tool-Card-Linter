# 测试报告

测试日期：2026-07-13。版本：0.4.0。

## 环境

- 工作目录：`/Users/inostarlin/code/MCP-Tool-Card-Linter`
- 平台：macOS 15.7.7 arm64
- Python：3.14.6
- 测试框架：标准库 `unittest`；`coverage.py` branch coverage
- 运行时依赖：`jsonschema>=4.23,<5`
- 公网依赖：测试本身不访问公网；HTTP/stdio 使用本地 adversarial fixtures。仅依赖安装、资料检索和 SBOM 工具验证使用了网络。

## 分层测试结果

| 层级 | 数量 | 覆盖范围 | 结果 |
| --- | ---: | --- | --- |
| 单元测试 | 61 | lint/schema/icon/security rules、policy/suppression、OAuth discovery/URI/scope/state/file/lock boundaries、credential provider、strict JSON/URL/config/env、report contracts、baseline、redaction、并发锁 | 61/61 通过 |
| 集成测试 | 34 | CLI/report；stdio strict/pagination/list_changed/server-ping/cleanup；HTTP JSON/SSE resume/Last-Event-ID/listener/list_changed/ping/session recovery/retry/version/capability；OAuth metadata/PKCE/resource/callback/token | 34/34 通过 |
| 系统测试 | 5 | config→discovery→lint→report→optimize；rug-pull baseline；partial source isolation；2,000 cards budget；两进程 OAuth CLI workflow | 5/5 通过 |
| 合计 | 100 | unit + integration + system | 100/100 通过 |

主测试命令与结果：

```bash
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  .venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage combine
.venv/bin/python -m coverage report --fail-under=75
```

```text
Ran 100 tests in 22.366s
OK
TOTAL  3681 statements  770 missed  1544 branches  383 partial  75%
```

`coverage.py` 开启 branch coverage、parallel data 和 subprocess patch；`coverage report --fail-under=75` 退出码为 0。重点模块：`rules.py` 96%、`models.py` 86%、`reporting.py` 84%、`oauth.py` 79%、`auth.py`/`lint.py` 78%、`cli.py`/`security.py` 77%、`policy.py` 76%、`discovery.py` 66%。较低覆盖集中在 transport/OAuth 的平台、TLS 与罕见 I/O 异常分支，已列入后续测试重点。

## 静态、类型、构建与发布链路验证

| 检查 | 实际结果 |
| --- | --- |
| `ruff check src tests` | 通过 |
| `mypy src`（strict） | 通过，12 个 source files 无问题 |
| `mypy --platform win32 src` / `--platform linux` | 两个平台视图均通过，复现并关闭 Windows `os.killpg` 类型回归 |
| `python -m compileall -q src tests` | 通过 |
| `git diff --check` | 通过 |
| `python -m build` | wheel 与 sdist 均成功：0.4.0 |
| clean wheel install + CLI smoke | 通过；`--version` 输出 0.4.0，good fixture lint 与 `authorize --help` 成功 |
| clean sdist install + rule catalog smoke | 通过 |
| GitHub CI/release/dependabot YAML | 三个文件均可解析 |
| `cyclonedx-py 7.3.0 environment` | 通过；从独立 product venv 生成有效 CycloneDX 1.6 SBOM（6 components） |
| MCP official conformance 0.1.15 | 通过；client `initialize` + `sse-retry` 场景 2/2、规范检查 4/4、0 failures/warnings，npm lock integrity 固定 |

说明：已读取远端 GitHub Actions run `29263797177` 的 check/job 原始日志并在本地复现根因；本表的“通过”是对修复后本地代码的验证。修复尚未推送，不宣称新的 3 OS × Python 3.11..3.14 远端矩阵已通过。OIDC Trusted Publishing 和 attestation 也必须在配置好 environment 的 GitHub 仓库中实际运行后才能最终确认。

## GitHub Actions 失败根因与回归

| 远端失败 | 日志证据 | 修复 | 修复后本地证据 |
| --- | --- | --- | --- |
| Windows 3.11..3.14 `mypy src` | `discovery.py:2011: Module has no attribute killpg` | 以 `sys.platform` 在模块加载时选择 POSIX/Windows process-group helper | strict mypy 的本机、`win32`、`linux` 视图全通过 |
| Linux/macOS oversized stdio | 期望 `exceeds`，实际 3 s timeout | `Popen` stdout/stderr 从 raw `bufsize=0` 改为 buffered；4 MiB line 和 8-message queue 上限不变 | 同一集成用例在 coverage 下 0.077 s 通过；全套通过 |
| Python 3.12 performance | coverage + `tracemalloc` 下分别 26.84 s/19.16 s | coverage 仅验证 2,000-card 功能；独立 job 无 coverage 计时，再单独开 `tracemalloc` 测内存 | 无插桩时间 0.3068 s；单独内存峰值 1.75 MiB |

## 关键负向用例

| 攻击/故障输入 | 预期行为 | 实际结果 |
| --- | --- | --- |
| duplicate JSON member、NaN、超长整数、invalid UTF-8 | 进入业务逻辑前拒绝，受控错误 | 通过 |
| 非法 Draft 2020-12 schema keyword/type | 完整元模式 error，bounded walker 继续给出工程建议 | 通过 |
| 过大/过深 schema、HTTP、stdio、credential、policy | 在硬上限拒绝，不无界分配/遍历 | 通过 |
| tool description/schema 中 injection、hidden Unicode、credential | 稳定 rule；报告证据脱敏 | 通过 |
| 两个 server 同名 tool；approved card 后 metadata 改变 | shadowing/change 可检索，changed 默认 block | 通过 |
| config command 未授权或自行请求 inheritEnv | 不执行/不自授权，source error 返回 2 | 通过 |
| Bearer 文件权限过宽或 token 含 CR/LF | 认证前拒绝，避免 header injection | 通过 |
| Bearer 正常使用 | header 认证成功；token 不出现在 URL/report metadata | 通过 |
| HTTP redirect/private target/错 Content-Type/超大 body | fail closed；不把 payload 当工具结果 | 通过 |
| 服务器协商受支持的上一协议版本 | 接受并在后续 HTTP header 使用 negotiated version | 通过 |
| server 未声明 tools capability | `unsupported_feature`，不发送 `tools/list` | 通过 |
| tools/list 重复 cursor | HTTP/stdio 均 fail closed | 通过 |
| 503 暂态失败 | 总 deadline 内有限 retry，第二次成功 | 通过 |
| POST SSE 在空 priming event 后断开 | GET 恢复并携带 `Last-Event-ID`；取得原 request response | 通过 |
| GET listener 收到 server `ping` 与 `tools/list_changed` | 回送同 ID 空 result；exactly-once re-list；metadata 记录 refresh | 通过 |
| 带 session 的 tools/list 返回 404 | 清空旧 session、重新 initialize，最多恢复一次 | 通过 |
| stdio 中 `tools/list_changed` 前有 server `ping` | JSON-RPC 回送、继续读取通知并重拉；stdout 仍严格 | 通过 |
| OAuth challenge/PRM/AS metadata | challenge URL 优先；resource/issuer exact；发现顺序符合规范 | 通过 |
| OAuth AS 不声明 S256 或 callback state/issuer 不符 | state/token 创建或交换前 fail closed；lock 释放 | 通过 |
| OAuth 正常 Authorization Code | authorization/token 都携带 resource；verifier 不进 URL；code 不进 argv；0600 token；输出无 token | 通过 |
| stdio 混入非 JSON stdout | 默认拒绝；显式 compatibility flag 时有界跳过 | 通过 |
| `__enter__` 初始化失败 | 关闭进程、pipe、stdout/stderr thread | 通过 |
| report atomic replace 模拟失败 | 原文件不变，temp 清理 | 通过 |
| expired suppression | 不隐藏 finding，expired audit 进入报告 | 通过 |
| deterministic report 连续生成 | JSON 字节完全相同；scan ID 为 content SHA-256 URN | 通过 |
| SARIF/JUnit/JSONL/GitHub output | JSON/XML/record contract 可解析；SARIF 超限显式截断 | 通过 |

## 性能系统测试

自动门限为 2,000 张 bounded、名称唯一的 cards，lint `<10 s` 且 tracemalloc peak `<128 MiB`。coverage 套件仍执行同一 2,000-card 功能路径，但性能断言只在 `MCP_LINTER_ENFORCE_PERFORMANCE_BUDGET=1` 的独立无 coverage job 中生效；wall time 与 `tracemalloc` 内存为两次独立 lint，避免双 tracer 污染时间。最终本机实测：

```text
performance_budget tools=2000 elapsed_seconds=0.3068 peak_mib=1.75
```

该结果不含 MCP server/network latency，也不是跨机器 SLA。完整 JSON Schema 元模式校验按 canonical schema 文本使用最多 1,024 项 LRU cache；攻击者控制的不同 schema 仍受 card/tool/schema traversal 上限约束。

## 端到端验收

1. reviewed `mcp.json` 在显式 `--allow-config-execution` 后完成 stdio initialize、分页 `tools/list`、lint、JSON/Markdown report 和 optimizer。
2. approved JSON report 作为 baseline 后修改 description，会产生 `TOOL_CARD_CHANGED`、`baseline.changed=1`、exit 1，optimizer 为 `block_until_review`。
3. 双 server config 中，一个未授权 command 返回 source error，另一个静态安全 server 仍进入报告；总 exit 2。
4. 两个独立 CLI process 完成 `authorize start`/`complete`；callback 仅经环境变量，token 写入私有文件且不出现在 stdout/argv。
5. 0.4.0 JSON report 通过 bundled Draft 2020-12 report schema；新版 bad fixture JSON/Markdown samples 已重新生成。
6. wheel 和 sdist 均在独立全新虚拟环境安装并运行 console entry point。

## 未覆盖/测试不能证明

- OAuth 使用本地 adversarial resource/authorization server，未连接外部身份提供商；未覆盖 DCR、Client ID Metadata Document、真实浏览器、refresh rotation、runtime step-up 或服务端 audience validation。
- 远端 run `29263797177` 已诊断，但修复后 Linux/Windows/macOS CI 尚未推送复验；尤其 Windows descendant cleanup 仍需要 Job Object 级覆盖。
- 未做 fuzzing、mutation testing、长时间 soak、真实 proxy/企业 TLS interception或 DNS rebinding 竞态；SSE/list_changed 为 bounded snapshot workflow，不是长期 daemon subscription。
- 未测试 runtime tool implementation/output、prompts/resources、source/SCA 或多步 toxic flow；本项目边界仍是 tool-card/static discovery gate。
- 100 tests、75% branch coverage 和官方场景 2/2（检查 4/4）是当前证据，不等价于不存在缺陷或达到形式化验证/完整 SDK conformance。
