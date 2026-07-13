# 测试报告

测试日期：2026-07-13。版本：0.3.0。

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
| 单元测试 | 50 | lint/schema/icon/security rules、finding/SARIF bounds、policy/suppression、credential provider、strict JSON/URL/config/env、report schema/format/atomic write、baseline、redaction、并发锁 | 50/50 通过 |
| 集成测试 | 26 | CLI/exit/report；stdio initialize/strictness/pagination/oversize/env/cleanup；HTTP JSON/SSE/session/redirect/content-type/retry/version/capability/auth | 26/26 通过 |
| 系统测试 | 4 | config→discovery→lint→report→optimize；rug-pull baseline；partial source isolation；2,000 cards budget | 4/4 通过 |
| 合计 | 80 | unit + integration + system | 80/80 通过 |

主测试命令与结果：

```bash
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  .venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage combine
.venv/bin/python -m coverage report --fail-under=75
```

```text
Ran 80 tests in 20.169s
OK
TOTAL  2757 statements  561 missed  1198 branches  304 partial  76%
```

`coverage.py` 开启 branch coverage、parallel data 和 subprocess patch；`coverage report --fail-under=75` 退出码为 0。重点模块：`rules.py` 96%、`models.py` 86%、`reporting.py` 84%、`lint.py` 77%、`policy.py` 76%、`security.py` 73%、`discovery.py` 68%。较低覆盖集中在 transport 的平台/网络异常分支，已列入后续测试重点。

## 静态、类型、构建与发布链路验证

| 检查 | 实际结果 |
| --- | --- |
| `ruff check src tests` | 通过 |
| `mypy src`（strict） | 通过，11 个 source files 无问题 |
| `python -m compileall -q src tests` | 通过 |
| `git diff --check` | 通过 |
| `python -m build` | wheel 与 sdist 均成功：0.3.0 |
| clean wheel install + CLI smoke | 通过；`--version` 输出 0.3.0，good fixture lint 成功 |
| clean sdist install + rule catalog smoke | 通过 |
| GitHub CI/release/dependabot YAML | 三个文件均可解析 |
| `cyclonedx-py 7.3.0 environment` | 通过；从独立 product venv 生成有效 CycloneDX 1.6 SBOM（6 components） |

说明：本地验证了 workflow 语法与其中关键命令，但没有伪造“远端 GitHub Actions 已运行”。3 OS × Python 3.11..3.14 矩阵、OIDC Trusted Publishing 和 attestation 必须在配置好 environment 的 GitHub 仓库中实际运行后才能最终确认。

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
| stdio 混入非 JSON stdout | 默认拒绝；显式 compatibility flag 时有界跳过 | 通过 |
| `__enter__` 初始化失败 | 关闭进程、pipe、stdout/stderr thread | 通过 |
| report atomic replace 模拟失败 | 原文件不变，temp 清理 | 通过 |
| expired suppression | 不隐藏 finding，expired audit 进入报告 | 通过 |
| deterministic report 连续生成 | JSON 字节完全相同；scan ID 为 content SHA-256 URN | 通过 |
| SARIF/JUnit/JSONL/GitHub output | JSON/XML/record contract 可解析；SARIF 超限显式截断 | 通过 |

## 性能系统测试

自动门限为 2,000 张 bounded、名称唯一的 cards，lint `<10 s` 且 tracemalloc peak `<128 MiB`。最终本机独立实测：

```text
tools=2000 lint_seconds=1.4029 peak_mib=5.98
```

该结果不含 MCP server/network latency，也不是跨机器 SLA。完整 JSON Schema 元模式校验按 canonical schema 文本使用最多 1,024 项 LRU cache；攻击者控制的不同 schema 仍受 card/tool/schema traversal 上限约束。

## 端到端验收

1. reviewed `mcp.json` 在显式 `--allow-config-execution` 后完成 stdio initialize、分页 `tools/list`、lint、JSON/Markdown report 和 optimizer。
2. approved JSON report 作为 baseline 后修改 description，会产生 `TOOL_CARD_CHANGED`、`baseline.changed=1`、exit 1，optimizer 为 `block_until_review`。
3. 双 server config 中，一个未授权 command 返回 source error，另一个静态安全 server 仍进入报告；总 exit 2。
4. 0.3.0 JSON report 通过 bundled Draft 2020-12 report schema；新版 bad fixture JSON/Markdown samples 已重新生成。
5. wheel 和 sdist 均在独立全新虚拟环境安装并运行 console entry point。

## 未覆盖/测试不能证明

- 未连接真实 OAuth MCP server；没有覆盖 Protected Resource Metadata、Authorization Server Metadata、Authorization Code + PKCE、Resource Indicators 和动态 token refresh。
- 远端 Linux/Windows/macOS CI 尚未在本次本地会话执行；尤其 Windows descendant cleanup 需要 Job Object 级覆盖。
- 未做 fuzzing、mutation testing、长时间 soak、真实 proxy/企业 TLS interception、DNS rebinding 竞态、GET SSE resumption 或 `list_changed` subscription。
- 未测试 runtime tool implementation/output、prompts/resources、source/SCA 或多步 toxic flow；本项目边界仍是 tool-card/static discovery gate。
- 80 tests 和 76% branch coverage 是当前证据，不等价于不存在缺陷或达到形式化验证。
