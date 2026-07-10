# 测试报告

测试日期：2026-07-10。版本：0.2.0。

## 环境

- 工作目录：`/Users/inostarlin/code/MCP-Tool-Card-Linter`
- 平台：macOS 15.7.7 arm64
- Python：3.14.6
- 测试框架：标准库 `unittest`
- 运行时第三方依赖：无
- 公网依赖：测试不访问公网；HTTP/stdio 使用本地 adversarial fixture

## 测试策略与结果

| 层级 | 数量 | 主要文件 | 覆盖范围 | 结果 |
| --- | ---: | --- | --- | --- |
| 单元测试 | 35 | `test_lint_rules.py`、`test_lint_security.py`、`test_discovery_static.py`、`test_discovery_security.py`、`test_security_primitives.py`、`test_reporting_security.py` | 全 metadata injection、secret redaction、shadowing、fingerprint/baseline、dangerous schema、bounds/ReDoS、strict JSON、URL/config/env/timeout、truncation accounting、request serialization、atomic report、Markdown escaping、optimizer validation | 35/35 通过 |
| 集成测试 | 20 | `test_cli_file.py`、`test_stdio_client.py`、`test_stdio_security.py`、`test_http_client.py`、`test_http_security.py` | CLI exit/report；stdio initialize/noise/strict JSON/pagination/oversize/env/cleanup；HTTP JSON/SSE/session/DELETE/redirect/oversize/repeated cursor/503 retry/content-type/protocol | 20/20 通过 |
| 系统测试 | 4 | `test_end_to_end_config.py`、`test_security_workflows.py`、`test_performance_budget.py` | config→discovery→lint→report→optimize；rug-pull baseline；partial source failure；2,000 cards performance budget | 4/4 通过 |
| 合计 | 59 | `tests/` | unit + integration + system | 59/59 通过 |

## 实际执行命令

```bash
PYTHONWARNINGS=error::ResourceWarning \
PYTHONPATH=src \
python3 -m unittest discover -s tests -v
```

结果：

```text
Ran 59 tests in 7.600s

OK
```

`ResourceWarning` 被提升为 error；结果仍通过，因此本次覆盖路径未观察到未关闭的 pipe、HTTP response、HTTPError、临时文件等资源告警。

```bash
python3 -m compileall -q src tests
git diff --check
```

结果：两条命令退出码均为 `0`。

## 安全负向用例

| 攻击/故障输入 | 预期行为 | 实际结果 |
| --- | --- | --- |
| duplicate JSON member、NaN、5,000 位整数、invalid UTF-8 | 进入业务逻辑前拒绝，受控错误 | 通过 |
| schema description 中的 ignore-system 指令 | 顶层 description 正常仍应发现 | `TOOL_POISONING_IGNORE_INSTRUCTIONS` |
| hidden Unicode、credential-like literal、encoded blob | 告警；报告不复写 credential | 通过 |
| 两个 server 暴露相同 tool name | 报 shadowing，不静默合并 | `CROSS_SERVER_TOOL_SHADOWING` |
| approved fingerprint 后 description 改变 | exit 1；baseline changed；optimizer block | 端到端通过 |
| external `$ref`、raw command/URL/path/secret、open extra fields | 分别给出可检索 rule code | 通过 |
| nested regex quantifier、inverted/ineffective bounds | ReDoS/bound 告警或错误 | 通过 |
| config 中本地 command 未授权 | 不执行，source error，exit 2 | marker 文件未生成 |
| config 自行请求 inheritEnv | 不能自授权，要求 CLI flag | 通过 |
| config 间接指向 loopback | 默认阻止，要求 private-network 授权 | 通过 |
| HTTP redirect 到 metadata 地址 | 不跟随 redirect | 通过 |
| HTTP Content-Length 超预算 | 读 body 前拒绝 | 通过 |
| stdio 单消息超 4 MiB | 拒绝并清理 server | 通过 |
| tools/list 重复 cursor | 在第二次重复时 fail-closed | HTTP/stdio 均通过 |
| tools/list 首次 503 | 同一 deadline 内有限 retry | 第二次成功，共 2 次 |
| HTTP 错 Content-Type/协议版本 | 拒绝，不把 payload 当可信结果 | 通过 |
| `__enter__` 初始化失败 | 关闭进程、pipe、stdout/stderr thread | 通过 |
| report atomic replace 模拟失败 | 原文件保持原内容，temp 清理 | 通过 |
| tool name 含 HTML/table/backtick/newline | Markdown 不形成活动 HTML/破坏表格 | 通过 |

## 性能测试

自动门限：2,000 张结构一致、名称唯一的 bounded cards；lint 阶段 `<10s` 且 tracemalloc peak `<128 MiB`。

本机单次额外实测（从构造 raw card 到 lint 完成，tracemalloc 从构造前启动）：

```text
tools=2000 build_and_lint_seconds=0.9226 peak_mib=5.26
```

解释：该结果用于回归量级，不是跨机器 SLA，也没有包含 MCP server/network latency。规则遍历和 fingerprint 对 card 总大小近似线性，但实际耗时仍受 schema 深度、字符串内容和 Python 版本影响。

## 端到端验收

1. reviewed `mcp.json` 在显式 `--allow-config-execution` 后完成 stdio initialize、分页 tools/list、lint JSON report、optimizer 输出。
2. approved JSON report 作为 `--baseline-report`，修改 description 后产生 `TOOL_CARD_CHANGED`、`baseline.changed=1`、exit `1`，optimizer 决策为 `block_until_review`。
3. 双 server config 中，一个未授权 command 返回 source error，另一个静态安全 server 仍完成 lint；总 exit `2`，报告保留两者结果。
4. `examples/good-tools.json` 在 `--fail-on error --format none` 下退出 `0`；`examples/bad-tools.json` 能生成新版 JSON/Markdown sample report。

## 未覆盖与不能由测试证明的事项

- 未连接真实认证远程 MCP server；因此未覆盖 OAuth/PKCE、proxy、企业 TLS interception、GET SSE multiplex、tasks。
- 未在 Windows/Linux CI 实机运行；跨平台 stdout queue 已不依赖 pipe `select`，但 Windows descendant cleanup 仍需 Job Object 级测试。
- 未做 fuzzing、mutation testing、coverage 百分比或长时间 soak test；“59 tests passed”不能等价为全路径覆盖。
- 未测试恶意 DNS 在 validation 与 connect 之间 rebinding；该风险需要网络层 egress policy 才能高保证缓解。
- 未测试 runtime tool implementation/output、prompts/resources、source/SCA 或多步 toxic flow；本项目范围仍是 tool-card/static discovery gate。
