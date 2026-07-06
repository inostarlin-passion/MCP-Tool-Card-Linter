# 质量自检表

| 质量方面 | 实现措施 | 验证方式 | 状态 |
| --- | --- | --- | --- |
| 输入校验 | CLI 使用互斥输入源；JSON 文件检查存在性、文件类型、10MB 大小上限、JSON 解析；config 校验 `mcpServers`、`command/args/env/cwd/url/tools` 类型；timeout/max-tools/concurrency 必须为正数。 | `tests/unit/test_discovery_static.py`、CLI 集成测试。 | 通过 |
| 边界检查 | `max_tools` 限制每个源 lint 数量；schema traversal 有最大深度和最大节点数；description/card size 有阈值；required/enum/array/items/properties 做结构检查。 | `tests/unit/test_lint_rules.py`，`compileall`。 | 通过 |
| 异常处理 | discovery 错误统一为 `DiscoveryError`；CLI 区分 lint finding exit code 1 和运行错误 exit code 2；HTTP/stdio JSON-RPC error 显式抛出；config 多 server discovery 单 server 失败不会阻断其他 server。 | CLI 文件测试、系统测试、人工审查。 | 通过 |
| 资源生命周期管理 | stdio MCP server 使用 context manager；初始化后发送 initialized notification；关闭 stdin，等待退出，超时后 terminate/kill，并关闭 stdout/stderr；HTTP client 关闭 session 时尝试 DELETE。 | `tests/integration/test_stdio_client.py`，无 ResourceWarning。 | 通过 |
| 并发控制 | config discovery 使用 `ThreadPoolExecutor`，worker 数限制在 `1..32` 且不超过 server 数；每个 stdio client 内部写入有 lock；无无界线程/进程创建。 | `tests/system/test_end_to_end_config.py`、代码审查。 | 通过 |
| 性能 | 无运行时第三方依赖；静态 lint 为线性遍历；schema 遍历有节点和深度上限；支持 `--format none` 避免 CI 输出大报告；工具卡过长会报告上下文成本风险。 | `python3 -m compileall -q src tests`、CLI 示例命令。 | 通过 |
| 韧性 | stdio 读取跳过非 JSON 日志行；stderr tail 保留用于超时诊断；HTTP 支持 JSON 和 SSE `data:` 响应解析；source errors 进入报告 summary；静态规则区分事实、推断、不确定性。 | stdio mock 分页测试、HTTP/SSE mock 测试、报告检查。 | 通过 |
| 可测试性 | 规则引擎是纯函数入口 `lint_sources`；transport client 和 reporting 独立；fixtures 覆盖 bad/good tools、stdio MCP mock 和 HTTP/SSE MCP mock；测试只用标准库 unittest。 | 12 个测试全部通过。 | 通过 |
| 可维护性 | `models.py`、`lint.py`、`discovery.py`、`reporting.py`、`cli.py` 分层；规则 code 稳定可检索；报告 JSON 保留结构化 fields；README 和研究依据记录设计边界。 | 代码结构审查、文档审查。 | 通过 |

## 剩余风险

- 规则是启发式，不能替代运行时权限控制、沙箱、approval UI 或源代码安全扫描。
- Streamable HTTP client 覆盖基本 JSON-RPC/SSE discovery，未覆盖 OAuth、长连接任务、多路 SSE、批处理和所有 draft 变更。
- 当前 optimizer 只输出 allow/approval/block 决策，没有自动重写 tool description 或 schema。
