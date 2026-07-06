# 测试报告

测试日期：2026-07-06。

环境：

- 工作目录：`/Users/inostarlin/code/MCP-Tool-Card-Linter`
- Python：`Python 3.14.6`
- 测试框架：标准库 `unittest`
- 运行时依赖：无第三方依赖

## 测试范围

| 层级 | 文件 | 覆盖点 |
| --- | --- | --- |
| 单元测试 | `tests/unit/test_lint_rules.py` | tool poisoning、泛化命名、参数描述缺失、unknown required field、高质量只读工具评分。 |
| 单元测试 | `tests/unit/test_discovery_static.py` | 静态 JSON tools/result.tools 提取、非法 payload 拒绝、文件加载映射。 |
| 集成测试 | `tests/integration/test_cli_file.py` | CLI 文件输入、JSON/Markdown 报告写入、`--fail-on error` 退出码。 |
| 集成测试 | `tests/integration/test_stdio_client.py` | stdio MCP initialize、initialized notification、分页 `tools/list`、进程清理。 |
| 集成测试 | `tests/integration/test_http_client.py` | Streamable HTTP initialize、session header、initialized notification、SSE `tools/list`、DELETE 关闭。 |
| 系统测试 | `tests/system/test_end_to_end_config.py` | 临时 `mcp.json` -> stdio discovery -> lint JSON report -> optimize 输出完整闭环。 |

## 已执行命令

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

结果：

```text
Ran 12 tests in 0.926s

OK
```

```bash
PYTHONPATH=src python3 -m mcp_tool_card_linter lint \
  --tools-file examples/bad-tools.json \
  --json-report docs/sample-bad-report.json \
  --markdown-report docs/sample-bad-report.md \
  --fail-on never \
  --format none
```

结果：退出码 `0`，生成 `docs/sample-bad-report.json` 和 `docs/sample-bad-report.md`。

```bash
PYTHONPATH=src python3 -m mcp_tool_card_linter lint \
  --tools-file examples/good-tools.json \
  --fail-on error \
  --format none
```

结果：退出码 `0`。

```bash
python3 -m compileall -q src tests
```

结果：退出码 `0`。

## 结论

当前版本通过单元、集成、系统测试和 Python 编译检查。核心路径已经覆盖静态文件、stdio MCP mock、Streamable HTTP/SSE mock、config discovery、报告输出、CI 退出码和 optimizer。

## 未覆盖项

- 未接入真实远程 Streamable HTTP MCP server 做外部联调，避免测试依赖公网服务和认证状态；当前使用本地 HTTP/SSE mock 覆盖协议路径。
- 未做性能基准压测；仅通过 schema/tool 数量上限控制最坏输入。
- 未做跨平台 Windows stdio 验证；当前 `select` 方案适合 macOS/Linux pipe。
