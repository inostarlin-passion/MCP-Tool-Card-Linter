# 研究依据

检索日期：2026-07-06。

## 事实

1. MCP 是连接 LLM 应用与外部数据源、工具和工作流的开放协议。官方 2025-11-25 specification 将其描述为标准化连接外部上下文的协议。
   来源：https://modelcontextprotocol.io/specification/2025-11-25

2. MCP tools 是可由语言模型调用的能力；tool definition 包含唯一 `name`、`description`、`inputSchema`，并可包含 `outputSchema` 和 `annotations`。
   来源：https://modelcontextprotocol.io/specification/2025-11-25/server/tools

3. MCP 使用 JSON-RPC 编码消息；标准 transport 包括 stdio 和 Streamable HTTP。Streamable HTTP 使用 HTTP POST/GET，并可用 SSE 返回多条 server message。
   来源：https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

4. MCP lifecycle 包括 initialization、operation 和 shutdown；初始化阶段用于协议版本和能力协商。
   来源：https://modelcontextprotocol.io/specification/2025-03-26/basic/lifecycle

5. OpenAI MCP 文档说明，一些 MCP server 可能暴露几十个 tools，暴露过多工具会增加成本和延迟，因此可以用 `allowed_tools` 只导入需要的子集。
   来源：https://developers.openai.com/api/docs/guides/tools-connectors-mcp

6. 论文 “Model Context Protocol (MCP) Tool Descriptions Are Smelly” 报告：在其分析的数据集中，97.1% 的 tool descriptions 至少有一个 smell，56% 没有清楚说明用途；增强描述提升部分成功指标，但也增加执行步骤并在部分场景回退。
   来源：https://arxiv.org/abs/2602.14878

7. 论文 “Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning” 将 tool poisoning 描述为 MCP 客户端侧重要风险，并建议静态元数据分析、决策路径追踪、行为异常检测和用户透明机制。
   来源：https://arxiv.org/abs/2603.22489

8. Cisco `mcp-scanner` 和 Snyk Agent Scan / MCP-Scan 已经覆盖 MCP tools、prompts、resources 或 agent 组件的安全扫描，说明 MCP supply-chain/security scanning 是实际存在的工程方向。
   来源：https://github.com/cisco-ai-defense/mcp-scanner
   来源：https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/

## 推断

1. 如果模型主要通过 tool name、description 和 JSON Schema 判断“该不该调用、如何填参数”，那么这些元数据就是 agent 调用外部能力的关键接口。提前 lint 它们可以降低误调用、参数错误和审查遗漏。

2. 个人开源项目不宜和大型安全 scanner 正面竞争；更清晰的定位是 “ESLint + OpenAPI linter + MCP tool metadata review”：聚焦工具卡质量、schema 完整性、描述可用性、CI 报告和最小暴露工具建议。

3. `readOnlyHint`、`destructiveHint` 等 annotations 对 tool filtering 和 approval 策略有实际价值，但不能被盲目信任；当 name/description 与 annotation 冲突时应报错。

4. tool poisoning 文本不只可能出现在 description，也可能藏在 schema 字段名、参数描述、server instructions 或资源描述里。本版本优先检查 tool description 和 schema 质量，后续可扩展到所有 model-visible metadata。

## 不确定内容

1. “Tool Card” 不是 MCP 官方术语；本项目把 tool metadata、风险和建议组合成可审查卡片，是工程包装。

2. MCP 规范仍在演进，draft specification 已经出现 session header 等变更。本项目实现的是对当前常见 2025 系列 stdio / Streamable HTTP 行为的兼容，不承诺覆盖所有 draft 变化。

3. 静态规则不能证明运行时代码行为。例如 tool 描述说 read-only，但 server 实现仍可能写数据库；这需要沙箱、policy proxy、runtime audit 或源代码扫描配合。

4. 当前风险判断是启发式，不是形式化安全证明。它适合 CI gate 和人工 review 前置，不适合作为唯一安全边界。

