# 研究依据与可核验推理

检索与复核日期：2026-07-10。

## 检索方法

本轮采用多查询、多跳检索，不以单篇文章作为结论依据：

1. 从 MCP 2025-11-25 规范的 schema、tools、transports 页面确认协议字段、JSON-RPC/transport 要求和 annotation 的信任边界。
2. 沿 MCP 官方 Security Best Practices 跳转并复核 SSRF、redirect、DNS rebinding、local server compromise、scope minimization 等攻击与缓解措施。
3. 以 OWASP MCP Security、Tool Poisoning、Input Validation 和 CWE 资源耗尽/循环条目交叉核验 metadata injection、输入验证和硬资源上限。
4. 以 JSON Schema 官方 2020-12 资料和 RFC 8259 核验 schema keyword、`additionalProperties`、重复 JSON key、解析器尺寸/深度限制。
5. 以 Python 官方 `subprocess`、`tempfile` 文档核验进程会话、显式环境映射和安全临时文件行为。
6. 对照 2025/2026 MCP 安全与工具描述论文，以及公开 scanner 的 rug-pull/command-execution实践，区分“规范事实”“工程推断”和“仍不确定事项”。

优先级为：正式规范/RFC/标准库官方文档 > OWASP/CWE > 论文原文 > 开源实现说明。论文为预印本或经验研究时，不把其结论表述为协议保证。

## 可核验事实

1. MCP Tool 的 `inputSchema` 根为 object；`outputSchema` 可选且根同样受 object 限制。`description` 可被客户端用于帮助模型理解工具。`readOnlyHint`、`destructiveHint`、`idempotentHint`、`openWorldHint` 都只是 hint，不能保证真实行为，且不能作为对不可信 server 的唯一决策依据。
   来源：[MCP 2025-11-25 Schema Reference](https://modelcontextprotocol.io/specification/2025-11-25/schema)

2. MCP 标准 transport 是 stdio 和 Streamable HTTP；stdio 消息按换行分隔且 stdout 不应混入非 MCP 文本。Streamable HTTP 要求 POST、同时声明 JSON/SSE Accept；server 侧必须校验 Origin 以防 DNS rebinding，本地 server 应只绑定 loopback 并应认证连接。
   来源：[MCP 2025-11-25 Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

3. MCP 官方安全指南明确列出 SSRF 中的 internal IP、cloud metadata、localhost、DNS rebinding 和 redirect chain；建议生产环境 HTTPS、阻止 private/reserved IP、对 redirect target 施加相同策略或禁用自动跳转，并指出 DNS 校验存在 TOCTOU。该指南也把本地 MCP command 视为任意代码执行面，要求 consent、显示完整命令并建议 sandbox/minimal privileges。
   来源：[MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

4. OWASP 将 tool description、parameter schema 和返回值都视为 tool-poisoning surface，并建议检查/固定 tool definition、严格 schema、最小权限、敏感操作人工确认、输入输出校验、SSRF allowlist 和 secret/PII 日志脱敏。
   来源：[OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)、[OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)

5. OWASP 输入校验指南要求尽早同时做 syntactic 与 semantic validation，优先 allowlist，并为文本定义最小/最大长度；同时提示不安全 regex 可能导致 ReDoS。
   来源：[OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

6. CWE-770 指出不限制资源数量/大小会造成 CPU、内存等 DoS，并建议明确最小/最大期望、throttling、有限线程池和“accept known good”校验。CWE-606/CWE-835说明由不可信输入控制循环条件或不可达退出条件会形成无限循环。
   来源：[CWE-770](https://cwe.mitre.org/data/definitions/770.html)、[CWE-606](https://cwe.mitre.org/data/definitions/606.html)、[CWE-835](https://cwe.mitre.org/data/definitions/835.html)

7. JSON Schema 默认允许未被 `properties`/`patternProperties` 匹配的额外字段；`additionalProperties: false` 才关闭它。字符串、数组、对象和数字分别有 `maxLength`、`maxItems`、`maxProperties`、`maximum` 等约束；`format` 默认只是 annotation，不等于强制 allowlist。
   来源：[JSON Schema Object Reference](https://json-schema.org/understanding-json-schema/reference/object)、[JSON Schema Type-specific Keywords](https://json-schema.org/understanding-json-schema/reference/type)、[JSON Schema 2020-12 Validation](https://json-schema.org/draft/2020-12/json-schema-validation)

8. RFC 8259 说明 JSON object member name 应唯一；重复 name 在不同实现中可能被保留、覆盖或拒绝，行为不可预测。RFC 同时允许解析器限制文本大小、嵌套深度、数字范围和字符串长度。
   来源：[RFC 8259 §4, §9](https://www.rfc-editor.org/rfc/rfc8259.html)

9. Python 官方文档说明 `env` mapping 会替代默认的父环境继承；`start_new_session=True` 在 POSIX 子进程执行前调用 `setsid()`。`tempfile.mkstemp()` 使用排他创建、默认仅创建用户可读写，调用方负责清理。
   来源：[Python subprocess](https://docs.python.org/3/library/subprocess.html)、[Python tempfile](https://docs.python.org/3/library/tempfile.html)

10. 2025 年 MCP metadata 安全论文把 tool poisoning、shadowing、rug pull 分成三类，并提出 descriptor integrity/guardrail 的分层缓解。2026 年 856 个工具的经验研究报告 97.1% description 至少有一种 smell，56% 未清楚说明用途；增强描述有收益，也会增加步骤且部分任务回退。
    来源：[Securing MCP Against Tool Poisoning and Adversarial Attacks](https://arxiv.org/abs/2512.06556)、[MCP Tool Descriptions Are Smelly](https://arxiv.org/abs/2602.14878)

11. 公开 scanner 已采用 hash 监测 rug pull/cross-origin escalation；Snyk Agent Scan 明确警告扫描 config 会执行其中 command，并建议对第三方 config 使用容器、VM 或 disposable environment。这证明“扫描器自身执行不可信配置”是实际工程风险，而不是纯理论场景。
    来源：[Snyk Agent Scan](https://github.com/snyk/agent-scan)、[MCP Armor](https://github.com/aira-security/mcp-checkpoint)

## 从事实到实现的推理链

| 事实/威胁 | 第一性原理 | 本项目措施 |
| --- | --- | --- |
| 模型会看到 description/schema 等 metadata | 能改变模型决策的所有外部文本都属于不可信输入 | 递归扫描 name/title/description/input/output schema/annotation/execution/_meta 的 key 与 string value；限制节点、深度和总字符数 |
| annotation 只是 hint | 声明不能证明行为，冲突本身是风险信号 | 类型校验；检查 read-only/destructive/open-world 冲突；风险仍由 name/description/schema 独立推断 |
| 同名工具共享模型上下文 | 名称冲突降低路由确定性并可形成 shadowing | 同 server duplicate 为 error；跨 server 同名为 `CROSS_SERVER_TOOL_SHADOWING` |
| 首次审批后 metadata 可变化 | 审批对象必须有稳定身份才可检测变化 | 对 canonical complete raw card 做 SHA-256；`--baseline-report` 区分 unchanged/changed/new/missing；changed 默认 block until review |
| Schema 是调用边界 | 只有约束实际参数空间才能降低误用/资源/注入风险 | 检查 root/type/composition/ref/bounds/additionalProperties/array/string/regex；标记 command/URL/path/secret 参数和 external `$ref` |
| 不可信 endpoint 可耗尽或触达内网 | timeout 不能限制已经读入的内存，也不能终止重复 cursor | 文件、HTTP body、stdio line、stderr、队列、page、cursor、tool、schema、server、worker、retry 全部硬上限；重复 cursor 失败关闭 |
| config command 等价于本地代码执行 | “读取配置”不应隐式扩大为“运行配置” | 默认拒绝；要求 `--allow-config-execution`；默认最小环境；`--inherit-env` 单独授权；报告 command 参数脱敏 |
| URL validation 与 fetch 之间可能变化 | 仅解析 scheme 不能阻止 SSRF/redirect/rebinding | HTTPS 默认、private/reserved 检查、config loopback 授权、禁用 redirect、每次 request 前重验；文档明确 DNS TOCTOU 剩余风险 |
| 部分写入会制造假报告 | 报告是 CI/审批输入，完整性优先于便利 | `mkstemp` + flush/fsync + `os.replace`；失败保留旧文件；POSIX 新文件 0600；Markdown/diagnostic 转义和 secret redaction |

## 推断

1. 静态 metadata lint 适合作为“连接前/发布前 gate”，不能成为运行时唯一安全边界。
2. 对可能写、删除、付费、联网、文件访问、代码执行或处理 secret 的工具，低误报不是最高目标；默认要求审批更符合最小权限原则。
3. fingerprint 只回答“是否变化”，不回答“谁发布”或“首次版本是否可信”。签名、可信分发和 baseline 访问控制属于更高一层。
4. 对 config command 采用显式授权会带来一次额外 CLI flag，但它避免把看似只读的扫描动作变成静默 RCE，安全收益明显高于兼容成本。
5. description 质量和长度存在可靠性/成本权衡，因此本项目报告缺失边界与过长文本，而不自动扩写或声称越长越好。

## 不确定与剩余边界

1. 规则是可解释的启发式，可能有 false positive/false negative；尤其无法静态证明 server implementation 与 card 一致。
2. 标准库 DNS 解析无法无竞态地 pin 到后续 socket；高保证部署仍需 egress proxy/network policy。项目已禁 redirect、重复校验和默认阻止 private/reserved 地址，但不宣称消除 DNS rebinding。
3. Streamable HTTP 当前覆盖 initialize、notification、分页 tools/list、JSON/SSE、session DELETE；不实现 OAuth、GET SSE multiplex、experimental tasks 或全部 draft 行为。
4. POSIX 使用独立 session 尽力终止进程组；Windows 能关闭直接子进程和 pipe，但没有实现 Job Object，因此不能保证清理任意脱离/再派生的后代。
5. SHA-256 baseline 未签名。若 baseline 和当前报告能被同一攻击者修改，change detection 失效。
6. 本项目只扫描 tool card，不扫描 MCP prompts/resources、server source code、依赖漏洞、runtime tool output 或多步 toxic flow；应与 sandbox、SAST/SCA、runtime policy、audit 和人工复核组合。
