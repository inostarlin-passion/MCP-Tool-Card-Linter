# 研究依据与可核验推理

检索与复核日期：2026-07-14。

## 检索方法

本轮采用多查询、多跳检索，不以单篇文章作为结论依据：

1. 从 MCP 2025-11-25 规范的 schema、tools、transports 页面确认协议字段、JSON-RPC/transport 要求和 annotation 的信任边界。
2. 沿 MCP 官方 Security Best Practices 跳转并复核 SSRF、redirect、DNS rebinding、local server compromise、scope minimization 等攻击与缓解措施。
3. 以 OWASP MCP Security、Tool Poisoning、Input Validation 和 CWE 资源耗尽/循环条目交叉核验 metadata injection、输入验证和硬资源上限。
4. 以 JSON Schema 官方 2020-12 资料和 RFC 8259 核验 schema keyword、`additionalProperties`、重复 JSON key、解析器尺寸/深度限制。
5. 以 Python 官方 `subprocess`、`tempfile` 文档核验进程会话、显式环境映射和安全临时文件行为。
6. 对照 2025/2026 MCP 安全与工具描述论文，以及公开 scanner 的 rug-pull/command-execution实践，区分“规范事实”“工程推断”和“仍不确定事项”。
7. 针对 v0.3 生产化增量继续做多跳核验：MCP lifecycle→version/capability negotiation→tools capability；transport→stdio purity/SSE→Retry-After RFC；authorization→RFC 9728/8414/8707/PKCE；报告→SARIF 2.1.0→GitHub ingestion limits；发布→PyPI Trusted Publishing→OIDC/attestation；SBOM→CycloneDX Python 工具。
8. 针对 v0.4 一致性增量复核 MCP Streamable HTTP 的空 `data` 预热事件、SSE `id`/`retry`、GET + `Last-Event-ID` 恢复和 `tools/list_changed`；再沿 MCP Authorization 跳转 RFC 9728、RFC 8414/OIDC discovery、RFC 7636、RFC 8707，并实际执行官方 conformance runner 0.1.15 的 2025-11-25 `initialize` 场景。
9. 针对 GitHub Actions run `29263797177` 做“check→job→失败 step→原始日志”多跳定位；再以 Python raw/buffered I/O、`tracemalloc`、coverage.py 和 mypy 的官方文档复核短读、插桩开销与平台 typeshed 行为，避免用放宽 timeout 掩盖实现问题。
10. 针对 v0.5 沿 MCP local-server/SSRF 指南继续跳转 Docker 官方运行时限制、Bubblewrap 官方实现、Microsoft Job Object、RFC 8785、RFC 8032、pyca/cryptography 与 Sigstore bundle/identity verification 文档；再用 OWASP SSRF 指南交叉检查 IPv4/IPv6、metadata 地址和 DNS rebinding 边界。
11. 针对 v1.0 继续做多跳核验：MCP versioning→current/previous final 生命周期；NIST/OWASP 静态分析评估→precision/recall 与 synthetic prevalence 限制；SOURCE_DATE_EPOCH→Python build backend→两次 wheel/sdist 字节比较；GitHub/Sigstore artifact attestation→PyPI PEP 740；OWASP/NIST logging→最小字段、secret 排除、tamper detection 与 WORM；RFC 9700→PKCE/issuer/resource/audience。
12. 针对 GitHub Actions run `29310433050` 做“run→17 jobs→4 个失败 job→失败 step→原始日志”检索；四份日志归并到同一 Windows error 87 后，再从 Microsoft Job Object 概览跳转 `JOBOBJECT_BASIC_LIMIT_INFORMATION`、extended structure、`SetInformationJobObject`、`AssignProcessToJobObject`、system error 与 `CloseHandle`，并以 Python ctypes 官方文档复核 foreign-function 原型和资源所有权。

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

12. MCP 初始化不是固定版本回显检查：客户端发送其支持的最新版本，服务端可返回自己支持的另一版本；客户端只有支持该返回值才能继续。能力协商同样是操作前提，server 只有声明 `tools` capability 才应接受 `tools/list`。HTTP 后续请求必须发送协商后的 `MCP-Protocol-Version`。
    来源：[MCP Lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)、[MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)

13. MCP 2025-11-25 的 `Icon` 包含必需 `src` 以及可选 `mimeType`、`sizes`、`theme`；icon URL 可能引入跟踪、凭据泄露、超大图片和可执行 SVG 风险。`Tool.execution.taskSupport` 只允许 `forbidden`、`optional`、`required`。本项目验证 icon/taskSupport 结构但不下载 icon、不调用工具，因此不会新增 icon fetch SSRF 或 task execution 面。
    来源：[MCP Schema Reference](https://modelcontextprotocol.io/specification/2025-11-25/schema)、[MCP Base Protocol icon security guidance](https://modelcontextprotocol.io/specification/2025-11-25/basic)

14. 2025-11-25 将 JSON Schema 2020-12 设为 MCP schema 默认 dialect。`jsonschema` 的 `Draft202012Validator.check_schema` 用元模式验证 schema 本身，因此适合把“规范合法性”和本项目启发式质量/安全规则分开。
    来源：[MCP 2025-11-25 Changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)、[JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)、[python-jsonschema validators](https://python-jsonschema.readthedocs.io/en/stable/validate/)

15. MCP HTTP authorization 要求发现 Protected Resource Metadata 和 Authorization Server Metadata，并对 Authorization Code 流验证 PKCE；Resource Indicators 用于把 token 绑定到目标资源，token passthrough 被明确禁止。因此“能发送预签发 Bearer token”不能表述为“完成 OAuth 2.1 支持”。
    来源：[MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)、[MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

16. GitHub 接受第三方 SARIF 2.1.0 并使用 rule、result、location、partial fingerprint 等字段；上传还有 10 MiB 压缩大小、每 run 25,000 results 等限制。机器接口因此需要显式 schema version、稳定 rule ID 和有界输出，而不应依赖 Markdown 文本。
    来源：[GitHub SARIF Support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)、[Uploading SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-vulnerabilities/analyze-code-with-code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)

17. PyPI Trusted Publishing 通过 GitHub OIDC claim 换取最长约 15 分钟的短期 token，避免长期 PyPI secret；但它不证明构建内容未被替换，仍需 attestation。GitHub artifact attestation把制品与 repository、commit、workflow 绑定，且明确指出 attestation 不是“制品安全”的证明。
    来源：[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)、[PyPI Trusted Publisher Security Model](https://docs.pypi.org/trusted-publishers/security-model/)、[GitHub Artifact Attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)

18. GitHub 安全使用指南说明完整 commit SHA 是引用 Action 的不可变方式；CycloneDX 官方 Python 生成器支持从 Python environment 产生标准 SBOM。这支持在 release workflow 中同时采用 Action SHA pin、wheel/sdist、SHA-256、CycloneDX SBOM 与 provenance。
    来源：[GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)、[CycloneDX Python](https://github.com/CycloneDX/cyclonedx-python)

19. HTTP `Retry-After` 可以是 delay-seconds 或 HTTP-date；503 可用它说明预计不可用时长，429 也可携带。客户端仍需用总 deadline 和最大等待上限约束服务端建议，避免把韧性机制变成任意阻塞。
    来源：[RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after)、[RFC 6585 §4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4)

20. Streamable HTTP 的 POST 可返回 JSON 或 SSE。SSE 长响应应先发送带 event ID 的空 `data` 事件；连接中断后客户端通过 GET 并携带 `Last-Event-ID` 恢复，且应尊重 SSE `retry` 毫秒值。GET listener 是 server 可选能力，不支持时返回 405。
    来源：[MCP 2025-11-25 Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

21. 声明 `tools.listChanged=true` 的 server 可发送 `notifications/tools/list_changed`；客户端收到后应刷新缓存。能力未声明时，等待该通知不是合法的协商后操作。
    来源：[MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)、[MCP Client Best Practices](https://modelcontextprotocol.io/docs/develop/clients/client-best-practices)

22. MCP Authorization 要求客户端优先使用 401 challenge 中的 Protected Resource Metadata URL，否则按 endpoint path、root 顺序查找；Authorization Server Metadata 对带 path issuer 必须依次尝试 RFC 8414 path insertion、OIDC path insertion、OIDC path append。challenge scope 对当前请求具有权威性；PKCE metadata 不含 `S256` 时必须拒绝。
    来源：[MCP 2025-11-25 Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)、[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)、[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html)

23. RFC 7636 的 S256 为 `BASE64URL(SHA256(ASCII(code_verifier)))`，verifier/challenge 长度为 43..128 个 unreserved 字符；RFC 8707 把 `resource` 定义在 authorization request 和 token request，并建议使用最具体、可网络寻址的 resource URI 以做 audience restriction。
    来源：[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html)、[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)

24. MCP 官方 conformance runner 会启动场景 server、把 URL 交给 client command、捕获交互并执行规范检查；`initialize` 验证版本、`clientInfo` 和响应处理，`sse-retry` 验证 graceful close 后 GET、`retry` 时序与 `Last-Event-ID`。v0.4 本地实际运行 integrity-locked 0.1.15，两个场景 2/2、规范检查 4/4 通过，并纳入 CI。
   来源：[MCP Conformance](https://github.com/modelcontextprotocol/conformance)

25. Python 的 raw stream `read(size)` 允许在尚未 EOF 时返回少于请求的字节；官方文档同时说明 buffered I/O 在跨平台上提供更可预测的行为与性能。因此，对“以换行结束、有硬字节上限”的 stdio JSON-RPC 消息，应在 buffered pipe 上做限长 `readline`，而不应把 raw 短读视为完整消息。
    来源：[Python `io` documentation](https://docs.python.org/3.14/library/io.html)

26. coverage.py 通过追踪执行事件测量覆盖，官方文档明确指出这会施加速度开销；`tracemalloc` 又会在 Python allocator 上安装 hook 并产生 CPU/内存开销。因此 coverage + `tracemalloc` 同时开启时的 wall time 不能作为产品裸运行性能门限；功能覆盖、时间预算和内存预算需分层测量。
    来源：[coverage.py source measurement](https://coverage.readthedocs.io/en/7.14.1/source.html)、[Python `tracemalloc`](https://docs.python.org/3/library/tracemalloc.html)

27. mypy 默认使用当前运行平台的 typeshed 视图，并支持 `--platform` 显式复核其他平台。`os.killpg` 是 Unix API，因此即使运行时调用者有 `os.name` 判断，函数定义仍需使用 mypy 能识别的平台分支。
    来源：[mypy platform configuration](https://mypy.readthedocs.io/en/stable/command_line.html#platform-configuration)、[Python `os.killpg`](https://docs.python.org/3/library/os.html#os.killpg)

28. MCP Security Best Practices 对 one-click 本地 server 要求执行前明确 consent、完整显示命令并允许取消；还建议以平台 sandbox 限制 filesystem/network/privilege。它同时把 internal IP、metadata、localhost、DNS rebinding 和 redirect chain 列为 SSRF 模式。
    来源：[MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

29. Docker 官方 CLI 提供 `--network none`、`--read-only`、`--cap-drop`、`--security-opt no-new-privileges`、`--pids-limit`、`--memory` 和 `--cpus`；无 memory limit 时容器默认可使用任意可用内存，因此这些限制必须显式设置。
    来源：[docker container run](https://docs.docker.com/reference/cli/docker/container/run)、[Running containers](https://docs.docker.com/engine/containers/run/)

30. Bubblewrap 从空 mount namespace 组装可见文件系统；`--ro-bind` 提供只读绑定，`--unshare-all` 包含 network namespace，`--die-with-parent` 把 child 生命周期绑定到父进程。它是低级构件，最终 policy 仍由调用方负责。
    来源：[Bubblewrap project](https://github.com/containers/bubblewrap)、[Bubblewrap option implementation](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c)

31. Windows Job Object 把进程组作为单元管理，可用 `SetInformationJobObject` 设置 active-process、memory、CPU 等限制；`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 会在最后一个 job handle 关闭时终止关联进程及子 job hierarchy。
    来源：[Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)、[SetInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject)

32. RFC 8785 规定用于 hash/sign 的 JSON 必须限制在 I-JSON、按 ECMAScript 序列化 primitive、确定性排序 property 并输出 UTF-8；普通 `sort_keys` JSON 在数字等边界并不等价。Trail of Bits 的 `rfc8785` 0.1.4 是无依赖实现并通过 Trusted Publishing 发布。
    来源：[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)、[rfc8785 package](https://pypi.org/project/rfc8785/)

33. RFC 8032 定义 Ed25519：32-byte public/private key material 和 64-byte signature，并提供测试向量。pyca/cryptography 提供 Ed25519 sign/verify 与 PEM serialization；密钥文件权限和 public-key 信任分发仍是调用方责任。
    来源：[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)、[pyca cryptographic primitives](https://cryptography.io/en/stable/hazmat/primitives/)

34. Sigstore 的验证模型同时检查 signature、artifact digest 和预期 identity/issuer；bundle 可携带离线验证材料和透明日志证明。这支持“签名必须绑定预期 publisher/server identity，不能只验证任意 key 的数学签名”的设计原则。
    来源：[Sigstore verifying signatures](https://docs.sigstore.dev/cosign/verifying/verify/)、[Sigstore bundle format](https://docs.sigstore.dev/about/bundle/)

35. OWASP SSRF 指南要求同时处理 IPv4/IPv6 的 private、localhost、link-local 等非公网范围，并指出 cloud metadata 是常见凭据窃取目标。应用层重复 DNS 校验不能替代网络层 allowlist/egress control。
    来源：[OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

36. MCP 官方 versioning 页面在本次复核日将 2025-11-25 标为 current；按正式版本序列，v1.0 的“当前+前一正式版本”是 2025-11-25/2025-06-18。尚未成为正式版本且未通过本项目 conformance gate 的 draft/RC 不属于生产兼容承诺。
    来源：[MCP Versioning](https://modelcontextprotocol.io/docs/learn/versioning)

37. NIST 的静态分析评估把 precision 定义为 TP/(TP+FP)、recall 定义为 TP/(TP+FN)，并强调测试用例需要 ground truth、相关性与统计意义；NIST 还指出 synthetic corpus 的 flaw prevalence 与生产软件不同，precision 不能直接外推。公开评估因此必须同时发布 corpus、标签范围、混淆矩阵和局限，而不能只给单一“准确率”。
    来源：[NIST Evaluating Bug Finders](https://www.nist.gov/publications/evaluating-bug-finders-test-and-measurement-static-code-analyzers)、[NIST SATE IV](https://www.nist.gov/itl/ssd/software-quality-group/static-analysis-tool-exposition-sate-iv)、[OWASP Benchmark](https://owasp.org/www-project-benchmark/)

38. `SOURCE_DATE_EPOCH` 是分发无关的可复现时间输入；Python build 官方说明完整复现还依赖固定 backend、Python 与平台。Setuptools wheel 能消费该变量，但普通 sdist gzip/tar 元数据仍可能不一致；`setuptools-reproducible` 对 tar uid/gid/mode/mtime 与 gzip header 做归一化。实际验收必须比较两个独立输出的完整字节，而不只是文件列表。
    来源：[SOURCE_DATE_EPOCH specification](https://reproducible-builds.org/specs/source-date-epoch/)、[Python build reproducibility](https://build.pypa.io/en/latest/explanation/how-it-works.html)、[setuptools-reproducible](https://pypi.org/project/setuptools-reproducible/0.1/)

39. GitHub artifact attestation 是由 OIDC 身份签署并绑定 repository、commit、workflow 与 artifact digest 的 provenance；公开仓库记录进入透明日志，但官方明确说明 attestation 不是“artifact 安全”的证明。Immutable Release 还锁定 tag/assets 并产生 release attestation，但必须在仓库设置中启用。
    来源：[GitHub Artifact Attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)、[GitHub Immutable Releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)

40. PyPI PEP 740 attestations 将每个 distribution digest 绑定到 Trusted Publisher 身份；官方 PyPI Action 默认生成并上传 publish attestation。其安全模型只回答“来自哪个身份且未在发布后修改”，不回答该身份或代码是否值得信任。
    来源：[PyPI Attestations](https://docs.pypi.org/attestations/)、[Producing Attestations](https://docs.pypi.org/attestations/producing-attestations/)、[Attestation Security Model](https://docs.pypi.org/attestations/security-model/)

41. OWASP logging 指南要求事件记录 when/where/who/what，排除 access token、password、key 等 secret，并在静态存储中提供 tamper detection、受限读取和尽快复制到只读介质。单个本地 hash chain 能发现未重算的修改，但不能阻止有写权限的管理员重算、截断或删除，因此生产还需集中/WORM 存储。
    来源：[OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)、[NIST Log Management](https://csrc.nist.gov/projects/log-management)

42. RFC 9700 要求 public client 使用 PKCE，S256 是当前不在 authorization request 暴露 verifier 的方法；多 authorization server client 需要 issuer mix-up 防护，access token 应做 resource/audience 与权限限制。这与 v1 保留 exact redirect/state/issuer、S256 和 RFC 8707 resource binding 一致。
    来源：[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)、[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)

43. GitHub Actions run `29310433050` 的 17 个 job 中，失败的 4 个恰好是 Windows + Python 3.11/3.12/3.13/3.14；四份日志均在 `SetInformationJobObject` 返回 Windows error 87，且随后产生三条未关闭 pipe 的 `ResourceWarning`，其余 13 个 job 成功。跨四个解释器的同一 Win32 错误支持“共享 Windows backend 参数错误”，不支持“Python 小版本偶发故障”。
    来源：[GitHub Actions run 29310433050](https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/actions/runs/29310433050)、[Microsoft system error codes 0–499](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)

44. Microsoft 定义 `JOB_OBJECT_LIMIT_PROCESS_TIME=0x2`、`JOB_OBJECT_LIMIT_ACTIVE_PROCESS=0x8`、`JOB_OBJECT_LIMIT_PROCESS_MEMORY=0x100`、`JOB_OBJECT_LIMIT_JOB_MEMORY=0x200`；process time 使用 100 ns 单位。ExtendedLimitInformation 的 process/job memory 是不同字段，`SetInformationJobObject` 的 class 9 对应 extended structure。因此 flags 必须只启用已赋予合法值的对应字段。
    来源：[JOBOBJECT_BASIC_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information)、[JOBOBJECT_EXTENDED_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)、[SetInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject)

45. Python ctypes 对 foreign function 的参数与返回值支持显式 `argtypes`/`restype`，这也是把 Windows HANDLE/LPVOID/DWORD/BOOL 宽度写入接口契约的方式；Microsoft 同时要求每个成功打开的 handle 最终由 `CloseHandle` 关闭。创建 Job 后，配置、分配和关闭都应使用明确原型，异常路径不能遗留 Job handle 或子进程 pipe。
    来源：[Python ctypes](https://docs.python.org/3/library/ctypes.html)、[AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject)、[CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

## 从事实到实现的推理链

| 事实/威胁 | 第一性原理 | 本项目措施 |
| --- | --- | --- |
| 模型会看到 description/schema 等 metadata | 能改变模型决策的所有外部文本都属于不可信输入 | 递归扫描 name/title/description/input/output schema/annotation/execution/_meta 的 key 与 string value；限制节点、深度和总字符数 |
| annotation 只是 hint | 声明不能证明行为，冲突本身是风险信号 | 类型校验；检查 read-only/destructive/open-world 冲突；风险仍由 name/description/schema 独立推断 |
| 同名工具共享模型上下文 | 名称冲突降低路由确定性并可形成 shadowing | 同 server duplicate 为 error；跨 server 同名为 `CROSS_SERVER_TOOL_SHADOWING` |
| 首次审批后 metadata 可变化 | 审批对象必须有稳定身份才可检测变化 | RFC 8785 complete-card/field SHA-256；Ed25519 bundle 绑定 publisher/server/source；区分 changed/identity/publisher/untrusted；changed 默认 block |
| Schema 是调用边界 | 只有约束实际参数空间才能降低误用/资源/注入风险 | 检查 root/type/composition/ref/bounds/additionalProperties/array/string/regex；标记 command/URL/path/secret 参数和 external `$ref` |
| 不可信 endpoint 可耗尽或触达内网 | timeout 不能限制已经读入的内存，也不能终止重复 cursor | 文件、HTTP body、stdio line、stderr、队列、page、cursor、tool、schema、server、worker、retry 全部硬上限；重复 cursor 失败关闭 |
| config command 等价于本地代码执行 | “读取配置”不应隐式扩大为“运行配置” | executor 默认 none；config 另需 consent；Docker/Bubblewrap/Job Object 后端；host 显式不安全；最小环境与 command 脱敏 |
| URL validation 与 fetch 之间可能变化 | 仅解析 scheme 不能阻止 SSRF/redirect/rebinding | HTTPS/public 默认、禁 redirect、每次 open 重验、DNS 地址集跨请求 pin；高保证仍要求 egress policy |
| 部分写入会制造假报告 | 报告是 CI/审批输入，完整性优先于便利 | `mkstemp` + flush/fsync + `os.replace`；失败保留旧文件；POSIX 新文件 0600；Markdown/diagnostic 转义和 secret redaction |
| 协议版本与能力会演进 | 互操作必须基于双方共同版本与显式能力，而不是本地常量猜测 | 支持 2025-11-25/2025-06-18 allowlist；记录 requested/negotiated/capabilities；后续 HTTP header 使用 negotiated；无 tools capability 则 `unsupported_feature` |
| 规范 Schema 与启发式是不同事实层 | 元模式回答合法性，质量/安全规则回答工程风险 | `Draft202012Validator.check_schema` 完整校验；不同 schema 结果有界 LRU 缓存；其后继续执行本项目 bounded walker |
| 组织需要稳定机器消费 | CI 不能依赖会变化的终端文案 | report schema 1.1.0、scan ID、JSON Pointer、rule metadata、deterministic JSON、SARIF/JUnit/JSONL/GitHub annotations |
| 审批记录可能并发交错或事后改写 | 审批顺序和内容必须同时可验证 | `O_EXCL` writer lock；sequence + previous hash + domain-separated Ed25519；全链验证；POSIX 0600 |
| 例外会成为永久绕过 | suppression 必须可归责并自动失效 | TOML policy 要求 reason/owner/expires；到期 finding 恢复且 expired record 进入报告 |
| 认证材料容易从 argv/URL/报告泄漏 | token 的输入面应与普通配置分离 | 只从 env/0600 file 提供预签发 Bearer token；endpoint/proxy 禁止 userinfo；报告只记录 authenticated boolean；自定义 CA/proxy/mTLS 分离 |
| SSE 连接会正常中断且事件可能滞后 | 网络连接不是事务边界；恢复必须有游标、deadline 和重复上限 | 增量 parser；空预热事件；`id`/`retry`；GET + `Last-Event-ID`；总 timeout、3 次重连、行/body/event 上限 |
| 工具目录可在扫描中变化 | 快照只有在消费变更通知后重取才与 server 当前声明一致 | 仅在 `tools.listChanged=true` 后等待；stdio/HTTP 共用精确通知判定；命中后 exactly-once re-list 并记录 metadata |
| OAuth code/token 可被截获、替换或错发 audience | 授权必须把发起者、回调、issuer 和 resource 绑定到同一事务 | S256 PKCE、随机 state、可选 `iss` 校验、exact redirect、双请求 `resource`、0600 有期限 state、O_EXCL completion lock、token 不进 argv/URL/output |
| raw pipe 可短读 | 消息边界必须由换行/EOF/字节上限决定，不能由单次 OS read 返回长度决定 | stdio stdout/stderr 使用 buffered pipe；JSON-RPC 仍限 4 MiB，队列仍限 8 条；超限立即受控失败 |
| 观测工具会改变被观测系统 | 性能门限必须定义测量环境，否则就是测量 tracer 开销 | coverage 套件只验证 2,000-card 功能；独立无 coverage job 先测时间、再用 `tracemalloc` 单独测峰值内存 |
| 稳定接口会被下游自动化绑定 | “不打算变化”不可验证，必须把契约变成数据和测试 | `contract` 输出 schema/rule/exit/protocol；规则集合 SHA-256 冻结；1.0/1.1 reader 集成测试；未知 rule 不再生成 metadata |
| 启发式必须用 ground truth 评价 | 没有显式正负标签就无法计算 FP/FN | 公共 JSONL corpus；只统计明确 labelled pairs；输出 TP/FP/TN/FN、per-rule、digest、precision/recall/F1 和外推限制 |
| 构建签名与可复现解决不同问题 | 签名绑定 identity，复现绑定 source→artifact；二者都不证明 benign | 同环境两次 wheel/sdist byte compare；SHA-256/SBOM；GitHub/Sigstore provenance；PyPI PEP 740；验证文档明确边界 |
| 审计日志本身可能泄密或被篡改 | 可归责性不能以复制 secret 为代价，local chain 也不是 WORM | lint/OAuth 只允许固定非敏感字段；actor/time/sequence/hash chain/lock/append/fsync/0600；要求外送 WORM/SIEM |
| Windows Job flag 与赋值字段不匹配 | native API 只看到结构和 bitmask；注释或变量意图不能修正错误 ABI | 使用 Microsoft 常量的显式名称；只启用 process time/process memory/active process/kill-on-close；测试捕获原始结构并逐字段断言 |
| 子进程创建后 native sandbox 配置可能失败 | spawn 成功已经取得进程和 pipe 资源；后续异常不自动转移或释放所有权 | 统一失败回滚：kill、bounded wait、关闭 stdin/stdout/stderr；Job handle 仍由 native `finally` 关闭 |

## 推断

1. 静态 metadata lint 适合作为“连接前/发布前 gate”，不能成为运行时唯一安全边界。
2. 对可能写、删除、付费、联网、文件访问、代码执行或处理 secret 的工具，低误报不是最高目标；默认要求审批更符合最小权限原则。
3. 签名回答“持有该 private key 的主体批准了什么”，但 key 与真实 publisher 的对应关系仍来自带外信任；因此 verifier 必须同时配置预期 key 和 publisher/server claim。
4. 对 config command 采用显式授权会带来一次额外 CLI flag，但它避免把看似只读的扫描动作变成静默 RCE，安全收益明显高于兼容成本。
5. description 质量和长度存在可靠性/成本权衡，因此本项目报告缺失边界与过长文本，而不自动扩写或声称越长越好。
6. v1 稳定性首先是“可验证不破坏下游”的承诺，因此 report schema 保持 1.1.0，而不是为了产品版本对齐无意义地改成 2.0.0。

## 不确定与剩余边界

1. 规则是可解释的启发式，可能有 false positive/false negative；尤其无法静态证明 server implementation 与 card 一致。
2. 标准库 DNS 解析无法无竞态地把已验证 IP 直接固定到后续 TLS socket；高保证部署仍需 egress proxy/network policy。地址集 pin 能检测变化，但不宣称消除所有 DNS TOCTOU。
3. Streamable HTTP v1.0 覆盖 discovery 所需的 initialize、notification、分页 tools/list、JSON/SSE、GET listener/resumption、list_changed 和 session cleanup；它不是通用 SDK，未声明或实现 sampling、roots、elicitation、experimental tasks 及全部 draft 行为。
4. Docker/Bubblewrap 的隔离强度依赖 runtime/kernel policy；Windows Job Object 只约束进程树和资源，不提供网络/文件系统 sandbox；显式 host backend 不隔离。
5. Ed25519 baseline 不能证明首次审批正确，也不能抵御 private key 被盗、public key 被替换或 approval log 被有权访问文件系统的攻击者整体截断；需要独立 key 分发与 WORM/透明日志。
6. 本项目只扫描 tool card，不扫描 MCP prompts/resources、server source code、依赖漏洞、runtime tool output 或多步 toxic flow；应与 sandbox、SAST/SCA、runtime policy、audit 和人工复核组合。
7. OAuth v1.0 仍是预注册 public-client 流程；不自动启动浏览器、不实现 DCR/Client ID Metadata Document、refresh-token rotation 或 runtime insufficient-scope step-up。token audience 最终仍必须由 authorization/resource server 验证。
8. 公开准确率 corpus 只有 12 个 synthetic cases、21 个 labelled pairs 和 8 个被计分规则；1.0 precision/recall 不能外推到未标注规则、真实语言分布或 runtime behavior。
9. operational audit hash chain 未签名，本地管理员可重算或删除；它只提供本地 tamper evidence 和 cooperating-writer serialization，组织级不可抵赖/留存依赖 authenticated central collector/WORM。
10. 当前 macOS 本地环境无法执行真实 Windows Job Object；新增替身测试能验证 ABI 输入与回滚，真实的 Python 3.11–3.14 Windows 结果必须在修复提交推送后由 GitHub-hosted runner 再验证。旧 run 的 4 个失败不能作为修复后成功证据。
