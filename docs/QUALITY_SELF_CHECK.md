# 质量自检表

自检日期：2026-07-13。版本：0.4.0。结论：“通过”表示本仓库定义的本地可执行验收条件已满足，不表示静态扫描器能够证明 MCP server 的运行时安全。规范事实、工程推理和剩余不确定性分别记录在 [RESEARCH_NOTES.md](RESEARCH_NOTES.md)。

## 九方面验收结果

| 质量方面 | 可执行验收标准 | 实现证据 | 测试/度量证据 | 结论 |
| --- | --- | --- | --- | --- |
| 输入校验 | 所有 CLI、JSON、TOML policy、config、URL、credential/OAuth、command/env、report/baseline、JSON-RPC/SSE 与 schema 输入在使用前校验类型、语法和语义 | strict JSON 拒绝重复 key、NaN/Infinity/float overflow、非法 UTF-8；OAuth metadata/resource/issuer/redirect/scope/state/token 全链校验；Bearer/callback 只读 env/私有文件；Draft 2020-12 元模式完整校验 | duplicate key、1e999、5,000 位整数、非法 UTF-8、header injection、0600、OAuth resource/state/issuer/PKCE、非法 schema/protocol/capability 均有负向用例 | 通过 |
| 边界检查 | 攻击者控制的长度、数量、深度、队列、线程、分页、流事件、重连、重试、缓存、finding 和等待时间都有硬上限 | 10 MiB 文件、4 MiB HTTP/stdio、64 KiB SSE line、10,000 SSE events、3 reconnect、1 session recovery、8 条 stdout queue、100 行 stderr、tool/page/server/worker/schema/depth/card/retry/OAuth metadata/scope/state 上限；SARIF 25,000 results；JSON Schema LRU 1,024 | oversized HTTP/stdio、重复 cursor、SSE resume、session expiry、schema node/depth、finding/SARIF truncation、concurrency=33、2,000 cards budget | 通过 |
| 异常处理 | 预期外部错误映射为稳定诊断和退出码；未知异常默认不泄露 traceback；单个 source 失败不吞掉其他 source | `DiscoveryError`、`JsonRpcError`、`UnsupportedFeatureError`、`SessionExpiredError`、`OAuthError`、`ReportError`、`InputValidationError`、`PolicyError`；顶层 bounded/redacted internal error | invalid JSON/SSE/OAuth metadata/callback/token、无 capability、HTTP 错误、partial config failure、atomic replace failure、CLI exit-code 回归 | 通过 |
| 资源生命周期管理 | 初始化/授权中途失败也清理；进程、pipe、线程、HTTP response/error/session、OAuth lock 与临时文件在所有路径关闭 | stdio context rollback、POSIX process group terminate/kill、reader thread join、HTTP context/HTTPError close、session DELETE、atomic token/report temp cleanup、OAuth lock `finally` 释放、state 成功后删除 | 全套测试在 `ResourceWarning` 提升为 error 后 100/100 通过；failed-enter、replace failure、state mismatch/lock 专门覆盖 | 通过；Windows 任意脱离后代仍是已知限制 |
| 并发控制 | 并发数有上限；共享 JSON-RPC round trip 不交错；背压队列有界；授权 code 不被并发兑换；失败隔离 | config `ThreadPoolExecutor` 为 1..32；stdio/HTTP request lock；stdout/stderr 有界 queue；OAuth `O_EXCL` completion lock；每个 future 独立收集 | 8 线程并发 request 最大 active=1；二次 state lock fail closed；过大 concurrency 拒绝；双 server 一坏一好仍保留安全结果 | 通过 |
| 性能 | 常见规模近线性；重复 schema 校验可复用；最坏输入在分配/遍历前截断 | 单次 bounded metadata/schema traversal；canonical SHA-256；`Draft202012Validator.check_schema` 结果有界 LRU 缓存 | 2,000 cards 自动门限 `<10 s`/`<128 MiB`；本机 lint 实测 1.4029 s、peak 5.98 MiB | 通过（回归量级，不是跨机器 SLA） |
| 韧性 | 兼容行为必须显式开启；暂态/断流/session 失效有限恢复且受总 deadline 约束；服务端等待建议不能无限阻塞 | stdio strict；tools/list 暂态 retry；`Retry-After` 与 SSE `retry` capped；POST SSE 断流 GET + Last-Event-ID；HTTP 404 仅重建 session 一次；cursor 去重 | 503→成功、POST→GET resume、session 404→reinitialize、server ping、重复 cursor、strict/compat stdio、unsupported capability、partial source failure | 通过 |
| 可测试性 | 规则、policy、transport、OAuth/credential、report、security primitive 均有可直接调用边界；协议测试不依赖业务公网 | `lint_sources` 纯入口；provider 分层；本地 adversarial OAuth/HTTP/stdio fixtures；deterministic output；官方 conformance adapter | 100 tests：unit 61、integration 34、system 5；总分支覆盖率 75%，CI 门槛 75%；官方 initialize+sse-retry 场景 2/2、检查 4/4 | 通过 |
| 可维护性 | 单一版本源、稳定规则目录/报告契约、类型/静态检查、变更和安全流程、可复现发布步骤齐备 | 0.4.0 单一 `__version__`；rule catalog/report schema 均保持 1.0.0；OAuth 与 transport helper 分层；协议矩阵、threat model、changelog | Ruff、strict mypy、compileall、diff check、wheel/sdist clean-install 全通过；CI 为 3 OS × Python 3.11..3.14 + integrity-locked MCP conformance | 通过；跨平台矩阵须由远端 CI 实际执行 |

## 协议、安全与供应链能力

| 能力 | 实现 | 状态/边界 |
| --- | --- | --- |
| MCP 版本与能力 | 协商 2025-11-25/2025-06-18，并允许 2025-03-26 基础传输兼容；记录 requested/negotiated/capabilities；HTTP 后续 header 使用 negotiated；tools capability gate | 已实现；版本特定字段边界见 [PROTOCOL_COMPATIBILITY.md](PROTOCOL_COMPATIBILITY.md) |
| stdio 纯净性 | stdout 默认只接受 JSON-RPC；兼容 noise 必须显式开启且有界 | 已实现 |
| Streamable HTTP | 增量 JSON/SSE、空 priming event、GET listener/resumption、Last-Event-ID、server ping、list_changed、session recovery/DELETE、禁 redirect、SSRF policy | 已实现 bounded tool discovery；不声明 sampling/roots/elicitation/tasks |
| 认证/TLS | 预签发 Bearer env/0600 file、CA/proxy/mTLS；或 PRM/AS metadata + Authorization Code/S256 PKCE/Resource Indicator + 0600 state/token | 已实现预注册 public client；不实现 DCR、refresh rotation、自动 step-up/browser |
| Schema/图标 | JSON Schema Draft 2020-12 完整元模式 + bounded quality/security rules；MCP icon 结构校验且不下载 | 已实现 |
| tool poisoning/integrity | 全 model-visible metadata、hidden Unicode、secret、shadowing、完整 card SHA-256 baseline | 已实现启发式检测；baseline 本身未签名 |
| 稳定报告 | Draft 2020-12 report schema、scan ID、JSON Pointer、rule metadata、deterministic JSON、SARIF/JUnit/JSONL/GitHub | 已实现；SARIF 达 25,000 results 时显式记录截断，消费端仍应施加自身 size 限制 |
| 组织 policy | profile、select/ignore、severity override、带 reason/owner/expires 的 suppression；到期恢复 finding 并审计 | 已实现 |
| CI/发布 | SHA 固定 Actions、3 OS/4 Python、coverage/type/static/build gate；Trusted Publishing、SHA-256、CycloneDX SBOM、provenance attestation | 配置和本地命令已验证；真正发布仍依赖仓库/PyPI environment 配置 |

## 本地质量门禁

```bash
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  python -m coverage run -m unittest discover -s tests
python -m coverage combine
python -m coverage report --fail-under=75
ruff check src tests
mypy src
python -m compileall -q src tests
python -m build
git diff --check
```

## 未解决风险与后续优先级

1. 高：静态 card 不能证明 runtime behavior。执行不可信 config/server 应放入容器、VM 或 OS sandbox，并结合最小权限、approval、runtime input/output validation 和 audit。
2. 高：OAuth token audience 最终只能由 authorization/resource server 验证；本项目不应接收或转发面向其他 resource 的 token。DCR、refresh rotation、自动 step-up/browser 不在 v0.4。
3. 中：标准库 URL 校验与 socket 使用之间仍有 DNS TOCTOU；高保证部署需要 egress proxy/network policy。
4. 中：baseline 未签名且首次快照可能已恶意；approved report 应进入受保护分支或绑定签名/attestation。
5. 中：list_changed 仅按显式 timeout 做一次 refresh；未实现长期 daemon cache、tasks，也不扫描 prompts/resources/source/dependencies/runtime responses/toxic multi-step flows。
6. 低至中：自然语言 injection、ReDoS 和参数危险性规则是可解释启发式，仍需 corpus、fuzzing、mutation testing 和误报/漏报校准。
7. 低：Windows 未使用 Job Object，恶意 server 主动脱离后可能留下 descendant；需在远端 Windows CI 加专门测试与实现。
