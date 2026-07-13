# 质量自检表

自检日期：2026-07-13。版本：0.3.0。结论：“通过”表示本仓库定义的本地可执行验收条件已满足，不表示静态扫描器能够证明 MCP server 的运行时安全。规范事实、工程推理和剩余不确定性分别记录在 [RESEARCH_NOTES.md](RESEARCH_NOTES.md)。

## 九方面验收结果

| 质量方面 | 可执行验收标准 | 实现证据 | 测试/度量证据 | 结论 |
| --- | --- | --- | --- | --- |
| 输入校验 | 所有 CLI、JSON、TOML policy、config、URL、credential、command/env、report/baseline、JSON-RPC 与 schema 输入在使用前校验类型、语法和语义 | strict JSON 拒绝重复 key、NaN/Infinity、非法 UTF-8；TOML 限 1 MiB 且 rule/suppression 全量校验；Bearer 只读 env/私有文件；endpoint/proxy 禁止凭据；Draft 2020-12 元模式完整校验 | duplicate key、5,000 位整数、非法 UTF-8、header injection、0600、未知 rule、无效 suppression、非法 schema/protocol/capability 均有负向用例 | 通过 |
| 边界检查 | 攻击者控制的长度、数量、深度、队列、线程、分页、重试、缓存、finding 和等待时间都有硬上限 | 10 MiB 文件、4 MiB HTTP/stdio、8 条 stdout queue、100 行 stderr、tool/page/server/worker/schema/depth/card/retry/credential/policy/suppression 上限；每 tool 1,000 findings 并显式截断；SARIF 25,000 results；JSON Schema LRU 最多 1,024 项 | oversized HTTP/stdio、重复 cursor、schema node/depth、finding truncation、SARIF truncation、concurrency=33、2,000 cards budget | 通过 |
| 异常处理 | 预期外部错误映射为稳定诊断和退出码；未知异常默认不泄露 traceback；单个 source 失败不吞掉其他 source | `DiscoveryError`、`JsonRpcError`、`ReportError`、`InputValidationError`、`PolicyError`、`CredentialError`；顶层 bounded/redacted internal error；source error 在 `--fail-on never` 下仍返回 2 | invalid JSON、无 capability、HTTP 错误、partial config failure、atomic replace failure、CLI exit-code 回归 | 通过 |
| 资源生命周期管理 | 初始化中途失败也清理；进程、pipe、线程、HTTP response/error/session 与临时文件在所有路径关闭 | stdio context rollback、POSIX process group terminate/kill、reader thread join、HTTP context/HTTPError close、session DELETE、atomic temp cleanup | 全套测试在 `ResourceWarning` 提升为 error 后 80/80 通过；failed-enter 与 replace failure 专门覆盖 | 通过；Windows 任意脱离后代仍是已知限制 |
| 并发控制 | 并发数有上限；共享 JSON-RPC round trip 不交错；背压队列有界；失败隔离 | config `ThreadPoolExecutor` 为 1..32 且不超过 server 数；stdio/HTTP request lock；stdout/stderr 有界 queue；每个 future 独立收集 | 8 线程并发 request 的最大 active round trip 为 1；过大 concurrency 拒绝；双 server 一坏一好仍保留安全结果 | 通过 |
| 性能 | 常见规模近线性；重复 schema 校验可复用；最坏输入在分配/遍历前截断 | 单次 bounded metadata/schema traversal；canonical SHA-256；`Draft202012Validator.check_schema` 结果有界 LRU 缓存 | 2,000 cards 自动门限 `<10 s`/`<128 MiB`；本机 lint 实测 1.4029 s、peak 5.98 MiB | 通过（回归量级，不是跨机器 SLA） |
| 韧性 | 兼容行为必须显式开启；暂态错误有限重试且受总 deadline 约束；服务端等待建议不能无限阻塞 | stdio 默认协议严格，legacy noise 需显式 flag；tools/list 仅对 429/502/503/504 重试；`Retry-After` 支持秒数/HTTP-date 且最多等待 30 s；分页 cursor 去重 | 503→成功、重复 cursor fail-closed、strict/compat stdio、unsupported version/capability、partial source failure | 通过 |
| 可测试性 | 规则、policy、transport、credential、report、security primitive 均有可直接调用边界；协议测试不依赖公网 | `lint_sources` 纯入口；可注入 `CredentialProvider`；本地 adversarial HTTP/stdio fixtures；deterministic output | 80 tests：unit 50、integration 26、system 4；总分支覆盖率 76%，CI 强制门槛 75% | 通过 |
| 可维护性 | 单一版本源、稳定规则目录/报告契约、类型/静态检查、变更和安全流程、可复现发布步骤齐备 | 0.3.0 单一 `__version__`；rule catalog 1.0.0；report schema 1.0.0；`py.typed`；policy/auth/rules 分层；README、threat model、compatibility、changelog、contributing、security | Ruff、strict mypy、compileall、diff check、wheel/sdist clean-install 全通过；CI 配置 3 OS × Python 3.11..3.14 | 通过；跨平台矩阵须由远端 CI 实际执行 |

## 协议、安全与供应链能力

| 能力 | 实现 | 状态/边界 |
| --- | --- | --- |
| MCP 版本与能力 | 协商 2025-11-25/2025-06-18；记录 requested/negotiated/capabilities；HTTP 后续 header 使用 negotiated；tools capability gate | 已实现；兼容范围见 [PROTOCOL_COMPATIBILITY.md](PROTOCOL_COMPATIBILITY.md) |
| stdio 纯净性 | stdout 默认只接受 JSON-RPC；兼容 noise 必须显式开启且有界 | 已实现 |
| Streamable HTTP | JSON/SSE response、session、DELETE、禁 redirect、SSRF policy、Retry-After | 已实现核心 discovery；未实现 GET SSE multiplex/resumption |
| 认证/TLS | 预签发 Bearer env/0600 file、custom CA、proxy、mTLS，token 不进 argv/URL/report | 已实现 credential provider；不宣称完整 OAuth Authorization Code/PKCE |
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
2. 高：尚未实现 OAuth Protected Resource/Authorization Server Metadata、Authorization Code + PKCE 与 Resource Indicators；当前只接受调用方预先获得的 Bearer token。
3. 中：标准库 URL 校验与 socket 使用之间仍有 DNS TOCTOU；高保证部署需要 egress proxy/network policy。
4. 中：baseline 未签名且首次快照可能已恶意；approved report 应进入受保护分支或绑定签名/attestation。
5. 中：未实现 `notifications/tools/list_changed` 持续发现、GET SSE resumption、tasks，也不扫描 prompts/resources/source/dependencies/runtime responses/toxic multi-step flows。
6. 低至中：自然语言 injection、ReDoS 和参数危险性规则是可解释启发式，仍需 corpus、fuzzing、mutation testing 和误报/漏报校准。
7. 低：Windows 未使用 Job Object，恶意 server 主动脱离后可能留下 descendant；需在远端 Windows CI 加专门测试与实现。
