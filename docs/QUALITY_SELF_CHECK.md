# 质量自检表

自检日期：2026-07-14。版本：0.5.0。结论中的“通过”表示本仓库可在当前本地环境执行的验收条件已满足；不表示静态扫描、应用层 DNS 检查或任一沙箱后端能够形式化证明 MCP server 无恶意行为。研究依据与剩余不确定性见 [RESEARCH_NOTES.md](RESEARCH_NOTES.md)，完整测试数据见 [TEST_REPORT.md](TEST_REPORT.md)。

## 九方面验收结果

| 质量方面 | 可执行验收标准 | v0.5 实现证据 | 测试/度量证据 | 结论 |
| --- | --- | --- | --- | --- |
| 输入校验 | CLI、JSON、URL/DNS、command/env、executor、key/bundle/log、report/baseline、JSON-RPC/SSE 与 schema 在使用前完成语法和语义校验 | strict JSON 拒绝 duplicate/NaN/overflow；executor backend/image/resource 范围校验；PEM 限长/类型/权限校验；baseline/log exact-field schema、base64、digest、claim、timestamp 和 key ID 校验；Draft 2020-12 metaschema | 负向覆盖非法 executor/image/limit、unknown signed field、签名/摘要篡改、错误 key、malformed chain、SSRF/DNS、已有 JSON/schema/OAuth 边界 | 通过 |
| 边界检查 | 攻击者控制的长度、数量、深度、队列、线程、分页、DNS pin、field hash/diff、approval log、重连、重试和等待时间均有硬上限 | 既有 file/HTTP/stdio/SSE/tool/page/schema/retry 上限；DNS endpoint 128；field hash 4,096、diff path 256；approval log 16 MiB/100,000 records/16 KiB record；key 64 KiB；executor CPU/memory/process/tmp 范围 | oversized/repeated cursor/schema/SARIF 既有用例；新增 pin-set、limit、field diff/log size结构用例；2,000-card 门限通过 | 通过 |
| 异常处理 | 外部错误映射为稳定诊断/退出码；未知异常默认不泄露 traceback；部分 source 失败隔离；签名失败不得降级 | `ExecutionError`、`TrustError` 纳入顶层受控错误；signed input 缺 public key、signature/digest/key mismatch 均 exit 2；source future 仍独立收集 | CLI unsigned-required、tampered signature、unknown field、default-deny executor、partial config、atomic replace 等均有回归 | 通过 |
| 资源生命周期管理 | 初始化/审批中途失败也清理；进程、pipe、thread、job handle、HTTP response、lock、临时文件和 descriptor 在所有路径关闭 | `ManagedProcess.release()` 幂等；stdio `finally` 释放 executor handle；Job Object close；process group terminate/kill；atomic baseline key/output；approval lock `finally`；fsync 文件/目录 | 全套在 `ResourceWarning` 提升为 error 下 127 tests 通过；failed-enter、managed release、atomic write、OAuth/approval lock、clean install 覆盖 | 通过；Windows Job 实际运行需 Windows CI 复验 |
| 并发控制 | 并发数受限；JSON-RPC 不交错；审批 append 不交错；失败隔离且不死锁 | config workers 1..32；stdio/HTTP request lock；bounded queues；OAuth 与 approval 均用 `O_EXCL` lock；approval append 在锁内先全链验证再 `O_APPEND`+fsync | 8-thread request serialization、OAuth duplicate completion、approval 两次顺序 append/chain verify、partial source failure 通过 | 通过；lock 为单主机协作式锁，不替代分布式事务/WORM |
| 性能 | 常见规模近线性；新增 canonicalization/field hash 不破坏既有预算；安全检查在分配前截断 | RFC 8785 与 leaf hash 单次 bounded traversal；validator LRU；field map/diff/report/log 均 bounded；性能门限脱离 coverage 测量 | 2,000 cards：0.3910 s，tracemalloc peak 7.81 MiB，门限 `<10 s`/`<128 MiB` | 通过（回归预算，不是跨机器 SLA） |
| 韧性 | 暂态网络与 SSE/session 有限恢复；安全漂移 fail closed；兼容例外显式开启 | retry/reconnect/session recovery 保持总 deadline；DNS 地址集变化立即拒绝；identity/publisher/untrusted 独立状态；legacy unsigned 仅迁移兼容，生产可强制 signed | 503→成功、SSE resume、session recovery、strict/compat stdio；新增 public→new IP、public→metadata、publisher/source drift、legacy reject | 通过 |
| 可测试性 | 纯逻辑、执行器、DNS、签名、transport 与 CLI 均可注入替身；unit/integration/system 分层 | `ProcessExecutor` protocol、resolver/Popen mock boundary、`lint_sources`、deterministic report、local adversarial fixtures、CLI subprocess workflow | unit 83、integration 36、system 8；127 total；branch coverage 75.05%；专项 v0.5 19 tests 本机通过 | 通过 |
| 可维护性 | 单一版本源、独立模块、稳定 schema、严格类型、变更/威胁/研究文档、可复现构建齐备 | 0.5.0 单一 `__version__`；`execution.py`/`trust.py` 与 discovery/lint 分层；report schema 1.1.0、baseline schema 1.0.0；依赖有上界 | Ruff；strict mypy 本机/`win32`/`linux` 三视图；compileall；diff check；wheel/sdist build 与 clean install；`pip check` 全通过 | 通过；远端 3 OS × 4 Python 矩阵须推送后复验 |

## v0.5 安全与信任能力

| 能力 | 强制条件 | 明确边界 |
| --- | --- | --- |
| Docker executor | `--network none`、read-only root、drop all caps、no-new-privileges、pids/memory/swap/cpus、bounded tmpfs，无隐式 host cwd/mount | 依赖 Docker daemon/runtime/kernel；image 必须由部署方按 digest 审核；Docker daemon 本身是高权限边界 |
| Bubblewrap executor | 空 mount namespace、runtime/workspace 只读 bind、`--unshare-all`、无 `--share-net`、die-with-parent、`prlimit`（若可用） | Linux only；依赖 user namespace/kernel policy；不是完整 OCI/cgroup 管理器 |
| Windows Job Object | kill-on-close、active process、per-process memory/CPU 限制，stdio 生命周期释放 handle | 不限制网络/文件系统；创建后立即 assign 仍依赖 Windows process semantics；真实用例仅 Windows CI 执行 |
| Host executor | 必须显式 `--executor host`；config 另需 consent | 无 sandbox，只适合已信任命令 |
| DNS policy | 每次 open 重验 IPv4/IPv6 public/private policy；跨请求固定完整 address set；禁 redirect | 标准库 resolve/connect 仍存在 TOCTOU；高保证需要 egress proxy/network namespace/direct-IP TLS 连接层 |
| Signed baseline | RFC 8785 canonical JSON、domain-separated Ed25519、外部 public key、report digest、publisher/server/source binding | 不证明首次审批正确；public key 分发和 private key 保管是外部信任根 |
| Field diff | 每个 bounded JSON Pointer leaf 仅保存 SHA-256；added/removed/changed 最多 256 paths | 不输出 raw value，避免报告复制秘密；超过上限显式 `truncated` |
| Approval log | exact schema、sequence、previous hash、Ed25519、全链验证、owner-only、append lock/fsync | 可被有文件权限者整体删除/截断；生产应复制到受保护分支、WORM 或透明日志 |

## 本地质量门禁

```bash
PYTHONWARNINGS=error::ResourceWarning PYTHONPATH=src \
  python -m coverage run -m unittest discover -s tests -v
python -m coverage combine
python -m coverage report --fail-under=75
ruff check src tests
mypy src
mypy --platform win32 src
mypy --platform linux src
MCP_LINTER_ENFORCE_PERFORMANCE_BUDGET=1 PYTHONPATH=src \
  python -m unittest tests.system.test_performance_budget -v
python -m compileall -q src tests
python -m build
python -m pip check
git diff --check
```

## 剩余风险与后续优先级

1. 高：静态 card 与签名 baseline 不能证明 runtime behavior；仍需 runtime authorization、输入/输出 enforcement、人工确认和审计。
2. 高：private signing key、public-key 分发与首次审批一旦失陷，数学签名无法恢复真实 publisher 信任；建议 KMS/HSM、双人审批与透明/WORM 日志。
3. 中高：DNS set pinning 不能把验证后的 IP 原子地传给 `urllib` socket；高保证环境必须叠加 egress proxy/network policy 和 metadata hard block。
4. 中：Docker/Bubblewrap/Job Object 的能力不等价；Windows 还需额外 filesystem/network sandbox，host backend 不能用于不可信代码。
5. 中：approval baseline 文件与 log 是两个独立文件，不能跨文件原子提交；失败会受控报告，但部署方需 reconciliation 流程。
6. 中：未做 fuzzing、mutation、soak、真实企业 proxy/TLS、恶意 container escape 或 Windows descendant race 测试。
7. 低至中：自然语言 injection、ReDoS 与危险参数规则仍是可解释启发式；需要持续 corpus 校准。
