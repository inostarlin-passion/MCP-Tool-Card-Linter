# 质量自检表

自检日期：2026-07-14。版本：1.0.0。这里的“通过”表示仓库内可执行的验收条件在当前环境满足，不表示静态元数据分析、OAuth 客户端、DNS 预检、审计哈希链或任一沙箱能够形式化证明 MCP server 安全。完整数据见 [TEST_REPORT.md](TEST_REPORT.md)，安全假设见 [THREAT_MODEL.md](THREAT_MODEL.md)，支持边界见 [SUPPORT_BOUNDARIES.md](SUPPORT_BOUNDARIES.md)。

## 九方面验收结果

| 质量方面 | v1.0 验收标准 | 实现证据 | 实测证据 | 结论与剩余边界 |
| --- | --- | --- | --- | --- |
| 输入校验 | 所有 CLI、JSON/JSONL、schema、URL/DNS、OAuth、密钥、报告、baseline、审计记录在使用前完成语法和语义校验 | strict JSON 拒绝 duplicate/NaN；Draft 2020-12；accuracy corpus 与 audit exact-field 校验；稳定 report reader；command、env、PEM、URL、proxy、CA、mTLS、OAuth metadata 均有限定 | 负向 corpus、未知 rule、越界 rate、篡改 audit/report/baseline、SSRF/DNS、OAuth state/issuer/audience、fuzz 805 个生成/变异输入均通过 | 通过；静态 schema 合法不代表服务端运行行为合法 |
| 边界检查 | 攻击者可控的长度、数量、深度、线程、队列、重试、分页、日志和等待时间均有硬上限 | accuracy：8 MiB/10,000 cases/1 MiB line；audit：32 MiB/200,000 records/32 KiB record；既有 tool/schema/SSE/HTTP/process/DNS/field diff/approval bounds | oversized JSON/schema/log、循环 cursor、DNS pin-set、report size 和 2,000-card 预算均有回归 | 通过；预算是产品边界，不是任意输入规模承诺 |
| 异常处理 | 外部错误映射为稳定退出码；默认不泄露 traceback；部分 source 失败隔离；验证失败不降级 | v1 契约固定 `0=success`、`1=findings/gate failure`、`2=input/operational error`、`130=interrupt`；`AuditError`/`EvaluationError` 纳入顶层受控错误；signed baseline 和 report validation fail closed | CLI 错误码、缺失文件、损坏签名、失败 audit、partial source 与 debug 分支回归通过 | 通过；不可恢复的解释器/内核故障不在应用异常契约内 |
| 资源生命周期管理 | 所有进程、pipe、线程、HTTP response、lock、handle、临时文件和 descriptor 在成功与失败路径释放 | `ManagedProcess.release()`；process group/Windows Job；Windows Job 配置失败时 kill/wait 并关闭三条 pipe；HTTP context；OAuth/approval/audit `finally` lock；原子文件替换；audit file/dir `fsync` | 143-test 全套在 `ResourceWarning=error` 下通过；专门回归验证 Windows Job 失败回滚；40 次 stdio soak 无线程或 descriptor 累积；wheel/sdist 干净安装通过 | 通过；修复后的 Windows Job 真实运行仍需下一次推送后的 Windows CI 复验 |
| 并发控制 | 并发度受限；协议请求不交错；协作写入不能破坏链；失败不造成无界等待 | workers 1..32；stdio/HTTP request lock；bounded queues；OAuth、approval、audit 使用 `O_EXCL` 协作锁；audit 在锁内先全链验证后 `O_APPEND` | 8-thread serialization、并发完成保护、approval/audit lock、partial failure 和 40-cycle soak 通过 | 通过；单机 lock 不是分布式锁，管理员仍可删除/重写本地日志 |
| 性能 | 常见规模近线性，安全校验先限界再分配，CI 有独立非 coverage 性能门 | validator cache、bounded traversal、单次 canonicalization/hash、流式 JSONL 记录模型、2,000 tool 上限 | 2,000 cards：规则计算 0.4048 s，tracemalloc peak 7.81 MiB；门限 `<10 s`/`<128 MiB` | 通过；是回归预算，不是跨硬件 SLA |
| 韧性 | 暂态网络和 session 有限恢复；身份/发布方/网络漂移 fail closed；审计与报告损坏可检测 | retry/reconnect/`Last-Event-ID`/session recovery 服从总 deadline；每次 open 重验 DNS；signed baseline；hash-chained audit；current + previous MCP final version | 503→成功、SSE resume、session recovery、DNS rebinding、publisher/identity drift、audit tamper、legacy/current report reader 均通过 | 通过；应用层 DNS 检查仍有 resolve/connect TOCTOU，高保证部署需外部 egress control |
| 可测试性 | 核心逻辑可注入替身，unit/integration/system/fuzz/mutation/soak 分层，规则准确率可复跑 | resolver/Popen/executor/Win32 API boundary；deterministic report；公开 JSONL corpus；固定随机种子 fuzz；输入 mutation；CLI subprocess workflow | unit 91、integration 40、system 9、fuzz 2、mutation 1，共 143；141 passed、2 platform skips；branch coverage 75.81%；accuracy precision/recall/F1 均 1.0（明确标注的 21 pairs） | 通过；小型合成 corpus 不代表生产数据分布 |
| 可维护性 | 稳定机器契约、单一版本源、模块分层、类型/静态检查、可复现构建、发布与威胁文档可审计 | `contracts.py` 固定 schema/rule IDs/exit codes/protocol；Win32 常量与 foreign-function prototypes 显式命名；106 个 rule IDs 的 digest 冻结；`audit.py`/`evaluation.py` 独立；语义化版本与弃用政策；所有 Actions 固定 SHA | Ruff、strict mypy 本机/win32/linux、compileall、YAML parse、pip check、diff check 通过；wheel/sdist 双构建逐字节相同；两种制品 clean install 通过 | 通过；修复后的远端 3 OS × 4 Python 和 tag 发布须推送/打 tag 后由 GitHub 复验 |

## v1.0 稳定版承诺

| 承诺 | 已实现的可验证接口 |
| --- | --- |
| 报告向后兼容 | 当前 report schema 1.1.0 使用完整 Draft 2020-12 校验；保留 1.0.0 reader；`validate-report` 可独立验收 |
| rule ID 稳定 | `contract` 发布 106 个完整 ID 及 ID-set SHA-256；未知 ID 在 metadata 层直接拒绝；AST 测试防止 literal issue 逃逸目录 |
| CLI exit code 稳定 | `contract` 发布 0/1/2/130 语义；实现集中引用常量并有 CLI 集成测试 |
| 协议兼容 | 正式版 2025-11-25（current）与 2025-06-18（previous）受支持；2025-03-26 作为 legacy；协商和 capability gate 保持回归 |
| 公开准确率 | `evaluation/rule_accuracy_v1.jsonl`、`evaluate` 命令、每规则 TP/FP/TN/FN、corpus digest、CI 0.95 precision/recall gate |
| 深度测试 | 确定性 fuzz、6 个安全 mutation operators、40-cycle stdio lifecycle soak 进入 CI |
| 可复现与签名发布 | 固定 `setuptools-reproducible`、`SOURCE_DATE_EPOCH`、双构建 `cmp`；release 生成 SHA-256、CycloneDX SBOM、GitHub provenance/SBOM attestations，并通过 PyPI Trusted Publishing/PEP 740 发布 |
| 企业连接能力 | Bearer provider、OAuth Authorization Code + PKCE/Resource Indicator、proxy、自定义 CA、mTLS；凭据不接受明文 CLI token |
| 审计治理 | `--audit-log`/`--audit-actor` 只写允许列表中的最小事件；0600、全链校验、sequence/previous hash、append+fsync；`audit verify` 可独立验证 |
| 明确边界 | [THREAT_MODEL.md](THREAT_MODEL.md)、[SUPPORT_BOUNDARIES.md](SUPPORT_BOUNDARIES.md)、[STABILITY_POLICY.md](STABILITY_POLICY.md)、[RELEASE_VERIFICATION.md](RELEASE_VERIFICATION.md) 分别说明威胁、非目标、兼容与制品验证 |

## 审慎结论

v1.0 达到“稳定的生产策略门禁”这一范围：它适合作为 MCP tool metadata 的确定性准入层，而不是恶意运行时行为证明器、网络防火墙、分布式审计存储或通用 MCP 安全网关。组织部署仍应配套 branch protection、外部 egress policy、隔离执行环境、密钥管理、集中 WORM/SIEM 与人工审批。
