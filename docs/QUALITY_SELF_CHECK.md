# 质量自检表

自检日期：2026-07-10。版本：0.2.0。

判定口径：“通过”表示当前仓库定义的可执行验收条件已满足，不表示不存在剩余风险。事实依据是代码、自动测试和本次实际命令输出；推理依据见 `docs/RESEARCH_NOTES.md`。

## 九方面验收结果

| 质量方面 | 可执行验收标准 | 实现证据 | 测试证据 | 结论 |
| --- | --- | --- | --- | --- |
| 输入校验 | 所有 CLI、JSON、config、URL、command/env、report/baseline、JSON-RPC 和 schema 外部输入在使用前校验类型、语法与语义；拒绝 NaN/Infinity、重复 JSON key、NUL、非法协议版本和矛盾 report shape | `security.py` 的 strict JSON/URL/path/redaction；`discovery.py` 的 command/env/config/initialize/JSON-RPC 校验；`models.py` 的 `LintConfig` 限制；`reporting.py` 的 report/baseline 校验 | duplicate key、超长整数、非法 UTF-8、NaN、invalid env/timeout、unsupported protocol、malformed optimize、CLI `nan` 等 | 通过 |
| 边界检查 | 攻击者控制的长度、数量、递归、循环、并发、重试和缓存均有硬上限；循环游标必须终止 | 10 MiB 文件；4 MiB HTTP/stdio 默认；8 条 stdout queue；100 行 stderr；tool/page/server/worker/schema/depth/description/card/retry/URL/arg/env 上限；重复 cursor 集合检测 | oversized HTTP/stdio、cursor repeat、schema node limit、CLI 最大值、2,000 cards budget | 通过 |
| 异常处理 | 预期外部错误转成稳定错误/退出码，无 traceback 泄漏；一个 server 失败不吞掉其他结果；source error 即使 `--fail-on never` 仍返回 2 | `DiscoveryError`/`JsonRpcError`/`ReportError`/`InputValidationError`；config future 独立收集；diagnostic 控制字符与 secret 脱敏 | invalid JSON controlled error、partial config failure、HTTP transient/redirect/content-type/version、exit-code 测试 | 通过 |
| 资源生命周期管理 | 初始化中途失败也清理；进程、pipe、reader thread、HTTP response/error/session、temp file 全路径关闭；报告替换失败保留旧文件 | stdio `__enter__` rollback、context manager、POSIX process session/terminate/kill、stdout/stderr thread join、HTTP context/HTTPError close/session DELETE、atomic temp cleanup | `PYTHONWARNINGS=error::ResourceWarning` 全套通过；failed-enter cleanup；atomic replace failure | 通过；Windows 后代进程仍有限制 |
| 并发控制 | config worker 数有上限；同一 JSON-RPC client 的 request ID/write/read round trip 不交错；队列有界 | config `ThreadPoolExecutor` 为 1..32 且不超过 server 数；stdio/HTTP request lock；stdout queue 为 8；stderr queue 为 100 | 8 线程并发 request 的最大 active round trip 为 1；concurrency=33 拒绝；多 server 系统测试 | 通过 |
| 性能 | 常见规模近线性；最坏输入被上限截断；2,000 cards 在宽松预算 10 s/128 MiB 内 | 单次 bounded traversal；metadata 总扫描字符/节点限制；SHA-256 canonical card；无第三方 runtime dependency | 自动 budget test；本机 build+lint 2,000 cards 实测 0.9226 s、tracemalloc peak 5.26 MiB | 通过（单机基准，不等同容量承诺） |
| 韧性 | 可容忍有限非协议 stdout noise；HTTP tools/list 暂态失败有限重试；分页、单 server 和 cleanup 失败不扩散；任何 retry 有 deadline | 有界 noise skip、总 request deadline、tools/list 仅对 429/502/503/504 最多 2 次重试、source isolation、best-effort DELETE | 3 行 noise 后成功、503 后第二次成功、repeated cursor fail-closed、safe server 在另一 source 失败时仍进入报告 | 通过 |
| 可测试性 | 规则、transport、report、security primitive 有可直接调用边界；mock server 不依赖公网或认证；测试可重复 | `lint_sources` 纯入口；`security.py` 独立；stdio/HTTP adversarial fixtures；CLI subprocess helper | 59 tests：unit 35、integration 20、system 4；均使用标准库 `unittest` | 通过 |
| 可维护性 | 稳定 rule code、结构化数据模型、集中 limits/redaction、明确 CLI contract、研究/测试/剩余风险同步；无隐式第三方 runtime | `models.py`/`security.py`/`discovery.py`/`lint.py`/`reporting.py`/`cli.py` 分层；0.2.0 README 和三份质量文档；rule code 可检索 | compileall、diff check、全回归；baseline JSON 保持机器可读 | 通过；`lint.py`/`discovery.py` 后续可继续按 rule family/transport 拆分 |

## 安全检查能力自检

| 能力 | 代表性 rule/机制 | 状态 |
| --- | --- | --- |
| 全 metadata tool poisoning | `TOOL_POISONING_*` 扫描 value 与 key，不限于顶层 description | 已覆盖 |
| 隐藏/混淆内容 | `HIDDEN_UNICODE_CONTROL`、`OBFUSCATED_METADATA`、`HARDCODED_SECRET_IN_METADATA` | 已覆盖（启发式） |
| tool shadowing | `DUPLICATE_TOOL_NAME`、`CROSS_SERVER_TOOL_SHADOWING` | 已覆盖 |
| rug pull | canonical SHA-256、`--baseline-report`、changed/new/missing | 已覆盖 change detection；未签名 |
| dangerous parameters | command/URL/path/secret、string/array bounds、additional properties | 已覆盖静态 schema 信号 |
| schema correctness | type/root/composition/ref/required/enum/bounds/annotation/subschema/dialect | 已覆盖核心 2020-12/MCP tool card 子集 |
| ReDoS/oversized inputs | nested quantifier heuristic、permissive pattern、ineffective/max missing bounds | 已覆盖启发式 |
| behavior/annotation conflicts | read-only/destructive/open-world/taskSupport/type validation | 已覆盖 |
| scanner self-protection | config execution consent、minimal env、SSRF policy、no redirect、bounded I/O、atomic private reports | 已覆盖当前 transport |

## 质量门禁命令

```bash
PYTHONWARNINGS=error::ResourceWarning \
PYTHONPATH=src \
python3 -m unittest discover -s tests -v

python3 -m compileall -q src tests
git diff --check
```

## 剩余风险与后续优先级

1. 高：静态 card 无法证明 runtime behavior；需 sandbox、least privilege、approval、runtime output validation/policy 和 audit。
2. 中：DNS validation 与 socket 使用间存在 TOCTOU；server/CI 环境应加 egress proxy/network policy。
3. 中：baseline 未签名且首次快照可能已恶意；应将 approved report 放入受保护分支或使用签名/attestation。
4. 中：当前不扫描 prompts/resources/source/dependencies/runtime responses/toxic multi-step flows。
5. 低至中：regex 与自然语言 injection 规则是启发式；需要基于真实 corpus 持续校准 false positive/negative。
6. 低：Windows 未使用 Job Object，恶意 server 主动脱离后可能留下 descendant；建议 Windows CI/实现验证。
7. 维护性：规则增长后应把 `lint.py` 拆成 metadata/schema/behavior rule family，把 `discovery.py` 拆成 stdio/http/config 模块；当前测试为后续重构提供保护网。
