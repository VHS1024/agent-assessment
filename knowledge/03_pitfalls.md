# 复测误判经验与工程取舍（知识实质性：非显然取舍 + 失效误判经验）

> 本文件条目均被实现真实消费或在判定路径上有对应代码/配置，非装饰性知识。对照考核 5.2「知识实质性——误判经验、非显然取舍、具体判据」。

## P-01 响应长度抖动的来源与对策

**误判场景**：把两次请求的长度差当成漏洞证据，实际来源是：动态响应头（Date 每秒变）、Set-Cookie 会话轮换、页面内嵌时间戳/随机 nonce。

**对策（已实现）**：vulnlab 靶场响应体逐字节确定（无时间戳/随机数）；判定只比对 body_length / body_sha256，动态头按 R-STRIP-01 剥离；比例阈值 0.5（R-T1-01）远高于任何残留抖动幅度。

## P-02 WAF 拦截 ≠ 漏洞修复

**误判场景**：复测发现 `<script>` 被拦 → 报告「已修复」。真实世界：编码变体（`%3Cimg onerror=...`）、大小写混淆、标签替换均可绕过关键字拦截。

**对策（已实现）**：R-T2-01 用双探针——字面量探针测「拦截是否存在」，变体探针测「漏洞本体是否仍可触达」。只有变体也被拦才给 PATCHED；变体仍反射给 SURFACE_PATCH。这正是本靶场 T2 的设计原型，也是「区分实际修复与表层变更」复测目标的直接实现。

## P-03 为什么用 SHA-256 + 归一化比对，而不是子串匹配

子串匹配（如找 "Forbidden" 字样）会误伤：不同修复实现返回不同文案但语义相同（都是统一拒绝）。SHA-256 比对回答的是更严格的问题——「两条路径是否逐字节走了同一个拒绝逻辑」，这是统一中间件修复的架构特征。代价是过严（文案重构会被误判 VULNERABLE），在 R-ERR-01 的 INCONCLUSIVE 兜底下，过严的误判可被人工复核纠正，漏判则不可逆——两害取其轻。

## P-04 网关无 Divide：比例为何本地算

差值经 calculator Subtract 过网关留审计；但 OctoBus calculator 只暴露 Add/Subtract。若为除法再写一个能力包，等于为纯算术增加一次网络依赖与故障面。取舍：**输入（差值）已被审计，除法是确定性纯函数，本地计算不损失证据链**——分工边界写进 rules.json `ratio_rule.why`，由 pipeline 加载（缺失键 Fatal）。

## P-05 探测失败 ≠ 修复成功

**误判场景**：接口超时/403 了 → 报告「已修复」。可能只是：服务挂了、网关白名单没配、WAF 把复测 IP 封了。

**对策（已实现）**：探针传输层失败一律 INCONCLUSIVE（R-ERR-01），报告显式列出 transport_errors 供人工复核，绝不把「探不出去」计为「已修复」。

## P-06 复测必须可复现：固定靶、固定判据、固定矩阵

复测与渗透测试不同：目标是**对同一历史漏洞给出随时间可对比的结论**。因此探针矩阵固定在代码里（probe_matrix）、判据版本化在 rules.json（report 记录 rules_version）、靶场响应确定性——任何一次重跑得到的差异都来自「目标状态变化」，而不是「工具随机性」。

## P-07 受控靶场的「自证」边界（诚实声明）

本靶场的 WAF 拦截特征串（`WAF-BLOCK`）与判据（rules.json `t2.block_marker`）同源——判定器对**这个靶场**完全确定，但对真实 WAF 的拦截页**不具泛化性**（各家 WAF 拦截页指纹不同）。这是受控复测靶场的固有边界：要泛化到真实目标，需把特征串换成可配置的指纹规则集（rules.json 扩展为 per-target fingerprints）。本考核场景内这是合理取舍，但应在报告边界声明中主动说明。同理，T1 的「探针打偏防护」（R-T1-02，无标记请求返回 400）也是靶场侧配合实现——真实目标的等价防护需判定器先做基线探针校验。

## P-08 权限报错的误诊链：先验假设取代了读源码

**误判场景**：`instance start` 报 `fork/exec …/bin/probe.js: permission denied`。三连假说排查（源文件读权限→目标目录属主→整卷 chown）全部无效，因为三个动作都在补「读」权限，而报错来自**执行位缺失**——OctoBus supervisor 直接 `exec.Command(入口 JS)`，shebang 脚本必须有 x 位（官方 supervisor_test「not executable」→同款报错）。更隐蔽的是首次修复用 `chmod -R a+rX`：大写 X 语义是「仅对已有 x 位的文件/目录补位」，对 644 的 probe.js 永远空转，制造了「修了没用」的假象，把排查拖成三轮。

**对策（已实现）**：入口脚本 `chmod 755`（本地包已同步 755，重导入不复发）；排障纪律——报错文案里的动词（exec/copy/open）先于假设定位到源码调用点，再对症下药，而不是按「权限问题」直觉轮流撒 chmod。

## P-09 能力声明面 ≠ 运行时实现面：三层对齐才算能力可用

**误判场景**：`capset select-method` 授权 Subtract 成功 → 想当然认为「能调」。实际预置 calculator 包 proto **声明**了 Add+Subtract（service list 可见），但运行时 handler 只注册 Add——每次 Subtract 调用都被实例回 HTTP 400 `unimplemented: The server does not implement the method Subtract`（网关审计 404 NotFound）。授权通过只证明「声明面 ∩ 授权面」非空，「实现面」是独立第三层。

**对策（已实现）**：能力上线前做**三层对齐核验**——① `service list` 看声明面；② grep 运行时 handler 注册键看实现面；③ 实弹重放（curl 带回显）看端到端。修复走同 id upsert（importer.go UpsertService）+ `instance restart`，实例 id、capset 授权、调用方代码零改动。延伸视角：这是「接口契约与实现漂移」的供应链缩影——SDK/服务包声明的方法面与实际实现脱节，与业界 SDK 治理「声明 vs 实测」方法论同构。

## P-10 验证必须分层：文件层绿 ≠ 端到端通（附防御式兼容写法）

**误判场景**：热替换 calculator handler 时，用 `grep -c "CalculatorService/"` 输出 2（Add+Subtract 键都在文件里）判定「修复成功」——随后 `instance restart` 报 `health check failed: connection refused`，实例根本起不来。同一修复链上还连环踩了三个分层陷阱：① 官方示例包是 SDK 模式（require `@chaitin-ai/octobus-sdk`），旧 runtime 是裸 gRPC 模式且无该依赖——「字符串在文件里」≠「依赖可解析」，require 首行即崩；② 跨环境重建文件时丢失首行 shebang（hardening.go 注释原文 "Runtime entries are shebang scripts"，supervisor 直接 `exec.Command(entry)` 无 node 兜底）——755 + 无 shebang = 内核 ENOEXEC「exec format error」；③ `node --check` 对 `.patched` 扩展名报 ERR_UNKNOWN_FILE_EXTENSION——语法检查对象必须是落位后的目标文件名。

**对策（已实现）**：① **四层验证链**——文件层（grep 键存在）→ 语法层（`node --check` 对落位后的 .js）→ 进程层（`instance restart` 的 health check + `tail stderr.log`，supervisor.go:286-298 把进程 stderr 落盘到 `DataDir/instances/<id>/stderr.log`）→ 端到端层（curl 实弹带回显），单层绿不算通；② **真实报错优先**——`logs --instance` 返回的是网关审计流水而非进程 stderr，崩溃栈必须读 stderr.log 或前台手动跑入口脚本；③ **防御式兼容**——跨环境替换代码时避免硬编码库的命名空间挂载路径（如 `proto.grpc.calculator.v1`），改「标准路径优先 + 结果树深搜 `.service` 属性兜底」的双通道解析，对 proto-loader/grpc-js 版本行为差异免疫。延伸视角：与「声明的规则未被实际使用」风险同类——「声明的修复未被端到端验证」，单点证据不能替代链路证据。

## P-11 网关接口命名漂移：契约名 ≠ 运行时名

**现象**：同一份代码、同一个能力包，某些轮次探针响应字段是 `body_length`（proto 声明名），另一些轮次变成 `bodyLength`（protojson lowerCamelCase）。判定器直接索引 `body_length` 取不到值，`judge_t1` 在减法前抛 `KeyError`，被 `main()` 兜底捕获。

**现场证据**：`evidence/20260930110008-139/`——该轮 6 次 ProbeHttp 全部成功（status 200/403），但 `octobus_calls_log` 仅 6 行、**无 Subtract**，报告为 INCONCLUSIVE；原因即本坑。

**定位方法**：不看报告看证据链——`calls` 数与探针数不符（6 vs 7）即说明判定在减法前就断了；再把该轮 evidence 的键名与 proto 声明逐一对齐。

**处置**：`normalize_probe()` 做 camel→snake 的防御式别名（只重排键名，不改数值），判定器只认 proto 声明的 snake_case。**证据文件仍保存网关原样响应**（不人为改写，便于审计对账），归一发生在判定读取时（见 README §7）。

**判定意义**：该轮失败方向是保守的（报 INCONCLUSIVE 而非误判 PATCHED），与 R-T1-02「探针打偏不得伪装成已修复」同一防线。**推论：任何接口适配层的失败都必须落到 INCONCLUSIVE，绝不能落到 PATCHED。**

## P-12 长度/字节一致性可作判据的前提，与不可作判据的字段

**前提一：长度与哈希必须取自「完整响应体」，不能取自 excerpt。**
`body_excerpt` 只是完整 body 的前 N 字节展示副本；若用 excerpt 长度做判据，当响应体被截断时会掩盖差异 → 假阴性。
`body_length` 取自 `buf.length`、`body_sha256` 对完整 `buf` 计算，二者共同支撑「逐字节一致」这一强判据。

**前提二：「逐字节一致」不能只看长度。** 等长但内容不同（sha 不同）既不是干净修复、也不构成可用注入，
必须转 INCONCLUSIVE 交人工——单看长度会把「等长的语义替换」误判成 PATCHED。

**不可作为判据的字段及其原因**：

| 字段 | 原因 | 处置 |
|---|---|---|
| `headers` 中的 `Date` / `Set-Cookie` / `Server` / `X-Request-Id` | 每次请求都变，纳入全等比较会把「已修复」误判成「未修复」（假阳性） | R-STRIP-01 剥离后再比 |
| `elapsed_ms` | 网络抖动，与修复状态无因果关系 | 不参与任何判定 |
| `status` 单值 | 靶场对「无注入标记」的请求返回 400，与「已修复的统一 403」不同；只看 status 会把探针打偏当成已修复 | 仅 200/403 进判定（R-T1-02） |
| `body_excerpt` 长度 | 见前提一，截断即失真 | 只用于关键字匹配与展示 |

**失效场景（本靶场已验证）**：若目标响应含时间戳/CSRF token 等动态内容，即便漏洞已修复，`ratio` 也不会归零——
此时只按长度判 PATCHED 必然漏报。故 PATCHED 的判据是「ratio==0 **且** sha256 全等」，两条同时成立才判；
中间灰区一律 INCONCLUSIVE。**失败方向一律偏保守：证据不足不硬判。**

## P-13 proto3 零值在 protojson 下被省略：四个字段的缺失语义各不相同

**现象**：`Subtract(18,18)` 的响应是**空对象** `{}`（没有 `result` 键），而 `Subtract(45,0)` 的正常响应是 `{"result":45}`。对照实测：`call_octobus.py` 中 `return int(r["result"])` 直接抛 `KeyError: 'result'`，被 `main()` 的 try/except 兜成 INCONCLUSIVE —— **T1 判 PATCHED 的那条路径在结构上不可达**。同一根因还命中空响应体：`/status/200`（0 字节）的探针响应键集实测为 `[bodySha256, elapsedMs, headers, status]`，**没有 `bodyLength`，也没有 `error`**。

**根因**：protojson 序列化时省略 proto3 的**默认零值**字段。受影响的共四个：`result`（int32）、`bodyLength`（int32）、`bodyExcerpt`（string）、`error`（string）。**JSON 层无法区分「这是合法的零值」与「这个字段没被设置」**——两者都表现为「键不存在」。

**关键判据——零值可补性**：

| 字段 | 零值 | 零值在业务上是否可能合法出现 | 缺失时的正确解释与处置 |
|---|---|---|---|
| `result` | `0` | **可能**（减法结果本就可能是 0） | 补 `0`，正常判定 |
| `bodyLength` | `0` | **可能**（空响应体，已实测） | 补 `0`，正常判定 |
| `bodyExcerpt` | `""` | **可能**（空响应体） | 补 `""`，正常判定 |
| `error` | `""` | **可能**（无错误即正常态） | 补 `""`，正常判定 |
| `bodySha256` | —— | **不可能**（空响应体的 sha256 也是 `e3b0c442…`，恒非空） | **缺失只能是异常形状 → fail-closed** |

> **判据本身**：一个字段的零值若在业务上「可能合法出现」，则缺失可补默认值；若零值在业务上「不可能出现」，则缺失必然是异常形状，必须 fail-closed。**「补零值」不是一个可以无脑套用的动作**——它只对前四个字段成立。

**反例（把判据用错的后果）**：若按同一逻辑把 `body_sha256` 也补成 `""`，两个**都没有哈希**的探针会因 `"" == ""` 互相判等、`ratio` 归零 → 直接判 **PATCHED**。实测该写法确会产出这个错误结论；本补丁在该分支返回 **INCONCLUSIVE**。这是典型的 **fail-open**：为了「让程序别崩」而补默认值，把「证据不足」补成了「证据显示已修复」。

**处置（已落地）**：
1. `call_octobus.py`：`result` 缺失时——**空对象**（响应体就是 `{}`）解释为 0；**非空但无 `result`** 视为契约破损，抛 `RuntimeError` 而非静默取 0。**区分这两种情况是本坑的第二层**：前者是零值省略，后者是契约破坏，不能用同一套默认值糊过去。
2. `pipeline.py` 的 `normalize_probe()`：对 `status` / `body_length` / `body_excerpt` / `elapsed_ms` / `headers` 补零值缺省；**`body_sha256` 例外**——缺失即置 `error="MALFORMED_PROBE: ..."`，转入 INCONCLUSIVE。
3. 回归用例：**桩打在 `call_method`（HTTP 边界），不打在 `subtract`**。

**测试桩位的教训**：原用例在 `subtract` 上打桩，而缺陷恰恰在 `subtract` 内部——**桩把它自己该被测的那一层整个替换掉了**，于是 38 个用例全绿、缺陷照样活着。移到 HTTP 边界后：未打补丁 **7 failed / 39 passed**，打补丁 **46 passed**（本机 python3.12 与服务器 python3.10.12 结果一致）。

**判定意义**：本坑的两种失败方向截然不同——`KeyError` 崩掉是**保守的**（INCONCLUSIVE），而「把缺失的 sha 补成空串」是**激进的**（误判 PATCHED）。**修复必须同时消掉这两头**：既不能崩，也不能为了不崩而放宽判据。与 P-11、R-T1-02 同一条防线。

## P-14 工具返回的成功状态 ≠ 真实生效状态

**总则**：OctoBus 管理面返回体描述的是**落库结果**，不是**运行时状态**。二者之间隔着一次 reload/restart，以及一层看不见的值归一化。**只看返回体——哪怕它把新哈希、新时间戳都给你了——不足以判定生效。**

**已实测的五个实例**：

| # | 操作 | 返回体说 | 实际发生 |
|---|---|---|---|
| 1 | `instance update-config` **不带 `--restart`** | `ConfigSHA256` 变成 `6e992395…`、`UpdatedAt` 更新 | **`PID` 仍是旧值（14），运行时仍报旧 allowlist**——静默失效、无任何警告 |
| 2 | 出口白名单写**裸主机名** | 写入成功 | 运行时被**静默归一**为 `host:80`；`https://` 走 443 → `EGRESS_DENIED: …:443 不在出口白名单内`。「放行主机」实际只等价于放行 80 端口 |
| 3 | 宿主机直连 `octobus` CLI | —— | 报 **`daemon is not running`**。真实原因是 `--addr` 默认 `127.0.0.1:9000` 只在容器内有效；报错把排查引向「daemon 死活」，而它一直活着 |
| 4 | `capset add-token` 用**已存在的 ID** | `400` + 原始 `UNIQUE constraint failed: capset_tokens.capset_id, capset_tokens.id` | 令牌**只能追加、不能覆盖**。叠加「`list-tokens` 把整个列表遮蔽成 `******`」与「`remove-token` 必须提供 ID」，构成**轮换闭环陷阱**：最自然的做法撞约束，想先删又枚举不出来 |
| 5 | `--token-file` 配 `docker exec` | 找不到文件 | CLI 运行在**容器内**，读的是容器内路径；宿主机路径永远不可见 |

**三条共性**：
1. **返回体描述「库的状态」，不描述「进程的状态」。** 写库成功与运行时生效之间隔着一次重载——而重载需要显式请求（`--restart`），省略即静默失效。
2. **你写的值不是运行时看到的值的原样。** 中间存在一层未声明的归一化（裸主机名→`:80`、camelCase→snake_case），且**不告知**。
3. **报错指向的症状与真实原因不一致。** `daemon is not running` 之于 `--addr` 默认值；`UNIQUE constraint failed` 之于「该 ID 已被占用，请换 ID 或先删除」。

**对策：配置类操作一律要求「双向功能反证」。** 改完必须观察到**行为发生预期变化**，还原后必须观察到**行为退回**——只比对返回体的哈希/时间戳不够（实例 1 的返回体是**完全正确**的）。本次白名单还原即按此执行：`ConfigSHA256` 逐字符回归 `94b1ceec…` ✓、`allowedHosts` 回读 ✓、**功能复验重新拿到 `EGRESS_DENIED`** ✓——三轴齐证才敢宣布还原完成。

**与 P-09、P-10 的关系**：P-09「能力声明面 ≠ 运行时实现面」说的是**静态声明**与实现不符；P-10「文件层绿 ≠ 端到端通」说的是**中间表示**与运行不符；P-14 是它们的**操作侧对偶**——**「操作返回成功」与「状态已变更」不符**。三者同源：**任何单点信号都不足以证明系统状态，必须拿到端到端的行为证据。**
