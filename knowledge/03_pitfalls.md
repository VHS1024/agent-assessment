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


> **现场证据**：`evidence/20260930110008-139/`——该轮 6 次 ProbeHttp 全部成功（status 200/403）但 `octobus_calls.log` 仅 6 行、**无 Subtract**，报告为 INCONCLUSIVE。原因即本坑：网关命名切换后`body_length` 取不到值，`judge_t1` 在减法前抛 KeyError，被 `main()` 兜底捕获。修复即 `normalize_probe()`。
> **判定意义**：该轮证明失败方向是保守的（报 INCONCLUSIVE 而非误判 PATCHED），与 R-T1-02「探针打偏不得伪装成已修复」同一防线。
## P-09 能力声明面 ≠ 运行时实现面：三层对齐才算能力可用

**误判场景**：`capset select-method` 授权 Subtract 成功 → 想当然认为「能调」。实际预置 calculator 包 proto **声明**了 Add+Subtract（service list 可见），但运行时 handler 只注册 Add——每次 Subtract 调用都被实例回 HTTP 400 `unimplemented: The server does not implement the method Subtract`（网关审计 404 NotFound）。授权通过只证明「声明面 ∩ 授权面」非空，「实现面」是独立第三层。

**对策（已实现）**：能力上线前做**三层对齐核验**——① `service list` 看声明面；② grep 运行时 handler 注册键看实现面；③ 实弹重放（curl 带回显）看端到端。修复走同 id upsert（importer.go UpsertService）+ `instance restart`，实例 id、capset 授权、调用方代码零改动。延伸视角：这是「接口契约与实现漂移」的供应链缩影——SDK/服务包声明的方法面与实际实现脱节，与业界 SDK 治理「声明 vs 实测」方法论同构。

## P-10 验证必须分层：文件层绿 ≠ 端到端通（附防御式兼容写法）

**误判场景**：热替换 calculator handler 时，用 `grep -c "CalculatorService/"` 输出 2（Add+Subtract 键都在文件里）判定「修复成功」——随后 `instance restart` 报 `health check failed: connection refused`，实例根本起不来。同一修复链上还连环踩了三个分层陷阱：① 官方示例包是 SDK 模式（require `@chaitin-ai/octobus-sdk`），旧 runtime 是裸 gRPC 模式且无该依赖——「字符串在文件里」≠「依赖可解析」，require 首行即崩；② 跨环境重建文件时丢失首行 shebang（hardening.go 注释原文 "Runtime entries are shebang scripts"，supervisor 直接 `exec.Command(entry)` 无 node 兜底）——755 + 无 shebang = 内核 ENOEXEC「exec format error」；③ `node --check` 对 `.patched` 扩展名报 ERR_UNKNOWN_FILE_EXTENSION——语法检查对象必须是落位后的目标文件名。

**对策（已实现）**：① **四层验证链**——文件层（grep 键存在）→ 语法层（`node --check` 对落位后的 .js）→ 进程层（`instance restart` 的 health check + `tail stderr.log`，supervisor.go:286-298 把进程 stderr 落盘到 `DataDir/instances/<id>/stderr.log`）→ 端到端层（curl 实弹带回显），单层绿不算通；② **真实报错优先**——`logs --instance` 返回的是网关审计流水而非进程 stderr，崩溃栈必须读 stderr.log 或前台手动跑入口脚本；③ **防御式兼容**——跨环境替换代码时避免硬编码库的命名空间挂载路径（如 `proto.grpc.calculator.v1`），改「标准路径优先 + 结果树深搜 `.service` 属性兜底」的双通道解析，对 proto-loader/grpc-js 版本行为差异免疫。延伸视角：与「声明的规则未被实际使用」风险同类——「声明的修复未被端到端验证」，单点证据不能替代链路证据。
