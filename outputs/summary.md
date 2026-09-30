# 漏洞复测结论摘要

- 运行批次 run_id：`20260930120007-129`
- 判据版本 rules_version：`1.0`
- 生成时间：2026-09-30T12:00:07+0000
- 数据来源：`outputs/report.json`（判定结果）+ `evidence/20260930120007-129/`（探针原始响应、`octobus_calls.log`）
- 靶场：`http://172.17.0.1:8081`（全部调用经 OctoBus 网关 `OCTOBUS_BASE_URL=http://octobus:9000` 转发）

## 总览

report.json 汇总计数：`total=3, VULNERABLE=1, SURFACE_PATCH=1, WAF_FULL_BLOCK=0, PATCHED=1, INCONCLUSIVE=0`。

| 漏洞 ID | 类型 | 判定 | 依据规则 |
|---|---|---|---|
| VULN-2026-001 用户查询接口布尔盲注 | boolean_blind | VULNERABLE | R-T1-01 / R-CALC-01 |
| VULN-2026-002 搜索接口反射型 XSS | reflection_diff | SURFACE_PATCH | R-T2-01 |
| VULN-2026-003 管理接口水平越权 | idem_forge | PATCHED | R-T3-01 / R-STRIP-01 |

## VULN-2026-001 用户查询接口布尔盲注 —— VULNERABLE

- 结论：漏洞仍未修复（VULNERABLE）。`1=1` 返回完整记录、`1=2` 返回空记录，两响应体差异显著且超过攻击阈值。
- 关键度量（取自 `outputs/report.json` 该条 `metrics`）：`len_true=72`、`len_false=27`、`delta=45`（经 OctoBus `calculator.v1.CalculatorService/Subtract` 计算，审计入参 `left=72, right=27`，见 `octobus_calls.log` 第 003 行）、`ratio=0.625`、`threshold=0.5`；`sha_true` 前缀 `38e272955835`、`sha_false` 前缀 `fae340d3cd27`。
- 判据：R-T1-01 双阈值——ratio ≥ 0.5 判 VULNERABLE（仅 ratio==0 判 PATCHED，`(0,0.5)` 为灰区）。本次 ratio 0.625 ≥ 0.5，直接判 VULNERABLE。
- 证据文件：
  - `evidence/20260930120007-129/probe_VULN-2026-001_tautology.json`（status `200`、`bodyLength=72`、体为完整记录 `{"id":1,"user":"admin","role":"user","balance":"1000","status":"active"}`）
  - `evidence/20260930120007-129/probe_VULN-2026-001_contradiction.json`（status `200`、`bodyLength=27`、体为 `{"result":"empty","rows":0}`）

## VULN-2026-002 搜索接口反射型 XSS —— SURFACE_PATCH（表层变更）

- 结论：表层变更（SURFACE_PATCH）。历史处置声称的「WAF 拦截 `<script` 关键字」确实生效，但拦截面仅覆盖单一字面特征；`<img onerror>` 变体仍被原样反射，漏洞本体仍可触达，**不构成真实修复**。
- 关键度量（取自 `outputs/report.json` 该条 `metrics`）：`waf_active=true`、`bypass_reflected=true`、`literal_status=403`、`bypass_status=200`；`bypass_excerpt=<html><body>Search results for: <img src=x onerror=alert(1)> | end</body></html>`。
- 判据：R-T2-01 四态——字面量被拦（403 + 命中 `WAF-BLOCK`）且变体仍原样反射 → SURFACE_PATCH（关键字拦截 ≠ 漏洞修复）。
- 证据文件：
  - `evidence/20260930120007-129/probe_VULN-2026-002_literal_script.json`（status `403`、`bodyLength=59`、体含 `WAF-BLOCK: keyword policy violation (rule: xss-keyword-001)`）
  - `evidence/20260930120007-129/probe_VULN-2026-002_variant_onerror.json`（status `200`、`bodyLength=80`、原样反射 `onerror=alert(1)`）

## VULN-2026-003 管理接口水平越权 —— PATCHED

- 结论：已修复（PATCHED）。普通请求与伪造 Cookie（`admin=1`）请求均统一返回 403，且响应逐字节一致——符合统一鉴权中间件修复的架构特征。
- 关键度量（取自 `outputs/report.json` 该条 `metrics`）：`plain_status=403`、`forged_status=403`、`sha_identical=true`、`headers_identical=true`（响应头已按 R-STRIP-01 剥离 `date`/`server` 等动态字段后比对）。两次响应均 `body_length=9`、`body_sha256=78342a0905a72ce44da083dcb5d23b8ea0c16992ba2a82eece97e033d76ba3d3`、`body_excerpt=Forbidden`。
- 证据文件：
  - `evidence/20260930120007-129/probe_VULN-2026-003_plain.json`
  - `evidence/20260930120007-129/probe_VULN-2026-003_forged_cookie.json`

## 执行说明与边界（如实声明）

- 出口合规：本轮全部能力调用（探针 `retest.v1.RetestService/ProbeHttp`、calculator `calculator.v1.CalculatorService/Subtract`）均经 `src/call_octobus.py` 唯一出口访问 `OCTOBUS_BASE_URL`；未自行拼接 URL、未绕过网关、未做端口/目录扫描或路径模糊测试。本摘要所有数值均取自 `outputs/report.json` 与证据文件，未做任何估算或心算。
- 判定完整性：三条漏洞探针传输层均无 `error`（`evidence/20260930120007-129/octobus_calls.log` 中 7 次调用 `ok=true`），判定结果为确定结论，无 INCONCLUSIVE 需转人工。
- 可复现性：探针矩阵固定在 `src/pipeline.py`，判据版本化于 `knowledge/rules.json`（`rules_version=1.0`），靶场响应逐字节确定；重跑差异来自目标状态变化而非工具随机性。
- 边界声明（P-07）：T2 的拦截特征串（`WAF-BLOCK`）与判据同源，仅对本受控靶场确定，对真实 WAF 拦截页不具泛化性；泛化需将 `rules.json` 扩展为 per-target 指纹规则集。
