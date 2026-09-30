# 漏洞复测结论摘要

- run_id: `20260930140005-128`
- 生成时间: 2026-09-30T14:00:06+0000
- 判据版本: rules.json `1.0`（判定由 `src/pipeline.py` 确定性执行，全部数值经 OctoBus 网关/脚本产生）
- 汇总: total=3，VULNERABLE=1，SURFACE_PATCH=1，WAF_FULL_BLOCK=0，PATCHED=1，INCONCLUSIVE=0

> 本文所有数值均摘自 `outputs/report.json` 与 `evidence/20260930140005-128/`，未做任何估算或推断。

---

## VULN-2026-001 用户查询接口布尔盲注 —— 判定: VULNERABLE

- 规则: R-T1-01（双阈值）；差值经 R-CALC-01 网关 Subtract 留审计
- 关键度量: `len_true=72`，`len_false=27`，`delta=45`（网关 Subtract），`ratio=0.625` ≥ 阈值 `0.5`
- 响应体: `sha_true=38e272955835…` vs `sha_false=fae340d3cd27…`，`sha_identical=false`
- 结论依据: `1=1` 返回完整记录（`{"id":1,"user":"admin",…}`），`1=2` 返回空结果（`{"result":"empty","rows":0}`），两 payload 响应长度差比例达 0.625，超过攻击阈值 → 注入仍有效。
- 两个探针状态码均为 200，符合 `expect_status`，排除 R-T1-02「探针打偏」。
- 证据文件:
  - `evidence/20260930140005-128/probe_VULN-2026-001_tautology.json`
  - `evidence/20260930140005-128/probe_VULN-2026-001_contradiction.json`

## VULN-2026-002 搜索接口反射型 XSS —— 判定: SURFACE_PATCH（表层变更）

- 规则: R-T2-01（拦截 vs 修复区分）
- 关键度量: `waf_active=true`，`bypass_reflected=true`，`literal_status=403`，`bypass_status=200`
- 字面量探针被拦: `<script>` → 403，响应体 `WAF-BLOCK: keyword policy violation (rule: xss-keyword-001)`
- 变体探针未被拦: `<img src=x onerror=alert(1)>` 原样反射，响应体为 `<html><body>Search results for: <img src=x onerror=alert(1)> | end</body></html>`
- 结论依据: 历史处置仅上线「WAF 拦截 `<script` 关键字」，仅覆盖单一关键字；标签替换变体仍原样反射、可触达漏洞本体 → 属表层变更，非真实修复（未证明输出转义/代码层修复）。
- 证据文件:
  - `evidence/20260930140005-128/probe_VULN-2026-002_literal_script.json`
  - `evidence/20260930140005-128/probe_VULN-2026-002_variant_onerror.json`

## VULN-2026-003 管理接口水平越权 —— 判定: PATCHED

- 规则: R-T3-01；响应头比对按 R-STRIP-01 剥离动态头
- 关键度量: `plain_status=403`，`forged_status=403`，`sha_identical=true`，`headers_identical=true`
- 响应体: 两次请求均为 `Forbidden`（`content-length=9`，`sha256=78342a0905a7…`），逐字节一致
- 结论依据: 普通请求与伪造 Cookie（`admin=1`）请求均走同一条 403 拒绝路径，剥离 `Date/Server` 等动态头后响应头一致 → 统一鉴权中间件生效。
- 证据文件:
  - `evidence/20260930140005-128/probe_VULN-2026-003_plain.json`
  - `evidence/20260930140005-128/probe_VULN-2026-003_forged_cookie.json`

---

## 审计与边界声明

- 全部能力调用经 `src/call_octobus.py` 网关出口，业务请求 id `20260930140005-128-001..007`，三方对账留痕见 `evidence/20260930140005-128/octobus_calls.log`（7 次调用全部 `ok=true`，无传输层失败，故无 R-ERR-01 触发的 INCONCLUSIVE）。
- VULN-2026-002 的 WAF 特征串 `WAF-BLOCK` 与判据 `rules.json t2.block_marker` 同源（P-07 受控靶场自证边界）。该判定对本靶场确定，对真实第三方 WAF 拦截页不具泛化性——泛化需将特征串替换为可配置的 per-target 指纹规则集。
