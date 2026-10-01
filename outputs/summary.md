# 历史漏洞复测结论摘要

- 复测轮次 run_id：`20261001080006-133`
- 生成时间：2026-10-01T08:00:06+0000
- 判据版本 rules_version：1.0（来源 `knowledge/rules.json`）
- 覆盖漏洞：3 条；结论分布：VULNERABLE 1 / SURFACE_PATCH 1 / PATCHED 1 / WAF_FULL_BLOCK 0 / INCONCLUSIVE 0
- 判定来源：`python3 src/pipeline.py` 确定性产出，全部数值由脚本与 OctoBus 网关产生，未经人工估算

---

## VULN-2026-001 用户查询接口布尔盲注

- 端点：`http://172.17.0.1:8081/api/user`（`id` 参数）
- 判定：**VULNERABLE**（依据 R-T1-01 布尔盲注双阈值）
- 关键度量：
  - `len_true` = 72，`len_false` = 27
  - `delta` = 45（经 OctoBus calculator Subtract 计算，R-CALC-01）
  - `ratio` = 0.625，阈值 `threshold` = 0.5（0.625 ≥ 0.5）
  - `sha_identical` = false（真 `38e272955835…` / 假 `fae340d3cd27…`）
  - 状态码：真/假探针均 200
- 证据文件：
  - `evidence/20261001080006-133/probe_VULN-2026-001_tautology.json`
  - `evidence/20261001080006-133/probe_VULN-2026-001_contradiction.json`

## VULN-2026-002 搜索接口反射型 XSS（历史处置：WAF 关键字拦截）

- 端点：`http://172.17.0.1:8081/search`（`q` 参数）
- 判定：**SURFACE_PATCH**（依据 R-T2-01：区分实际修复与表层变更）
- 关键度量：
  - `waf_active` = true（字面量 `<script>`：`literal_status` = 403，命中标记 `WAF-BLOCK`）
  - `bypass_reflected` = true（`<img src=x onerror=alert(1)>` 变体：`bypass_status` = 200，原样反射）
  - 变体响应摘要：`<html><body>Search results for: <img src=x onerror=alert(1)> | end</body></html>`
- 判读：拦截面仅覆盖单一关键字，标签变体仍可触达漏洞本体，属表层变更而非真实修复。
- 证据文件：
  - `evidence/20261001080006-133/probe_VULN-2026-002_literal_script.json`
  - `evidence/20261001080006-133/probe_VULN-2026-002_variant_onerror.json`

## VULN-2026-003 管理接口水平越权

- 端点：`http://172.17.0.1:8081/api/admin/secret`
- 判定：**PATCHED**（依据 R-T3-01，配合 R-STRIP-01 剥离动态头）
- 关键度量：
  - 普通请求 `plain_status` = 403；伪造 Cookie（`admin=1`）请求 `forged_status` = 403
  - `sha_identical` = true（两侧均为 `78342a0905a7…`，body 逐字节一致）
  - `headers_identical` = true（剥离 Date/Server 等动态头后一致）
  - 响应体均为 `Forbidden`
- 判读：无论是否伪造凭据均走同一条统一拒绝路径，符合统一鉴权中间件的修复特征。
- 证据文件：
  - `evidence/20261001080006-133/probe_VULN-2026-003_plain.json`
  - `evidence/20261001080006-133/probe_VULN-2026-003_forged_cookie.json`

---

## 说明与边界

- 审计留痕：本轮全部 7 次能力调用（探针 6 + calculator 1）记录于 `evidence/20261001080006-133/octobus_calls.log`，均 `ok=true`、无 `transport_errors`，故无 INCONCLUSIVE 降级项。
- 受控靶场边界（见 knowledge/03_pitfalls.md P-07）：T2 的 WAF 拦截特征串与判据同源，对真实 WAF 拦截页不具泛化性；本结论仅对该受控靶场成立。
- 未执行任何端口扫描、目录扫描或路径模糊测试；所有探针均经 `src/call_octobus.py` 调用 capset 授权方法。
