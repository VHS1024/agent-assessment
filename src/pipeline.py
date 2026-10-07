#!/usr/bin/env python3
"""漏洞复测确定性判定管线（5.1.1 / 5.1.2 对标实现）。

分工铁律：
  - Agent（LLM）：读 vulns.json 与规则文档，调度本脚本，解读报告——不做任何数值估算；
  - OctoBus 网关：探针与算术能力的唯一出口（capset 方法级授权 + 审计留痕）；
  - 本脚本：全部判定为确定性代码，判据唯一来源 knowledge/rules.json（启动加载，缺失即报错）。

用法：python3 src/pipeline.py
输出：outputs/report.json + evidence/<run_id>/（探针原始响应 + octobus_calls.log），
     stdout 打印摘要供 Agent 撰写 summary.md。
"""

import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import call_octobus  # noqa: E402

RUN_ID = time.strftime("%Y%m%d%H%M%S") + f"-{os.getpid()}"
if (REPO / "evidence" / RUN_ID).exists():  # 同 run_id 复跑会污染证据链，直接拒绝
    raise SystemExit(f"FATAL evidence 目录已存在: {RUN_ID}（同秒/同 pid 碰撞）")


def load_rules() -> dict:
    """加载机器可读判据。任一必需键缺失直接 Fatal——确保规则真实被消费而非仅作声明。"""
    raw = json.loads((REPO / "knowledge" / "rules.json").read_text(encoding="utf-8"))
    required = [
        ("version", raw.get("version")),
        ("header_strip", raw.get("header_strip")),
        ("t1", raw.get("t1")),
        ("t2", raw.get("t2")),
        ("t3", raw.get("t3")),
        ("ratio_rule", raw.get("ratio_rule")),
        ("strip_rule", raw.get("strip_rule")),
        ("error_policy", raw.get("error_policy")),
    ]
    missing = [k for k, v in required if not v]
    if missing:
        raise SystemExit(f"FATAL rules.json 缺失必需键: {missing}")
    for key in ("ratio_threshold", "expect_status", "threshold_basis", "empty_body_rule_id"):
        if key not in raw["t1"]:
            raise SystemExit(f"FATAL rules.json t1 缺失 {key}")
    return raw


def strip_headers(headers: dict, rules: dict) -> dict:
    """按 R-STRIP-01 剥离动态响应头，仅返回可参与比对的部分。"""
    banned = {h.lower() for h in rules["header_strip"]}
    return {k: v for k, v in (headers or {}).items() if k.lower() not in banned}


def _failed(probe: dict) -> bool:
    return bool(probe.get("error"))


def normalize_probe(probe: dict) -> dict:
    """把探针响应归一化为判定器使用的 snake_case 字段（返回副本，不改动原对象）。

    OctoBus Connect/JSON 模式按 protojson 规范将 body_length 等字段编码为
    lowerCamelCase（bodyLength）；不同网关/库版本命名不一致（见 03_pitfalls.md
    P-11「网关接口命名漂移：契约名 ≠ 运行时名」）。判定器只认 proto 声明的 snake_case，这里做
    防御式双命名兼容——只重排键名，不改变任何数值来源与判定语义。
    """
    aliases = {
        "bodyLength": "body_length",
        "bodySha256": "body_sha256",
        "bodyExcerpt": "body_excerpt",
        "elapsedMs": "elapsed_ms",
    }
    out = dict(probe)
    for camel, snake in aliases.items():
        if snake not in out and camel in out:
            out[snake] = out[camel]
    # protojson 零值省略（03_pitfalls.md P-13）：下列字段的「缺键」语义上等价于
    # proto3 零值，补齐以保证判定器取值不崩。实测空响应体（/status/200）时网关
    # 只回 bodySha256/elapsedMs/headers/status，缺的正是 bodyLength(0) 与 bodyExcerpt("")。
    out.setdefault("status", 0)
    out.setdefault("body_length", 0)
    out.setdefault("body_excerpt", "")
    out.setdefault("elapsed_ms", 0)
    out.setdefault("headers", {})
    # body_sha256 是例外：实测空响应体仍返回 e3b0c442…（sha256 恒为 64 位非空串），
    # 「缺 sha」只可能来自异常响应，不能按零值补成 ""——否则两个都没有哈希的探针会
    # 互相判等并凑出 PATCHED（fail-open）。此处转为显式失败，由各判定器首行的
    # _failed() 短路为 INCONCLUSIVE（fail-closed）。
    if not str(out.get("body_sha256") or "").strip() and not out.get("error"):
        out["error"] = ("MALFORMED_PROBE: 响应缺少 body_sha256"
                        "（超出 protojson 零值省略的异常形状）")
    out.setdefault("error", "")
    return out


def judge_t1(probe_true: dict, probe_false: dict, rules: dict) -> dict:
    """布尔盲注：1=1 与 1=2 响应差异显著 → VULNERABLE；一致 → PATCHED；灰区 → INCONCLUSIVE。真探针响应体为空时一律 INCONCLUSIVE（R-T1-04）。"""
    t1 = rules["t1"]
    if _failed(probe_true) or _failed(probe_false):
        return _inconclusive(rules, "R-ERR-01", probe_true, probe_false)
    if probe_true["status"] != t1["expect_status"] or probe_false["status"] != t1["expect_status"]:
        # 含「探针打偏」：靶场对无注入标记的请求返回 400（R-T1-02），打偏不会伪装成 PATCHED
        return _inconclusive(rules, f"status 非 {t1['expect_status']}",
                             probe_true, probe_false, rule_ref=t1["rule_id"])
    len_true = probe_true["body_length"]
    if len_true == 0:
        # R-T1-04：真探针响应体为空，比例的分母无意义。旧写法
        # max(len_true, 1) 兜底除法，恰好把「两个探针都空」凑成
        # ratio==0 且 sha 同为 e3b0c442…，误判 PATCHED（fail-open）。
        return _inconclusive(
            rules,
            f"真探针响应体为空（len_true={len_true}, "
            f"len_false={probe_false['body_length']}）："
            "空响应不构成判定依据",
            probe_true, probe_false, rule_ref=t1["empty_body_rule_id"])
    delta = call_octobus.subtract(
        len_true, probe_false["body_length"], RUN_ID, _next_seq())
    ratio = round(abs(delta) / len_true, 4)
    # PATCHED 的判据是「响应体逐字节一致」，故必须比对 sha256 而不只是长度：
    # 等长但内容不同（sha 不同）既不是干净修复、也不构成可用注入，转人工而非判 PATCHED。
    same_body = probe_true["body_sha256"] == probe_false["body_sha256"]
    if ratio >= t1["ratio_threshold"]:
        verdict = "VULNERABLE"
    elif ratio == 0 and same_body:
        verdict = "PATCHED"
    else:
        return _inconclusive(
            rules,
            f"未达攻击阈值且响应体不一致（ratio={ratio}, sha 相等={same_body}）",
            probe_true, probe_false, rule_ref=t1["rule_id"])
    return {
        "verdict": verdict,
        "metrics": {
            "len_true": probe_true["body_length"], "len_false": probe_false["body_length"],
            "delta": delta, "ratio": ratio, "threshold": t1["ratio_threshold"],
            "sha_identical": same_body,
            "sha_true": probe_true["body_sha256"][:12], "sha_false": probe_false["body_sha256"][:12],
        },
        "rule_refs": [t1["rule_id"], rules["ratio_rule"]["rule_id"]],
    }


def judge_t2(probe_literal: dict, probe_bypass: dict, rules: dict) -> dict:
    """反射 XSS：区分 WAF 拦截（表层变更）与真实修复。

    四态语义（R-T2-01）：
      VULNERABLE      字面量未被拦且原样反射（WAF 未生效）
      SURFACE_PATCH   字面量被拦但变体仍反射（表层变更）
      WAF_FULL_BLOCK  字面量与变体均被拦——拦截面完整，但只证明「必要条件」，
                      未证明代码层修复，单列第四态而非并入 PATCHED
      INCONCLUSIVE    其余组合（如 WAF 生效但变体行为不符合任何已知模式）
    """
    t2 = rules["t2"]
    if _failed(probe_literal) or _failed(probe_bypass):
        return _inconclusive(rules, "R-ERR-01", probe_literal, probe_bypass)
    waf_active = (probe_literal["status"] == t2["block_status"]
                  and t2["block_marker"] in probe_literal["body_excerpt"])
    bypass_reflected = (probe_bypass["status"] == t2["expect_status"]
                        and t2["reflect_marker"] in probe_bypass["body_excerpt"])
    bypass_blocked = (probe_bypass["status"] == t2["block_status"]
                      and t2["block_marker"] in probe_bypass["body_excerpt"])
    if not waf_active:
        verdict = "VULNERABLE"          # 关键字拦截未生效
    elif bypass_reflected:
        verdict = "SURFACE_PATCH"       # 拦截了字面量但变体仍反射 = 表层变更
    elif bypass_blocked:
        verdict = "WAF_FULL_BLOCK"      # 拦截面完整 = 真实修复的必要条件，非充分
    else:
        return _inconclusive(rules, "WAF 生效但变体行为不符合已知模式",
                             probe_literal, probe_bypass, rule_ref=t2["rule_id"])
    return {
        "verdict": verdict,
        "metrics": {
            "waf_active": waf_active, "bypass_reflected": bypass_reflected,
            "literal_status": probe_literal["status"],
            "bypass_status": probe_bypass["status"],
            "bypass_excerpt": probe_bypass["body_excerpt"][:120],
        },
        "rule_refs": [t2["rule_id"]],
    }


def judge_t3(probe_plain: dict, probe_forged: dict, rules: dict) -> dict:
    """水平越权：伪造凭据与普通请求响应逐字节一致（统一 403）→ PATCHED。"""
    t3 = rules["t3"]
    if _failed(probe_plain) or _failed(probe_forged):
        return _inconclusive(rules, "R-ERR-01", probe_plain, probe_forged)
    identical = (probe_plain["body_sha256"] == probe_forged["body_sha256"]
                 and strip_headers(probe_plain["headers"], rules) == strip_headers(probe_forged["headers"], rules))
    unified_403 = probe_plain["status"] == t3["forbidden_status"] and probe_forged["status"] == t3["forbidden_status"]
    verdict = "PATCHED" if (identical and unified_403) else "VULNERABLE"
    return {
        "verdict": verdict,
        "metrics": {
            "plain_status": probe_plain["status"], "forged_status": probe_forged["status"],
            "sha_identical": probe_plain["body_sha256"] == probe_forged["body_sha256"],
            "headers_identical": strip_headers(probe_plain["headers"], rules) == strip_headers(probe_forged["headers"], rules),
        },
        "rule_refs": [t3["rule_id"], rules["strip_rule"]["rule_id"]],
    }


_SEQ = {"n": 0}


def _next_seq() -> int:
    _SEQ["n"] += 1
    return _SEQ["n"]


def _inconclusive(rules, reason, *args, rule_ref: str = "R-ERR-01") -> dict:
    """统一 INCONCLUSIVE 出口。verdict 取自 rules.error_policy——规则值被真实消费，
    修改 rules.json 的 on_transport_error 会直接改变报告输出（规则被真实消费的验证）。"""
    probes = [a for a in args if isinstance(a, dict)]
    errs = [p.get("error") for p in probes if p.get("error")]
    return {
        "verdict": rules["error_policy"]["on_transport_error"],
        "metrics": {"reason": reason, "transport_errors": errs},
        "rule_refs": [rule_ref],
    }


def probe_matrix(vuln: dict) -> list[tuple[str, dict]]:
    """按漏洞类型构造探针矩阵（URL 来自 vulns.json 历史记录）。

    网关级失败（token 失效/OctoBus 宕机/HTTP 4xx-5xx）不抛出逃逸：
    返回结构化 error 对象，流入 R-ERR-01 → 该漏洞 INCONCLUSIVE，报告仍可产出。
    """
    ep = vuln["endpoint"]
    kind = vuln["type"]
    steps_def: list[tuple[str, dict]] = []
    if kind == "boolean_blind":
        steps_def = [
            ("tautology", {"url": f"{ep}?id=1%20AND%201%3D1"}),
            ("contradiction", {"url": f"{ep}?id=1%20AND%201%3D2"}),
        ]
    elif kind == "reflection_diff":
        steps_def = [
            ("literal_script", {"url": ep + "?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"}),
            ("variant_onerror", {"url": ep + "?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"}),
        ]
    elif kind == "idem_forge":
        steps_def = [
            ("plain", {"url": ep}),
            ("forged_cookie", {"url": ep, "headers": {"Cookie": "admin=1"}}),
        ]
    else:
        raise SystemExit(f"FATAL 未知漏洞类型 {kind}（vuln {vuln.get('id')}）")

    steps = []
    for name, kw in steps_def:
        try:
            probe = call_octobus.probe_http(kw["url"], RUN_ID, _next_seq(),
                                            headers=kw.get("headers"))
        except Exception as exc:  # noqa: BLE001 网关级失败 → 结构化降级（R-ERR-01）
            probe = {"status": 0, "headers": {}, "body_length": 0, "body_sha256": "",
                     "body_excerpt": "", "elapsed_ms": 0,
                     "error": f"GATEWAY: {type(exc).__name__}: {exc}"}
        steps.append((name, probe))
    return steps


JUDGES = {"boolean_blind": judge_t1, "reflection_diff": judge_t2, "idem_forge": judge_t3}


def save_evidence(vuln_id: str, step: str, probe: dict) -> str:
    d = REPO / "evidence" / RUN_ID
    d.mkdir(parents=True, exist_ok=True)
    fp = d / f"probe_{vuln_id}_{step}.json"
    fp.write_text(json.dumps(probe, ensure_ascii=False, indent=1), encoding="utf-8")
    return str(fp.relative_to(REPO))


def main() -> int:
    rules = load_rules()
    vulns = json.loads((REPO / "data" / "vulns.json").read_text(encoding="utf-8"))["vulns"]
    results = []
    for vuln in vulns:
        try:
            steps = probe_matrix(vuln)
            for name, probe in steps:
                probe["evidence_file"] = save_evidence(vuln["id"], name, probe)
            judge = JUDGES[vuln["type"]]
            outcome = judge(normalize_probe(steps[0][1]), normalize_probe(steps[1][1]), rules)
            outcome["evidence"] = [p[1]["evidence_file"] for p in steps]
        except Exception as exc:  # noqa: BLE001 兜底：单漏洞失败不影响整轮报告产出
            outcome = _inconclusive(rules, f"pipeline 异常: {type(exc).__name__}: {exc}")
            outcome["evidence"] = []
        results.append({
            "vuln_id": vuln["id"], "title": vuln["title"], "type": vuln["type"],
            **outcome,
        })

    report = {
        "run_id": RUN_ID,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "rules_version": rules["version"],
        "results": results,
        "summary": {
            "total": len(results),
            "VULNERABLE": sum(1 for r in results if r["verdict"] == "VULNERABLE"),
            "SURFACE_PATCH": sum(1 for r in results if r["verdict"] == "SURFACE_PATCH"),
            "WAF_FULL_BLOCK": sum(1 for r in results if r["verdict"] == "WAF_FULL_BLOCK"),
            "PATCHED": sum(1 for r in results if r["verdict"] == "PATCHED"),
            "INCONCLUSIVE": sum(1 for r in results if r["verdict"] == "INCONCLUSIVE"),
        },
    }
    out = REPO / "outputs"
    out.mkdir(exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"run_id={RUN_ID}")
    for r in results:
        m = r["metrics"]
        brief = m.get("ratio", m.get("waf_active", m.get("sha_identical", "")))
        print(f"  {r['vuln_id']} [{r['type']}] -> {r['verdict']}  (key={brief})")
    print(f"summary={json.dumps(report['summary'])}")
    print(f"report={out / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
