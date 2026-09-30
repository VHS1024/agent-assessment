"""判定器单测：不依赖网络与网关（calculator Subtract 打桩）。

覆盖：三类判定器的全部判定位、R-ERR-01 传输失败、R-STRIP-01 头剥离、
rules.json 必需键校验、探针矩阵 URL 构造。
"""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import pipeline  # noqa: E402


@pytest.fixture(scope="module")
def rules():
    return pipeline.load_rules()


def _probe(status=200, length=100, sha="a" * 64, excerpt="", error="", headers=None):
    return {
        "status": status, "headers": headers or {}, "body_length": length,
        "body_sha256": sha, "body_excerpt": excerpt, "elapsed_ms": 1.0, "error": error,
    }


# ── rules.json 消费性 ──

def test_rules_required_keys(rules):
    assert rules["header_strip"]
    assert "ratio_threshold" in rules["t1"] and "expect_status" in rules["t1"]
    for key in ("block_status", "block_marker", "reflect_marker", "expect_status"):
        assert key in rules["t2"]
    assert "forbidden_status" in rules["t3"]
    assert rules["error_policy"]["on_transport_error"] == "INCONCLUSIVE"


# ── R-STRIP-01 头剥离 ──

def test_strip_headers(rules):
    h = {"Date": "now", "Set-Cookie": "sid=1", "content-type": "application/json"}
    stripped = pipeline.strip_headers(h, rules)
    assert stripped == {"content-type": "application/json"}


# ── T1 布尔盲注 ──

def test_t1_vulnerable(rules, monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=140), _probe(length=30), rules)
    assert out["verdict"] == "VULNERABLE"
    assert out["metrics"]["delta"] == 110
    assert out["metrics"]["ratio"] == pytest.approx(0.7857, abs=1e-3)


def test_t1_patched_identical(rules, monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=100), _probe(length=100), rules)
    assert out["verdict"] == "PATCHED"


def test_t1_gray_zone_inconclusive(rules, monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=100), _probe(length=80), rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T1-01"]  # 灰区归因到判定规则，非传输错误


def test_t1_status_mismatch_inconclusive(rules):
    # 假探针打偏：靶场对无注入标记返回 400 → 状态异常 → INCONCLUSIVE（非 PATCHED）
    out = pipeline.judge_t1(_probe(length=140), _probe(status=400, length=40), rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T1-01"]


def test_t1_transport_error_consumes_rules(rules, monkeypatch):
    # 规则消费性验证：verdict 取自 rules.error_policy，改值即改输出（规则被真实消费）
    out = pipeline.judge_t1(_probe(error="TIMEOUT: x"), _probe(length=60), rules)
    assert out["verdict"] == rules["error_policy"]["on_transport_error"]
    mutated = dict(rules)
    mutated["error_policy"] = {**rules["error_policy"], "on_transport_error": "MANUAL_REVIEW"}
    out2 = pipeline.judge_t1(_probe(error="TIMEOUT: x"), _probe(length=60), mutated)
    assert out2["verdict"] == "MANUAL_REVIEW"


# ── T2 反射 XSS（表层变更场景）──

def test_t2_surface_patch(rules):
    lit = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    byp = _probe(excerpt='<html><body>Search results for: <img src=x onerror=alert(1)> | end</body></html>')
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "SURFACE_PATCH"


def test_t2_vulnerable_waf_off(rules):
    lit = _probe(excerpt='<html><body>Search results for: <script>alert(1)</script> | end</body></html>')
    byp = _probe(excerpt='onerror=alert(1)')
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "VULNERABLE"


def test_t2_waf_full_block_not_patched(rules):
    # 双拦 = 拦截面完整，仅必要条件 → 第四态 WAF_FULL_BLOCK，不并入 PATCHED
    lit = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    byp = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "WAF_FULL_BLOCK"


def test_t2_inconclusive_unknown_pattern(rules):
    # WAF 生效但变体行为不符合任何已知模式 → INCONCLUSIVE
    lit = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    byp = _probe(status=500, excerpt="internal error")
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T2-01"]


# ── T3 水平越权 ──

def test_t3_patched_identical_forbidden(rules):
    same = _probe(status=403, sha="f" * 64)
    out = pipeline.judge_t3(same, _probe(status=403, sha="f" * 64), rules)
    assert out["verdict"] == "PATCHED"


def test_t3_vulnerable_data_difference(rules):
    out = pipeline.judge_t3(
        _probe(status=200, sha="1" * 64), _probe(status=200, sha="2" * 64), rules)
    assert out["verdict"] == "VULNERABLE"


def test_t3_header_difference_only(rules):
    # 体相同但剥离后响应头不同 → 存在差异面 → VULNERABLE
    out = pipeline.judge_t3(
        _probe(status=403, sha="f" * 64, headers={"content-type": "text/plain"}),
        _probe(status=403, sha="f" * 64, headers={"content-type": "application/json"}),
        rules)
    assert out["verdict"] == "VULNERABLE"


# ── 探针矩阵（URL 构造正确性 + 网关级失败兜底）──

def test_probe_matrix_urls(monkeypatch):
    captured = []

    def fake_probe(url, rid, seq, method="GET", headers=None, timeout_ms=8000):
        captured.append((url, headers or {}))
        return _probe()

    monkeypatch.setattr(pipeline.call_octobus, "probe_http", fake_probe)
    for kind in ("boolean_blind", "reflection_diff", "idem_forge"):
        pipeline.probe_matrix({"endpoint": "http://172.17.0.1:8081/x", "type": kind})
    urls = [u for u, _ in captured]
    assert "1%3D1" in urls[0] and "1%3D2" in urls[1]
    assert "script" in urls[2] and "onerror" in urls[3]
    assert captured[5][1].get("Cookie") == "admin=1"


def test_probe_matrix_gateway_failure_degrades(monkeypatch):
    # 网关级失败（token 失效/OctoBus 宕机）不抛出逃逸：结构化降级 → R-ERR-01 路径
    def boom(url, rid, seq, method="GET", headers=None, timeout_ms=8000):
        raise RuntimeError("HTTP 403: token expired")

    monkeypatch.setattr(pipeline.call_octobus, "probe_http", boom)
    steps = pipeline.probe_matrix({"endpoint": "http://172.17.0.1:8081/x",
                                   "type": "boolean_blind"})
    assert all(s[1]["error"].startswith("GATEWAY:") for s in steps)
    assert all(s[1]["status"] == 0 for s in steps)


def test_probe_matrix_unknown_type():
    with pytest.raises(SystemExit):
        pipeline.probe_matrix({"endpoint": "http://x", "type": "unknown_kind"})
