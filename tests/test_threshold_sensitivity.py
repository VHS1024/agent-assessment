"""R-T1-03 回归防线：阈值区间敏感性 + 阈值依据被强制消费。

实测命题（见 knowledge/rules.json t1.threshold_basis）：
  1) 分离带 (0, 0.625)：未修复 ratio=0.625、已修复 ratio=0；
  2) 阈值 ∈ (0, 0.625] → VULNERABLE；> 0.625 → INCONCLUSIVE；
  3) 任意阈值下都不产生 PATCHED——上调阈值只更保守，不会假阳性。
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
import pipeline  # noqa: E402

TRUE = {"status": 200, "headers": {}, "body_length": 72, "body_sha256": "a" * 64,
        "body_excerpt": "x", "elapsed_ms": 3}
FALSE = {"status": 200, "headers": {}, "body_length": 27, "body_sha256": "b" * 64,
         "body_excerpt": "y", "elapsed_ms": 3}


@pytest.fixture(autouse=True)
def stub_subtract(monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda a, b, rid, seq: a - b)


@pytest.fixture()
def rules():
    return pipeline.load_rules()


def _verdict(rules, threshold):
    r = json.loads(json.dumps(rules))
    r["t1"]["ratio_threshold"] = threshold
    return pipeline.judge_t1(TRUE, FALSE, r)["verdict"]


@pytest.mark.parametrize("th", [0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.625])
def test_below_separation_is_vulnerable(rules, th):
    assert _verdict(rules, th) == "VULNERABLE"


@pytest.mark.parametrize("th", [0.63, 0.70, 0.90, 1.00])
def test_above_separation_is_inconclusive(rules, th):
    assert _verdict(rules, th) == "INCONCLUSIVE"


@pytest.mark.parametrize("th", [0.05, 0.20, 0.50, 0.625, 0.70, 1.00])
def test_never_patched_for_unpatched_target(rules, th):
    assert _verdict(rules, th) != "PATCHED"


def test_threshold_basis_declared(rules):
    assert rules["t1"]["threshold_basis"].strip()


def test_missing_threshold_basis_is_fatal(tmp_path, monkeypatch):
    d = json.loads((REPO / "knowledge" / "rules.json").read_text(encoding="utf-8"))
    del d["t1"]["threshold_basis"]
    (tmp_path / "knowledge").mkdir()
    (tmp_path / "knowledge" / "rules.json").write_text(json.dumps(d), encoding="utf-8")
    monkeypatch.setattr(pipeline, "REPO", tmp_path)
    with pytest.raises(SystemExit):
        pipeline.load_rules()
