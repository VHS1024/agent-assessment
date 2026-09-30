#!/usr/bin/env python3
"""OctoBus 统一调用客户端（Agent 侧唯一合法出口）。

约定：
  - 所有能力调用（探针 / calculator）必须经本模块，禁止自行拼 URL——与
    system_prompt 红线一一对应；
  - 每次调用携带 x-octobus-ext-business-request-id（run_id + 序号），与
    OctoBus 审计日志、vulnlab 访问日志三方对账；
  - 每次调用追加一行 JSON 到 evidence/<run_id>/octobus_calls.log（真实留痕）。
"""

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = REPO / "evidence"

DEFAULT_BASE = "http://172.17.0.1:9000"  # octobus 容器绑定 docker0 网关地址


def _base() -> str:
    return os.environ.get("OCTOBUS_BASE_URL", DEFAULT_BASE).rstrip("/")


def _token() -> str:
    # 仅使用 retester 专用令牌（capset retester 最小授权）；缺失即 Fatal，
    # 不做静默回退——回退到旧 capset 令牌只会产生难排查的 403，且与最小授权叙事冲突
    tok = os.environ.get("OCTOBUS_TOKEN_RETESTER") or ""
    if not tok:
        raise RuntimeError("缺少 OCTOBUS_TOKEN_RETESTER 环境变量（capset retester 访问令牌）")
    return tok


def call_method(capset: str, instance: str, method: str, payload: dict,
                run_id: str, seq: int, timeout: float = 15.0) -> dict:
    """经 Connect 协议（JSON 模式）调用 capset 授权的实例方法。"""
    url = f"{_base()}/capsets/{capset}/connect/{instance}/{method}"
    biz_id = f"{run_id}-{seq:03d}"
    body = json.dumps(payload).encode()
    started = time.monotonic()
    ok, result, err = True, None, ""
    try:
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + _token(),
                "x-octobus-ext-business-request-id": biz_id,
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        ok = False
        err = f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}"
    except Exception as e:  # noqa: BLE001
        ok = False
        err = f"{type(e).__name__}: {e}"
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)

    _append_call_log(run_id, {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "capset": capset, "instance": instance, "method": method,
        "business_request_id": biz_id,
        "payload_summary": {k: (v if k != "headers" else "…") for k, v in payload.items()},
        "elapsed_ms": elapsed_ms, "ok": ok, "error": err,
    })
    if not ok:
        raise RuntimeError(f"OctoBus 调用失败 {method}: {err}")
    return result


def probe_http(url: str, run_id: str, seq: int, method: str = "GET",
               headers: dict | None = None, timeout_ms: int = 8000) -> dict:
    """探针调用：返回 ProbeHttpResponse 字段（error 非空 = 传输层失败，判定侧按规则处理）。"""
    return call_method(
        "retester", "retest-test", "retest.v1.RetestService/ProbeHttp",
        {"url": url, "method": method, "headers": headers or {}, "body": "",
         "timeoutMs": timeout_ms}, run_id, seq,
    )


def subtract(left: int, right: int, run_id: str, seq: int) -> int:
    """确定性差值计算经网关留审计（5.1.2：可确定性计算不由 LLM 估算）。"""
    r = call_method("retester", "calculator-test",
                    "calculator.v1.CalculatorService/Subtract",
                    {"left": left, "right": right}, run_id, seq)
    return int(r["result"])


def _append_call_log(run_id: str, record: dict) -> None:
    d = EVIDENCE_DIR / run_id
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "octobus_calls.log", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    rid = "manual-" + time.strftime("%Y%m%d%H%M%S")
    print(json.dumps(subtract(1450, 1200, rid, 1), ensure_ascii=False))
