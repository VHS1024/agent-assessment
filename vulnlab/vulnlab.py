#!/usr/bin/env python3
"""vulnlab —— 漏洞复测三态靶场（python3 标准库，零第三方依赖）。

用途：为「漏洞复测 Agent」提供本地受控目标，内置三个历史漏洞的三种真实修复状态，
对标「区分实际修复与表层变更」的复测目标：

  T1 VULN-2026-001 布尔盲注   /api/user?id=...      → 未修复（UNPATCHED）
     1=1 返回完整记录、1=2 返回空记录，响应长度差显著 → 注入有效 → VULNERABLE
  T2 VULN-2026-002 反射型 XSS /search?q=...         → 表层变更（SURFACE_PATCH）
     字面 <script 关键字被 WAF 拦截（403 固定特征页），但 <img onerror> 编码变体
     原样反射 → 拦截而非修复 → SURFACE_PATCH
  T3 VULN-2026-003 水平越权   /api/admin/secret     → 已修复（PATCHED）
     无论是否伪造 Cookie，一律 403 + 逐字节相同的通用页（sha256 一致）→ PATCHED

确定性保证（可复测的前提）：
  - 响应体逐字节稳定：无时间戳、无随机数、无动态字段；
  - 动态响应头（Date 等）由判定侧按 knowledge/rules.json 剥离，不参与比对；
  - 每个请求写一行访问日志（含 UA 特征），可与 OctoBus 审计日志交叉核对，
    检测「绕过网关直连靶场」的行为。

绑定：默认 172.17.0.1:8081（docker0 网关地址）——容器可达、宿主机可达、公网不可达。
     注意：172.17.0.1 依赖 docker0 接口存在，因此 systemd 单元配置 Restart=always
     以在 docker 启动前失败重试（详见坑点手册）。
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus

HOST = os.environ.get("VULNLAB_HOST", "172.17.0.1")
PORT = int(os.environ.get("VULNLAB_PORT", "8081"))
LOG_PATH = os.environ.get("VULNLAB_LOG", "/var/log/vulnlab.log")

PROBE_UA_MARKER = "octobus-retest-probe"  # 探针 UA 特征：日志交叉核对用

# ── 固定响应体（逐字节确定性）───────────────────────────────────────────

BODY_USER_RECORD = json.dumps(
    {"id": 1, "user": "admin", "role": "user", "balance": "1000", "status": "active"},
    separators=(",", ":"),
).encode()

BODY_USER_EMPTY = json.dumps({"result": "empty", "rows": 0}, separators=(",", ":")).encode()

BODY_WAF_BLOCK = (
    "WAF-BLOCK: keyword policy violation (rule: xss-keyword-001)"
).encode()

BODY_ADMIN_FORBIDDEN = b"Forbidden"

BODY_HEALTHZ = b"ok"

LOG_LOCK = threading.Lock()


def write_log(line: str) -> None:
    with LOG_LOCK:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            print(line, file=sys.stderr)  # 日志文件不可写时降级 stderr，不影响响应


class VulnLabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "vulnlab/1.0"

    # ── 基础设施 ──
    def log_message(self, fmt, *args):  # 吞掉默认 stderr 日志，统一走 write_log
        pass

    def _respond(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self) -> None:
        # 访问日志：与 OctoBus 审计日志交叉核对，检测绕网关直连
        ua = self.headers.get("User-Agent", "")
        marker = PROBE_UA_MARKER if PROBE_UA_MARKER in ua else "direct-or-other"
        write_log(
            f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}|{self.client_address[0]}|"
            f"{self.command}|{self.path}|{marker}"
        )

        path, _, query = self.path.partition("?")
        params = parse_qs(query, keep_blank_values=True)
        first = lambda key: (params.get(key) or [""])[0]  # noqa: E731

        if path == "/healthz":
            self._respond(200, BODY_HEALTHZ)

        # ── T1 布尔盲注（未修复）──
        elif path == "/api/user":
            q = unquote_plus(query).lower()
            if "1=1" in q:
                self._respond(200, BODY_USER_RECORD, "application/json")
            elif "1=2" in q:
                self._respond(200, BODY_USER_EMPTY, "application/json")
            else:
                # 无注入标记 → 400：让「探针打偏」（payload 未按预期到达）表现为
                # 状态码异常 → 判定侧 INCONCLUSIVE，堵死「打偏被误判为已修复」的假阴性通道
                self._respond(400, b"bad request: missing injection marker")

        # ── T2 反射型 XSS（表层变更：WAF 关键字拦截，非真实修复）──
        elif path == "/search":
            q = unquote_plus(first("q"))
            if "<script" in q.lower():
                self._respond(403, BODY_WAF_BLOCK)  # 关键字拦截：只挡这一个特征
            else:
                # 原样反射（不转义）——漏洞本体仍在，编码/变体即可触达
                body = f"<html><body>Search results for: {q} | end</body></html>".encode()
                self._respond(200, body, "text/html; charset=utf-8")

        # ── T3 水平越权（已修复：统一 403，逐字节一致）──
        elif path == "/api/admin/secret":
            self._respond(403, BODY_ADMIN_FORBIDDEN)

        else:
            self._respond(404, b"not found")

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), VulnLabHandler)
    server.daemon_threads = True
    write_log(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}|vulnlab|START|{HOST}:{PORT}")
    print(f"vulnlab serving on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
