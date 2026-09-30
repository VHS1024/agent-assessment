#!/usr/bin/env node
// retest-probe: HTTP 探针能力（OctoBus service package）
// 职责边界：只做「测量」，不做「判定」——判定由 Agent 侧 src/pipeline.py 确定性完成。
// 出口控制：实例 config.allowedHosts 白名单（fail-closed，未配置 = 全部拒绝），
//           这是网关方法级授权（capset）之外的第二层出口控制。

import crypto from "node:crypto";

import { defineService, runServiceMain } from "@chaitin-ai/octobus-sdk";

const USER_AGENT = "octobus-retest-probe/1.0";
const ALLOWED_METHODS = new Set(["GET", "POST", "HEAD"]);
const EXCERPT_CHARS = 200;

// 归一化 host:port（缺省端口按协议补全），便于白名单精确匹配
function canonicalHost(hostname, port, protocol) {
  const p = port || (protocol === "https:" ? "443" : "80");
  return `${hostname.toLowerCase()}:${p}`;
}

function assertEgressAllowed(rawUrl, allowedHosts) {
  if (!Array.isArray(allowedHosts) || allowedHosts.length === 0) {
    throw new Error("EGRESS_DENIED: allowedHosts 未配置或为空，探针 fail-closed 拒绝所有目标");
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`EGRESS_DENIED: 无法解析目标 URL: ${rawUrl}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`EGRESS_DENIED: 仅允许 http/https，收到 ${parsed.protocol}`);
  }
  const target = canonicalHost(parsed.hostname, parsed.port, parsed.protocol);
  const allow = new Set(
    allowedHosts.map((h) => {
      const [host, port] = String(h).trim().split(":");
      return canonicalHost(host, port, "http:");
    }),
  );
  if (!allow.has(target)) {
    throw new Error(`EGRESS_DENIED: ${target} 不在出口白名单内（allowedHosts=${[...allow].join(",")}）`);
  }
}

// 消毒控制字符，保证 excerpt 可安全进入 JSON/日志/审计
function sanitizeExcerpt(buf) {
  const head = buf.subarray(0, EXCERPT_CHARS * 4).toString("utf8");
  return head
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "\uFFFD")
    .slice(0, EXCERPT_CHARS);
}

function headersToPlain(headers) {
  const out = {};
  for (const [k, v] of headers.entries()) {
    out[k] = v; // set-cookie 等多值头由 Headers 联合为逗号串；判定侧按 rules 剥离动态头
  }
  return out;
}

async function probeHttp(ctx) {
  const req = ctx.request;
  const config = ctx.config ?? {};

  // 传输层错误不抛异常：以 error 字段结构化返回，判定侧可确定性分类（rules.error_policy）
  const fail = (msg) => ({
    status: 0,
    headers: {},
    body_length: 0,
    body_sha256: "",
    body_excerpt: "",
    elapsed_ms: 0,
    error: msg,
  });

  try {
    assertEgressAllowed(req.url, config.allowedHosts);

    const method = (req.method || "GET").toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
      return fail(`EGRESS_DENIED: 方法 ${method} 不在探针白名单（${[...ALLOWED_METHODS].join("/")}）`);
    }

    const timeoutMs = req.timeoutMs > 0 ? Math.min(req.timeoutMs, 30000) : 8000;
    // UA 强制覆盖调用方传入值（spread 顺序不可反转）：靶场访问日志靠此特征与
    // OctoBus 审计日志对账、检测绕网关直连——README §7 安全声明的前提
    const headers = { ...(req.headers || {}), "User-Agent": USER_AGENT };
    const hasBody = method !== "GET" && method !== "HEAD" && req.body && req.body.length > 0;

    const started = Date.now();
    const res = await fetch(req.url, {
      method,
      headers,
      body: hasBody ? req.body : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const elapsed = Date.now() - started;

    return {
      status: res.status,
      headers: headersToPlain(res.headers),
      body_length: buf.length,
      body_sha256: crypto.createHash("sha256").update(buf).digest("hex"),
      body_excerpt: sanitizeExcerpt(buf),
      elapsed_ms: elapsed,
      error: "",
    };
  } catch (err) {
    const name = err?.name === "TimeoutError" || err?.name === "AbortError" ? "TIMEOUT" : "TRANSPORT_ERROR";
    return fail(`${name}: ${err?.message ?? String(err)}`);
  }
}

const service = defineService({
  handlers: {
    "retest.v1.RetestService/ProbeHttp": probeHttp,
  },
});

runServiceMain(service);
