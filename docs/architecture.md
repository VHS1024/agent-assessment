# 架构说明

> 配套 README.md 阅读。第 1 节为分层架构与数据流，第 2 节说明三层职责划分，第 3 节为端口与暴露面。

## 1. 分层架构与数据流

```mermaid
flowchart TB
    subgraph L1["① 触发层"]
        direction LR
        T1["agent-compose scheduler<br/>cron 每小时 · Asia/Shanghai"]
        T2["手动触发<br/>ac run reviewer --prompt …"]
    end

    subgraph L2["② 运行时（agent-compose）"]
        direction LR
        D["agent-compose daemon<br/>127.0.0.1:7410（仅本机）"]
        G["guest 容器<br/>agent-compose-guest@sha256:a9958462…<br/>workspace: mount（产物落宿主机）"]
    end

    subgraph L3["③ Agent（LLM · codex provider）——只读与调度，不做数值估算"]
        direction LR
        A1["读 data/vulns.json<br/>读 knowledge/01_rules.md · 03_pitfalls.md"]
        A2["调度 python3 src/pipeline.py"]
        A3["读 outputs/report.json<br/>撰写 outputs/summary.md"]
    end

    subgraph L4["④ 判定层（确定性代码，不含 LLM）"]
        direction LR
        P["src/pipeline.py<br/>probe_matrix + judge_t1 / t2 / t3"]
        R["knowledge/rules.json<br/>唯一判据来源（启动加载，缺失即 Fatal）"]
    end

    subgraph L5["⑤ 出口层（Agent 侧唯一合法出口）"]
        C["src/call_octobus.py<br/>Bearer + x-octobus-ext-business-request-id"]
    end

    subgraph L6["⑥ OctoBus 网关（能力唯一出口 · 172.17.0.1:9000）"]
        direction LR
        CS["capset retester<br/>方法级最小授权"]
        I1["instance retest-test<br/>→ ProbeHttp"]
        I2["instance calculator-test<br/>→ Subtract（仅授权此一方法）"]
    end

    subgraph L7["⑦ 能力包与目标"]
        direction LR
        SP["services/retest-probe<br/>出口白名单 fail-closed · UA 固定"]
        VL["vulnlab 三态靶场<br/>172.17.0.1:8081（systemd 自愈）"]
    end

    subgraph L8["⑧ 证据链（三方对账）"]
        direction LR
        E1["evidence/&lt;run_id&gt;/<br/>probe_*.json + octobus_calls.log"]
        E2["outputs/<br/>report.json + summary.md"]
        E3["网关审计 octobus logs --capset<br/>靶场日志 /var/log/vulnlab.log"]
    end

    T1 --> D
    T2 --> D
    D --> G
    G --> A1
    A1 --> A2
    A2 --> A3
    A2 --> P
    R -. 判据 .-> P
    P --> C
    C --> CS
    CS --> I1
    CS --> I2
    I1 --> SP
    SP --> VL
    I2 --> VL
    P --> E1
    A3 --> E2
    CS --> E3
    VL --> E3
```

## 2. 三层职责划分

| 层 | 做什么 | 不做什么 | 依据 |
|---|---|---|---|
| Agent（LLM，codex provider） | 读记录与规则、调度管线、解读报告、撰写结论摘要 | 不做任何数值估算，不绕过网关直连目标 | `agent-compose.yml` 的 `system_prompt` |
| OctoBus 网关 | 方法级授权、探针出口白名单、全程审计留痕、能力契约 | 不做安全判定 | `services/retest-probe/config.schema.json`、`bin/probe.js` 的 `assertEgressAllowed` |
| 代码工件 | 取数、比对、比例、哈希；判据装载与校验 | —— | `src/pipeline.py` + `knowledge/rules.json` |

判定逻辑放在 `src/pipeline.py`，没有下沉为 OctoBus 能力包，原因有四条：

1. 考核 5.1.2 要求「可确定性计算的部分（取数、统计、格式校验、评分）应由代码实现」，判定属确定性计算；
2. 下沉只是给一个纯函数多加一次网络往返和一个故障面（同类取舍见 `knowledge/03_pitfalls.md` P-04）；
3. 判定逻辑与 `rules.json` 同版本演进，下沉后「能力包版本」和「判据版本」要分两处维护；
4. 判定的全部输入（探针原始响应、减法差值）都已经过网关并留审计，本地算不减损证据链。

OctoBus 承担的是安全控制，不是安全判定。

## 3. 端口与暴露面

| 组件 | 绑定地址 | 可达范围 |
|---|---|---|
| agent-compose daemon | `127.0.0.1:7410` | 仅本机 |
| OctoBus daemon | `172.17.0.1:9000` | 仅 docker0 内网（guest 容器内经 `http://octobus:9000` 访问） |
| vulnlab 靶场 | `172.17.0.1:8081` | 仅 docker0 内网 |

三个端口均未绑定 `0.0.0.0`，不对公网暴露（`sudo ss -tlnp` 可验）。
