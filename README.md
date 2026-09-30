# agent-assessment —— 漏洞复测 Agent（基于 agent-compose + OctoBus）

> 交付基线：agent-compose v2609.4.0 · OctoBus v0.5.0 · 单机部署（阿里云 Ubuntu 22.04）

## 1. 项目简介

本项目实现一个**漏洞复测 Agent**：依据历史漏洞记录自动复测，并输出「未修复 / 表层变更 / 已修复」三态判定。核心设计是三层分工：

| 层 | 角色 | 边界 |
|---|---|---|
| Agent（LLM，codex provider） | 读记录、调度管线、解读报告 | 不做任何数值估算（system_prompt 红线） |
| OctoBus 网关 | 能力唯一出口 | capset 方法级授权 + 全程审计留痕 + 探针出口白名单 |
| pipeline.py（确定性脚本） | 全部判定逻辑 | 判据唯一来源 knowledge/rules.json，启动加载、缺失即 Fatal |

一句话：**LLM 负责「想」，网关负责「管」，脚本负责「判」**——判定不经过任何概率环节，同一输入永远得到同一结论。

## 2. 登录信息

- SSH：`ssh <用户名>@<服务器IP> -p <端口>`（运维访问公钥已就位 `authorized_keys`，权限 700/600）
- agent-compose daemon：`127.0.0.1:7410`（仅本机）
- OctoBus daemon：`172.17.0.1:9000`（docker0 网关地址，仅内网）
- vulnlab 靶场：`172.17.0.1:8081`（仅内网）
- 项目目录：`~/agent-assessment`

> 三个服务端口均**未绑定 0.0.0.0**，不对公网暴露（`ss -tlnp` 可验）。

## 3. 快速验证（约 10 分钟）

> 逐条命令 + 成功/异常判据的完整实施手册见 **RUNBOOK.md**（Phase 2-6：上传→接线→全链路→自愈实测→推送）。

```bash
# ① 靶场存活（systemd 自愈服务）
systemctl is-active vulnlab && curl -s http://172.17.0.1:8081/healthz

# ② 网关三层链路（service → instance → capset）
docker exec octobus octobus instance list
docker exec octobus octobus capset list-methods retester

# ③ 手动触发一轮完整复测
cd ~/agent-assessment && ac run reviewer --prompt "读取 data/vulns.json 与 knowledge/01_rules.md，执行 python3 src/pipeline.py 完成三条历史漏洞的复测，阅读 outputs/report.json，撰写 outputs/summary.md 结论摘要。禁止自行估算任何数值。"

# ④ 看判定结果与证据链
cat outputs/report.json | python3 -m json.tool
ls evidence/
docker exec octobus octobus logs --capset retester --tail 10   # 网关审计
sudo tail -10 /var/log/vulnlab.log                              # 靶场访问日志（UA 可见探针来源）
```

**预期结果**：`VULN-2026-001 → VULNERABLE`（盲注未修复）、`VULN-2026-002 → SURFACE_PATCH`（WAF 只拦关键字，变体仍反射）、`VULN-2026-003 → PATCHED`（统一 403 逐字节一致）。

## 4. 三条历史漏洞与三态判定

| 漏洞 | 类型 | 靶场状态 | 判定路径 |
|---|---|---|---|
| VULN-2026-001 布尔盲注 | boolean_blind | **未修复**：`1=1` 返回完整记录、`1=2` 返回空记录 | 长度差经网关 Subtract 计算，比例 ≥ 0.5 → VULNERABLE |
| VULN-2026-002 反射 XSS | reflection_diff | **表层变更**：`<script>` 被 WAF 403，但 `<img onerror>` 变体仍原样反射 | 双探针：拦截存在 + 变体可达 → SURFACE_PATCH |
| VULN-2026-003 水平越权 | idem_forge | **已修复**：伪造 Cookie 与普通请求均统一 403、响应逐字节一致 | SHA-256 + 剥离动态头后全等 → PATCHED |

「表层变更」态是三态判定的设计要点：**判定不看「有没有拦截动作」，看「变体是否仍可触达漏洞本体」**——WAF 关键字拦截是最常见的表层修复。判定器还支持第四态 `WAF_FULL_BLOCK`（字面量与变体均被拦）：拦截面完整只是真实修复的必要条件，单列不并入 PATCHED（见 knowledge/01_rules.md R-T2-01）。

## 4.5 从零部署（可复制粘贴）

```bash
# ① OctoBus daemon（named volume 持久化，绑 docker0 网关地址）
docker run -d --name octobus --restart=always \
  -p 172.17.0.1:9000:9000 \
  -v octobus-data:/var/lib/octobus \
  ghcr.io/chaitin/octobus:v0.5.0

# ② 容器内 npm 换国内源（service import 时 daemon 会在容器内 npm install）
docker exec octobus npm config set registry https://registry.npmmirror.com

# ③ 导入 retest-probe 能力包（3.3 核心动作）
docker cp services/retest-probe octobus:/tmp/retest-probe
docker exec octobus octobus service import retest-probe /tmp/retest-probe

# ④ 创建实例（出口白名单 fail-closed：只允许打靶场）
docker exec octobus octobus instance create retest-test --service retest-probe \
  --config-json '{"allowedHosts":["172.17.0.1:8081"]}' --no-start
docker exec octobus octobus instance start retest-test

# ⑤ 创建 capset：方法级最小授权（探针全量 + calculator 仅 Subtract）
docker exec octobus octobus capset create retester --name "Retest Agent"
docker exec octobus octobus capset add-instance retester retest-test --no-all-methods
docker exec octobus octobus capset select-method retester retest-test retest.v1.RetestService/ProbeHttp
docker exec octobus octobus capset add-instance retester calculator-test --no-all-methods
docker exec octobus octobus capset select-method retester calculator-test calculator.v1.CalculatorService/Subtract

# ⑥ 生成访问令牌（stdin 方式，不落 shell history）
openssl rand -hex 24 | docker exec -i octobus octobus capset add-token retester retester-agent --name "assessment agent" --token-stdin

# ⑦ 靶场安装（宿主机 systemd，非容器）
sudo mkdir -p /opt/vulnlab
sudo cp vulnlab/vulnlab.py /opt/vulnlab/vulnlab.py
sudo cp vulnlab/vulnlab.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vulnlab

# ⑧ 项目层 .env（三键，令牌来自 ⑥）
cat > .env <<'EOF'
OCTOBUS_BASE_URL=http://172.17.0.1:9000
OCTOBUS_TOKEN_RETESTER=<粘贴⑥生成的令牌>
EOF

# ⑨ 应用项目并跑通一轮
cd ~/agent-assessment && ac up
```

## 5. 目录结构

```
agent-assessment/
├── agent-compose.yml          # Agent 定义（provider/driver/workspace/env/scheduler）
├── RUNBOOK.md                 # 实施运行手册（Phase 2-6，逐条命令+成功/异常判据）
├── .env                       # OCTOBUS_BASE_URL / OCTOBUS_TOKEN_RETESTER（不入库）
├── services/retest-probe/     # 自研 OctoBus 能力包：受控 HTTP 探针
│   ├── service.json           #   包清单（schema chaitin.octobus.service.v1）
│   ├── proto/retest.proto     #   ProbeHttp 能力契约（status/length/sha256/excerpt/error）
│   ├── bin/probe.js           #   实现：出口白名单 fail-closed，只测量不判定
│   └── config.schema.json     #   allowedHosts 出口白名单
├── vulnlab/                   # 三态靶场（宿主机 systemd 服务，非容器）
├── src/
│   ├── call_octobus.py        # 网关统一调用客户端（Bearer + business-request-id + 调用留痕）
│   └── pipeline.py            # 确定性判定管线（探针矩阵 + 三类判定器 + 报告产出）
├── knowledge/
│   ├── rules.json             # 机器可读判据（pipeline 唯一判据来源）
│   ├── 01_rules.md            # 人类可读规则（规则 ID 与 json 一一对应）
│   └── 03_pitfalls.md         # 误判经验与工程取舍
├── data/vulns.json            # 三条历史漏洞记录（复测依据）
├── tests/                     # 判定器单测（不依赖网络）
├── outputs/report.json        # 复测报告（每轮覆盖）
└── evidence/<run_id>/         # 每轮证据：探针原始响应 + octobus_calls.log
```

## 6. calculator 链路定位（为何保留）

calculator 是本项目第一个接入 OctoBus 的能力，**有意保留**，定位有三：

1. **算术审计载体**：盲注判定的长度差值经 `calculator.v1.CalculatorService/Subtract` 计算——确定性计算也过网关留审计，是 5.1.2「LLM 与脚本分工」的可审计实现，而非口头原则；
2. **capset 最小授权演示**：`retester` capset 对 retest-test 授权全量方法、对 calculator-test **仅授权 Subtract 一个方法**（`--no-all-methods` + `select-method`）——「按角色而非按服务授权」的活示例；
3. **金丝雀**：已验证的最小链路，新能力包异常时可二分定位「网关问题 vs 包问题」。

它不参与业务判定路径的核心逻辑（只承担差值这一步），不是装饰性组件。

## 7. 安全边界

- **网关方法级授权**：capset `retester` 白名单到单个方法（ProbeHttp、Subtract）；
- **Agent 行为边界**：system_prompt 明令禁止端口/目录扫描与路径模糊测试，仅允许调用 capset 授权方法；网关不可达时输出 INCONCLUSIVE 并停止，不降级、不绕行；
- **探针出口白名单**：retest-probe 实例 config `allowedHosts=["172.17.0.1:8081"]`，fail-closed——白名单外的目标一律拒绝（网关授权之外的第二层出口控制）；
- **绕网关检测**：探针 UA 固定 `octobus-retest-probe/1.0`，靶场访问日志与 OctoBus 审计日志逐笔可对账，guest 直连靶场会以 `direct-or-other` 标记暴露；
- **端口边界**：三服务均绑定 127.0.0.1 / 172.17.0.1，不对公网暴露；
- **凭据**：`.env` 不入库；capset token 经 stdin 生成；git 历史经全量扫描无密钥残留（`git log --all -p` 正则 0 命中）。

## 8. 自愈与可用性

| 组件 | 自愈机制 |
|---|---|
| agent-compose daemon | Docker `restart=always`，SQLite 恢复 project/run 状态 |
| OctoBus daemon | Docker `restart=always`，named volume `octobus-data` 持久化服务包/capset/token，instance 自动恢复 |
| vulnlab | systemd `Restart=always`（依赖 docker0 就绪，启动竞态由重试兜底） |

整机 `sudo reboot` 实测：双 daemon 自动拉起、instance 自动恢复、capset 配置零漂移（重启前后 `capset list` diff 为空）、端到端复测重跑通过。证据见 `evidence/reboot-*/`。

## 9. 遇到的问题与处理

- **服务器直连 github.com:443 超时**：推送改用 Deploy Key + `ssh.github.com:443`；代码上传用 scp 直传；
- **宿主机 octobus CLI 误报 daemon not running**：daemon 绑 172.17.0.1 而 CLI 默认连 127.0.0.1——管理操作统一走 `docker exec octobus octobus ...`；
- **ac CLI 必须在项目目录内执行**：daemon 以 agent-compose.yml 为上下文，home 下执行报「找不到文件」；
- **vulnlab 绑 172.17.0.1 的启动竞态**：docker 未就绪时 bind 失败，systemd `Restart=always` 每 3 秒重试至 docker0 就绪。

## 10. 交付自检清单

- [x] 两套服务重启自愈（docker restart + 整机 reboot 双实测）
- [x] SSH 公钥落位（权限 700/600）
- [x] `ac run` 端到端可查询（outputs/report.json + evidence/）
- [x] 至少一轮完整运行留痕（outputs + evidence + 双侧审计日志）
- [x] 仓库无明文密钥（历史全量正则扫描 0 命中；token 仅存 .env 与 OctoBus 库）
- [x] 服务不对公网暴露（ss -tlnp 全部 127.0.0.1 / 172.17.0.1）
