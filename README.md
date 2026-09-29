# Agent 工程师实操考核 - Agent 设计说明

## 1. 任务目标与选题
- **选题方向**：安全技术 - 漏洞复测（HTTP 响应差异对比）
- **目标**：基于 OctoBus 受控能力，实现对 HTTP 响应样本的自动化复测和证据留存。

## 2. 环境说明
- **云服务器**：阿里云 ECS，Ubuntu 22.04 LTS，4 核 8G，系统盘 40G。
- **网络拓扑**：agent-compose daemon (127.0.0.1:7410) <-> OctoBus (172.17.0.1:9000) <-> Agent Guest (通过 Docker 网络访问)。
- **安全检查**：已禁用 root 的 SSH 登录，使用普通用户 `agentadmin` 配合 sudo。

## 3. 部署步骤
1. 安装 Docker 和 Compose v2（官方源）。
2. 部署 agent-compose（本地工作区挂载方式 `provider: file`）。
3. 部署 OctoBus（端口绑定 `172.17.0.1`，仅允许容器网络访问，不对公网暴露）。
4. 配置项目层 `.env`（OCTOBUS_BASE_URL / OCTOBUS_TOKEN），配置 daemon 层 `.env`（模型凭据）。

## 4. agent-compose 配置说明
- 使用 `provider: file` 挂载本地工作区，避免国内网络拉取 GitHub 不稳定的问题。
- Agent 类型：`codex`，沙箱镜像：`ghcr.io/chaitin/agent-compose-guest:latest`。
- Scheduler：每小时触发一次（`0 * * * *`），时区 `Asia/Shanghai`。

## 5. OctoBus service/instance/capset 说明
- **Service**：`calculator`（手动编写的 gRPC 服务，实现了 Add 方法及健康检查）。
- **Instance**：`calculator-test`（运行状态良好，监听随机端口）。
- **Capset**：`dev`（最小权限，仅暴露 `calculator.v1.CalculatorService/Add` 方法，并配置了 `dev-secret` 令牌）。

## 6. Agent 与 OctoBus 的调用路径
- Agent 通过 `src/call_octobus.py` 脚本调用 OctoBus 的 Connect RPC 接口，脚本负责鉴权、请求发送和错误处理，Agent 只负责决定何时调用，不自行拼接 URL。
- 调用路径：Agent -> `src/call_octobus.py` -> OctoBus (172.17.0.1:9000) -> `calculator` 实例。

## 7. 领域知识注入说明
- 知识文件：`knowledge/00_scope.md`（定义接口契约和边界）、`knowledge/01_rules.md`（定义确定性判据和阈值）。
- 代码规则：`src/pipeline.py` 负责确定性计算（归一化、差值、比例、状态判定）。
- system_prompt 约束：禁止扫描，禁止凭空估计，必须调用已授权方法。

## 8. 规则、阈值和样本来源
- 规则编号：VR-HTTP-001。
- 阈值来源：基于本地合成样本的保守初值（差异比例 >= 0.15 判 POSITIVE，<= 0.03 判 NEGATIVE）。
- 样本：`data/fixtures/sample.json`（本地合成，无真实数据）。

## 9. 一次成功运行
- 执行命令：`ac run reviewer --prompt "读取 data/fixtures/sample.json，调用 src/call_octobus.py 计算，并输出 JSON 格式结果"`
- 运行结果：`outputs/result.json` 输出 `verdict: POSITIVE`，`difference: 250`。

## 10. 日志和证据位置
- Agent 运行日志：`ac logs --agent reviewer`
- 网关审计日志：`octobus logs --capset dev --instance calculator-test`
- 业务证据文件：`evidence/` 目录下的 `sample_summary.json` 和 `octobus_calls.log`。

## 11. 遇到的问题与处理
- **问题 1**：国内云主机无法直连 GitHub，代理不稳定（403）。
  - **处理**：切换 agent-compose 工作区为本地挂载 `provider: file`，将代码直接挂载到沙箱内。
- **问题 2**：Agent 在 OctoBus 不可达时发生过度探索行为（端口扫描）。
  - **处理**：严格约束 system_prompt，并封装 `src/call_octobus.py` 脚本，将确定性调用逻辑与 LLM 解耦。
- **问题 3**：OctoBus 实例健康检查失败。
  - **处理**：手写标准 gRPC 健康检查接口（Health Check），确保实例状态为 `running`。

## 12. 已知限制和后续改进
- 目前仅暴露了 `Add` 方法，未来可扩展 `Subtract`、`Multiply` 等能力，并配置更复杂的规则。
- 模型输出格式依赖 Prompt 约束，未来可在脚本中加入更严格的 JSON Schema 校验。

## 13. 安全说明：密钥、端口、脱敏和授权边界
- 所有敏感密钥（模型 Key、管理 Token）均存储在服务器 `.env` 中，未入库。
- OctoBus 仅绑定 `172.17.0.1:9000`，不对公网暴露。
- Agent 只能访问 Capset 暴露的 Add 方法，禁止越权。
