# 任务范围与接口契约

## 输入
- `data/fixtures/sample.json`：包含 baseline_length 和 observed_length 的样本数据。

## 授权能力
- 通过 OctoBus 网关调用 `calculator` 能力，仅暴露 `calculator.v1.CalculatorService/Add` 方法。
- 入参：`{"left": int, "right": int}`
- 出参：`{"result": int}`
- 网关地址：`http://octobus:9000`
- 鉴权令牌：从环境变量 `OCTOBUS_TOKEN` 读取，使用 `Authorization: Bearer <token>`。

## 禁止事项
- 禁止读取或输出未授权目标的敏感数据。
- 禁止执行任何形式的端口扫描、目录扫描或路径模糊测试。
