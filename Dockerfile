# agent-assessment 考核兼容性 Dockerfile
# 说明：本项目主部署方式为 agent-compose（ac up），guest 镜像通过 workspace mount 挂载代码。
# 本 Dockerfile 仅提供可复现的 Python 运行时环境，不包含项目代码（代码由 agent-compose 挂载）。

FROM python:3.11-slim

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制并安装 Python 依赖
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# 创建非 root 用户
RUN useradd -m -u 1000 agent

# 工作目录（agent-compose 会挂载项目代码到此）
WORKDIR /app

# 切换到非 root 用户
USER agent

# 默认命令：保持容器运行（实际命令由 agent-compose 注入）
CMD ["tail", "-f", "/dev/null"]
