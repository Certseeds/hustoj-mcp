# hustoj-mcp

一个面向 HUSTOJ 的本地 Model Context Protocol (MCP) 辅助工具，目前正在逐步实现以下能力：

- 使用网页登录凭据并安全地将会话 Cookie 持久化到本地。
- 在启动 MCP 服务前，通过命令行辅助完成验证码获取与登录校验。
- 为后续题目描述抓取、竞赛列表获取、提交代码等功能提供基础 HTTP 客户端封装。

## 运行前提

- Python 3.13（项目使用 [uv](https://github.com/astral-sh/uv) 进行依赖管理）。
- HUSTOJ 目标站点可从本地网络访问。

## 安装依赖

```powershell
uv sync
```

## 命令行用法

当前的 `main.py` 提供了一个简易 CLI，帮助在启动 MCP 服务前完成登录验证与会话保存。

### 登录并保存会话

```powershell
uv run python main.py login --domain https://oj.example.com --user your_id
```

若未传入 `--password` 将在终端中安全提示输入。若站点启用了验证码，可配合 `captcha` 子命令先下载验证码图片，再回到 `login` 命令中通过 `--vcode` 传入。

### 获取验证码

```powershell
uv run python main.py captcha --domain https://oj.example.com --output captcha.jpg
```

命令会自动在 `sessions` 目录中为指定 `--profile`（默认为 `default`）初始化会话，并将验证码图片保存到本地文件。

### 查看本地会话

```powershell
uv run python main.py sessions
```

列出当前保存的配置名，可用于区分不同的 OJ 实例或不同的登录账号。

## 目录结构

```text
hustoj_mcp/
	client.py        # 与 HUSTOJ 交互的高层 HTTP 客户端
	session_store.py # 本地会话持久化逻辑
tests/
	...              # 针对关键组件的单元测试
```

## 后续计划

- 基于 `mcp.server.fastmcp` 暴露正式的 MCP Tool 接口。
- 补充题目描述抓取、竞赛题目映射、代码提交与结果轮询。
- 针对真实 HUSTOJ 部署增加端到端测试（在可用的情况下）。

欢迎在实现过程中提出建议或提交 PR。
