# hustoj-mcp

一个面向 HUSTOJ 的本地 Model Context Protocol (MCP) 辅助工具，目前正在逐步实现以下能力：

- 使用网页登录凭据并安全地将会话 Cookie 持久化到本地。
- 在启动 MCP 服务前，通过命令行辅助完成验证码获取与登录校验。
- 为后续题目描述抓取、竞赛列表获取、提交代码等功能提供mcp/cli封装

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
uv run python main.py config set
```

设置账户密码

### 查看本地会话

```powershell
uv run python main.py sessions
```

列出当前保存的配置

## 目录结构

```text
src/
	client.py        # 与 HUSTOJ 交互的高层 HTTP 客户端
	session_store.py # 本地会话持久化逻辑
tests/
	...              # 针对关键组件的单元测试
```

## 后续计划

- 基于 `mcp.server.fastmcp` 暴露正式的 MCP Tool 接口。
- 补充题目描述抓取、竞赛题目映射、代码提交与结果轮询。

## 本地启动方式

1. 不向pypi发布
2. 将仓库加入vscode 的 workspace中
3. 在仓库.vscode目录加入以下配置

``` json
{
	"servers": {
		"hustoj-mcp-01": {
			"type": "stdio",
			"command": "uv",
			"args": [
				"run",
				"{app.py的绝对路径}"
			],
			"cwd": "{仓库的绝对路径}"
		}
	},
	"inputs": []
}
```

随后启动server

之后即可在copilot中与mcp server进行沟通
