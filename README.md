# hustoj-mcp

一个面向 HUSTOJ 的本地 CLI 辅助工具

- 使用网页登录凭据并安全地将会话 Cookie 持久化到本地。
- 通过命令行登录。
- 将提交代码封装到cli中

## 运行前提

- Python 3.13（项目使用 [uv](https://github.com/astral-sh/uv) 进行依赖管理）。
- HUSTOJ 目标站点可从本地网络访问。

## 安装依赖

```powershell
uv sync
```

## 命令行用法

当前的 `main.py` 提供了一个简易 CLI

### 设置域名, 账户名, 密码

```powershell
uv run ./main.py \
  config set \
    --domain {domain} \
    --user {userName} 
    --password {passWord}
```

### 登录并保存会话

```powershell
uv run ./main.py login
```

### 查看本地会话

```powershell
uv run ./main.py session show
```

### 提交代码

``` powershell
uv run ./main.py \
  submit \
    --id 1471 \
    --file "{postfix}\algorithm\2021F\lab_10\lab_10_B\main.cpp" \ --language "cpp"
```

1. 传入problem_id, 或者 cid&pid
2. 传入文件的绝对路径
3. 传入语言, c/cpp/java

## 目录结构

```text
src/
  client.py        # 与 HUSTOJ 交互的高层 HTTP 客户端
  session_store.py # 本地会话持久化逻辑
  config_store.py # 用户名密码持久化逻辑
```

## 后续计划

- 补充更多功能, 如看排行榜
- 针对真实 HUSTOJ 部署增加端到端测试（在可用的情况下）。

欢迎在实现过程中提出建议或提交 PR。
