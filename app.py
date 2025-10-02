"""MCP adapter using the Model Context Protocol Python SDK (FastMCP).

This module registers a small set of tools exposing configuration and
session management for hustoj-mcp so MCP-aware clients can call them.

Usage:
    uv run src.mcp_fastmcp:main
or
    python -m src.mcp_fastmcp

Note: requires `mcp` package to be installed in the environment.
"""

from __future__ import annotations
from typing import Optional
import os
from mcp.server.fastmcp import FastMCP
from src import ConfigStore, SessionStore, HUSTOJClient


mcp = FastMCP("hustoj-mcp")


@mcp.tool()
def config_set(domain: str, user: str, password: str) -> dict:
    """设置域名, 用户名, 密码"""
    cfg = ConfigStore()
    cfg.save(domain=domain, user=user, password=password)
    return {"ok": True, "path": str(cfg.path)}


@mcp.tool()
def config_show() -> dict:
    """展示域名, 用户名, 密码"""
    cfg = ConfigStore()
    data = cfg.load() or {}
    return {"ok": True, "config": data}


@mcp.tool()
def config_delete() -> dict:
    """移除域名, 用户名, 密码"""
    cfg = ConfigStore()
    cfg.delete()
    return {"ok": True}


@mcp.tool()
def session_set() -> dict:
    """使用域名, 用户名, 密码来登录"""
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    store = SessionStore()
    client = HUSTOJClient(cfg_data.get("domain"), session_store=store)
    user = cfg_data.get("user")
    password = cfg_data.get("password")
    try:
        result = client.login(username=user, password=password, persist=True)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "requires_captcha": result.requires_captcha,
        "cookies": result.cookies,
    }


@mcp.tool()
def session_show() -> dict:
    """展示现有的session内容"""
    store = SessionStore()
    fp = store.file_path
    if not fp.exists():
        return {"ok": True, "session": None}
    try:
        data = fp.read_text(encoding="utf-8")
        return {"ok": True, "session": data}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def session_delete() -> dict:
    """删除现有的session内容"""
    store = SessionStore()
    store.delete()
    return {"ok": True}


@mcp.tool()
def problem(problem_id: int) -> dict:
    """Fetch a problem page and return extracted parts."""
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    domain = cfg_data.get("domain")
    if not domain:
        return {"ok": False, "error": "domain required"}
    store = SessionStore()
    client = HUSTOJClient(domain, session_store=store)
    try:
        res = client.fetch_problem(problem_id)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    md_content = HUSTOJClient.problem_to_md(res.get("html", ""))

    return {"ok": True, "problem": md_content}


@mcp.tool()
def contest(cid: int) -> dict:
    """Fetch contest problem list."""
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    domain = cfg_data.get("domain")
    if not domain:
        return {"ok": False, "error": "domain required"}
    client = HUSTOJClient(domain, session_store=SessionStore())
    try:
        problems = client.fetch_contest_problems(cid)
        return {"ok": True, "problems": problems}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def submit(
    file_name: str = None,
    problem_id: Optional[int] = None,
    cid: Optional[int] = None,
    pid: Optional[int] = None,
    language: Optional[str] = "cpp",
    vcode: Optional[str] = None,
    test_run: Optional[bool] = False
) -> dict:
    """Submit source code to a problem or contest.

    file_name: 文件的绝对路径

    Provide either `problem_id` for single problem submit, or `cid` and `pid` for contest submit.
    """
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    domain = cfg_data.get("domain")
    store = SessionStore()
    client = HUSTOJClient(domain, session_store=store)
    with open(file_name, "r", encoding="utf-8") as f:
        source = f.read()
    try:
        runid = client.submit_solution(
            problem_id=problem_id,
            cid=cid,
            pid=pid,
            source=source,
            language=language,
            vcode=vcode,
            test_run=bool(test_run),
        )
        return {"ok": True, "runid": runid}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def main():
    if FastMCP is None:
        raise RuntimeError("mcp package not installed. Install via 'uv add mcp[cli]'")
    # 默认使用 stdio 以便 VS Code / MCP 客户端通过 spawn 直接通信。
    # 若需要 HTTP 模式: 设置环境变量 MCP_TRANSPORT=http (可选再设 MCP_PORT / MCP_HOST)
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    if transport in {"http", "streamable-http"}:
        host = os.getenv("MCP_HOST", "127.0.0.1")
        port_str = os.getenv("MCP_PORT", "8001")
        try:
            port = int(port_str)
        except ValueError:
            port = 8001
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        mcp.run()  # stdio 模式


if __name__ == "__main__":
    main()
