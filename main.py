from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from pathlib import Path

from src import HUSTOJClient, SessionStore
from src import ConfigStore


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


def _cmd_login(args: argparse.Namespace) -> int:
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    domain = cfg_data.get("domain") or input("域名: ")
    user = cfg_data.get("user") or input("用户名: ")
    password = cfg_data.get("password") or getpass.getpass("密码: ")
    store = SessionStore()
    client = HUSTOJClient(domain, session_store=store)
    try:
        result = client.login(username=user, password=password, persist=True)
    except Exception as exc:  # pragma: no cover - thin CLI wrapper
        logging.error("登录失败: %s", exc)
        return 1

    logging.info(
        "登录成功, 是否需要验证码: %s", "是" if result.requires_captcha else "否"
    )
    print(json.dumps(result.cookies, indent=2, ensure_ascii=False))
    return 0


def _cmd_session(args: argparse.Namespace) -> int:
    """Manage the single local session: set (login), show, delete."""
    store = SessionStore()
    cfg = ConfigStore()
    if args.action == "show":
        fp = store.file_path
        if not fp.exists():
            print("暂无已保存的会话。")
            print(f"期望文件: {fp}")
            return 0
        try:
            content = fp.read_text(encoding="utf-8")
            parsed = json.loads(content)
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
        except Exception:
            print(fp.read_text(encoding="utf-8"))
        return 0

    if args.action == "delete":
        store.delete()
        print(f"已删除会话文件: {store.file_path}")
        return 0
    _cmd_login(None)
    return 0


def _cmd_problem(args: argparse.Namespace) -> int:
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    domain = cfg_data.get("domain") or input("域名: ")
    store = SessionStore()
    client = HUSTOJClient(domain, session_store=store)
    try:
        result = client.fetch_problem(args.id)
    except Exception as exc:
        logging.error("获取题目失败: %s", exc)
        return 1

    title = result.get("title") or ""
    print(f"URL: {result.get('url')}")
    print(f"Status: {result.get('status_code')}")
    print(f"Title: {title}")
    sections = result.get("parts", {}).get("sections", {})
    if sections:
        print("Sections found:")
        for k, v in sections.items():
            print(f"--- {k} ---\n{v[:400]}\n")

    output = args.output
    md_content = HUSTOJClient.problem_to_md(result.get("html", ""))
    if output:
        Path(output).write_text(md_content , encoding="utf-8")
        print(f"已保存完整 HTML 到 {output}")
    else:
        print(md_content)
    return 0


def _cmd_contest(args: argparse.Namespace) -> int:
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    domain = cfg_data.get("domain") or input("域名: ")
    client = HUSTOJClient(domain, session_store=SessionStore())
    try:
        problems = client.fetch_contest_problems(args.cid)
    except Exception as exc:
        logging.error("获取比赛题目失败: %s", exc)
        return 1
    print(json.dumps(problems, indent=2, ensure_ascii=False))
    return 0


def _cmd_submit(args: argparse.Namespace) -> int:
    # refresh session by performing a login before each submit
    login_rc = _cmd_login(None)
    if login_rc != 0:
        logging.error("在提交前刷新会话失败，取消提交")
        return 1
    cfg = ConfigStore()
    cfg_data = cfg.load() or {}
    domain = cfg_data.get("domain") or input("域名: ")
    store = SessionStore()
    client = HUSTOJClient(domain, session_store=store)

    # read source from file or stdin
    if args.file:
        src = Path(args.file).read_text(encoding="utf-8")
    else:
        logging.info("不支持从stdin读取代码")
        return 1

    try:
        client.submit_solution(
            problem_id=args.id,
            cid=args.cid,
            pid=args.pid,
            source=src,
            language=args.language,
            vcode=args.vcode,
            test_run=args.test_run,
        )
    except Exception as exc:
        logging.error("提交失败: %s", exc)
        return 1
    logging.info("提交成功")
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    cfg = ConfigStore()
    if args.action == "show":
        data = cfg.load()
        if not data:
            print("未找到配置。使用 'config set' 来保存域名/用户名/密码")
            return 0
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    if args.action == "delete":
        cfg.delete()
        print(f"已删除配置文件: {cfg.path}")
        return 0

    # set
    domain = args.domain or input("域名: ")
    user = args.user or input("用户名: ")
    password = args.password or getpass.getpass("密码: ")
    cfg.save(domain=domain, user=user, password=password)
    print(f"已保存配置至 {cfg.path}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HUSTOJ MCP 辅助 CLI")
    parser.add_argument("--verbose", action="store_true", help="显示调试日志")

    subparsers = parser.add_subparsers(dest="command", required=True)

    config_parser = subparsers.add_parser(
        "config", help="管理本地配置(域名/用户名/密码)"
    )
    config_parser.add_argument(
        "action", choices=["set", "show", "delete"], help="操作: set/save/show/delete"
    )
    config_parser.add_argument("--domain", help="HUSTOJ 域名(可选, set 时使用)")
    config_parser.add_argument("--user", help="用户名(可选, set 时使用)")
    config_parser.add_argument(
        "--password", help="密码(可选, set 时使用；留空将提示输入)"
    )
    config_parser.set_defaults(func=_cmd_config)

    login_parser = subparsers.add_parser("login", help="登录并保存会话")
    login_parser.set_defaults(func=_cmd_login)

    session_parser = subparsers.add_parser(
        "session", help="管理本地会话（set/show/delete），set 将执行 login 并保存会话"
    )
    session_parser.add_argument(
        "action", choices=["set", "show", "delete"], help="操作: set/show/delete"
    )
    session_parser.add_argument("--domain", help="可选，覆盖配置的域名")
    session_parser.add_argument("--user", help="可选，覆盖配置的用户名")
    session_parser.add_argument(
        "--password", help="可选，覆盖配置的密码；留空将提示输入"
    )
    session_parser.set_defaults(func=_cmd_session)

    problem_parser = subparsers.add_parser("problem", help="获取题目页面并提取内容")
    problem_parser.add_argument("--id", type=int, required=True, help="题目 id")
    problem_parser.add_argument("--output", help="可选，将完整 HTML 保存到文件")
    problem_parser.set_defaults(func=_cmd_problem)

    contest_parser = subparsers.add_parser("contest", help="获取比赛下的题目列表")
    contest_parser.add_argument("--cid", type=int, required=True, help="比赛 cid")
    contest_parser.set_defaults(func=_cmd_contest)

    submit_parser = subparsers.add_parser("submit", help="提交代码到指定题目或比赛")
    submit_group = submit_parser.add_mutually_exclusive_group(required=True)
    submit_group.add_argument("--id", type=int, help="题目 id (单题提交)")
    submit_group.add_argument("--cid", type=int, help="比赛 cid (比赛提交需同时提供 --pid)")
    submit_parser.add_argument("--pid", type=int, help="比赛中的 pid (从 0 开始)")
    submit_parser.add_argument("--file", help="包含代码的文件 (不提供则从 stdin 读取)")
    submit_parser.add_argument(
        "--language",
        choices=["c", "cpp", "java"],
        default="cpp",
        help="语言 (c, cpp, java)，默认 cpp",
    )
    submit_parser.add_argument("--vcode", help="验证码 (如果站点要求)")
    submit_parser.add_argument("--test-run", dest="test_run", action="store_true", help="执行测试运行")
    submit_parser.set_defaults(func=_cmd_submit)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
