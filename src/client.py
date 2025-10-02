"""HTTP client abstraction for interacting with a HUSTOJ instance."""

from __future__ import annotations

import hashlib
import logging
import secrets
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests import Session
from requests.exceptions import RequestException
from requests.utils import dict_from_cookiejar

from .session_store import SessionData, SessionStore

_LOGGER = logging.getLogger(__name__)


def _normalize_base_url(domain: str) -> str:
    url = domain.strip()
    if not url:
        raise ValueError("domain 不能为空")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


@dataclass(slots=True)
class LoginResult:
    success: bool
    message: str
    requires_captcha: bool
    cookies: Dict[str, str]


class LoginError(RuntimeError):
    def __init__(self, message: str, *, requires_captcha: bool = False) -> None:
        super().__init__(message)
        self.requires_captcha = requires_captcha


class HUSTOJClient:
    """High level helper around the HUSTOJ web endpoints."""

    def __init__(
        self,
        domain: str,
        *,
        session_store: Optional[SessionStore] = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = _normalize_base_url(domain)
        self.session_store = session_store or SessionStore()
        # store/load use single session file
        self.timeout = timeout
        self._session: Optional[Session] = None

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------
    def _new_session(self) -> Session:
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "hustoj-mcp/0.1 (+https://github.com/Certseeds/hustoj-mcp)",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )
        return session

    def _url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _ensure_session(self) -> Session:
        if self._session is not None:
            return self._session
        stored = self.session_store.load()
        session = self._new_session()
        if stored:
            session.cookies.update(stored.cookies)
            _LOGGER.debug("已从存储文件加载会话 cookie")
        self._session = session
        return session

    def clear_cached_session(self) -> None:
        self._session = None

    # ------------------------------------------------------------------
    # Login flow
    # ------------------------------------------------------------------
    def login(
        self,
        username: str,
        password: str,
        *,
        vcode: Optional[str] = None,
        persist: bool = True,
    ) -> LoginResult:
        session = self._new_session()
        try:
            login_page = session.get(
                self._url("onlinejudge/loginpage.php"), timeout=self.timeout
            )
            login_page.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network guard
            raise LoginError(f"无法访问登录页: {exc}") from exc

        requires_captcha = self._detect_captcha(login_page.text)
        if requires_captcha and not vcode:
            raise LoginError(
                "当前站点要求验证码，请先获取验证码", requires_captcha=True
            )

        hashed_password = hashlib.md5(password.encode("utf-8")).hexdigest()
        payload = {
            "user_id": username,
            "password": hashed_password,
        }
        if requires_captcha:
            payload["vcode"] = vcode or ""

        try:
            response = session.post(
                self._url("onlinejudge/login.php"),
                data=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network guard
            raise LoginError(f"登录请求失败: {exc}") from exc

        message, success = self._interpret_login_response(response.text)
        if not success:
            raise LoginError(
                message or "用户名或密码错误", requires_captcha=requires_captcha
            )

        cookies_dict = dict_from_cookiejar(session.cookies)

        if persist:
            self.session_store.save(
                SessionData(
                    domain=self.base_url,
                    cookies=session.cookies,
                    stored_at=datetime.now(timezone.utc),
                )
            )
            _LOGGER.info("已保存登录状态到存储文件")

        self._session = session
        return LoginResult(
            success=True,
            message=message or "登录成功",
            requires_captcha=requires_captcha,
            cookies=cookies_dict,
        )

    def fetch_captcha(self) -> bytes:
        """Fetches the current captcha image associated with the login session."""

        session = self._ensure_session()
        # 确保 session 中含有验证码会话所需 cookie
        try:
            session.get(self._url("onlinejudge/loginpage.php"), timeout=self.timeout)
        except RequestException as exc:  # pragma: no cover - network guard
            raise LoginError(f"无法初始化验证码会话: {exc}") from exc

        params = {"_": secrets.token_hex(4)}
        try:
            response = session.get(
                self._url("onlinejudge/vcode.php"), params=params, timeout=self.timeout
            )
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network guard
            raise LoginError(f"获取验证码失败: {exc}") from exc
        return response.content

    def fetch_problem(self, problem_id: int) -> Dict[str, object]:
        """Fetch the full problem page and extract main parts.

        Returns a dict with keys: url, status_code, html, title (if found), parts(dict).
        """
        session = self._ensure_session()
        url = self._url(f"onlinejudge/problem.php?id={problem_id}")
        try:
            resp = session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network guard
            raise LoginError(f"无法获取题目页面: {exc}") from exc

        html = resp.text
        parts = self._extract_problem_parts(html)
        title = parts.get("title") or ""
        return {
            "url": url,
            "status_code": resp.status_code,
            "html": html,
            "title": title,
            "parts": parts,
        }

    @staticmethod
    def _extract_problem_parts(html: str) -> Dict[str, object]:
        """Heuristic extraction of problem parts from HustOJ HTML.

        We try several common selectors used by HUSTOJ templates. If not
        found, we return the full body under 'body_html'.
        """
        soup = BeautifulSoup(html, "html.parser")
        # title
        title = None
        # common patterns
        selectors = [
            ("h1", {}),
            ("h2", {}),
            ("div", {"class": "panel_title"}),
            ("div", {"class": "title"}),
        ]
        for tag, attrs in selectors:
            el = soup.find(tag, attrs=attrs)
            if el and el.get_text(strip=True):
                title = el.get_text(strip=True)
                break

        def _as_html(el):
            return "" if el is None else str(el)

        # try to find main problem content container
        candidates = [
            {"id": "problem"},
            {"class": "problem_content"},
            {"class": "panel-body"},
            {"id": "content"},
        ]
        body_html = None
        for sel in candidates:
            el = soup.find(attrs=sel)
            if el:
                body_html = str(el)
                break

        if not body_html:
            # fallback to body
            body = soup.find("body")
            body_html = _as_html(body) if body is not None else html

        # Attempt to extract sections by headings
        sections = {}
        # Common section headings
        for heading in [
            "Description",
            "题目描述",
            "Input",
            "输入",
            "Output",
            "输出",
            "Sample Input",
            "样例输入",
            "Sample Output",
            "样例输出",
            "提示",
            "HINT",
        ]:
            el = soup.find(
                lambda t: t.name in ("h2", "h3", "h4")
                and heading.lower() in t.get_text(strip=True).lower()
            )
            if el:
                # gather following siblings until next heading
                parts = []
                for sib in el.find_next_siblings():
                    if sib.name in ("h2", "h3", "h4"):
                        break
                    parts.append(str(sib))
                sections[heading] = "\n".join(parts)

        return {"title": title, "body_html": body_html, "sections": sections}

    @staticmethod
    def html_to_post_md(html: str) -> str:
        """Convert a fetched problem HTML (pre.*) into post.* Markdown format.

        The output mirrors the repository's `example/post.1000.md` layout.
        """
        parts = HUSTOJClient._extract_problem_parts(html)
        title = parts.get("title") or ""
        sections = parts.get("sections", {})
        body_html = parts.get("body_html", "")

        def normalize_whitespace(s: str) -> str:
            # collapse any whitespace (including newlines) to single spaces
            return re.sub(r"\s+", " ", s).strip()

        desc = ""
        # try common headings
        for key in ["Description", "题目描述"]:
            if key in sections:
                soup = BeautifulSoup(sections[key], "html.parser")
                # convert superscripts like 10<sup>6</sup> -> 10^6
                for sup in soup.find_all("sup"):
                    sup.replace_with("^" + sup.get_text())
                desc = normalize_whitespace(soup.get_text(" ", strip=True))
                break
        if not desc:
            # fallback to first paragraph of body_html
            soup = BeautifulSoup(body_html, "html.parser")
            p = soup.find("p")
            desc = normalize_whitespace(p.get_text(" ", strip=True)) if p else ""

        inp = ""
        for key in ["Input", "输入"]:
            if key in sections:
                soup = BeautifulSoup(sections[key], "html.parser")
                for sup in soup.find_all("sup"):
                    sup.replace_with("^" + sup.get_text())
                inp = normalize_whitespace(soup.get_text(" ", strip=True))
                break

        out = ""
        for key in ["Output", "输出"]:
            if key in sections:
                soup = BeautifulSoup(sections[key], "html.parser")
                for sup in soup.find_all("sup"):
                    sup.replace_with("^" + sup.get_text())
                out = normalize_whitespace(soup.get_text(" ", strip=True))
                break

        sample_in = ""
        sample_out = ""
        # try to extract sample data from sections
        for k in ["Sample Input", "样例输入"]:
            if k in sections and sections[k].strip():
                sample_in = normalize_whitespace(
                    BeautifulSoup(sections[k], "html.parser").get_text(" ", strip=True)
                )
                break
        for k in ["Sample Output", "样例输出"]:
            if k in sections and sections[k].strip():
                sample_out = normalize_whitespace(
                    BeautifulSoup(sections[k], "html.parser").get_text(" ", strip=True)
                )
                break

        # fallback: look for pre.sampledata in full HTML
        if not sample_in or not sample_out:
            soup = BeautifulSoup(html, "html.parser")
            samples = [
                s.get_text("\n", strip=True)
                for s in soup.select("pre .sampledata, pre span.sampledata")
            ] or [
                s.get_text("\n", strip=True)
                for s in soup.select("pre.sampledata, pre span.sampledata")
            ]
            if samples:
                if not sample_in:
                    sample_in = samples[0]
                if len(samples) > 1 and not sample_out:
                    sample_out = samples[1]

        hint = ""
        for key in ["HINT", "提示"]:
            if key in sections:
                soup = BeautifulSoup(sections[key], "html.parser")
                hint = normalize_whitespace(
                    BeautifulSoup(sections[key], "html.parser").get_text(
                        " ", strip=True
                    )
                )
                break

        md_lines = []
        md_lines.append("## Description\n")
        md_lines.append(desc or "")
        md_lines.append("\n## Input\n")
        md_lines.append(inp or "")
        md_lines.append("\n## Output\n")
        md_lines.append(out or "")
        if sample_in:
            md_lines.append("\n## Sample Input\n")
            md_lines.append("``` log")
            md_lines.append(sample_in)
            md_lines.append("```")
        if sample_out:
            md_lines.append("\n## Sample Output\n")
            md_lines.append("``` log")
            md_lines.append(sample_out)
            md_lines.append("```")
        if hint:
            md_lines.append("\n## HINT\n")
            md_lines.append(hint)
        md_lines.append("")

        return "\n".join([line for line in md_lines if line is not None])

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_captcha(html: str) -> bool:
        soup = BeautifulSoup(html, "html.parser")
        return soup.find("input", attrs={"name": "vcode"}) is not None

    @staticmethod
    def _interpret_login_response(html: str) -> Tuple[str, bool]:
        lowered = html.lower()
        if "verify code wrong" in lowered:
            return ("验证码错误", False)
        if "username or password wrong" in lowered:
            return ("用户名或密码错误", False)
        if "cookie" in lowered and "失效" in lowered:
            return ("登录 Cookie 失效", False)
        if "alert" in lowered and "wrong" in lowered:
            return ("登录失败", False)
        return ("登录成功", True)
