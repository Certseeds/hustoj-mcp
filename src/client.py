"""HTTP client abstraction for interacting with a HUSTOJ instance."""

from __future__ import annotations

import hashlib
import logging
import secrets
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Dict, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote_plus

import requests
from bs4 import BeautifulSoup
from requests import Session
from requests.exceptions import RequestException
from requests.utils import dict_from_cookiejar

from .session_store import SessionData, SessionStore

LOGGER = logging.getLogger(__name__)


class Language(IntEnum):
    C = 0
    CPP = 1
    JAVA = 3


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
            LOGGER.debug("已从存储文件加载会话 cookie")
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
                    cookies=session.cookies,
                    stored_at=datetime.now(timezone.utc),
                )
            )
            LOGGER.info("已保存登录状态到存储文件")

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
    def problem_to_md(html: str) -> str:
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

    def fetch_contest_problems(self, cid: int) -> list[dict]:
        """Fetch contest page and extract list of problems with Order/Problem.

        Returns a list of dicts like: {"Order": "1470", "Problem": "A"}
        """
        session = self._ensure_session()
        url = self._url(f"onlinejudge/contest.php?cid={cid}")
        try:
            resp = session.get(url, timeout=self.timeout)
            resp.raise_for_status()
        except RequestException as exc:
            raise LoginError(f"无法获取竞赛页面: {exc}") from exc
        return self.parse_contest_html(resp.text)

    def submit_solution(
        self,
        *,
        problem_id: int | None = None,
        cid: int | None = None,
        pid: int | None = None,
        source: str,
        language: Union[int, str, Language] = None,
        vcode: Optional[str] = None,
        test_run: bool = False,
    ) -> int:
        """Submit source code to the judge and return the resulting run id.

        - For single problem submissions provide `problem_id`.
        - For contest submissions provide `cid` and `pid`.

        The method posts to submit.php?ajax and parses the returned solution id.
        """
        session = self._ensure_session()

        # Normalize language input: accept Language enum, int, or str like 'c','cpp','java'
        if language is None:
            # default to cpp
            lang_val = int(Language.CPP)
        elif isinstance(language, str):
            mapping = {
                "c": int(Language.C),
                "cpp": int(Language.CPP),
                "java": int(Language.JAVA),
            }
            key = language.lower()
            if key not in mapping:
                raise ValueError("未知的语言: %s. 支持: c, cpp, java" % language)
            lang_val = mapping[key]
        elif isinstance(language, Language):
            lang_val = int(language)
        else:
            # assume numeric
            try:
                lang_val = int(language)
            except Exception:
                raise ValueError("language 必须是 int/str/Language 之一")

        # warm up session by loading the submit page (some servers check referer/cookies)
        if problem_id is not None:
            submitpage_path = f"onlinejudge/submitpage.php?id={problem_id}"
        else:
            # contest submitpage
            submitpage_path = f"onlinejudge/submitpage.php?cid={cid}&pid={pid}"
        try:
            r = session.get(self._url(submitpage_path), timeout=self.timeout)
        except Exception:
            pass
            # ignore failures here; submission may still work

        # set a lastlang cookie so server-side may pick a template if needed
        session.cookies.set("lastlang", str(int(lang_val)))

        payload = {}
        if problem_id is not None:
            # for test runs some templates expect negative id
            payload["id"] = -problem_id if test_run else problem_id
        else:
            if cid is None or pid is None:
                raise ValueError("需要提供 problem_id 或 (cid 和 pid) 之一")
            payload["cid"] = cid
            payload["pid"] = pid if not test_run else -pid

        payload["language"] = str(int(lang_val))
        payload["source"] = source
        if vcode:
            payload["vcode"] = vcode
        else:
            payload["vcode"] = ""

        # Try to fetch CSRF token (many templates expose it via csrf.php)
        try:
            # ensure using the same session
            LOGGER.debug(
                "Session cookies before csrf fetch: %s", list(session.cookies.keys())
            )
            # Use headers that closely mirror a browser AJAX request (see user-provided curl)
            headers_csrf = {
                "Referer": self._url(submitpage_path),
                "Accept": "text/html, */*; q=0.01",
                # requests will handle Accept-Encoding automatically, but include common values
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "X-Requested-With": "XMLHttpRequest",
                "DNT": "1",
                "Sec-GPC": "1",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "TE": "trailers",
            }
            csrf_url_candidates = ("onlinejudge/csrf.php", "csrf.php")
            csrf_value = None
            for path in csrf_url_candidates:
                csrf_url = self._url(path)
                LOGGER.debug("Trying csrf url: %s", csrf_url)
                r = session.get(
                    csrf_url,
                    timeout=self.timeout,
                    headers=headers_csrf,
                    allow_redirects=True,
                )
                if r.status_code != 200:
                    LOGGER.debug(
                        "csrf url %s returned status %s", csrf_url, r.status_code
                    )
                    continue
                if not r.text or r.text.strip() == "":
                    LOGGER.debug("csrf url %s returned empty body", csrf_url)
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                inp = soup.find("input", attrs={"name": "csrf"})
                if inp and inp.get("value"):
                    csrf_value = inp.get("value")
                    LOGGER.debug("Found csrf token from %s", csrf_url)
                    break
            if csrf_value:
                payload["csrf"] = csrf_value
            else:
                LOGGER.debug(
                    "No csrf token found from candidates: %s", csrf_url_candidates
                )
        except Exception as exc:
            # non-fatal; continue without csrf
            LOGGER.debug("Failed to fetch csrf token, continuing without it: %s", exc)
        LOGGER.debug("csrf: %s", payload.get("csrf"))
        # Attempt to extract all form fields from the submit page and merge into payload.
        # This ensures hidden fields (including any anti-forgery tokens or flags) are included.

        # Post to non-AJAX endpoint (browser form posts to submit.php)
        url = self._url("onlinejudge/submit.php")
        # make the POST look more like a browser form submission (match HAR)
        headers = {
            "Referer": self._url(submitpage_path),
            "Origin": self.base_url,
            # mimic a real browser User-Agent (some sites have UA checks)
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            # explicit content type to match browser POST
            "Content-Type": "application/x-www-form-urlencoded",
            "DNT": "1",
            "Sec-GPC": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Priority": "u=0, i",
            "TE": "trailers",
        }

        # debug: log payload keys and redact large source content
        try:
            short_payload = {
                k: (
                    f"<source {len(v)} bytes>"
                    if k == "source" and isinstance(v, str)
                    else v
                )
                for k, v in payload.items()
            }
            LOGGER.debug(
                "Submitting POST %s with payload keys/preview: %s", url, short_payload
            )
            # Prepare an encoded preview for diagnostics (requests will still encode when sending dict)
            try:
                encoded_preview = urlencode(payload, doseq=True, quote_via=quote_plus)
            except Exception:
                encoded_preview = ""
            LOGGER.debug("Encoded form body preview: %s", encoded_preview[:300])

            # Use requests to encode the form data (pass dict) rather than pre-encoding
            LOGGER.debug("Attempting non-AJAX (browser-like) submit to %s", url)
            LOGGER.debug("Current session cookies: %s", session.cookies.get_dict())
            # prepare request to inspect exact headers/body that will be sent
            req = requests.Request("POST", url, data=payload, headers=headers)
            prep = session.prepare_request(req)
            try:
                body_preview = (
                    prep.body[:1000]
                    if isinstance(prep.body, (bytes, str))
                    else str(type(prep.body))
                )
            except Exception:
                body_preview = "<unprintable>"
            LOGGER.debug("Prepared request headers: %s", dict(prep.headers))
            LOGGER.debug("Prepared request body preview: %s", body_preview)
            resp = session.send(prep, timeout=self.timeout, allow_redirects=True)
            LOGGER.debug(
                "POST status_code=%s headers=%s final_url=%s",
                resp.status_code,
                dict(resp.headers),
                resp.url,
            )

            # If server redirected or returned 200 with a script calling fresh_result, handle below
            # If response looks like AJAX echo, try that too
            if resp.status_code == 200 and resp.text:
                m_ajax = re.search(r"\b(\d{3,})\b", resp.text)
                if m_ajax:
                    return int(m_ajax.group(1))

        except RequestException as exc:
            raise LoginError(f"提交请求失败: {exc}") from exc

        # If server returned an error code, include a snippet for debugging
        if resp.status_code >= 400:
            body = resp.text[:2000] if resp.text else ""
            LOGGER.error("提交返回 %s, 响应片段: %s", resp.status_code, body)
            raise LoginError(
                f"提交请求失败: {resp.status_code} {resp.reason}. 响应片段: {body}"
            )


    @staticmethod
    def parse_contest_html(html: str) -> list[dict]:
        """Parse contest HTML and return list of {Order: int, problem: str}.

        The function implements heuristics for standard HUSTOJ contest pages.
        """
        soup = BeautifulSoup(html, "html.parser")
        result: list[dict] = []

        # Prefer the problemset table if present
        table = soup.find("table", id="problemset") or soup.find("table")
        rows = table.find_all("tr") if table else soup.find_all("tr")

        for tr in rows:
            # skip header/empty rows
            if not tr.find_all("td"):
                continue
            tds = tr.find_all("td")
            # expect the layout similar to the example: [., OrderTD, TitleTD, ...]
            order_val = None
            problem_letter = None

            # try to parse order from the second td
            if len(tds) >= 2:
                txt = tds[1].get_text(" ", strip=True)
                m = re.search(r"(\d+)", txt)
                if m:
                    try:
                        order_val = int(m.group(1))
                    except ValueError:
                        order_val = None

            # try to derive problem letter from a pid= query param on the problem link
            # usually the title column contains a link like problem.php?cid=1039&pid=0
            anchor = None
            if len(tds) >= 3:
                anchor = tds[2].find("a")
            if not anchor:
                # fallback: any anchor in the row
                anchor = tr.find("a")

            if anchor and anchor.get("href"):
                href = anchor.get("href")
                try:
                    parsed = urlparse(href)
                    qs = parse_qs(parsed.query)
                    pid_vals = qs.get("pid") or qs.get("p")
                    if pid_vals:
                        pid = int(pid_vals[0])
                        if pid >= 0:
                            problem_letter = chr(ord("A") + pid)
                except Exception:
                    problem_letter = None

            # final fallback: try to extract a trailing uppercase letter from the order td
            if not problem_letter and len(tds) >= 2:
                txt = tds[1].get_text(" ", strip=True)
                m2 = re.search(r"\b([A-Z])\b$", txt)
                if m2:
                    problem_letter = m2.group(1)

            # if we successfully parsed an order and a problem letter, append
            if order_val is not None and problem_letter:
                result.append({"Order": order_val, "problem": problem_letter})

        return result
