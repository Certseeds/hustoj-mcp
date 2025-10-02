from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is on sys.path so the local `src` package can be imported
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.client import HUSTOJClient, _normalize_base_url


def test_normalize_base_url_adds_scheme() -> None:
    assert _normalize_base_url("oj.example.com") == "https://oj.example.com"
    assert _normalize_base_url("https://already.example.com/") == "https://already.example.com"


def test_detect_captcha() -> None:
    html_with = "<form><input name='vcode'></form>"
    html_without = "<form><input name='password'></form>"
    assert HUSTOJClient._detect_captcha(html_with) is True
    assert HUSTOJClient._detect_captcha(html_without) is False


def test_interpret_login_response() -> None:
    success_html = "<script>window.location.href='index.php';</script>"
    wrong_pwd_html = "<script>alert('UserName or Password Wrong!');</script>"
    captcha_html = "<script>alert('Verify Code Wrong!');</script>"

    assert HUSTOJClient._interpret_login_response(success_html) == ("登录成功", True)
    assert HUSTOJClient._interpret_login_response(wrong_pwd_html) == ("用户名或密码错误", False)
    assert HUSTOJClient._interpret_login_response(captcha_html) == ("验证码错误", False)
