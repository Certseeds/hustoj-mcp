from __future__ import annotations

import sys
from pathlib import Path
from datetime import datetime, timezone

# Ensure repository root is on sys.path so the local `src` package can be imported
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from requests.utils import cookiejar_from_dict

from src.session_store import SessionData, SessionStore


def test_session_store_roundtrip(tmp_path) -> None:
    store = SessionStore(base_dir=tmp_path)
    cookies = cookiejar_from_dict({"php": "12345"})
    original = SessionData(
        profile="test",
        domain="https://oj.example.com",
        cookies=cookies,
        stored_at=datetime.now(timezone.utc),
    )
    store.save(original)

    loaded = store.load("test")

    assert loaded is not None
    assert loaded.profile == "test"
    assert loaded.domain == original.domain
    assert loaded.cookies.get("php") == "12345"


def test_session_store_list_profiles(tmp_path) -> None:
    store = SessionStore(base_dir=tmp_path)
    assert list(store.list_profiles()) == []

    store.save(
        SessionData(
            profile="alpha",
            domain="https://a",
            cookies=cookiejar_from_dict({}),
            stored_at=datetime.now(timezone.utc),
        )
    )
    store.save(
        SessionData(
            profile="beta",
            domain="https://b",
            cookies=cookiejar_from_dict({}),
            stored_at=datetime.now(timezone.utc),
        )
    )

    assert list(store.list_profiles()) == ["alpha", "beta"]


def test_load_missing_profile_returns_none(tmp_path) -> None:
    store = SessionStore(base_dir=tmp_path)
    assert store.load("missing") is None


def test_delete_profile(tmp_path) -> None:
    store = SessionStore(base_dir=tmp_path)
    store.save(
        SessionData(
            profile="temp",
            domain="https://domain",
            cookies=cookiejar_from_dict({}),
            stored_at=datetime.now(timezone.utc),
        )
    )
    assert store.load("temp") is not None
    store.delete("temp")
    assert store.load("temp") is None
