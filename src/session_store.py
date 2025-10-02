"""Persistent storage for HUSTOJ web sessions."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from .config_dir import get_config_dir
from requests.cookies import RequestsCookieJar, cookiejar_from_dict
from requests.utils import dict_from_cookiejar


@dataclass(frozen=True, slots=True)
class SessionData:
    """Represents a persisted authenticated browser session."""

    cookies: RequestsCookieJar = field(repr=False)
    stored_at: datetime

    def to_dict(self) -> Dict[str, object]:
        return {
            "cookies": dict_from_cookiejar(self.cookies),
            "stored_at": self.stored_at.astimezone(timezone.utc).isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "SessionData":
        stored_at_raw = data.get("stored_at")
        stored_at = (
            datetime.fromisoformat(stored_at_raw)
            if isinstance(stored_at_raw, str)
            else datetime.now(timezone.utc)
        )
        cookies_raw = data.get("cookies")
        if not isinstance(cookies_raw, dict):  # pragma: no cover - sanity guard
            cookies_raw = {}
        cookies = cookiejar_from_dict({str(k): str(v) for k, v in cookies_raw.items()})
        return cls(cookies=cookies, stored_at=stored_at)


@staticmethod
def default_file() -> Path:
    conf_dir = get_config_dir()
    return conf_dir / ".sessions.json"


class SessionStore:
    """Manages on-disk persistence of `SessionData` instances."""

    def __init__(self) -> None:
        self._file = default_file()
        # ensure parent exists
        self._file.parent.mkdir(parents=True, exist_ok=True)

    @property
    def file_path(self) -> Path:
        """Path to the single JSON file storing all sessions."""
        return self._file

    def save(self, session: SessionData) -> None:
        # write the single session entry (store under key 'session')
        payload = session.to_dict()
        wrapper = {"session": payload}
        self._file.write_text(
            json.dumps(wrapper, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def load(self) -> Optional[SessionData]:
        """Load the single stored session."""
        if not self._file.exists():
            return None
        try:
            wrapper = json.loads(self._file.read_text(encoding="utf-8")) or {}
        except Exception:
            return None
        data = wrapper.get("session")
        if not isinstance(data, dict):
            return None
        session = SessionData.from_dict(data)
        return SessionData(
            cookies=session.cookies, stored_at=session.stored_at
        )

    def delete(self) -> None:
        """Delete the single stored session file."""
        try:
            if self._file.exists():
                self._file.unlink()
        except Exception:
            pass
