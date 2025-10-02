from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional
from .config_dir import get_config_dir


DEFAULT_DOTFILE = get_config_dir() / ".hustoj-mcp.json"


class ConfigStore:
    """Simple dotfile-backed config store for domain/user/password.

    Stores a small JSON blob at ~/.hustoj-mcp.json by default. The file contains
    keys: domain, user, password.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path else DEFAULT_DOTFILE

    @property
    def path(self) -> Path:
        return self._path

    def save(self, domain: str, user: str, password: str) -> None:
        payload: Dict[str, str] = {
            "domain": domain or "",
            "user": user or "",
            "password": password or "",
        }
        self._path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        # try to restrict permissions on POSIX
        try:
            if os.name == "posix":
                os.chmod(self._path, 0o600)
        except Exception:
            # best-effort only
            pass

    def load(self) -> Optional[Dict[str, str]]:
        if not self._path.exists():
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return None
            return {k: str(v) for k, v in data.items()}
        except Exception:
            return None

    def delete(self) -> None:
        if self._path.exists():
            self._path.unlink()
