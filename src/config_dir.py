from __future__ import annotations

from pathlib import Path

def get_config_dir() -> Path:
    """Return a config directory Path.

    Strategy:
    - Prefer repository-local <repo>/.config if available (created if missing).
    - Fallback to platform-specific user config dir (user_config_dir).
    """
    repo_root = Path(__file__).resolve().parents[1]
    conf_dir = repo_root / ".config"
    conf_dir.mkdir(parents=True, exist_ok=True)
    return conf_dir
