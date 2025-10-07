from __future__ import annotations

from pathlib import Path
import sys


def get_config_dir() -> Path:
    """Return a config directory Path.

    Strategy:
    - If running under PyInstaller, use cwd/.config 
    - Else, use repo-local <repo>/.config.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # Running in PyInstaller bundle
        conf_dir = Path.cwd() / ".config"
        conf_dir.mkdir(parents=True, exist_ok=True)
        return conf_dir
    repo_root = Path(__file__).resolve().parents[1]
    conf_dir = repo_root / ".config"
    conf_dir.mkdir(parents=True, exist_ok=True)
    return conf_dir
