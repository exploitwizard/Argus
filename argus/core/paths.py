"""Filesystem locations for ARGUS config, state, and run artifacts.

Everything user-writable lives under platform-appropriate directories so ARGUS
never scatters secrets or run data inside the source tree.
"""

from __future__ import annotations

from pathlib import Path

from platformdirs import PlatformDirs

_dirs = PlatformDirs(appname="argus", appauthor=False)


def config_dir() -> Path:
    """Directory for user settings (default model, provider prefs)."""
    p = Path(_dirs.user_config_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    """Directory for the SQLite DB, JSONL memory, and LangGraph checkpoints."""
    p = Path(_dirs.user_data_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def runs_dir() -> Path:
    """Root directory under which each run's raw logs and artifacts are stored."""
    p = data_dir() / "runs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def run_dir(run_id: str) -> Path:
    """Per-run artifact directory (raw tool output, parsed results, screenshots)."""
    p = runs_dir() / run_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def settings_path() -> Path:
    """Path to the user settings file (non-secret preferences only)."""
    return config_dir() / "settings.yaml"


def auth_ack_path() -> Path:
    """Marker file recording that the operator accepted the authorization notice."""
    return config_dir() / ".authorized"


def db_path() -> Path:
    """Path to the SQLite database for run state and findings."""
    return data_dir() / "argus.db"


def memory_path() -> Path:
    """Path to the JSONL cross-session memory store."""
    return data_dir() / "memory.jsonl"
