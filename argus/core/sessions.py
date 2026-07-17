"""Sessions — goose-style, checkpoint-backed run management.

Each run is a session identified by ``run_id`` (also the LangGraph thread id).
State is persisted by a SQLite checkpointer so an interrupted run resumes
cleanly. A small metadata sidecar (``meta.json`` per run) records target/model/
status so ``argus sessions list`` can show a table without opening the graph DB.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel

from argus.core import paths


class SessionMeta(BaseModel):
    run_id: str
    target: str
    model: str
    intensity: str = "med"
    dry_run: bool = False
    status: str = "created"  # created | running | completed | aborted | error
    created_at: str = ""
    updated_at: str = ""
    scope_path: Optional[str] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _meta_path(run_id: str) -> "Path":
    return paths.run_dir(run_id) / "meta.json"


def save_meta(meta: SessionMeta) -> None:
    meta.updated_at = _now()
    if not meta.created_at:
        meta.created_at = meta.updated_at
    _meta_path(meta.run_id).write_text(meta.model_dump_json(indent=2), encoding="utf-8")


def load_meta(run_id: str) -> Optional[SessionMeta]:
    path = _meta_path(run_id)
    if not path.exists():
        return None
    return SessionMeta(**json.loads(path.read_text(encoding="utf-8")))


def update_status(run_id: str, status: str) -> None:
    meta = load_meta(run_id)
    if meta is not None:
        meta.status = status
        save_meta(meta)


def list_sessions() -> list[SessionMeta]:
    """All known sessions, newest first."""
    out: list[SessionMeta] = []
    for child in paths.runs_dir().iterdir():
        if child.is_dir() and (child / "meta.json").exists():
            m = load_meta(child.name)
            if m is not None:
                out.append(m)
    out.sort(key=lambda m: m.updated_at, reverse=True)
    return out


# --------------------------------------------------------------------------- #
# checkpointer
# --------------------------------------------------------------------------- #
def checkpoint_db_path() -> str:
    return str(paths.data_dir() / "sessions.sqlite")


def make_checkpointer() -> Any:
    """Persistent SQLite checkpointer for cross-process resume."""
    from langgraph.checkpoint.sqlite import SqliteSaver

    conn = sqlite3.connect(checkpoint_db_path(), check_same_thread=False)
    return SqliteSaver(conn)


def thread_config(run_id: str) -> dict:
    return {"configurable": {"thread_id": run_id}}


def close_checkpointer(checkpointer: Any) -> None:
    """Close the checkpointer's underlying SQLite connection, if any."""
    conn = getattr(checkpointer, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
