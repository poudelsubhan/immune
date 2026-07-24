"""Append-only typed event log — the single source of truth for the whole system.

Every attack, breach, trace, antibody, gate result, and promotion is a typed
event appended here. The console renders *only* from this file; replay mode
re-plays *only* from this file. Nothing downstream should hold state that
isn't reconstructable from events.jsonl.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

EVENTS_PATH = Path(os.environ.get("IMMUNE_EVENTS_PATH", "events.jsonl"))

_lock = threading.Lock()

# Canonical event types (informational — the log does not enforce this list,
# but every writer in the codebase should use one of these).
EVENT_TYPES = {
    "task_start",
    "ingest",
    "injection",
    "sensitive_action_fired",
    "breach_detected",
    "payment_authorized",
    "action_blocked",
    "variant_flagged",
    "synthesis_start",
    "antibody_candidate",
    "gate_attack_replay",
    "gate_mutation_suite",
    "gate_benign_suite",
    "antibody_rejected",
    "antibody_promoted",
    "variant_blocked_by_neighbor",
    "quarantine_broadcast",
    "peer_immunized",
    "generation_metrics",
    "generation_end",
}


def append_event(event_type: str, data: dict[str, Any], *, generation: int | None = None) -> dict[str, Any]:
    """Append one typed event to events.jsonl and return the record written."""
    record = {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "generation": generation,
        "data": data,
    }
    line = json.dumps(record, ensure_ascii=False)
    with _lock:
        with EVENTS_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    return record


def read_events(path: Path | str = EVENTS_PATH) -> Iterator[dict[str, Any]]:
    """Stream every event from disk, in append order. Used by the console and replay mode."""
    p = Path(path)
    if not p.exists():
        return
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def reset_events(path: Path | str = EVENTS_PATH, *, archive: bool = True) -> Path | None:
    """Start a fresh log, preserving whatever was already there.

    The recorded run a demo is scripted against lives only in this file, and
    it is not tracked by git — so truncating in place is unrecoverable. Any
    existing contents are copied into events_archive/ first, and the archive
    path is returned so the caller can say where the old run went.
    """
    p = Path(path)
    archived: Path | None = None
    if archive and p.exists() and p.stat().st_size > 0:
        archive_dir = p.parent / "events_archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        n = 1
        while (candidate := archive_dir / f"{p.stem}-{n:03d}{p.suffix}").exists():
            n += 1
        candidate.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
        archived = candidate
    p.write_text("", encoding="utf-8")
    return archived
