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
    "action_blocked",
    "synthesis_start",
    "antibody_candidate",
    "gate_attack_replay",
    "gate_benign_suite",
    "antibody_rejected",
    "antibody_promoted",
    "variant_blocked_by_neighbor",
    "quarantine_broadcast",
    "peer_immunized",
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


def reset_events(path: Path | str = EVENTS_PATH) -> None:
    """Truncate the event log. Use at the start of a fresh recorded run — never mid-run."""
    Path(path).write_text("", encoding="utf-8")
