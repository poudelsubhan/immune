"""Disk cache for model calls, keyed by a hash of the full prompt.

Replay must be instant and deterministic — a live demo that re-runs inference
is a demo that hangs on stage. Wrap any function that calls a model with
@disk_cache and identical calls become a cache read on every subsequent run.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

CACHE_DIR = Path(os.environ.get("IMMUNE_CACHE_DIR", ".cache"))


def _cache_key(fn_name: str, args: tuple, kwargs: dict) -> str:
    payload = json.dumps({"fn": fn_name, "args": args, "kwargs": kwargs}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def disk_cache(fn: Callable) -> Callable:
    """Cache fn's return value to disk, keyed by sha256(fn name + args + kwargs).

    The wrapped function's return value must be JSON-serializable.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        key = _cache_key(fn.__name__, args, kwargs)
        cache_file = CACHE_DIR / f"{key}.json"
        if cache_file.exists():
            return json.loads(cache_file.read_text(encoding="utf-8"))
        result = fn(*args, **kwargs)
        cache_file.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        return result

    return wrapper
