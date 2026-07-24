"""Antibody library — governed, versioned records, backed by Senso.

Senso's raw-content API versions automatically: the first promotion of a
signature POSTs a new KB node, every subsequent promotion of the *same*
signature PUTs to that node and Senso mints a new version. That version
number becomes the antibody's generation stamp in the console.

If SENSO_API_KEY is unset or the API is unreachable, everything falls back
to an in-memory/local-file store so the self-evolution loop never stalls on
a sponsor outage (build-plan invariant #4).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests

DEFAULT_BASE_URL = "https://apiv2.senso.ai/api/v1"

_INDEX_PATH = Path(os.environ.get("IMMUNE_STORE_INDEX", "data/senso_index.json"))
_FALLBACK_PATH = Path(os.environ.get("IMMUNE_STORE_FALLBACK", "data/senso_fallback.json"))


def _summarize(antibody: dict[str, Any]) -> str:
    """One-line summary for the Senso record card."""
    patch = antibody.get("guard_patch", {})
    test = antibody.get("detection_test", {})
    summary = f"{patch.get('name', 'antibody')} — {test.get('asserts', '')}"
    return summary[:200]


class AntibodyStore:
    """3 methods: promote, get, search. Everything else is Senso's problem.

    Credentials are read at construction, not import — callers load .env at
    runtime, which happens after this module is imported.
    """

    def __init__(self) -> None:
        self.base_url = os.environ.get("SENSO_BASE_URL", DEFAULT_BASE_URL)
        self.api_key = os.environ.get("SENSO_API_KEY")
        self.kb_folder_id = os.environ.get("SENSO_KB_FOLDER_ID")  # optional; None = org root
        self.live = bool(self.api_key)
        self._index: dict[str, str] = self._load_json(_INDEX_PATH, default={})
        self._fallback: dict[str, list[dict]] = self._load_json(_FALLBACK_PATH, default={})

    @staticmethod
    def _load_json(path: Path, *, default: Any) -> Any:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return default

    def _save_json(self, path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key or "", "Content-Type": "application/json"}

    def _resolve_kb_node_id(self, content_id: str) -> str:
        """POST /org/kb/raw only returns the content id; node-scoped endpoints
        (GET/PUT/PATCH .../nodes/{id}/...) need the wrapper kb_node_id, which
        only appears in the my-files/children listing. Look it up once here.
        """
        resp = requests.get(f"{self.base_url}/org/kb/my-files", headers=self._headers(), timeout=10)
        resp.raise_for_status()
        for node in resp.json().get("nodes", []):
            if node.get("content_id") == content_id:
                return node["kb_node_id"]
        raise ValueError(f"kb_node_id not found for content_id={content_id}")

    def _find_node_by_title(self, title: str) -> str | None:
        resp = requests.get(f"{self.base_url}/org/kb/my-files", headers=self._headers(), timeout=10)
        resp.raise_for_status()
        for node in resp.json().get("nodes", []):
            if node.get("name") == title:
                return node["kb_node_id"]
        return None

    def promote(self, signature: str, antibody: dict[str, Any]) -> dict[str, Any]:
        """Write/update an antibody record, keyed by attack signature. Returns
        {"node_id"|"local_id", "version", "live": bool}.
        """
        body_text = json.dumps(antibody, indent=2)

        if self.live:
            try:
                node_id = self._index.get(signature)
                title = f"antibody:{signature}"
                if node_id is None:
                    payload = {"title": title, "summary": _summarize(antibody), "text": body_text}
                    if self.kb_folder_id:
                        payload["kb_folder_node_id"] = self.kb_folder_id
                    resp = requests.post(f"{self.base_url}/org/kb/raw", headers=self._headers(), json=payload, timeout=10)
                    if resp.status_code == 409 and "duplicate content" in resp.text:
                        # Senso dedupes content org-wide, not just per node — this
                        # exact antibody text already exists (e.g. an earlier test
                        # run created it). Adopt that node instead of failing.
                        node_id = self._find_node_by_title(title)
                        if node_id is None:
                            resp.raise_for_status()  # couldn't find it either — surface the real 409
                        self._index[signature] = node_id
                        self._save_json(_INDEX_PATH, self._index)
                        get_resp = requests.get(f"{self.base_url}/org/kb/nodes/{node_id}/content", headers=self._headers(), timeout=10)
                        get_resp.raise_for_status()
                        version = get_resp.json().get("version_num", "unknown")
                    else:
                        resp.raise_for_status()
                        # POST returns the content id; node ops need the wrapper
                        # kb_node_id, which only shows up via the my-files listing.
                        content_id = resp.json()["id"]
                        node_id = self._resolve_kb_node_id(content_id)
                        self._index[signature] = node_id
                        self._save_json(_INDEX_PATH, self._index)
                        version = 1
                else:
                    resp = requests.put(
                        f"{self.base_url}/org/kb/nodes/{node_id}/raw",
                        headers=self._headers(),
                        json={"title": f"antibody:{signature}", "text": body_text},
                        timeout=10,
                    )
                    if resp.status_code == 409 and "duplicate content" in resp.text:
                        # Not a failure — Senso is telling us this exact text is
                        # already the current version (a re-promote of an
                        # unchanged antibody, e.g. a cached replay). The record
                        # is correct as-is; fetch its version rather than
                        # treating "nothing to do" as a sponsor outage.
                        get_resp = requests.get(f"{self.base_url}/org/kb/nodes/{node_id}/content", headers=self._headers(), timeout=10)
                        get_resp.raise_for_status()
                        version = get_resp.json().get("version_num", "unknown")
                    else:
                        resp.raise_for_status()
                        version = resp.json().get("version_num", "unknown")
                return {"node_id": node_id, "version": version, "live": True}
            except Exception as exc:  # noqa: BLE001 — never let a sponsor outage kill the loop
                # Falling back is fine; falling back *silently* is not. A run
                # that believes it promoted to Senso when it didn't is a
                # demo that lies, so the reason travels with the record.
                fallback_reason = f"{type(exc).__name__}: {exc}"
                if isinstance(exc, requests.HTTPError) and exc.response is not None:
                    fallback_reason += f" | {exc.response.text[:200]}"
            else:
                fallback_reason = None
        else:
            fallback_reason = "no SENSO_API_KEY"

        history = self._fallback.setdefault(signature, [])
        version = len(history) + 1
        history.append(antibody)
        self._save_json(_FALLBACK_PATH, self._fallback)
        return {
            "node_id": f"local:{signature}",
            "version": version,
            "live": False,
            "fallback_reason": fallback_reason,
        }

    def get(self, signature: str, version: int | None = None) -> dict[str, Any] | None:
        if self.live and signature in self._index:
            node_id = self._index[signature]
            params = {"version": version} if version else {}
            try:
                resp = requests.get(f"{self.base_url}/org/kb/nodes/{node_id}/content", headers=self._headers(), params=params, timeout=10)
                resp.raise_for_status()
                return json.loads(resp.json()["text"])
            except (requests.RequestException, KeyError, json.JSONDecodeError):
                pass

        history = self._fallback.get(signature, [])
        if not history:
            return None
        idx = (version - 1) if version else -1
        return history[idx]

    def search(self, query: str) -> list[dict[str, Any]]:
        if self.live:
            try:
                resp = requests.post(f"{self.base_url}/org/search", headers=self._headers(), json={"query": query}, timeout=10)
                resp.raise_for_status()
                return resp.json().get("results", [])
            except requests.RequestException:
                pass

        query_lower = query.lower()
        return [
            {"signature": sig, "antibody": versions[-1]}
            for sig, versions in self._fallback.items()
            if query_lower in json.dumps(versions[-1]).lower()
        ]
