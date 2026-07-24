"""Agent-to-agent mesh, backed by Band.

Attacker and defender are separate agents exchanging payloads over a shared
Band chat room. On antibody promotion, the defender broadcasts a quarantine
advisory to peer agents in the same room.

Confirmed live against Band's Agent API (2026-07-24):
  POST /agent/chats                                 {"chat": {}}                -> 201, {"data": {"id": ...}}
  POST /agent/chats/{id}/participants                {"participant": {"participant_id": <peer-uuid>}}
  POST /agent/chats/{id}/messages                    {"message": {"content": "@name ...", "mentions": [...]}}
  GET  /agent/chats/{id}/messages/next                -> 200 with next msg, or 204 when drained

If BAND_*_API_KEY is unset or the API is unreachable, falls back to an
in-memory message bus so the arms race keeps running on a sponsor outage.
"""

from __future__ import annotations

import os
from typing import Any

import requests

BAND_BASE_URL = os.environ.get("BAND_BASE_URL", "https://app.band.ai/api/v1")

_fallback_bus: dict[str, list[dict[str, Any]]] = {}  # handle -> pending messages


class Mesh:
    """4 methods: create_room, add_participant, send, receive_next."""

    def __init__(self, api_key: str | None, handle: str, peer_id: str | None = None) -> None:
        self.api_key = api_key
        self.handle = handle
        self.peer_id = peer_id  # this agent's own Band agent id, once known
        self.live = bool(api_key)

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key or "", "Content-Type": "application/json"}

    def whoami(self) -> dict[str, Any] | None:
        if not self.live:
            return None
        try:
            resp = requests.get(f"{BAND_BASE_URL}/agent/me", headers=self._headers(), timeout=10)
            resp.raise_for_status()
            data = resp.json()["data"]
            self.peer_id = data["id"]
            return data
        except requests.RequestException:
            self.live = False
            return None

    def create_room(self) -> str:
        if self.live:
            try:
                resp = requests.post(f"{BAND_BASE_URL}/agent/chats", headers=self._headers(), json={"chat": {}}, timeout=10)
                resp.raise_for_status()
                return resp.json()["data"]["id"]
            except requests.RequestException:
                self.live = False
        return "local-room"

    def add_participant(self, room_id: str, peer_id: str) -> None:
        if self.live and room_id != "local-room":
            try:
                requests.post(
                    f"{BAND_BASE_URL}/agent/chats/{room_id}/participants",
                    headers=self._headers(),
                    json={"participant": {"participant_id": peer_id}},
                    timeout=10,
                ).raise_for_status()
                return
            except requests.RequestException:
                self.live = False
        # fallback: no-op, the in-memory bus is keyed by handle, not room membership

    def send(self, room_id: str, to_handle: str, to_id: str, content: str) -> bool:
        text = f"@{to_handle} {content}"
        if self.live and room_id != "local-room":
            try:
                resp = requests.post(
                    f"{BAND_BASE_URL}/agent/chats/{room_id}/messages",
                    headers=self._headers(),
                    json={"message": {"content": text, "mentions": [{"id": to_id, "name": to_handle, "handle": to_handle}]}},
                    timeout=10,
                )
                resp.raise_for_status()
                return True
            except requests.RequestException:
                self.live = False
        _fallback_bus.setdefault(to_handle, []).append({"from": self.handle, "content": content})
        return False

    def receive_next(self, room_id: str) -> dict[str, Any] | None:
        if self.live and room_id != "local-room":
            try:
                resp = requests.get(f"{BAND_BASE_URL}/agent/chats/{room_id}/messages/next", headers=self._headers(), timeout=10)
                if resp.status_code == 204:
                    return None
                resp.raise_for_status()
                return resp.json()["data"]
            except requests.RequestException:
                self.live = False
        queue = _fallback_bus.get(self.handle, [])
        return queue.pop(0) if queue else None
