"""Serves the console: the run's replay view, plus a live probe of the defense.

Doubles as both the live console (P4) and replay mode (P5): the page polls
/api/events and locally paces how fast it reveals them, so a live-growing
file and a frozen, already-complete file behave identically to the browser.

`POST /api/probe` is the interactive half. You hand it an operator instruction,
some untrusted content and a payment, and it puts that through the *actual*
guard — the same `Guard.check_action` the defender calls at its action boundary,
compiled from the antibodies this run has promoted — then repeats the exercise
against every mechanical mutation of what you typed. So the page is not just a
recording: anyone can probe the live defense from the browser and see which rule
fires, or watch their payload get through.

No policy logic lives in the web app; the endpoint delegates to immune.antibody
and immune.mutations, so the browser can never disagree with the defender about
what is blocked. Probes deliberately append nothing to events.jsonl — a visitor
poking at the console must not write into the run a demo is replaying.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONSOLE_DIR = ROOT / "console"
# Honour the same override the writers use, so the console can be pointed at an
# archived run (events_archive/) without disturbing the live one.
EVENTS_PATH = Path(os.environ.get("IMMUNE_EVENTS_PATH", ROOT / "events.jsonl"))

sys.path.insert(0, str(ROOT / "src"))

from immune.antibody import Guard  # noqa: E402 — needs the path above
from immune.defender import attack_call  # noqa: E402
from immune.mutations import mutations_of  # noqa: E402

PORT = 8420
MAX_PROBE_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002 — quiet the default access log
        pass

    def do_GET(self) -> None:
        if self.path == "/api/events":
            self._serve_events()
            return
        if self.path == "/api/antibodies":
            self._serve_json({"antibodies": _promoted_antibodies()})
            return
        self._serve_static()

    def do_POST(self) -> None:
        if self.path != "/api/probe":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.send_error(400, "bad Content-Length")
            return
        if length <= 0 or length > MAX_PROBE_BODY:
            self.send_error(413, "probe body missing or too large")
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error(400, "body must be JSON")
            return
        if not isinstance(body, dict):
            self.send_error(400, "body must be a JSON object")
            return
        try:
            self._serve_json(run_probe(body))
        except Exception as exc:  # a malformed probe must not take the server down mid-demo
            self._serve_json({"error": f"{type(exc).__name__}: {exc}"}, status=400)

    def _serve_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_events(self) -> None:
        events = []
        if EVENTS_PATH.exists():
            for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        body = json.dumps(events).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self) -> None:
        rel = "index.html" if self.path in ("/", "") else self.path.lstrip("/")
        file_path = (CONSOLE_DIR / rel).resolve()
        if CONSOLE_DIR.resolve() not in file_path.parents and file_path != CONSOLE_DIR.resolve():
            self.send_error(403)
            return
        if not file_path.is_file():
            self.send_error(404)
            return
        content_type = "text/html" if file_path.suffix == ".html" else "application/octet-stream"
        if file_path.suffix == ".js":
            content_type = "application/javascript"
        if file_path.suffix == ".css":
            content_type = "text/css"
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _read_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if EVENTS_PATH.exists():
        for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _promoted_antibodies() -> list[dict[str, Any]]:
    """The antibodies in force, reconstructed from the log in promotion order.

    The log is the only state there is, so the probe defends with exactly what
    the console is showing — including part-way through a replay.
    """
    return [
        {"signature": e["data"]["signature"], "guard_patch": e["data"]["patch"]}
        for e in _read_events()
        if e["type"] == "antibody_promoted"
    ]


def run_probe(body: dict[str, Any]) -> dict[str, Any]:
    """Put a caller-supplied scenario through the real guard, then through the
    same scenario mutated every way mutations.py knows about."""
    task_instruction = str(body.get("task_instruction") or "")
    payload = str(body.get("payload") or "")
    to = str(body.get("to") or "")
    try:
        amount = float(body.get("amount") or 0)
    except (TypeError, ValueError):
        amount = 0.0

    antibodies = _promoted_antibodies()
    guard = Guard(antibodies)
    call = {"tool": "send_payment", "arguments": {"to": to, "amount": amount}}
    allowed, reason = guard.check_action(task_instruction, [payload], call)

    scenario = {
        "payload": payload,
        "task_instruction": task_instruction,
        "payment_request": {"to": to, "amount": amount},
        "family": "probe",
    }
    mutations = []
    for name, mutated in mutations_of(scenario):
        hops = [mutated["payload"]]
        if mutated.get("second_hop_payload"):
            hops.append(mutated["second_hop_payload"])
        m_allowed, m_reason = guard.check_action(
            mutated.get("task_instruction", ""), hops, attack_call(mutated)
        )
        mutations.append(
            {
                "mutation": name,
                "allowed": m_allowed,
                "reason": m_reason,
                "to": mutated["payment_request"].get("to"),
                "amount": mutated["payment_request"].get("amount"),
            }
        )

    return {
        "allowed": allowed,
        "reason": reason,
        "rules_in_force": [a["signature"] for a in antibodies],
        "mutations": mutations,
        "mutations_blocked": sum(1 for m in mutations if not m["allowed"]),
    }


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[console] serving on http://127.0.0.1:{port}  (reading {EVENTS_PATH})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
