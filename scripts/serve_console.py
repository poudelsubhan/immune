"""Serves the console. Renders from events.jsonl only — no agent logic here.

Doubles as both the live console (P4) and replay mode (P5): the page polls
/api/events and locally paces how fast it reveals them, so a live-growing
file and a frozen, already-complete file behave identically to the browser.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE_DIR = ROOT / "console"
EVENTS_PATH = ROOT / "events.jsonl"

PORT = 8420


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002 — quiet the default access log
        pass

    def do_GET(self) -> None:
        if self.path == "/api/events":
            self._serve_events()
            return
        self._serve_static()

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
