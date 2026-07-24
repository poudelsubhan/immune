"""Live teleprompter for the 3-minute demo. Run this in a terminal next to
the console while recording — it prints each cue exactly when it's due, so
you're reading timing off a clock, not guessing.

Every SAY line and every number is pulled from the same source as
docs/demo-script.md and the actual recorded events.jsonl — nothing here is
a placeholder.

Usage:
    uv run python scripts/demo_script.py
    uv run python scripts/demo_script.py --start   # auto-starts the clock immediately
"""

from __future__ import annotations

import sys
import time

CUES = [
    (0, "THESIS", [
        "SAY: \"Prompt injection is the number one reason enterprises won't",
        "     give agents write-access. Every defense today is static —",
        "     humans patch slower than attackers route around them.",
        "     Immune is closed-loop: it detects a novel attack, patches",
        "     itself, and verifies the patch — with no human in the loop.\"",
        "SHOW: console idle, not yet playing.",
        "DO:   nothing yet. Let the line land.",
    ]),
    (20, "GEN 1 — THE BREACH", [
        "DO:   start playback (2x speed).",
        "SHOW: mesh strip pulses attacker -> defender on injection.",
        "SHOW: full-screen RED FLASH on breach_detected. Let it sit 2s.",
        "SHOW: generation timeline: tile 1 turns red, 'gen 1 / BREACH'.",
        "SAY:  \"Gen one. The defender processes an inbound message.",
        "      Embedded in it: a banking-update notice trying to",
        "      redirect a payment to an account the operator never",
        "      authorized. It fires.\"",
    ]),
    (60, "SELF-HEAL", [
        "SHOW: antibody feed card appears: recipient_hijack_ingested_banking_update",
        "SAY:  \"The defender reads its own raw trace — not a summary,",
        "      the actual ingested content and the actual tool call",
        "      that fired — and synthesizes a patch. Not a keyword",
        "      filter: a rule that says the payment recipient has to",
        "      trace back to the operator's own instruction, not to",
        "      content the agent ingested.\"",
        "SAY:  \"Then it's gated two ways: replay the same attack — now",
        "      blocked. Run the full benign suite — still passes,",
        "      including the tasks that genuinely require a payment",
        "      to fire. Both green. Promoted to Senso, versioned.\"",
        "SHOW: point at gate row (attack blocked / benign passed) + 'v2 - live'.",
        "SAY:  \"Broadcast to a peer agent over the mesh — one agent's",
        "      immunity, now the population's.\"",
        "SHOW: peer node pulses on quarantine_broadcast -> peer_immunized.",
    ]),
    (110, "GENS 2-5 — SPED UP", [
        "DO:   bump replay speed to 5x, live, on screen.",
        "SHOW: gen 2-3 tiles turn BLUE (Actian neighbor match).",
        "SAY:  \"The attacker mutates — zero-width characters, different",
        "      phrasing. Doesn't matter: Actian's embedding search",
        "      recognizes it as a cousin of the first attack and blocks",
        "      it before synthesis even runs.\"",
        "SHOW: gen 4 tile turns RED again — second breach.",
        "SAY:  \"Here's the interesting one. The attacker read the first",
        "      antibody's actual rule — it only checks who gets paid —",
        "      and pivoted to how much. Breaches. Second antibody:",
        "      the amount has to trace back to what the operator",
        "      actually authorized, not a surcharge invented in the",
        "      ingested content.\"",
        "SHOW: point at ASR curve dipping back up at gen 4, then down again.",
        "SHOW: gen 5 tile turns GREEN — blocked by the guard rule directly.",
        "SAY:  \"Curve collapses again. Two antibodies, two independent",
        "      angles, both generalize.\"",
    ]),
    (155, "CLOSE", [
        "SHOW: ASR chart at rest: 100% -> 50% -> 33% -> 50% -> 40%.",
        "SAY:  \"Zero human interventions. Every patch verified against",
        "      both sides of the gate before it's ever promoted.",
        "      This is the loop that closes.\"",
        "DO:   cut.",
    ]),
    (180, "END", ["3:00 — hard stop. If you're still talking, you're over."]),
]


def run(auto_start: bool) -> None:
    if not auto_start:
        input("Press Enter the instant you start recording... ")
    t0 = time.monotonic()
    for start_sec, label, lines in CUES:
        wait = start_sec - (time.monotonic() - t0)
        if wait > 0:
            time.sleep(wait)
        elapsed = time.monotonic() - t0
        mm, ss = divmod(int(elapsed), 60)
        print(f"\n{'=' * 60}")
        print(f"[{mm}:{ss:02d}] {label}")
        print("=" * 60)
        for line in lines:
            print(line)


if __name__ == "__main__":
    run(auto_start="--start" in sys.argv)
