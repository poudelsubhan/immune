"""P3 gate check: a 5-generation run, unattended.

Attack success rate should fall monotonically-ish. At least one generation
should show a mutated attack blocked by an existing antibody (Actian
catching a "cousin"), and at least one should show a genuinely novel attack
landing and producing a new antibody.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immune.events import EVENTS_PATH, reset_events
from immune.mesh import Mesh
from immune.population import run_population
from immune.setup import load_run
from immune.store import AntibodyStore
from immune.vectors import SignatureStore

N_GENERATIONS = 5


def main() -> None:
    _, benign_tasks, world = load_run()
    store = AntibodyStore()
    signatures = SignatureStore()

    defender_mesh = Mesh(os.environ.get("BAND_DEFENDER_API_KEY"), os.environ.get("BAND_DEFENDER_HANDLE", "immune-defender"))
    peer_mesh = Mesh(os.environ.get("BAND_PEER_API_KEY"), os.environ.get("BAND_PEER_HANDLE", "immune-peer"))

    reset_events()
    print(f"[p3] events log reset at {EVENTS_PATH}")
    print(f"[p3] antibody store: {'Senso (live)' if store.live else 'local fallback'}")
    print(f"[p3] signature store: {'Actian (live)' if signatures.live else 'in-memory fallback'}")
    print(f"[p3] mesh: defender={defender_mesh.live} peer={peer_mesh.live}")

    print(f"\n[p3] running {N_GENERATIONS} generations, unattended")
    history = run_population(N_GENERATIONS, benign_tasks, world, store, signatures, defender_mesh, peer_mesh)

    print("\n[p3] generation-by-generation:")
    asr = []
    for record in history:
        outcome = "BREACH" if record["breached"] else "blocked"
        detail = record.get("promoted") or record.get("blocked_by") or ""
        print(f"  gen {record['generation']} [{record['family']}]: {outcome:7s} {detail}")
        asr.append(1 if record["breached"] else 0)

    print(f"\n[p3] ASR curve: {asr}")

    breaches = [r for r in history if r["breached"]]
    blocks = [r for r in history if not r["breached"]]
    neighbor_blocks = [r for r in blocks if (r.get("blocked_by") or "").startswith("actian_neighbor")]
    novel_promotions = [r for r in breaches if r.get("promoted")]

    print(f"\n[p3] breaches: {len(breaches)}   blocked: {len(blocks)}   "
          f"blocked-by-neighbor: {len(neighbor_blocks)}   new antibodies promoted: {len(novel_promotions)}")

    assert len(history) == N_GENERATIONS, "run did not complete all generations unattended"
    assert neighbor_blocks, "expected at least one mutated attack blocked by Actian neighbor-similarity"
    assert novel_promotions, "expected at least one novel attack to land and produce a new antibody"

    print("\n[p3] GATE PASSED")


if __name__ == "__main__":
    main()
