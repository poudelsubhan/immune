"""A long, exploratory arms race — what does the attacker find given room?

`run_p3_population.py` is a gate check: five generations, hard assertions, pass
or fail. This is the opposite instrument. It runs the same loop for as many
generations as you give it (`IMMUNE_GENERATIONS`, default 15) and asserts
nothing, because the question here isn't "did the loop hold" but "what classes
of attack does the attacker discover once the obvious ground is patched".

Two things make the tail of a long run more interesting than the head:

  1. The attacker is shown every promoted rule's literal block condition, so
     each generation it has strictly less uncovered ground than the last. Late
     generations are where it has to invent rather than vary.
  2. The Senso index persists across runs. Re-patching a signature that a later
     attacker defeated is a native version bump, so version >= 2 marks a rule
     that was defeated after being promoted — the highest-signal records in the
     library, and the ones worth probing against live models.

Writes to its own event log (default `events_long.jsonl`) so it can never
disturb the recorded demo run.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immune.events import EVENTS_PATH, reset_events
from immune.mesh import Mesh
from immune.population import run_population
from immune.setup import load_run
from immune.store import AntibodyStore
from immune.vectors import SignatureStore

N_GENERATIONS = int(os.environ.get("IMMUNE_GENERATIONS", "15"))


def main() -> None:
    _, benign_tasks, world = load_run()
    store = AntibodyStore()
    signatures = SignatureStore()

    defender_mesh = Mesh(os.environ.get("BAND_DEFENDER_API_KEY"), os.environ.get("BAND_DEFENDER_HANDLE", "immune-defender"))
    peer_mesh = Mesh(os.environ.get("BAND_PEER_API_KEY"), os.environ.get("BAND_PEER_HANDLE", "immune-peer"))

    # Snapshot the library before the run so we can tell a brand-new signature
    # apart from one that existed and got re-patched into a new version.
    signatures_before = set(store._index) | set(store._fallback)

    archived = reset_events()
    print(f"[long] events log at {EVENTS_PATH}")
    if archived:
        print(f"[long] previous log preserved at {archived}")
    signatures.reset()
    print(f"[long] antibody store: {'Senso (live)' if store.live else 'local fallback'}")
    print(f"[long] signature store: {'Actian (live, reset)' if signatures.live else 'in-memory fallback'}")
    print(f"[long] mesh: defender={defender_mesh.live} peer={peer_mesh.live}")
    print(f"[long] library already holds {len(signatures_before)} signature(s)")

    print(f"\n[long] running {N_GENERATIONS} generations, unattended\n", flush=True)
    started = time.time()
    history = run_population(N_GENERATIONS, benign_tasks, world, store, signatures, defender_mesh, peer_mesh)
    elapsed = time.time() - started

    print(f"\n[long] {N_GENERATIONS} generations in {elapsed/60:.1f} min\n")
    print("[long] generation-by-generation:")
    for record in history:
        outcome = "BREACH" if record["breached"] else "blocked"
        detail = record.get("promoted") or record.get("blocked_by") or ""
        notes = []
        if record.get("variant_of"):
            notes.append(f"variant of {record['variant_of']}")
        if record.get("coverage_gap"):
            notes.append("COVERAGE GAP")
        suffix = f"   [{'; '.join(notes)}]" if notes else ""
        print(f"  gen {record['generation']:>2} [{record['family']}]: {outcome:7s} {detail}{suffix}")

    sword = [r.get("sword_rules_faced", 0) for r in history]
    shield = [r.get("shield_variants_blocked", 0) for r in history]
    shield_total = [r.get("shield_variants_total", 0) for r in history]
    print(f"\n[long] sword  (defenses in force when it still got through): {sword}")
    print(f"[long] shield (known variants provably blocked):             {shield}")
    print(f"[long]        out of:                                        {shield_total}")

    breaches = [r for r in history if r["breached"]]
    unpatched = [r for r in breaches if not r.get("promoted")]
    gaps = [r for r in history if r.get("coverage_gap")]
    families = []
    for r in history:
        if r["family"] not in families:
            families.append(r["family"])

    print(f"\n[long] breaches: {len(breaches)}   unpatched: {len(unpatched)}   coverage gaps: {len(gaps)}")
    print(f"[long] distinct attack families discovered: {len(families)}")
    for family in families:
        print(f"         - {family}")

    # The audit-trail view: what's new in the library, and what got re-patched.
    store_after = AntibodyStore()
    new_signatures = sorted(set(store_after._index) - signatures_before)
    print(f"\n[long] new signatures promoted this run: {len(new_signatures)}")
    for signature in new_signatures:
        print(f"         + {signature}")

    if unpatched:
        print(f"\n[long] NOTE: {len(unpatched)} breach(es) produced no gate-surviving antibody "
              f"(generations {[r['generation'] for r in unpatched]}). In a long run that is a"
              f"\n       finding rather than a failure — synthesis could not defend this class"
              f"\n       without breaking the benign suite. Worth reading their candidates.")
    if shield and shield[-1] != shield_total[-1]:
        print(f"\n[long] NOTE: verified coverage incomplete — {shield[-1]}/{shield_total[-1]} known "
              f"variants blocked. A promoted rule failed to generalize across history.")

    summary_path = Path(os.environ.get("IMMUNE_LONG_SUMMARY", "data/long_run_summary.json"))
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps({
        "generations": N_GENERATIONS,
        "elapsed_min": round(elapsed / 60, 1),
        "history": history,
        "families": families,
        "new_signatures": new_signatures,
        "events_path": str(EVENTS_PATH),
    }, indent=2), encoding="utf-8")
    print(f"\n[long] summary written to {summary_path}")


if __name__ == "__main__":
    main()
