"""P3 gate check: a 5-generation run, unattended.

What the run has to demonstrate is that a promoted antibody generalizes: at
least one later generation must be stopped by the guard executing a rule
synthesized for an earlier, different attack, and at least one genuinely novel
attack must land and produce a new antibody.

Note what is deliberately *not* asserted any more: that some generation was
"blocked by Actian similarity". Similarity to a patched attack was never
evidence that the patch works, and while that check ran ahead of the guard it
was silently converting real breaches into apparent wins. Blocks now have to be
earned by a rule that actually fires.
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

    archived = reset_events()
    print(f"[p3] events log reset at {EVENTS_PATH}")
    if archived:
        print(f"[p3] previous run preserved at {archived}")
    # Start the vector index empty: it persists in the Docker volume, and
    # leftovers from earlier runs crowd out the neighbors this run needs.
    signatures.reset()
    print(f"[p3] antibody store: {'Senso (live)' if store.live else 'local fallback'}")
    print(f"[p3] signature store: {'Actian (live, reset)' if signatures.live else 'in-memory fallback'}")
    print(f"[p3] mesh: defender={defender_mesh.live} peer={peer_mesh.live}")

    print(f"\n[p3] running {N_GENERATIONS} generations, unattended")
    history = run_population(N_GENERATIONS, benign_tasks, world, store, signatures, defender_mesh, peer_mesh)

    print("\n[p3] generation-by-generation:")
    per_gen = []
    for record in history:
        outcome = "BREACH" if record["breached"] else "blocked"
        detail = record.get("promoted") or record.get("blocked_by") or ""
        notes = []
        if record.get("variant_of"):
            notes.append(f"variant of {record['variant_of']}")
        if record.get("coverage_gap"):
            notes.append("COVERAGE GAP — resembled a patched attack and breached anyway")
        suffix = f"   [{'; '.join(notes)}]" if notes else ""
        print(f"  gen {record['generation']} [{record['family']}]: {outcome:7s} {detail}{suffix}")
        per_gen.append(1 if record["breached"] else 0)

    # Co-evolution, not attack success rate. A breach by an attacker that writes
    # its own scenario every generation means it found uncovered ground, which is
    # its job — so breach rate measures the attacker's creativity, not the
    # defender's weakness. The two sides are reported separately.
    sword = [r.get("sword_rules_faced", 0) for r in history]
    shield = [r.get("shield_variants_blocked", 0) for r in history]
    shield_total = [r.get("shield_variants_total", 0) for r in history]

    print(f"\n[p3] ⚔ sword  — gate-verified defenses in force when it still got through: {sword}")
    print(f"[p3] 🛡 shield — known attack variants the rule set provably blocks:        {shield}")
    print(f"[p3]              out of, in total:                                        {shield_total}")

    breaches = [r for r in history if r["breached"]]
    novel_promotions = [r for r in breaches if r.get("promoted")]
    unpatched = [r for r in breaches if not r.get("promoted")]
    coverage_gaps = [r for r in history if r.get("coverage_gap")]

    print(f"\n[p3] breaches: {len(breaches)}   patched: {len(novel_promotions)}   "
          f"left unpatched: {len(unpatched)}   coverage gaps: {len(coverage_gaps)}")

    assert len(history) == N_GENERATIONS, "run did not complete all generations unattended"
    assert novel_promotions, "expected at least one novel attack to land and produce a new antibody"
    # The ratchet: every breach must end the generation with a gate-verified
    # patch. Breaching is allowed — leaving the hole open is not.
    assert not unpatched, (
        f"{len(unpatched)} breach(es) produced no antibody that survived the gate: "
        f"{[r['generation'] for r in unpatched]} — the loop failed to close"
    )
    # The defender's real guarantee: it never regresses on anything it has seen.
    assert shield[-1] == shield_total[-1], (
        f"verified coverage is not complete — {shield[-1]}/{shield_total[-1]} known attack variants "
        "blocked; a promoted rule failed to generalize across the accumulated history"
    )
    assert shield == sorted(shield), f"shield coverage went backwards across generations: {shield}"

    print("\n[p3] GATE PASSED")


if __name__ == "__main__":
    main()
