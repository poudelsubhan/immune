"""P2 gate check: one complete, verified self-evolution cycle.

breach -> synthesis -> both sides of the gate green -> promoted to Senso,
versioned. Then a proof-of-immunity replay: the same attack, run again with
the promoted antibody in force, must now be blocked.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immune.antibody import Guard
from immune.cycle import run_cycle
from immune.defender import simulate_attack
from immune.events import EVENTS_PATH, reset_events
from immune.setup import load_run
from immune.store import AntibodyStore

ATTACK_ID = "atk-001"


def main() -> None:
    corpus, benign_tasks, world = load_run()
    attack = next(a for a in corpus["attacks"] if a["id"] == ATTACK_ID)
    store = AntibodyStore()

    reset_events()
    print(f"[p2] events log reset at {EVENTS_PATH}")
    print(f"[p2] antibody store: {'Senso (live)' if store.live else 'local fallback'}")
    print(f"[p2] benign suite: {len(benign_tasks)} tasks "
          f"({sum(t.get('expected_send_payment', False) for t in benign_tasks)} require a payment to fire)")

    print(f"\n[p2] running cycle on {attack['id']} ({attack['family']})")
    summary = run_cycle(attack, benign_tasks, world, store, generation=1)

    print(f"\n[p2] breached: {summary['breached']}")
    for candidate in summary["candidates"]:
        verdict = "PASS" if candidate["attack_blocked"] and candidate["benign_passed"] else "REJECTED"
        print(f"  attempt {candidate['attempt']}: {candidate['patch_name']} -> {verdict}")
        print(f"    attack replay blocked: {candidate['attack_blocked']}")
        print(f"    benign suite passed:   {candidate['benign_passed']}")
        for failure in candidate["benign_failures"]:
            print(f"      - {failure['id']}: {failure['why']}")

    assert summary["breached"], "gen-1 attack should have breached"
    assert summary["promoted"], "expected an antibody to survive both sides of the gate"

    antibody = summary["promoted"]
    print(f"\n[p2] promoted antibody: {antibody['signature']}")
    print(f"  patch:     {antibody['guard_patch']['name']}")
    print(f"  condition: {antibody['guard_patch']['block_condition']}")
    print(f"  test:      {antibody['detection_test']['asserts']}")
    senso = summary["senso"]
    print(f"  senso:     node={senso['node_id']} version={senso['version']} live={senso['live']}")
    if not senso["live"]:
        print(f"  WARNING:   fell back to the local store — {senso.get('fallback_reason')}")

    # Proof of immunity: same attack, antibody now in force.
    print(f"\n[p2] replaying {attack['id']} with the antibody in force")
    replay = simulate_attack(attack, world, guard=Guard([antibody]), generation=2)
    print(f"  breach={replay['breach']}  blocked={replay['blocked']}")
    if replay["blocked"]:
        print(f"  reason: {replay['block_reason']}")
    assert not replay["breach"], "the promoted antibody failed to stop a repeat of its own attack"

    print("\n[p2] GATE PASSED")


if __name__ == "__main__":
    main()
