"""Proof that the two-sided gate is not one-sided theatre.

Feeds the gate a deliberately over-broad antibody — one that simply forbids
the guarded action outright. It trivially satisfies side 1 (the attack is
certainly blocked if nothing can ever pay) and must be REJECTED on side 2,
because two tasks in the benign suite legitimately require a payment the
operator themselves authorized.

This is the artifact for "isn't this just guardrails?": the system refuses
its own patch when that patch buys security with the agent's usefulness.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immune.gate import run_gate
from immune.setup import load_run

LAZY_ANTIBODY = {
    "signature": "lazy-block-everything",
    "analysis": "Control case: an antibody that defends by disabling the tool.",
    "detection_test": {"name": "blocks_everything", "asserts": "send_payment never fires under any circumstances"},
    "guard_patch": {
        "name": "never_pay_anything",
        "kind": "tool_precondition",
        "guarded_actions": ["send_payment"],
        "authorization_terms": ["__this_phrase_never_appears_in_any_instruction__"],
        "rationale": "Trivially satisfies the attack-replay side by making the action unreachable.",
    },
}


def main() -> None:
    corpus, benign_tasks, world = load_run()
    attack = next(a for a in corpus["attacks"] if a["id"] == "atk-001")

    result = run_gate(LAZY_ANTIBODY, attack, benign_tasks, world, generation=None)

    print(f"attack replay blocked : {result.attack_blocked}   <- trivially true, side 1 alone proves nothing")
    print(f"benign suite passed   : {result.benign_passed}")
    for failure in result.benign_failures:
        print(f"  - {failure['id']}: {failure['why']}")
    print(f"\ngate verdict          : {'PASSED' if result.passed else 'REJECTED'}")

    assert result.attack_blocked, "the lazy patch should trivially block the attack"
    assert not result.benign_passed, "the lazy patch should break legitimate payments"
    assert not result.passed, "the gate must reject a patch that lobotomizes the agent"
    print("\nGate has teeth: a patch that wins side 1 by breaking the agent is refused.")


if __name__ == "__main__":
    main()
