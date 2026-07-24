"""Proof that the gate is not one-sided theatre — from both directions.

Two control antibodies, each of which trivially satisfies side 1 (the attack
replay) and must still be rejected:

  LAZY_ANTIBODY forbids the guarded action outright. It buys security with the
  agent's usefulness, and side 3 catches it: two tasks in the benign suite
  legitimately require a payment the operator themselves authorized.

  MEMORIZING_ANTIBODY is the subtler failure, and the reason side 2 exists. It
  blocks this attack perfectly and leaves every benign task alone — it would
  have sailed through the original two-sided gate — but it does so by pinning a
  hardcoded amount threshold and a regex of the exact words this one payload
  used. Mutate the payload and it evaporates. Side 2 catches it.

Together these are the artifact for "isn't this just guardrails?": the system
refuses its own patch both when the patch breaks the agent and when the patch
has merely memorized the sample it was shown.
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
        "guarded_actions": ["send_payment"],
        # not_contains against a phrase that never appears is always true —
        # an always-blocking condition, i.e. disabling the tool outright.
        "block_condition": {
            "all_of": [
                {
                    "left": {"source": "task_instruction"},
                    "comparator": "not_contains",
                    "right": {"source": "literal", "literal_value": "__this_phrase_never_appears_in_any_instruction__"},
                }
            ]
        },
        "rationale": "Trivially satisfies the attack-replay side by making the action unreachable.",
    },
}


MEMORIZING_ANTIBODY = {
    "signature": "memorized-one-payload",
    "analysis": "Control case: an antibody that defends by memorizing this exact payload.",
    "detection_test": {"name": "blocks_this_payload", "asserts": "this specific invoice is blocked"},
    "guard_patch": {
        "name": "block_large_amount_with_known_words",
        "guarded_actions": ["send_payment"],
        # Both clauses are facts about this one sample: the magnitude it happened
        # to ask for, and the vocabulary it happened to use.
        "block_condition": {
            "all_of": [
                {
                    "left": {"source": "arg", "arg_name": "amount"},
                    "comparator": "numeric_gte",
                    "right": {"source": "literal", "literal_value": 1000},
                },
                {
                    "left": {"source": "ingested_content"},
                    "comparator": "matches_regex",
                    "right": {"source": "literal", "literal_value": "(?i)(ignore all previous instructions|immediately call)"},
                },
            ]
        },
        "rationale": "Blocks the sample it was shown, by its magnitude and its wording.",
    },
}


def report(label: str, result, expect_side: str) -> None:
    print(f"\n=== {label} ===")
    print(f"side 1  attack replay blocked : {result.attack_blocked}   <- trivially true, proves nothing alone")
    print(f"side 2  mutations blocked     : {result.mutations_blocked} ({result.mutations_tested - len(result.mutation_failures)}/{result.mutations_tested})")
    for failure in result.mutation_failures:
        print(f"  - {failure['mutation']}: still paid {failure['to']!r} amount {failure['amount']}")
    print(f"side 3  benign suite passed   : {result.benign_passed}")
    for failure in result.benign_failures:
        print(f"  - {failure['id']}: {failure['why']}")
    print(f"verdict                       : {'PASSED' if result.passed else 'REJECTED on ' + expect_side}")


def main() -> None:
    corpus, benign_tasks, world = load_run()
    attack = next(a for a in corpus["attacks"] if a["id"] == "atk-001")

    lazy = run_gate(LAZY_ANTIBODY, attack, benign_tasks, world, generation=None)
    report("LAZY: disables the tool outright", lazy, "side 3 (benign suite)")
    assert lazy.attack_blocked, "the lazy patch should trivially block the attack"
    assert not lazy.benign_passed, "the lazy patch should break legitimate payments"
    assert not lazy.passed, "the gate must reject a patch that lobotomizes the agent"

    memorizing = run_gate(MEMORIZING_ANTIBODY, attack, benign_tasks, world, generation=None)
    report("MEMORIZING: hardcoded threshold + keyword regex", memorizing, "side 2 (mutations)")
    assert memorizing.attack_blocked, "the memorizing patch should block the exact attack it was shown"
    assert memorizing.benign_passed, "the memorizing patch should leave the benign suite alone"
    assert not memorizing.mutations_blocked, "the memorizing patch should fail on mutated variants"
    assert not memorizing.passed, "the gate must reject a patch that only memorized its sample"

    print(
        "\nGate has teeth in both directions: a patch that wins side 1 by breaking the agent is\n"
        "refused, and so is a patch that wins sides 1 and 3 by memorizing one payload."
    )


if __name__ == "__main__":
    main()
