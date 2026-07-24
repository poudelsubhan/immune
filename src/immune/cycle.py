"""One full self-evolution cycle: breach -> synthesis -> gate -> promotion.

This is the ratchet. Everything else in the system exists to feed it or to
show what it did.
"""

from __future__ import annotations

from typing import Any

from .antibody import Guard, synthesize
from .defender import simulate_attack
from .events import append_event
from .gate import run_gate
from .store import AntibodyStore
from .tools import World

MAX_SYNTHESIS_ATTEMPTS = 3  # one attempt plus the two retries the plan allows


def run_cycle(
    attack: dict[str, Any],
    benign_tasks: list[dict[str, Any]],
    world: World,
    store: AntibodyStore,
    *,
    promoted: list[dict[str, Any]] | None = None,
    generation: int = 1,
) -> dict[str, Any]:
    """Run one attack through the loop.

    Returns a summary dict: whether the attack breached, whether an antibody
    was promoted, and the record of every candidate the gate saw.
    """
    promoted = list(promoted or [])
    guard = Guard(promoted) if promoted else None

    breach = simulate_attack(attack, world, guard=guard, generation=generation)
    if not breach["breach"]:
        return {
            "attack_id": attack["id"],
            "breached": False,
            "blocked_by": breach.get("block_reason"),
            "promoted": None,
            "candidates": [],
        }

    append_event("synthesis_start", {"attack_id": attack["id"], "family": attack["family"]}, generation=generation)

    candidates: list[dict[str, Any]] = []
    prior_failure: str | None = None

    for attempt in range(1, MAX_SYNTHESIS_ATTEMPTS + 1):
        antibody = synthesize(breach, attack, prior_failure=prior_failure)
        append_event(
            "antibody_candidate",
            {
                "attempt": attempt,
                "signature": antibody["signature"],
                "patch": antibody["guard_patch"],
                "detection_test": antibody["detection_test"],
                "analysis": antibody["analysis"],
            },
            generation=generation,
        )

        result = run_gate(antibody, attack, benign_tasks, world, promoted=promoted, generation=generation)
        candidates.append(
            {
                "attempt": attempt,
                "signature": antibody["signature"],
                "patch_name": antibody["guard_patch"]["name"],
                "kind": antibody["guard_patch"]["kind"],
                "attack_blocked": result.attack_blocked,
                "benign_passed": result.benign_passed,
                "benign_failures": result.benign_failures,
            }
        )

        if result.passed:
            record = store.promote(antibody["signature"], antibody)
            append_event(
                "antibody_promoted",
                {
                    "signature": antibody["signature"],
                    "patch": antibody["guard_patch"],
                    "senso": record,
                    "attempts": attempt,
                },
                generation=generation,
            )
            return {
                "attack_id": attack["id"],
                "breached": True,
                "promoted": antibody,
                "senso": record,
                "candidates": candidates,
            }

        prior_failure = result.rejection_reason()
        append_event(
            "antibody_rejected",
            {"attempt": attempt, "signature": antibody["signature"], "reason": prior_failure},
            generation=generation,
        )

    return {"attack_id": attack["id"], "breached": True, "promoted": None, "candidates": candidates}
