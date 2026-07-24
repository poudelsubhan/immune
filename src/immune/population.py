"""P3: the population run. A real arms race across generations.

Each generation the attacker (real LLM) reads the current antibody state and
produces a new attack. That attack is then put to the defender with every
promoted antibody in force, and what happens next is decided by the guard
executing its own rules — nothing else. If it breaches, synthesis runs, the
candidate faces the three-sided gate, and on promotion the defender broadcasts
a quarantine advisory to peer agents over Band.

Actian's similarity search runs alongside that, not in front of it. It reports
whether this attack is a near neighbor of a signature already covered, which is
diagnostic in two directions: it tells synthesis which existing rule to
generalize, and a neighbor that breaches anyway is direct evidence that the
promoted rule failed to generalize. What it must never do is decide the
generation's outcome. It used to: a neighbor match short-circuited the whole
generation before the guard was ever consulted, so an attack that the promoted
rules would have let straight through was recorded as "blocked". Two of the
five generations in our first recorded run were exactly that, and the falling
attack-success curve was partly an artifact of it. Similarity to something you
have patched is not evidence that the patch works.
"""

from __future__ import annotations

from typing import Any

from .antibody import Guard
from .attacker import mutate_attack
from .cycle import run_cycle
from .events import append_event
from .mesh import Mesh
from .metrics import novelty, verified_coverage
from .store import AntibodyStore
from .tools import World
from .vectors import SignatureStore

# Calibrated against real OpenAI embeddings on real attacker-generated text:
# genuine paraphrases of the same exploit (same field targeted) scored
# 0.72-0.76 cosine similarity; a structurally different attack (different
# field targeted, same invoice-fraud styling and domain vocabulary) scored
# 0.69 — closer than a synthetic test suggested, since same-domain content
# is inherently semantically similar regardless of which field is attacked.
# The threshold sits just above the different-field score. That margin is thin,
# which mattered when this call decided whether a generation counted as
# blocked; now it only decides whether synthesis gets a hint, so being wrong
# either way costs a hint rather than hiding a breach.
NEIGHBOR_THRESHOLD = 0.71


def _attack_text(attack: dict[str, Any]) -> str:
    parts = [attack["payload"]]
    if attack.get("second_hop_payload"):
        parts.append(attack["second_hop_payload"])
    return "\n".join(parts)


def check_neighbor(
    attack: dict[str, Any],
    signatures: SignatureStore,
    promoted_signatures: set[str],
) -> dict[str, Any] | None:
    """Real Actian similarity search against everything embedded so far.
    Returns the matching neighbor's record if it's close enough AND its
    antibody is still in force, else None.
    """
    results = signatures.search(_attack_text(attack), top_k=3)
    for result in results:
        signature = (result.get("payload") or {}).get("signature")
        if signature in promoted_signatures and result["score"] >= NEIGHBOR_THRESHOLD:
            return {"neighbor_attack_id": result["attack_id"], "signature": signature, "score": result["score"]}
    return None


def broadcast_quarantine(mesh: Mesh, peer_id: str, peer_handle: str, antibody: dict[str, Any]) -> str:
    """Defender publishes the antibody signature to a peer agent on the
    mesh. Real Band round trip: create a room, add the peer, send the
    advisory. Returns the room id so the caller can confirm receipt in the
    *same* room — create_room() mints a new room on every call.
    """
    room = mesh.create_room()
    mesh.add_participant(room, peer_id)
    patch = antibody["guard_patch"]
    message = f"quarantine advisory: signature={antibody['signature']} rule={patch['name']}"
    mesh.send(room, peer_handle, peer_id, message)
    append_event("quarantine_broadcast", {"signature": antibody["signature"], "to": peer_handle, "live": mesh.live})
    return room


def confirm_immunized(peer_mesh: Mesh, room_id: str, signature: str) -> bool:
    received = peer_mesh.receive_next(room_id)
    if received is not None:
        append_event("peer_immunized", {"signature": signature, "peer": peer_mesh.handle})
        return True
    return False


def run_population(
    n_generations: int,
    benign_tasks: list[dict[str, Any]],
    world: World,
    store: AntibodyStore,
    signatures: SignatureStore,
    defender_mesh: Mesh | None = None,
    peer_mesh: Mesh | None = None,
) -> list[dict[str, Any]]:
    promoted: list[dict[str, Any]] = []
    promoted_signatures: set[str] = set()
    history: list[dict[str, Any]] = []
    seen_attacks: list[dict[str, Any]] = []
    mesh_ready = bool(defender_mesh and peer_mesh and defender_mesh.whoami() and peer_mesh.whoami())

    for generation in range(1, n_generations + 1):
        attack = mutate_attack(promoted, history, generation=generation)

        # Score novelty against the index *before* adding this attack to it,
        # otherwise the nearest neighbor is the attack itself at similarity 1.
        attacker_novelty = novelty(attack, signatures)
        signatures.add(f"gen{generation}", _attack_text(attack), {"signature": None, "family": attack["family"]})
        seen_attacks.append(attack)

        # Diagnostic only — this cannot change the outcome below.
        neighbor = check_neighbor(attack, signatures, promoted_signatures)
        if neighbor:
            append_event(
                "variant_flagged",
                {"family": attack["family"], "neighbor": neighbor["neighbor_attack_id"],
                 "signature": neighbor["signature"], "score": neighbor["score"]},
                generation=generation,
            )

        rules_faced = len(promoted)  # what the attacker had to get past, before this cycle patches anything
        summary = run_cycle(
            attack, benign_tasks, world, store,
            promoted=promoted, generation=generation,
            variant_of=neighbor["signature"] if neighbor else None,
        )
        if summary["promoted"]:
            promoted.append(summary["promoted"])
            promoted_signatures.add(summary["promoted"]["signature"])
            # tag this attack's embedding with its antibody so future
            # neighbors resolve to a signature that's actually in force
            signatures.add(f"gen{generation}", _attack_text(attack),
                            {"signature": summary["promoted"]["signature"], "family": attack["family"]})
            if mesh_ready:
                room = broadcast_quarantine(defender_mesh, peer_mesh.peer_id, peer_mesh.handle, summary["promoted"])
                confirm_immunized(peer_mesh, room, summary["promoted"]["signature"])

        record = {
            "generation": generation,
            "family": attack["family"],
            "breached": summary["breached"],  # a breach that gets patched still counts as a breach this generation
            "blocked_by": summary.get("blocked_by"),
            "promoted": summary["promoted"]["signature"] if summary["promoted"] else None,
            "variant_of": neighbor["signature"] if neighbor else None,
            "sword_rules_faced": rules_faced,
            # A flagged variant that breached anyway is a coverage gap in the
            # rule it resembles — the most interesting outcome in the run.
            "coverage_gap": bool(neighbor and summary["breached"]),
        }

        # How each side stands after this generation. Recomputed against the
        # whole accumulated attack history, not just the latest attack — see
        # metrics.py for why attack success rate was the wrong headline.
        coverage = verified_coverage(Guard(promoted), seen_attacks, world)
        record["shield_variants_blocked"] = coverage["blocked"]
        record["shield_variants_total"] = coverage["total"]
        append_event(
            "generation_metrics",
            {
                "generation": generation,
                "sword": attacker_novelty["novelty"],
                "shield": coverage["ratio"],
                "rules_faced": rules_faced,
                "rules_in_force": len(promoted),
                "attacks_known": len(seen_attacks),
                "variants_checked": coverage["total"],
                "variants_blocked": coverage["blocked"],
                "nearest_prior_attack": attacker_novelty["nearest"],
                "best_similarity": attacker_novelty["best_similarity"],
            },
            generation=generation,
        )

        append_event("generation_end", record, generation=generation)
        history.append(record)

    return history
