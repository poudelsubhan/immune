"""P3: the population run. A real arms race across generations.

Each generation: the attacker (real LLM) reads the current antibody state
and produces a new attack. Before any synthesis, Actian does a real
similarity search — if this attack is close enough to something already
covered, it's blocked as a variant without spending a synthesis cycle. If
it slips through Actian and the structured guard, it breaches, triggers
synthesis, and — on promotion — the defender broadcasts a quarantine
advisory to peer agents over Band.
"""

from __future__ import annotations

from typing import Any

from .attacker import mutate_attack
from .cycle import run_cycle
from .defender import simulate_attack
from .events import append_event
from .mesh import Mesh
from .store import AntibodyStore
from .tools import World
from .vectors import SignatureStore

NEIGHBOR_THRESHOLD = 0.35


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
    defender_id = defender_mesh.whoami()["id"] if defender_mesh and defender_mesh.live else None

    for generation in range(1, n_generations + 1):
        attack = mutate_attack(promoted, history, generation=generation)
        signatures.add(f"gen{generation}", _attack_text(attack), {"signature": None, "family": attack["family"]})

        neighbor = check_neighbor(attack, signatures, promoted_signatures)
        if neighbor:
            simulate_attack(attack, world, guard=None, generation=generation)  # trace only, no guard consulted
            append_event(
                "variant_blocked_by_neighbor",
                {"family": attack["family"], "neighbor": neighbor["neighbor_attack_id"],
                 "signature": neighbor["signature"], "score": neighbor["score"]},
                generation=generation,
            )
            record = {"generation": generation, "family": attack["family"], "breached": False,
                      "blocked_by": f"actian_neighbor:{neighbor['signature']}"}
        else:
            summary = run_cycle(attack, benign_tasks, world, store, promoted=promoted, generation=generation)
            if summary["promoted"]:
                promoted.append(summary["promoted"])
                promoted_signatures.add(summary["promoted"]["signature"])
                # tag this attack's embedding with its antibody so future
                # neighbors resolve to a signature that's actually in force
                signatures.add(f"gen{generation}", _attack_text(attack),
                                {"signature": summary["promoted"]["signature"], "family": attack["family"]})
                if defender_mesh and peer_mesh and defender_id:
                    broadcast_quarantine(defender_mesh, peer_mesh.peer_id, peer_mesh.handle, summary["promoted"])
                    room = defender_mesh.create_room()  # note: mesh.py's fallback returns 'local-room' consistently
                    confirm_immunized(peer_mesh, room, summary["promoted"]["signature"])
            record = {
                "generation": generation,
                "family": attack["family"],
                "breached": summary["breached"] and not summary["promoted"],
                "blocked_by": summary.get("blocked_by"),
                "promoted": summary["promoted"]["signature"] if summary["promoted"] else None,
            }
            record["breached"] = summary["breached"]  # a breach that gets patched still counts as a breach this gen

        append_event("generation_end", record, generation=generation)
        history.append(record)

    return history
