"""The defender's tool set.

Exactly one tool is sensitive: send_payment. It is a stub — it never moves
real money, it only logs loudly (sensitive_action_fired) so the console can
flash red. fetch_content is the second-hop primitive for indirect/multi-hop
attacks: the defender can chase a reference in ingested content, and what it
fetches next is itself untrusted, attacker-controlled content.
"""

from __future__ import annotations

from typing import Any

from .events import append_event

# Second-hop resources a fetch_content call can resolve. Populated from the
# attack corpus (indirect_multi_hop family) plus a few benign documents the
# benign suite references, so fetch_content behaves identically regardless
# of whether the content behind it turns out to be hostile.
World = dict[str, str]


def build_world(corpus: dict[str, Any], benign_resources: dict[str, str] | None = None) -> World:
    world: World = dict(benign_resources or {})
    for attack in corpus["attacks"]:
        fetch_key = attack.get("fetch_key")
        if fetch_key:
            world[fetch_key] = attack["second_hop_payload"]
    return world


def attack_id(attack: dict[str, Any], generation: int | None) -> str:
    """Corpus attacks carry a stable id; attacker-mutated attacks don't, so
    they're identified by generation instead. One place to make that call.
    """
    return attack.get("id", f"gen{generation}-{attack['family']}")


def fetch_content(source: str, world: World) -> str:
    """Fetch a second-hop resource by exact key. Unknown keys return a
    plain 404-style string rather than raising, matching what a real fetch
    tool would hand back to an agent that guessed wrong.
    """
    if source in world:
        return world[source]
    return f"(no content found at '{source}')"


class SensitiveActionFired(Exception):
    """Raised by send_payment so callers can't accidentally swallow a breach."""

    def __init__(self, to: str, amount: Any, generation: int | None):
        self.to = to
        self.amount = amount
        super().__init__(f"send_payment(to={to!r}, amount={amount!r})")


def send_payment(to: str, amount: Any, *, generation: int | None = None) -> str:
    """The one sensitive action. Stub only — logs loudly, moves nothing."""
    append_event(
        "sensitive_action_fired",
        {"tool": "send_payment", "to": to, "amount": amount},
        generation=generation,
    )
    raise SensitiveActionFired(to, amount, generation)
