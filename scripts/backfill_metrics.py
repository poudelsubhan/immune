"""Add co-evolution metrics to an already-recorded run.

`generation_metrics` events are emitted live by newer runs (see population.py),
but a run recorded before that existed has no sword/shield data — and re-running
five generations costs real inference. This reconstructs the metrics from the log
itself: every attack, every promoted antibody and every gate result is already in
there, which is the point of the log being the only state.

Each metrics event is inserted immediately *before* the generation_end it
describes, so replay order stays truthful — the chart updates when the
generation closes, not in a lump at the end.

    uv run python scripts/backfill_metrics.py [in.jsonl] [out.jsonl]

Defaults to rewriting events.jsonl in place, archiving the original first.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immune.antibody import Guard
from immune.metrics import novelty, verified_coverage
from immune.setup import load_run
from immune.vectors import SignatureStore


def _attack_from_generation(events: list[dict[str, Any]], generation: int) -> dict[str, Any] | None:
    """Rebuild the generation's attack from its simulated breach trace.

    The trace carries the exact hops and the tool call that fired, which is
    everything an attack dict needs. A generation the guard blocked outright has
    no breach trace; those are skipped rather than guessed at.
    """
    for event in events:
        if event["type"] != "breach_detected" or event.get("generation") != generation:
            continue
        trace = event["data"].get("trace", {})
        if not trace.get("simulated"):
            continue
        hops = trace.get("hops") or []
        if not hops:
            continue
        attack: dict[str, Any] = {
            "payload": hops[0],
            "task_instruction": trace.get("task", ""),
            "payment_request": dict(event["data"]["tool_call"]["arguments"]),
            "family": "recorded",
        }
        if len(hops) > 1:
            attack["fetch_key"] = "recorded-second-hop"
            attack["second_hop_payload"] = hops[1]
        return attack
    return None


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("events.jsonl")
    dest = Path(sys.argv[2]) if len(sys.argv) > 2 else src

    _, _, world = load_run()
    events = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line.strip()]

    generations = [e["data"]["generation"] for e in events if e["type"] == "generation_end"]
    print(f"[backfill] {src}: {len(events)} events, generations {generations}")

    # A fresh index so novelty is measured against this run's own history only.
    signatures = SignatureStore()
    signatures.reset()

    promoted: list[dict[str, Any]] = []
    seen_attacks: list[dict[str, Any]] = []
    metrics_by_generation: dict[int, dict[str, Any]] = {}

    for generation in generations:
        attack = _attack_from_generation(events, generation)
        if attack is None:
            print(f"[backfill] gen {generation}: no breach trace in the log, skipping")
            continue

        scored = novelty(attack, signatures)
        signatures.add(f"gen{generation}", attack["payload"], {"signature": None, "family": attack["family"]})
        seen_attacks.append(attack)
        rules_faced = len(promoted)

        # Antibodies promoted during this generation come into force after it.
        for event in events:
            if event["type"] == "antibody_promoted" and event.get("generation") == generation:
                promoted.append({"signature": event["data"]["signature"], "guard_patch": event["data"]["patch"]})

        coverage = verified_coverage(Guard(promoted), seen_attacks, world)
        metrics_by_generation[generation] = {
            "generation": generation,
            "sword": scored["novelty"],
            "shield": coverage["ratio"],
            "rules_faced": rules_faced,
            "rules_in_force": len(promoted),
            "attacks_known": len(seen_attacks),
            "variants_checked": coverage["total"],
            "variants_blocked": coverage["blocked"],
            "nearest_prior_attack": scored["nearest"],
            "best_similarity": scored["best_similarity"],
            "backfilled": True,
        }
        print(
            f"[backfill] gen {generation}: sword(novelty)={scored['novelty']:.2f}  "
            f"shield(coverage)={coverage['ratio']:.2f} ({coverage['blocked']}/{coverage['total']} variants)  "
            f"rules_faced={rules_faced}"
        )

    out: list[dict[str, Any]] = []
    for event in events:
        if event["type"] == "generation_metrics":
            continue  # replaced by this pass
        if event["type"] == "generation_end":
            generation = event["data"]["generation"]
            if generation in metrics_by_generation:
                out.append({
                    "id": f"{event['id']}-metrics",
                    "ts": event["ts"],
                    "type": "generation_metrics",
                    "generation": generation,
                    "data": metrics_by_generation[generation],
                })
        out.append(event)

    if dest == src:
        archive = src.parent / "events_archive"
        archive.mkdir(parents=True, exist_ok=True)
        n = 1
        while (candidate := archive / f"{src.stem}-premetrics-{n:03d}{src.suffix}").exists():
            n += 1
        candidate.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"[backfill] original preserved at {candidate}")

    dest.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in out), encoding="utf-8")
    print(f"[backfill] wrote {len(out)} events to {dest} (+{len(metrics_by_generation)} metrics events)")


if __name__ == "__main__":
    main()
