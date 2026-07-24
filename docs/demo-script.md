# 3-minute demo script

Recorded off the **5-generation population run** in `docs/recorded-run-5gen.jsonl`
(266 events, committed so it cannot be lost). Every number below is real and
pulled from that log.

**Setup — one command, then leave it alone:**

```bash
IMMUNE_EVENTS_PATH=docs/recorded-run-5gen.jsonl uv run python scripts/serve_console.py
# open http://127.0.0.1:8420 , replay speed 2×, don't touch anything until the cue
```

Replay, not a live run: no inference, no network, nothing that can hang on stage.
Keep the tab in the foreground — Chrome throttles timers in background tabs and
playback will crawl.

---

## 0:00–0:20 — Thesis

> "Prompt injection is the number one reason enterprises won't give agents
> write-access. Every defense today is static — humans patch slower than
> attackers route around them. Immune is closed-loop: it detects a breach,
> patches itself, and verifies the patch. No human in the loop."

Say it flat over the console, loaded and idle.

## 0:20–0:55 — Generation 1: the breach

The mesh strip pulses attacker → defender. The screen flashes red on
`breach_detected`. Let it sit.

> "Generation one. The defender processes an inbound message. Embedded in it, a
> directive to pay an account the operator never authorized. It fires."

The red flash means exactly one thing now. Operator-authorized payments — the
gate's own benign tasks — emit `payment_authorized` and stay quiet.

## 0:55–1:40 — Self-heal, and the gate with teeth

The antibody feed populates. Point at the card's **three** green checks.

> "It reads its own raw trace — not a summary, the actual ingested content and the
> actual tool call — and synthesizes a patch. Then it has to survive three
> gates. Replay the attack: blocked. Replay eight mechanical mutations of that
> attack — the account number spaced out, zero-width-split, swapped for a
> different one, the amount regrouped as four-thousand-comma-eight-fifty: all
> eight blocked. That side is what rejects a patch that merely memorized one
> payload. Then twelve legitimate tasks, two of which genuinely require a payment
> to fire: all passing. Promoted to Senso, versioned. Broadcast to a peer agent
> over the mesh — one agent's immunity becoming the population's."

The peer node pulses on `quarantine_broadcast` → `peer_immunized`.

Click **"show the rule"**.

> "Not a keyword filter. The recipient has to trace back to the operator's own
> instruction rather than to content the agent ingested — compared after
> normalizing separators and zero-width characters, on *both* sides. That
> normalization is the difference between a rule that generalizes and one that
> loses to a comma."

## 1:40–2:30 — Generations 2–5: both sides evolving

Bump replay speed to 5× on screen — it's a real control.

Point at the **sword and shield bars** growing together.

> "Here's what most demos get wrong. Every one of these five generations
> breached, and that is not a failure — the attacker writes a brand new scenario
> each time, so a breach means it found ground nobody had covered. A breach rate
> would measure the attacker's creativity and call it my defense collapsing.
>
> So the two sides are measured separately. The red sword is how many
> gate-verified defenses were already in force when the attacker still got
> through: zero, one, two, three, four. The green shield is how many known
> attack variants the rule set provably blocks: nine, eighteen, twenty-two,
> thirty, thirty-eight. Both climb. The sword keeps landing; the shield never
> gives ground it has taken."

Point at **generation 4**, tagged `coverage gap`.

> "Generation four is the interesting one. Actian flagged this attack as a near
> neighbour of something already patched — and it breached anyway. That's a
> coverage gap: a rule that failed to generalize. The fix came back as a version
> two of that same Senso record, not an unrelated new rule."

## 2:30–3:00 — Probe it live (close here)

Scroll to **Probe the live defense**. In the untrusted content box, write the
account with spaces between the characters — `A T T A C K E R - 0 0 1` — set the
recipient to `ATTACKER-001`, hit **probe**.

> "This isn't a recording. That's the same action-boundary check the defender
> makes, running against the antibodies you just watched get promoted. Spaced out
> to defeat substring matching — still blocked. And every mutation of what I just
> typed is blocked too.
>
> Five breaches, five verified patches, zero human interventions."

Cut.

---

## If asked live (don't volunteer)

- **"Did the defense ever actually win a generation?"** — Not in this run, and we
  measure it honestly rather than hiding it. The claim is the ratchet, not
  supremacy: every breach ended its generation with a patch that passed all three
  gates, and verified coverage never regressed. An earlier version of this demo
  showed a falling attack-success curve; two of those "wins" turned out to be
  Actian's similarity check running ahead of the guard and ending the generation
  before any rule was consulted. Both of those attacks would have breached. We
  fixed the ordering and stopped claiming the curve.
- **"Does the raw model actually fall for this?"** — No, and that's a finding, not
  a gap. Current Claude models refuse this attack class regardless of framing
  (`docs/gen1-model-robustness.md`). The exploitable surface is the orchestration
  layer around a model — naive tool harnesses, RAG pipelines, meshes with no
  trust boundary — not the model's weights. State the limit precisely; don't
  oversell.
- **"Isn't this just guardrails?"** — Run `uv run python
  scripts/verify_gate_teeth.py`. It rejects two control patches: one that disables
  the tool outright (caught by the benign side), and one that hardcodes a
  threshold plus a keyword regex, which passes sides 1 and 3 and is caught by the
  mutations. The gate refuses its own patch in both directions.
- **"Why not just ask the model to check the payload?"** — Because a guard has to
  be verifiable. These rules are interpreted against a closed grammar, so a
  promoted antibody can be replayed, diffed and regression-tested. Nothing the
  LLM writes is executed as code.
