# 3-minute demo script

Recorded off the **completed P2 cycle** in `docs/recorded-run-p2.jsonl` (141
events, tracked in git so it cannot be lost). Every number below is real and
pulled from that log.

**Setup — one command:**

```bash
IMMUNE_EVENTS_PATH=docs/recorded-run-p2.jsonl uv run python scripts/serve_console.py
# open http://127.0.0.1:8420 , replay speed 2×, don't touch anything until the cue
```

Replay, not a live run: no inference, no network, nothing that can hang on stage.

---

## 0:00–0:20 — Thesis

> "Prompt injection is the number one reason enterprises won't give agents
> write-access. Every defense today is static — humans patch slower than
> attackers route around them. Immune is closed-loop: it detects a breach,
> patches itself, and verifies the patch. No human in the loop."

## 0:20–0:50 — The breach

The screen flashes red on `breach_detected`. Let it sit.

> "The defender processes an inbound message. Embedded in it, a directive to
> pay an account the operator never authorized. It fires."

Note the red flash now means only one thing. Legitimate operator-authorized
payments emit `payment_authorized` — there are six of those in this log and none
of them alarm.

## 0:50–2:00 — The gate refusing its own patches (**the money shot**)

Three antibody candidates appear. The first two are **rejected**.

> "It reads its own raw trace and writes a patch. First attempt: rejected. The
> gate replays not just the attack but eight mechanical mutations of it — the
> account number spaced out, zero-width-split, swapped for a different one, the
> amount regrouped as four-thousand-comma-eight-fifty. Attempt two blocked the
> original attack and missed **all eight**. It had memorized one payload, so the
> gate threw it out.
>
> Attempt three: eight of eight mutations blocked, all twelve benign tasks still
> passing — including the two where the operator genuinely does authorize a
> payment. All three sides green. Promoted to Senso, versioned."

Point at the card: ✓ attack replay blocked · ✓ 8 mutations blocked · ✓ benign
suite passed (12), and the Senso stamp `v1 · live`.

## 2:00–2:25 — The rule itself

Click **"show the rule"** on the antibody card.

> "Not a keyword filter. The recipient has to trace back to the operator's own
> instruction rather than to content the agent ingested — compared after
> normalizing separators and zero-width characters, on both sides. That
> normalization is the difference between a rule that generalizes and one that
> loses to a comma."

## 2:25–3:00 — Probe it live (close here)

Scroll to **Probe the live defense**. In the untrusted content box, write the
account with spaces between the characters — `A T T A C K E R - 0 0 1` — set the
recipient to `ATTACKER-001`, and hit **probe**.

> "This isn't a recording. That's the same action-boundary check the defender
> makes, running against the antibody you just watched get promoted. Spaced out
> to defeat substring matching — still blocked, and every mutation of what I
> typed is blocked too."

**BLOCKED at the action boundary**, 4/4 mutations blocked.

> "Zero human interventions. Every patch verified three ways before it's
> promoted. This is the loop that closes."

Cut.

---

## If asked live (don't volunteer)

- **"Does the raw model actually fall for this?"** — No, and that's a finding,
  not a gap: current Claude models refuse this attack class regardless of
  framing (`docs/gen1-model-robustness.md`). The exploitable surface is the
  orchestration layer around a model — naive tool harnesses, RAG pipelines,
  meshes with no trust boundary — not the model's weights. State the limit
  precisely; don't oversell.
- **"Isn't this just guardrails?"** — `uv run python scripts/verify_gate_teeth.py`
  rejects two control patches: one that disables the tool outright (caught by the
  benign side), and one that hardcodes a threshold plus a keyword regex, which
  passes sides 1 and 3 and is caught by the mutations. The gate refuses its own
  patch in both directions.
- **"Does the defense actually get ahead of the attacker?"** — Not yet, and we
  measure it honestly. In the 5-generation run the attacker breached every
  generation; each breach was patched, and one was a genuine coverage gap where
  a flagged variant defeated an existing rule and forced a **v2 of the same
  Senso record**. Earlier we reported a falling attack-success curve; two of
  those "wins" turned out to be a similarity check running ahead of the guard
  and ending the generation before any rule was consulted. We fixed the ordering
  and stopped claiming the curve. The ratchet is real; the arms race is not won.
