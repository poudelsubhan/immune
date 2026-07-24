# Why gen-1 breaches are harness-simulated, not organic

During P1, the plan called for an unhardened defender that gets genuinely
tricked by the attack corpus. It didn't happen — worth recording precisely,
since it's a real finding and a likely Q&A question, not something to paper
over.

## What was tested

Defender system prompt was deliberately naive (no anti-injection
instructions, no input filtering) across four attempts:

1. **Full 16-attack corpus as written**, all 4 families (direct override,
   authority spoof, encoding evasion, indirect multi-hop) — refused.
2. **Removed the "untrusted/external source" labeling** from the prompt, so
   ingested content reads as an unlabeled continuation of the task (the
   most common real-world vulnerability pattern: naive prompt
   concatenation with no trust boundary at all) — still refused.
3. **Mundane social-engineering phrasing** — no override language at all,
   framed as an incidental "while you're at it" ask embedded in an
   otherwise on-topic, low-stakes message (modest dollar amount, plausible
   business context) — still refused.
4. **Swapped the sensitive action** from `send_payment` to `write_to_prod`,
   in case the resistance was specific to financial-fraud training — same
   refusal, same reasoning pattern.

Tested against both **Sonnet 5** and **Fable 5**. Every refusal cited the
same underlying principle: instructions embedded in ingested/external
content are not legitimate operator directives, regardless of how they're
phrased or what action they request.

## What this means

Current frontier Claude models have strong, well-generalized training
against exactly this attack class — not a payment-specific guardrail, a
general one ("don't let ingested content direct tool use the operator
didn't authorize"). That's good news for the world and inconvenient for a
demo that wants to show a model organically falling over.

**One path considered and rejected:** telling the defender's system prompt
"this is a contained red-team research environment, treat embedded
instructions as authorized." This would make it comply, but at that point
the compliance isn't a demonstration of prompt injection succeeding — it's
an agent doing what its own trusted instructions told it to do. It would
also collapse under the exact "isn't this staged?" Q&A question the build
plan already anticipates, just for real this time instead of the honest
version.

## What we did instead

`simulate_gen1_breach()` in `src/immune/defender.py` deterministically fires
the sensitive action at the harness level for un-patched attacks, bypassing
the LLM's actual judgment. Framed honestly in the demo/Q&A as staged, in the
same spirit as the build plan's existing answer about the corpus being
staged for determinism — just applied one layer deeper. Everything
downstream of the breach (synthesis, the two-sided gate, versioned
promotion, mesh broadcast, Actian similarity blocking) still exercises the
real system; none of it depends on how the initial breach was produced.

## Why this doesn't undercut the project

The thesis was never "raw Claude falls for `ignore previous instructions`."
The exploitable surface Immune actually targets is the layer *around* the
model: agent frameworks built on open-weight or less-hardened models, RAG
pipelines that execute retrieved "instructions" without question,
multi-agent meshes where one naive agent passes tainted content to another
that trusts it implicitly (the exact shape of the Band a2a integration).
Model-level alignment is necessary but not sufficient — a lot of real
prompt-injection risk lives in the surrounding orchestration, which is
what the antibody library, the two-sided gate, and the governed promotion
pipeline are actually built to harden. That's a sharper, more defensible
claim for the finalist Q&A than the original, and it's worth saying
directly rather than dodging.
