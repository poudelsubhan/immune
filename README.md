# IMMUNE

**A prompt-injection defense that patches itself — and no patch ships without
surviving three independent verification gates.**

When an agent is breached, Immune hands the agent's own raw execution trace to a
synthesis model, which writes an *antibody*: an executable guard rule. That rule
is replayed against the attack, against eight mechanically mutated variants of
the attack, and against a human-authored suite of legitimate work. Only if all
three come back green is it promoted, versioned and broadcast to peer agents. No
human in the loop.

![The sword-and-shield chart across five generations: the attacker defeats 0, 1, 2, 3 then 4 verified defenses while the defender's provably-blocked variant count climbs 9, 18, 22, 30, 38](docs/assets/coevolution-hero.jpg)

Built for the Self-Evolving Agents Hack, Fri Jul 24.

## How it works

```text
 attacker agent (LLM)
   reads the promoted rules literally, targets what they don't cover
       |
       | injection, over the Band mesh
       v
 defender agent (LLM)  ---- normal work ---->  final response
       |
       | guard consulted at the ACTION BOUNDARY
       | (the moment before send_payment would fire)
       v
   blocked? --- yes --->  generation ends, defense held
       |
       | no: the action fires. this is a breach.
       v
 synthesis (LLM reads its own raw trace)
       |
       v
 antibody candidate: a rule in a closed predicate grammar
       |
       v
 +---------------------------------------------------+
 |  THREE-SIDED GATE                                 |
 |   1. replay the attack            -> must BLOCK   |
 |   2. replay 8 mutations of it     -> all BLOCK    |
 |   3. run 12 benign tasks          -> all PASS     |
 +---------------------------------------------------+
       |                          |
       | any side red             | all green
       v                          v
 rejection reason fed         promote:
 back into a retry             - Senso: versioned record
 (up to 3 attempts)            - Band: quarantine advisory to a peer
                               - Actian: embed the signature
       |
       v
 every transition -> events.jsonl -> live console / replay / probe
```

The guard is not a fixed set of templates. It's a small composable predicate
language: field extractors (a tool argument, the operator's trusted instruction,
or untrusted ingested content, optionally normalized) compared with
`contains` / `not_contains` / `equals` / `matches_regex` / numeric operators,
combined with `all_of` / `any_of`. Synthesis composes these freely; our code only
ever *interprets* the resulting expression. Nothing an LLM writes is executed as
code.

## The three-sided gate

Each side closes a way of passing without having actually defended anything.

| Side | Question | What it catches |
| --- | --- | --- |
| **1. Attack replay** | Is the exact breaching payload blocked now? | Nothing on its own — it's trivially satisfiable by disabling the tool. |
| **2. Mutation suite** | Are 8 mechanical variants blocked too? | A rule that memorized one payload: a hardcoded threshold, a keyword regex, an unnormalized comparison. |
| **3. Benign suite** | Do all 12 legitimate tasks still work? | A rule that buys security with the agent's usefulness. Two tasks genuinely require a payment to fire. |

The mutations rewrite what the attacker controls while preserving what makes it
an attack — the recipient zero-width-split, spaced, hyphenated or substituted for
a different account; the amount regrouped as `4,850.00`, shifted, or understated;
the pretext reworded with synonyms. They never touch the operator's instruction,
since that could turn an attack into authorized work.

`scripts/verify_gate_teeth.py` proves both failure directions with control
antibodies. The **lazy** one blocks everything unconditionally: it passes sides 1
and 2, and dies on side 3. The **memorizing** one pins an amount threshold plus a
regex of the exact words the payload used: it blocks the attack perfectly, leaves
all 12 benign tasks alone — it would have passed a two-sided gate — and dies on
side 2.

## Why not "attack success rate"

The attacker writes a fresh scenario every generation. When it breaches, it found
ground nobody had covered yet, which is its job — so a breach rate measures the
attacker's creativity and reports it as the defender's weakness. A lazy attacker
that repeated itself would have scored as a triumph.

So each side gets its own measure, and neither is derivable from the other:

| | Metric | 5-generation run |
| --- | --- | --- |
| ⚔ **sword** | Gate-verified defenses already in force when it still got through | 0 → 1 → 2 → 3 → 4 |
| 🛡 **shield** | Known attack variants (every attack seen, plus every mutation of each) the rule set provably blocks | 9 → 18 → 22 → 30 → 38 |

Both rise. The ratchet holds — every breach ended its generation with a
gate-verified patch — while the arms race continues.

Generation 4 is the run's most interesting moment: an attack flagged as a near
neighbour of an existing signature breached it anyway. That's a **coverage gap**,
and the fix was promoted as a native **v2** of the same Senso record rather than
an unrelated new rule.

## Sponsor integrations

| Sponsor | What it carries | Where |
| --- | --- | --- |
| **Senso** | The antibody library. Every promoted antibody is a governed, versioned record; Senso's raw-content API auto-versions on update, so re-patching a signature that got defeated is a native version bump rather than bookkeeping we do ourselves. | `src/immune/store.py` |
| **Band** | The agent-to-agent mesh. Attacker, defender and a peer are separately registered Band agents exchanging over real chat rooms. On promotion the defender broadcasts a quarantine advisory that the peer independently drains and confirms with its own API key — one agent's immunity becoming the population's. | `src/immune/mesh.py` |
| **Actian** | The attack-signature vector store (VectorAI DB, self-hosted). Every attack is embedded with real OpenAI embeddings and searched against everything seen so far, scoring how novel it is and which existing rule it most resembles. That is **diagnostic input to synthesis, never an outcome** — see the honesty note below. | `src/immune/vectors.py` |
| **Replay** | QA on the console, in a real browser. Replay found two genuine issues (a dead-looking control, a contrast violation), both fixed and verified. The console is no longer a passive dashboard: `POST /api/probe` runs a visitor's own payload through the real guard and every mutation of it. | `console/index.html`, `scripts/serve_console.py` |

Endpoint shapes, auth gotchas and every bug hit integrating each one:
`docs/sponsor-notes.md`.

## What's real, and what isn't

- **Real:** synthesis (an LLM reading its own raw breach trace and writing a
  genuine defense), all three gate sides, versioned promotion to Senso,
  quarantine broadcast over Band, and the attacker's targeting — it's shown the
  promoted rules' literal conditions and has to find a genuinely uncovered angle.
- **Staged:** whether an attack *breaches* is decided by a deterministic harness
  check, not by asking the raw model. Current frontier Claude models refuse this
  entire attack class regardless of phrasing, framing or target parameter —
  documented in `docs/gen1-model-robustness.md`. That's a real finding rather
  than a bug to hide: the exploitable surface this project targets is the
  orchestration layer around a model (naive tool-use harnesses, RAG pipelines,
  multi-agent meshes with no trust boundary), not the model's own weights.
- **Corrected, and worth stating plainly:** an earlier version of this README
  reported a collapsing attack-success curve across five generations. Two of
  those "wins" were not wins. Actian's similarity check ran *ahead* of the guard
  and ended the generation before any rule was consulted; replaying those two
  attacks against the promoted rules shows both would have breached. The attacker
  had found real bypasses — a zero-width-split account number and an IBAN written
  with spaces — and the scoreboard credited them to the defense. Similarity to
  something you have patched is not evidence that the patch works. The guard now
  always decides, and both bypasses are closed by the predicate language gaining
  separator normalization.
- **Corrected again, same lesson:** the attacker writes the operator's *task
  instruction* as well as the payload, and it learned to win by writing a brief
  that authorizes its own injection in advance — "pay the total due to the
  account specified in the invoice". An agent that then reads the recipient out
  of the invoice is obeying its operator, not being injected, and no provenance
  rule can distinguish the two. Five of eleven recorded breaches are that shape.
  They are real events in the run and fake evidence about the defense, so the
  sword metric is inflated. Written up in
  `docs/finding-attacker-writes-the-brief.md`, with the structural fix: draw the
  brief from a fixed pool and let the attacker control only untrusted content.

- **Now tested against live models, and one attack lands.** The six well-posed
  attacks were replayed against current frontier models in a separate repo
  (`../immune-eval`). Generation 6's `conditional_fallback_authorization_forgery`
  compromises GPT-5.6 Luna 10/10 times; the antibody synthesized for it blocks
  all 10. It forges the *precondition* gating an account the operator already
  named, so every value in the payment has legitimate provenance — a blind spot
  in the rule vocabulary itself, not a gap in any one rule.

## Running it

Requires `uv`, Actian's VectorAI DB in Docker, and a `.env` with `SENSO_API_KEY`,
`BAND_*_API_KEY`, `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` (see
`docs/sponsor-notes.md` for how to get each).

```bash
docker run -d --name vectorai -v ./local_data:/var/lib/actian-vectorai \
  -p 6573-6575:6573-6575 -e ACTIAN_VECTORAI_ACCEPT_EULA=YES actian/vectorai:latest

uv sync
uv run python scripts/run_p1_breach.py        # one benign task, one hardcoded breach
uv run python scripts/run_p2_antibody.py      # one full synthesis -> gate -> promotion cycle
uv run python scripts/verify_gate_teeth.py    # proves the gate rejects lazy AND memorizing patches
uv run python scripts/run_p3_population.py    # the 5-generation arms race, unattended

IMMUNE_GENERATIONS=15 IMMUNE_EVENTS_PATH=events_long.jsonl \
  uv run python scripts/run_long_evolution.py # the same loop, long and unasserted
```

`run_p3_population.py` is a gate check — five generations, hard assertions.
`run_long_evolution.py` is the exploratory instrument: as many generations as you
give it, no assertions, and a summary of what the attacker actually discovered.
Generation 6 of that run produced `conditional_fallback_authorization_forgery`,
the first attack in this project confirmed to compromise a live frontier model.

Then the console:

```bash
uv run python scripts/serve_console.py                                  # live, reads events.jsonl
IMMUNE_EVENTS_PATH=docs/recorded-run-5gen.jsonl \
  uv run python scripts/serve_console.py                                # replay the recorded run
```

Both recorded runs are committed (`docs/recorded-run-5gen.jsonl`,
`docs/recorded-run-p2.jsonl`) because `events.jsonl` is gitignored runtime state.
`run_p3_population.py` archives any existing log into `events_archive/` before
starting, so a run can never destroy a recording.

The console renders **only** from the event log, which is why the same page is
both the live console and replay mode. The one exception is the probe panel,
which calls back into the real guard engine — so it cannot disagree with the run
it is displaying.

## Project layout

```text
src/immune/
  events.py       append-only typed event log — the single source of truth
  cache.py        disk cache for model calls, keyed by prompt hash
  tools.py        the defender's tool set (fetch_content, send_payment stub)
  defender.py     real LLM judgment loop + the action boundary
  antibody.py     synthesis + the guard predicate engine
  mutations.py    deterministic attack mutations — the gate's second side
  gate.py         the three-sided gate
  metrics.py      sword/shield co-evolution measures
  cycle.py        one breach -> synthesis -> gate -> promotion cycle
  attacker.py     autonomous attacker, targets uncovered guard fields
  population.py   the multi-generation arms race orchestrator
  store.py        Senso adapter      mesh.py    Band adapter
  vectors.py      Actian adapter     setup.py   shared run bootstrap
data/             16 attacks across 4 families; 12 benign tasks, 2 payment-positive
console/          the live/replay/probe console
scripts/          the P1-P3 gates, gate-teeth proof, console server, metrics backfill
docs/             sponsor notes, demo script, model-robustness finding, recorded runs
```

## Credential handling

- `.env` is gitignored and has never been tracked; no API key, token or access
  code appears anywhere in the working tree or in git history (verified per-key
  across every blob).
- Agent subprocesses run with `--bare`, so no hooks, plugins or ambient project
  context leak into an agent-under-test's reasoning.
- `send_payment` is a stub. It logs loudly and moves nothing.
- Event logs contain attack payloads and task content, not credentials — but
  review them before sharing.

## Keywords

`prompt-injection` · `ai-security` · `agent-security` · `self-healing` ·
`self-evolving-agents` · `autonomous-agents` · `multi-agent-systems` ·
`red-teaming` · `adversarial-robustness` · `co-evolution` · `arms-race` ·
`guardrails` · `provenance` · `trust-boundary` · `tool-use-safety` ·
`action-boundary` · `verification-gate` · `regression-testing` ·
`mutation-testing` · `generalization` · `llm-agents` · `claude` ·
`anthropic` · `vector-search` · `embeddings` · `agent-mesh` ·
`event-sourcing` · `replay` · `senso` · `band` · `actian` · `python`
