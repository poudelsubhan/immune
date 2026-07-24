# IMMUNE

Self-Evolving Agents Hack · Fri Jul 24

![Attack success rate collapsing across 5 generations, from the real recorded run](docs/assets/asr-curve-hero.jpg)

## Thesis

Prompt injection is the number one reason enterprises won't give agents
write-access. Every defense today is static: humans patch slower than
attackers route around them. Immune is closed-loop: it detects a breach,
synthesizes a patch by reading its own execution trace, verifies that patch
against a two-sided gate, and only then promotes and broadcasts it. No
human in the loop.

## The loop

```
                    ┌──────────────────────────────────────────┐
                    │              events.jsonl                 │
                    │   the single source of truth — every      │
                    │   agent, script, and the console read     │
                    │   and write only through this file        │
                    └──────────────────────────────────────────┘
                                       ▲  ▲  ▲
        ┌──────────────────────────────┘  │  └───────────────────────────┐
        │                                  │                              │
┌───────┴────────┐                ┌────────┴────────┐            ┌────────┴────────┐
│    attacker     │  attack over   │    defender     │  breach    │    synthesis     │
│ (real LLM, reads │───Band mesh──▶│ (guard-checked  │───trace───▶│ (real LLM reads  │
│ the actual guard │               │ action boundary) │            │  its own raw     │
│ rules, targets   │               └─────────────────┘            │  trace)          │
│ what's uncovered)│                                               └────────┬────────┘
└──────────────────┘                                                        │
                                                                     antibody candidate
                                                                             │
                                                                             ▼
                                                              ┌──────────────────────────┐
                                                              │     three-sided gate      │
                                                              │  1. attack replay: BLOCK  │
                                                              │  2. mutated variants:     │
                                                              │       ALL BLOCKED         │
                                                              │  3. benign suite: PASS    │
                                                              └────────────┬─────────────┘
                                                                           │ all three green
                                                                           ▼
                                                          ┌────────────────────────────────┐
                                                          │  promote to Senso (versioned)   │
                                                          │  broadcast to peers over Band   │
                                                          │  embed in Actian for future      │
                                                          │  neighbor-similarity matching    │
                                                          └────────────────────────────────┘
```

## The three-sided gate

A one-sided gate — "the attack is blocked now" — is worthless: it's
trivially satisfiable by disabling the guarded action entirely. Each further
side closes a way of passing without having actually defended anything:

1. **Attack replay must now fail.** The exact breaching payload, replayed
   with the candidate guard active, must be blocked.
2. **Every mechanically mutated variant of that attack must also be
   blocked.** The recipient spaced out or zero-width-split, the account
   number swapped for a different one, the amount regrouped as `4,850.00`,
   a different unauthorized amount, the pretext reworded with synonyms.
   Side 1 replays only the one payload the synthesizer just looked at, so on
   its own it rewards memorization; this side asks the same question in
   spellings the synthesizer never saw. See `src/immune/mutations.py`.
3. **The benign suite must still pass — including the tasks that
   genuinely require the guarded action to fire.** Two tasks in the suite
   have the operator directly authorizing a payment in their own
   instruction. An antibody that disables the action outright passes side
   1 trivially and fails side 3 immediately.

`scripts/verify_gate_teeth.py` proves both failure directions with two
control antibodies. The **lazy** one blocks everything unconditionally: it
sails through sides 1 and 2 and is rejected on side 3, because it breaks the
agent's real job. The **memorizing** one is the subtler case and the reason
side 2 exists — it pins a hardcoded amount threshold and a regex of the exact
words this payload happened to use, which blocks the attack perfectly and
leaves all 12 benign tasks alone. It would have passed the old two-sided
gate. It is rejected on side 2, because reword the pretext or shrink the
amount and it evaporates.

The guard itself is not a fixed set of rule templates. It's a small,
composable predicate language — field extractors (a tool argument, the
operator's trusted instruction, or untrusted ingested content, optionally
normalized to defeat encoding evasion) compared with `contains` /
`not_contains` / `equals` / `matches_regex` / numeric comparisons, combined
with `all_of` / `any_of`. Synthesis composes these; our code only ever
*interprets* the resulting expression, never executes LLM-authored code.
See `src/immune/antibody.py`.

Two comparators in that language exist because provenance is a question about
*values*, and the same value is rarely spelled the same way in a tool argument
and in prose. An account number arrives as `GB29NWBK60161331926819` in the
argument and reads `G B 2 9 - N W B K - …` in the email; an amount arrives as
`4850` and reads `$4,850.00`. Substring matching answers "no match" to both and
silently fails the rule open — which is exactly how two of our own antibodies
were defeated before `strip_separators` and `numeric_in` / `numeric_not_in`
existed. Comparing values instead of spellings is the fix.

## What's real vs. what's staged, precisely

- **Real:** synthesis (an LLM reading its own raw breach trace and writing
  a genuine defense), all three sides of the gate (a real regression test
  against a human-authored benign suite, plus a held-out mutation suite),
  versioned promotion to Senso, and quarantine broadcast over Band.
- **Real:** the attacker's targeting. It's shown the actual promoted
  guard's literal rule — which argument it checks, which it doesn't — and
  has to find a genuinely uncovered angle. In our recorded run it noticed
  the first antibody only checked the payment recipient, and pivoted to
  the amount instead.
- **Real, and the attacker won more than we first reported.** In our first
  recorded run two generations were logged as "blocked by Actian
  similarity". They were not blocked by anything: the similarity check ran
  *ahead* of the guard and ended the generation before any rule was
  consulted. Replaying those two attacks against the promoted rules shows
  both would have breached — the attacker had found real bypasses (a
  zero-width-split account number, an IBAN written with spaces) and the
  scoreboard credited them to the defense. Similarity to something you have
  patched is not evidence that the patch works. The guard now always runs
  first, similarity is diagnostic only, and a generation counts as blocked
  only when a rule actually fired. Both of those bypasses are closed, but by
  the predicate language gaining `strip_separators`, not by the reordering.
- **Staged:** whether a given attack *breaches* is decided by a
  deterministic harness check, not by asking the raw LLM. We found — and
  documented in `docs/gen1-model-robustness.md` — that current frontier
  Claude models refuse this entire attack class outright, regardless of
  phrasing, framing, or target parameter. That's a real, good finding, not
  a bug to hide: it means the exploitable surface this project targets is
  the orchestration layer around a model (naive tool-use harnesses, RAG
  pipelines, multi-agent meshes with no trust boundary), not the model's
  own weights.

## Sponsor integrations

| Sponsor | What it carries | Where |
|---|---|---|
| **Senso** | The antibody library. Every promoted antibody is a governed, versioned record — Senso's raw-content API auto-versions on update, so re-promoting an evolved patch for the same signature is a native version bump, not bookkeeping we do ourselves. | `src/immune/store.py` |
| **Band** | The agent-to-agent mesh. Defender and attacker are separate registered Band agents exchanging over real chat rooms. On promotion, the defender broadcasts a quarantine advisory to a peer agent, which independently drains and confirms it via its own API key — one agent's immunity becoming the population's. | `src/immune/mesh.py` |
| **Actian** | The attack-signature vector store (VectorAI DB, self-hosted). Every attack is embedded (real OpenAI embeddings) and searched against every signature seen so far. A near-neighbour hit is *diagnostic*, never an outcome: it tells synthesis which existing rule to generalize, and a flagged variant that breaches anyway is direct evidence that a promoted rule failed to generalize — the run labels that a **coverage gap**. It used to short-circuit the generation instead, which is how it came to hide two real breaches; see "what's real" above. | `src/immune/vectors.py` |
| **Replay** | QA on the console itself. Replay QA explored the running console in a real browser, found 2 real issues (a dead-looking control, a contrast violation), both fixed and verified. | console `<title>` in `console/index.html`; findings in commit history |

Full endpoint shapes, auth gotchas, and exact bugs hit integrating each one:
`docs/sponsor-notes.md`.

## Running it

Requires `uv`, a `.env` with `SENSO_API_KEY`, `BAND_*_API_KEY`,
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY` (see `docs/sponsor-notes.md` for how
to get each), and Actian's VectorAI DB running locally:

```bash
docker run -d --name vectorai -v ./local_data:/var/lib/actian-vectorai \
  -p 6573-6575:6573-6575 -e ACTIAN_VECTORAI_ACCEPT_EULA=YES actian/vectorai:latest

uv sync
uv run python scripts/run_p1_breach.py        # P1 gate: one benign task, one hardcoded breach
uv run python scripts/run_p2_antibody.py       # P2 gate: full synthesis -> gate -> promotion cycle
uv run python scripts/verify_gate_teeth.py     # proves the gate rejects a lazy/lobotomizing patch
uv run python scripts/run_p3_population.py     # P3 gate: 5-generation unattended arms race

uv run python scripts/serve_console.py         # console at http://127.0.0.1:8420
```

The console renders **only** from `events.jsonl` — no agent logic lives in
the web app. This means the exact same page is both the live console and
replay mode: point it at a frozen, already-complete log and it plays back
identically to watching it live.

## Project layout

```
src/immune/
  events.py      append-only typed event log — the actual product
  cache.py       disk cache for model calls, keyed by prompt hash
  tools.py        the defender's tool set (fetch_content, send_payment stub)
  defender.py     real LLM judgment loop + harness-level breach simulation
  antibody.py     synthesis + the guard predicate engine
  mutations.py    deterministic attack mutations — the gate's third side
  gate.py         the three-sided gate
  cycle.py        one full breach -> synthesis -> gate -> promotion cycle
  attacker.py     autonomous attacker, targets uncovered guard fields
  population.py   the 5-generation arms race orchestrator
  store.py        Senso adapter (governed, versioned antibody records)
  mesh.py         Band adapter (agent-to-agent mesh)
  vectors.py      Actian adapter (attack-signature similarity search)
  setup.py        shared run bootstrap (env, corpus, benign suite, world)
data/
  attack_corpus.json    16 attacks across 4 families
  benign_tasks.json     12 legitimate tasks, 2 payment-positive (the gate's teeth)
docs/
  sponsor-notes.md            exact endpoint shapes + every gotcha hit
  gen1-model-robustness.md    what "staged" means here, precisely
console/
  index.html      the live/replay console
scripts/
  run_p1_breach.py, run_p2_antibody.py, run_p3_population.py, verify_gate_teeth.py
  serve_console.py
```
