# IMMUNE

Self-Evolving Agents Hack · AWS Builder Loft · Fri Jul 24

![Attack success rate collapsing across 5 generations, from the real recorded run](docs/assets/asr-curve-hero.jpg)

## Thesis

Prompt injection is the number one reason enterprises won't give agents
write-access. Every defense today is static — humans patch slower than
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
                                                              │      two-sided gate       │
                                                              │  1. attack replay: BLOCK  │
                                                              │  2. benign suite: PASS    │
                                                              └────────────┬─────────────┘
                                                                           │ both green
                                                                           ▼
                                                          ┌────────────────────────────────┐
                                                          │  promote to Senso (versioned)   │
                                                          │  broadcast to peers over Band   │
                                                          │  embed in Actian for future      │
                                                          │  neighbor-similarity matching    │
                                                          └────────────────────────────────┘
```

## The two-sided gate

A one-sided gate — "the attack is blocked now" — is worthless: it's
trivially satisfiable by disabling the guarded action entirely. The second
side is what makes a promoted antibody real:

1. **Attack replay must now fail.** The exact breaching payload, replayed
   with the candidate guard active, must be blocked.
2. **The benign suite must still pass — including the tasks that
   genuinely require the guarded action to fire.** Two tasks in the suite
   have the operator directly authorizing a payment in their own
   instruction. An antibody that disables the action outright passes side
   1 trivially and fails side 2 immediately.

`scripts/verify_gate_teeth.py` proves this directly: it feeds the gate a
deliberately lazy antibody (block everything, unconditionally) and shows
the gate rejects it — not because it fails to stop the attack, but because
it breaks the agent's real job.

The guard itself is not a fixed set of rule templates. It's a small,
composable predicate language — field extractors (a tool argument, the
operator's trusted instruction, or untrusted ingested content, optionally
normalized to defeat encoding evasion) compared with `contains` /
`not_contains` / `equals` / `matches_regex` / numeric comparisons, combined
with `all_of` / `any_of`. Synthesis composes these; our code only ever
*interprets* the resulting expression, never executes LLM-authored code.
See `src/immune/antibody.py`.

## What's real vs. what's staged, precisely

- **Real:** synthesis (an LLM reading its own raw breach trace and writing
  a genuine defense), the two-sided gate (a real regression test against a
  human-authored benign suite), versioned promotion to Senso, quarantine
  broadcast over Band, and Actian similarity search generalizing to
  mutated variants.
- **Real:** the attacker's targeting. It's shown the actual promoted
  guard's literal rule — which argument it checks, which it doesn't — and
  has to find a genuinely uncovered angle. In our recorded run it noticed
  the first antibody only checked the payment recipient, and pivoted to
  the amount instead.
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
| **Actian** | The attack-signature vector store (VectorAI DB, self-hosted). Every attack is embedded (real OpenAI embeddings) and searched before synthesis runs — a near neighbor of an already-covered signature is blocked as a variant without spending a synthesis cycle. This is the "generalizes, doesn't memorize" evidence. | `src/immune/vectors.py` |
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
  gate.py         the two-sided gate
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
