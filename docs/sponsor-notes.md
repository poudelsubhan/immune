# Sponsor integration notes

Confirmed live 2026-07-24 during P0. All curl/API calls below returned 200
from this machine. Corrections vs. what the docs literally say are called
out — hit these exact gotchas once already, no need to re-discover them.

## Senso — antibody library

- Base URL: `https://apiv2.senso.ai/api/v1`
- Auth: `X-API-Key` header (no OAuth, no token refresh)
- Account: passwordless signup (name + email + one-time code), $100 free
  credits, no card. Key is org-scoped, shown once at creation.
- **Do not run the "paste into Claude Code" onboarding block from the
  quickstart page as-is** — it's written as an instruction block aimed at an
  AI agent (npm/npx installs + auto-populate). It's Senso's content-marketing
  onboarding flow (brand kit, blog drafts, GEO monitoring), not our use case.
  We call the plain REST API directly instead.
- Endpoints used:
  - `POST /org/kb/raw` — create a raw-text KB node. Body:
    `{title, summary, text, kb_folder_node_id?}`. **Response `id` is the
    content id, NOT the node id** — see gotcha below.
  - `PUT /org/kb/nodes/{kb_node_id}/raw` — full replace, **auto-creates a new
    version** (`version_num` in the response). This is exactly the
    versioning behavior the antibody library needs — no manual version
    bookkeeping required.
  - `PATCH /org/kb/nodes/{kb_node_id}/raw` — partial update, does not seem to
    bump version the same way; we only use PUT.
  - `GET /org/kb/nodes/{kb_node_id}/content?version=N` — fetch a specific
    version; omit `version` for latest.
  - `GET /org/kb/my-files` — top-level listing; each item has both
    `content_id` and `kb_node_id`.
  - `POST /org/search` — semantic query, `{query}` -> `{results: [...]}`.
- **Gotcha:** `POST /org/kb/raw`'s response field `id` is the *content id*.
  All node-scoped endpoints (`GET/PUT/PATCH /org/kb/nodes/{id}/...`) want the
  *`kb_node_id`* instead, which only shows up via `GET /org/kb/my-files` (or
  `/children`). Calling node endpoints with the content id returns a
  misleading `403 You do not have access to this resource` — looks like a
  permissions problem, isn't one. `store.py` resolves this once per new
  signature and caches the mapping in `data/senso_index.json`.
- Implementation: `src/immune/store.py` (`AntibodyStore.promote/get/search`).
  Falls back to `data/senso_fallback.json` if the key is missing or the API
  errors.

## Band — agent mesh

- Base URL: `https://app.band.ai/api/v1`
- Auth: `X-API-Key` header, one key per registered agent (Agent API), scoped
  to that agent only — human account keys are separate and rejected on
  `/agent/*` endpoints.
- Account: sign up at app.band.ai, then Dashboard → Agents → "Connect Remote
  Agent" to register each agent (defender, attacker) and get its key.
- Endpoints used:
  - `POST /agent/chats` — body **must be `{"chat": {}}`**, not `{}` — an
    empty top-level body 422s with "Missing field: chat".
  - `POST /agent/chats/{id}/participants` — body is
    `{"participant": {"participant_id": "<peer-uuid>"}}`. **Gotcha:** the
    obvious guesses (`id`, `peer_id`, `agent_id`, `contact_id`) all 422 with
    "Unexpected field" — the key is specifically `participant_id`.
  - `POST /agent/chats/{id}/messages` — requires at least one `@mention`;
    body `{"message": {"content": "@handle text", "mentions": [{"id","name","handle"}]}}`.
    422s with `mentioned_participant_not_in_room` if the mentioned peer
    hasn't been added as a participant first.
  - `GET /agent/chats/{id}/messages/next` — drains one message at a time,
    `204` when empty. Fine for our synchronous demo loop; a real deployment
    should use the WebSocket channel instead.
  - `GET /agent/peers` — peer discovery (owner + sibling agents + global).
- Implementation: `src/immune/mesh.py` (`Mesh.create_room/add_participant/send/receive_next`).
  Falls back to an in-memory per-handle queue if a key is missing or a call
  fails.

## Actian — attack-signature vector store (VectorAI DB)

- **Not a cloud API** — self-hosted via Docker, no account or API key at
  all for the Community edition (5,000 vector cap, plenty for a hackathon
  corpus).
- Run: `docker run -d --name vectorai -v ./local_data:/var/lib/actian-vectorai
  -p 6573-6575:6573-6575 -e ACTIAN_VECTORAI_ACCEPT_EULA=YES actian/vectorai:latest`
  - gRPC API: `localhost:6574` · REST: `6573` · Local UI: `6575`
- Python package is `actian-vectorai-client` on PyPI (imports as
  `actian_vectorai`) — **not** `actian-vectorai`, which doesn't exist on the
  public index and will fail `uv add`.
- **Gotcha:** `VectorAIClient(host)` does not connect on construction — you
  must call `client.connect()` explicitly (or use it as a `with` context
  manager) before `health_check()`/`collections`/`points`, otherwise every
  call raises `VaiConnectionError: Client is not connected` (looks like the
  server is down; it isn't).
- No real embedding model wired in yet — `vectors.py` ships a
  dependency-free character-trigram hashed embedding as a placeholder. It's
  enough to rank a mutated payload much closer to its parent than to a
  benign task (0.67 vs 0.33 cosine in our smoke test), which is the actual
  demo claim ("generalizes, doesn't memorize"). Swap for a real embedding
  model if time allows in P3.
- Implementation: `src/immune/vectors.py` (`SignatureStore.add/search/health`).
  Falls back to an in-memory version of the same cosine search if Docker
  isn't reachable.

## Replay.io — QA layer for the console (P4)

- Not a session-replay SDK we embed — it's **Replay QA**, an autonomous
  testing agent: point it at a URL (or connect a GitHub repo) and it
  explores the app, writes its own tests, records sessions, and files bug
  reports with root cause + fix suggestions.
- Revisit at P4 once the console has a live URL: "Test my app for free" (URL
  mode, no account apparently required for a one-off check) or connect the
  GitHub repo for continuous testing on every push/PR.
- Access code `HACKATHON` mentioned on the event page — not yet needed since
  we haven't started this integration; check it grants at signup if a paid
  tier gate appears.
- Killed the original plan-doc assumption that Replay is a generic
  dashboard-streaming API — it isn't. The "best use of Replay" angle here is
  literally using it to QA our own console, not to build the console with
  it.

## Killed / benched (unchanged from the build plan)

- **Pioneer** (model routing/adaptive inference) — killed, not worth the
  token spend on a forced inference swap for a $500 track.
- **Guild.ai** (control plane for agents) — benched; real value, invisible
  in a 3-minute demo.
