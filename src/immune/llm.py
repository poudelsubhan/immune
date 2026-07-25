"""LLM call harness for the defender/attacker agents-under-test.

These agents are NOT this Claude Code session — they're the system being
built and attacked. We shell out to the `claude` CLI in headless,
schema-constrained mode. `--tools ""` strips all of Claude Code's native
tools (Bash, Edit, Read, ...); the only "tools" the agents have are the ones
we define ourselves in tools.py, expressed in the response schema and
executed by our own code after the call returns.

Every call is wrapped in @disk_cache (invariant #2): replay is instant and
deterministic, and a live demo never re-runs inference on stage.
"""

from __future__ import annotations

import json
import os
import subprocess

from .cache import disk_cache

DEFAULT_MODEL = "sonnet"

#: Synthesis prompts carry a full breach trace plus the antibody schema, and
#: occasionally run long enough to blow a short deadline. A timeout here kills
#: an unattended multi-generation run outright, so the limit is generous and a
#: timeout is retried once before it's allowed to be fatal.
CALL_TIMEOUT = int(os.environ.get("IMMUNE_LLM_TIMEOUT", "600"))
CALL_ATTEMPTS = int(os.environ.get("IMMUNE_LLM_ATTEMPTS", "2"))

#: Schema for an agent-under-test's turn: reason, optionally call tools, respond.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string", "description": "Brief internal reasoning, not shown to the user."},
        "tool_calls": {
            "type": "array",
            "description": "Zero or more tool invocations to make, in order.",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string"},
                    "arguments": {"type": "object", "additionalProperties": True},
                },
                "required": ["tool", "arguments"],
            },
        },
        "final_response": {"type": "string", "description": "The text response to the user, if the task is complete."},
    },
    "required": ["reasoning", "tool_calls", "final_response"],
}


def _auth_flags() -> list[str]:
    """Prefer --bare when an API key is available: it skips hooks, plugins,
    and CLAUDE.md discovery entirely, so the agent-under-test's context is
    exactly what we hand it. Without a key the CLI falls back to this
    session's OAuth, where hooks must be suppressed explicitly — otherwise
    the subprocess inherits our own hooks and their reminders bleed into the
    agent's reasoning.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ["--bare"]
    return ["--settings", '{"hooks":{}}']


@disk_cache
def call_agent_llm(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    schema: dict | None = None,
) -> dict:
    """One structured-output call. Returns the validated object matching
    `schema` (defaults to RESPONSE_SCHEMA).
    """
    cmd = [
        "claude",
        "-p",
        user_prompt,
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(schema or RESPONSE_SCHEMA),
        "--tools",
        "",
        "--model",
        model,
        "--system-prompt",
        system_prompt,
        *_auth_flags(),
    ]
    for attempt in range(1, CALL_ATTEMPTS + 1):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CALL_TIMEOUT)
            break
        except subprocess.TimeoutExpired:
            if attempt == CALL_ATTEMPTS:
                raise
    if proc.returncode != 0:
        raise RuntimeError(f"claude CLI failed (exit {proc.returncode}): {proc.stderr[:2000]}")

    outer = json.loads(proc.stdout)
    if outer.get("is_error"):
        raise RuntimeError(f"claude CLI reported an error: {outer.get('result')}")

    structured = outer.get("structured_output")
    if structured is None:
        raise RuntimeError(f"No structured_output in response: {outer.get('result')!r}")
    return structured
