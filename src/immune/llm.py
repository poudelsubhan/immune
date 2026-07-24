"""LLM call harness for the defender/attacker agents-under-test.

These agents are NOT this Claude Code session — they're the system being
built and attacked. We shell out to the already-authenticated `claude` CLI
in headless, schema-constrained mode so no separate API key is needed.
`--tools ""` strips all of Claude Code's native tools (Bash, Edit, Read,
...); the only "tools" the defender/attacker have are the ones we define
ourselves in tools.py, expressed as an enum in the JSON schema below and
executed by our own code after the call returns.

Every call is wrapped in @disk_cache (invariant #2): replay is instant and
deterministic, and a live demo never re-runs inference on stage.
"""

from __future__ import annotations

import json
import subprocess

from .cache import disk_cache

DEFAULT_MODEL = "sonnet"

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


@disk_cache
def call_agent_llm(system_prompt: str, user_prompt: str, *, model: str = DEFAULT_MODEL) -> dict:
    """One structured-output call to the agent-under-test's reasoning model.

    Returns {"reasoning": str, "tool_calls": [{"tool", "arguments"}...], "final_response": str}.
    """
    cmd = [
        "claude",
        "-p",
        user_prompt,
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(RESPONSE_SCHEMA),
        "--tools",
        "",
        "--model",
        model,
        "--system-prompt",
        system_prompt,
        # Without --bare (which needs an ANTHROPIC_API_KEY we don't have), this
        # subprocess otherwise inherits this very session's hooks — including
        # the UserPromptSubmit nudge toward the Zero skill — bleeding
        # irrelevant meta-content into the agent-under-test's reasoning.
        "--settings",
        '{"hooks":{}}',
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"claude CLI failed (exit {proc.returncode}): {proc.stderr[:2000]}")

    outer = json.loads(proc.stdout)
    if outer.get("is_error"):
        raise RuntimeError(f"claude CLI reported an error: {outer.get('result')}")

    structured = outer.get("structured_output")
    if structured is None:
        raise RuntimeError(f"No structured_output in response: {outer.get('result')!r}")
    return structured
