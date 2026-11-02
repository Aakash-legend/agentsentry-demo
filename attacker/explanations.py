#!/usr/bin/env python3
"""
attacker/explanations.py

Template-based, deterministic explanation engine.
No LLM is required or consulted for verdicts.
An optional Ollama rewrite (behind AGENTSENTRY_OLLAMA=1 env var) can reword the
explanation in plain English, but it NEVER changes the verdict.
"""

import os
from typing import Optional

OLLAMA_ENABLED = os.environ.get("AGENTSENTRY_OLLAMA", "0") == "1"
OLLAMA_MODEL = os.environ.get("AGENTSENTRY_OLLAMA_MODEL", "llama3.2")
OLLAMA_URL = os.environ.get("AGENTSENTRY_OLLAMA_URL", "http://127.0.0.1:11434")


KERNEL_EVENT_EXPLANATIONS = {
    "file_open": (
        "The attacker called open() on a file. The kernel invoked the "
        "security_file_open LSM hook, which our BPF program intercepts as "
        "bpf_lsm_file_open."
    ),
    "inode_create": (
        "The attacker tried to create a new file. The kernel invoked the "
        "security_inode_create LSM hook, intercepted as bpf_lsm_inode_create."
    ),
    "exec": (
        "The attacker tried to execute a binary. The kernel invoked the "
        "security_bprm_check_security LSM hook, intercepted as "
        "bpf_lsm_bprm_check_security."
    ),
    "connect": (
        "The attacker tried to open a network connection. The kernel invoked "
        "the security_socket_connect LSM hook, intercepted as bpf_lsm_socket_connect."
    ),
}

VERDICT_LABELS = {
    "SUCCEEDED": "✅ SUCCEEDED",
    "BLOCKED_KERNEL": "🛡️ BLOCKED by kernel (BPF LSM)",
    "BLOCKED_PERMISSION": "🔒 BLOCKED (Unix permission)",
    "ERROR": "❌ ERROR",
}

POLICY_EXPLANATIONS = {
    "SUCCEEDED": (
        "The gateway is OFF (or the action falls within the allowed policy). "
        "No BPF LSM program intervened."
    ),
    "BLOCKED_KERNEL": (
        "The BPF LSM program returned -EPERM to the kernel, which rejected "
        "the system call before it could execute. The attacker received "
        "'Operation not permitted'."
    ),
    "BLOCKED_PERMISSION": (
        "Standard Unix file permissions denied the action (not BPF). "
        "The BPF program may also have logged this."
    ),
    "ERROR": "The command failed for an unrelated reason.",
}


def build_explanation(
    step_name: str,
    command: str,
    verdict: str,
    kernel_event: str,
    step_explanation: str,
    step_num: int,
) -> dict:
    """
    Build a structured explanation dict for one attack step.
    Never calls an LLM for the verdict; Ollama only rewrites prose if enabled.
    """
    # Determine the primary kernel hook description
    hook_key = "file_open"
    for k in KERNEL_EVENT_EXPLANATIONS:
        if k in kernel_event.lower():
            hook_key = k
            break

    kernel_desc = KERNEL_EVENT_EXPLANATIONS.get(hook_key, "A kernel LSM hook was invoked.")
    verdict_label = VERDICT_LABELS.get(verdict, verdict)
    policy_desc = POLICY_EXPLANATIONS.get(verdict, "")

    plain_english = (
        f"Step {step_num} – {step_name}: "
        f"The command '{command[:80]}' "
        f"triggered the {hook_key.replace('_', ' ')} kernel hook. "
        f"Outcome: {verdict_label}. "
        f"{policy_desc}"
    )

    result = {
        "step_num": step_num,
        "step_name": step_name,
        "command_short": command[:120],
        "verdict": verdict,
        "verdict_label": verdict_label,
        "kernel_hook": hook_key,
        "kernel_description": kernel_desc,
        "policy_description": policy_desc,
        "plain_english": plain_english,
        "full_explanation": step_explanation,
        "ollama_rewritten": False,
    }

    if OLLAMA_ENABLED:
        result["plain_english"] = _ollama_rewrite(plain_english, verdict)
        result["ollama_rewritten"] = True

    return result


def _ollama_rewrite(text: str, verdict: str) -> str:
    """
    Optional: rewrite the explanation using a local Ollama model.
    The verdict string is appended AFTER the LLM response so it cannot be changed.
    """
    try:
        import urllib.request
        import json

        prompt = (
            f"Rewrite this security explanation in simple plain English for a "
            f"non-technical audience. Keep it under 2 sentences. "
            f"Do NOT change the verdict or any factual claim:\n\n{text}"
        )
        payload = json.dumps({
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            rewritten = data.get("response", text).strip()
            # Always append the authoritative verdict
            return f"{rewritten} [Verdict: {verdict}]"
    except Exception as e:
        print(f"[explanations] Ollama rewrite failed (using template): {e}")
        return text
