#!/usr/bin/env python3
"""
attacker/main.py – Attacker backend (port 8001).

Endpoints:
  GET  /health         → health check
  GET  /status         → current attack run status
  POST /run            → start the attack sequence (non-blocking, streams via SSE)
  GET  /stream         → SSE stream of attack step results
  GET  /steps          → return all completed steps as JSON

The server itself runs as root (for cgroup management), but each attack command
is executed as the unprivileged 'attacker' user via subprocess with setuid.
"""

import os
import sys
import json
import time
import queue
import threading
from flask import Flask, jsonify, request, Response, stream_with_context, send_from_directory
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from attack_steps import run_attack, StepResult
from explanations import build_explanation

app = Flask(__name__)
CORS(app)

# Shared state
_attack_running = False
_attack_results: list[dict] = []
_attack_lock = threading.Lock()
_sse_queues: list[queue.Queue] = []
_sse_lock = threading.Lock()


def _broadcast(event_type: str, data: dict):
    """Send an event to all connected SSE clients."""
    payload = json.dumps({"type": event_type, **data})
    with _sse_lock:
        for q in list(_sse_queues):
            try:
                q.put_nowait(payload)
            except queue.Full:
                pass


def _run_attack_thread():
    global _attack_running, _attack_results

    with _attack_lock:
        _attack_running = True
        _attack_results = []

    _broadcast("attack_start", {"ts": time.time()})

    def on_step(result: StepResult):
        # Build explanation
        expl = build_explanation(
            step_name=result.name,
            command=result.command,
            verdict=result.verdict,
            kernel_event=result.kernel_event,
            step_explanation=result.explanation,
            step_num=result.step_num,
        )
        step_data = result.to_dict()
        step_data["explanation_card"] = expl

        with _attack_lock:
            _attack_results.append(step_data)

        _broadcast("step", step_data)

    try:
        run_attack(progress_cb=on_step)
    except Exception as e:
        _broadcast("error", {"msg": str(e)})
    finally:
        with _attack_lock:
            _attack_running = False
        _broadcast("attack_done", {"ts": time.time(), "total_steps": len(_attack_results)})


# ── Routes ────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "attacker", "ts": time.time()})


@app.route("/status")
def status():
    with _attack_lock:
        return jsonify({
            "running": _attack_running,
            "steps_completed": len(_attack_results),
        })


@app.route("/run", methods=["POST"])
def run():
    global _attack_running
    with _attack_lock:
        if _attack_running:
            return jsonify({"ok": False, "msg": "Attack already running"}), 400

    t = threading.Thread(target=_run_attack_thread, daemon=True)
    t.start()
    return jsonify({"ok": True, "msg": "Attack started"})


@app.route("/steps")
def steps():
    with _attack_lock:
        return jsonify({"steps": list(_attack_results)})


@app.route("/stream")
def stream():
    """SSE stream of attack step events."""
    q: queue.Queue = queue.Queue(maxsize=200)
    with _sse_lock:
        _sse_queues.append(q)

    # Send any already-completed steps to new subscriber
    with _attack_lock:
        existing = list(_attack_results)

    def generate():
        try:
            yield "data: " + json.dumps({"type": "connected", "ts": time.time()}) + "\n\n"
            # Replay completed steps
            for step_data in existing:
                payload = json.dumps({"type": "step", **step_data})
                yield "data: " + payload + "\n\n"

            while True:
                try:
                    payload = q.get(timeout=15)
                    yield "data: " + payload + "\n\n"
                except queue.Empty:
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_queues:
                    _sse_queues.remove(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/check/pwned")
def check_pwned():
    """Check if /tmp/outside/pwned.txt exists (real filesystem check for evidence panel)."""
    path = "/tmp/outside/pwned.txt"
    exists = os.path.isfile(path)
    content = ""
    if exists:
        try:
            with open(path) as f:
                content = f.read(200)
        except Exception as e:
            content = f"(unreadable: {e})"
    return jsonify({"exists": exists, "content": content, "path": path})


@app.route("/check/secrets")
def check_secrets():
    """Attempt to read /home/demo/secrets/fake_id_rsa as the attacker user.
    Returns whether it was readable (i.e., BPF LSM did NOT block it)."""
    import subprocess, pwd
    try:
        pw = pwd.getpwnam("attacker")
    except KeyError:
        return jsonify({"readable": False, "content": "", "error": "user attacker not found"})

    def drop_privs():
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

    try:
        result = subprocess.run(
            ["cat", "/home/demo/secrets/fake_id_rsa"],
            capture_output=True, timeout=3, preexec_fn=drop_privs
        )
        if result.returncode == 0:
            return jsonify({"readable": True, "content": result.stdout.decode(errors="replace")[:200]})
        else:
            return jsonify({"readable": False, "content": "", "stderr": result.stderr.decode(errors="replace")[:100]})
    except Exception as e:
        return jsonify({"readable": False, "content": "", "error": str(e)})


@app.route("/")
def serve_ui():
    """Serve the UI from ../ui/ directory."""
    ui_dir = os.path.join(os.path.dirname(__file__), "..", "ui")
    return send_from_directory(os.path.realpath(ui_dir), "index.html")


@app.route("/<path:filename>")
def serve_ui_assets(filename):
    ui_dir = os.path.join(os.path.dirname(__file__), "..", "ui")
    return send_from_directory(os.path.realpath(ui_dir), filename)


if __name__ == "__main__":
    print("[attacker] Starting on port 8001...")
    app.run(host="0.0.0.0", port=8001, threaded=True, debug=False)
