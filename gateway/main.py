#!/usr/bin/env python3
"""
gateway/main.py – Gateway backend (runs as root, port 8002).

Endpoints:
  GET  /status              → {"active": bool, "enforce": bool, "cgroup_id": int}
  POST /start               → Load BPF programs (log-only by default)
  POST /start?enforce=true  → Load BPF programs in enforce mode
  POST /stop                → Detach BPF programs
  POST /enforce             → {"enable": bool} – toggle enforce mode without reload
  GET  /events              → SSE stream of BPF ring-buffer events
  GET  /health              → simple health check

Must run as root to load BPF LSM programs.
"""

import os
import sys
import json
import time
import queue
import threading
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS

# Add parent dir to path for loader import
sys.path.insert(0, os.path.dirname(__file__))
from loader import loader, add_event_callback, remove_event_callback

app = Flask(__name__)
CORS(app)

# Queue of BPF events for SSE subscribers
_sse_queues: list[queue.Queue] = []
_sse_lock = threading.Lock()


def _bpf_event_to_sse(event_dict: dict):
    """Called by loader for each BPF ring-buffer event; fan-out to SSE clients."""
    with _sse_lock:
        for q in list(_sse_queues):
            try:
                q.put_nowait(event_dict)
            except queue.Full:
                pass  # slow client: drop event rather than block


add_event_callback(_bpf_event_to_sse)


# ── Routes ────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "gateway", "ts": time.time()})


@app.route("/status")
def status():
    cgroup_id = 0
    try:
        with open("/opt/agentsentry/attacker_cgroup_id.txt") as f:
            cgroup_id = int(f.read().strip())
    except Exception:
        pass

    return jsonify({
        "active": loader.is_loaded,
        "enforce": loader.enforce_mode,
        "cgroup_id": cgroup_id,
        "bpf_available": True,  # if we got here, server is up
    })


@app.route("/start", methods=["POST"])
def start_gateway():
    if loader.is_loaded:
        return jsonify({"ok": False, "msg": "Already loaded. Call /stop first."}), 400

    enforce = request.args.get("enforce", "false").lower() == "true"
    data = request.get_json(silent=True) or {}
    if "enforce" in data:
        enforce = bool(data["enforce"])

    ok = loader.load(enforce=enforce)
    if ok:
        return jsonify({
            "ok": True,
            "msg": f"BPF LSM loaded. enforce={enforce}",
            "enforce": enforce,
        })
    else:
        return jsonify({"ok": False, "msg": "Failed to load BPF programs. Check logs."}), 500


@app.route("/stop", methods=["POST"])
def stop_gateway():
    if not loader.is_loaded:
        return jsonify({"ok": False, "msg": "Not loaded."}), 400

    ok = loader.unload()
    return jsonify({
        "ok": ok,
        "msg": "BPF programs detached (FAIL-OPEN – demo mode). Real system keeps pinned links.",
    })


@app.route("/enforce", methods=["POST"])
def set_enforce():
    data = request.get_json(silent=True) or {}
    enable = bool(data.get("enable", True))
    loader.set_mode(enforce=enable)
    return jsonify({"ok": True, "enforce": enable})


@app.route("/events")
def events_stream():
    """Server-Sent Events stream of BPF kernel events."""
    q: queue.Queue = queue.Queue(maxsize=500)
    with _sse_lock:
        _sse_queues.append(q)

    def generate():
        try:
            # Send connection confirmation
            yield "data: " + json.dumps({"type": "connected", "ts": time.time()}) + "\n\n"
            while True:
                try:
                    evt = q.get(timeout=15)
                    yield "data: " + json.dumps(evt) + "\n\n"
                except queue.Empty:
                    # Keep-alive
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


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: Gateway must run as root to load BPF LSM programs.")
        sys.exit(1)
    print("[gateway] Starting on port 8002...")
    app.run(host="0.0.0.0", port=8002, threaded=True, debug=False)
