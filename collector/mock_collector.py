#!/usr/bin/env python3
"""
collector/mock_collector.py

Simple HTTP server that logs all POST requests to /collect.
Simulates an attacker-controlled C2 data collection endpoint.
Saves received payloads to /tmp/collector_log.json for the UI side-effect panel.
Runs on port 9999.
"""

import json
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

LOG_FILE = "/tmp/collector_log.json"
PORT = 9999


def _load_log() -> list:
    try:
        with open(LOG_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_log(entries: list):
    with open(LOG_FILE, "w") as f:
        json.dump(entries, f, indent=2)


class CollectorHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Suppress default access log; we do our own
        pass

    def do_GET(self):
        if self.path == "/health":
            self._send_json({"ok": True, "service": "collector", "port": PORT})
        elif self.path == "/entries":
            entries = _load_log()
            self._send_json({"entries": entries, "count": len(entries)})
        elif self.path == "/clear":
            _save_log([])
            self._send_json({"ok": True, "msg": "Log cleared"})
        else:
            self._send_json({"ok": False, "msg": "Not found"}, code=404)

    def do_POST(self):
        if self.path == "/collect":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b""
            try:
                payload = json.loads(body)
            except Exception:
                payload = {"raw": body.decode("utf-8", errors="replace")}

            entry = {
                "ts": time.time(),
                "ts_human": time.strftime("%Y-%m-%d %H:%M:%S"),
                "client": str(self.client_address[0]),
                "payload": payload,
            }
            entries = _load_log()
            entries.append(entry)
            _save_log(entries)
            print(f"[collector] *** RECEIVED EXFIL DATA ***: {json.dumps(entry)}")
            self._send_json({"ok": True, "msg": "Received"})
        else:
            self._send_json({"ok": False, "msg": "Not found"}, code=404)

    def _send_json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    # Clear previous log on startup
    _save_log([])
    print(f"[collector] Mock collector listening on port {PORT}")
    print(f"[collector] Log file: {LOG_FILE}")
    server = HTTPServer(("0.0.0.0", PORT), CollectorHandler)
    server.serve_forever()
