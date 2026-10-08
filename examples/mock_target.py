#!/usr/bin/env python3
"""
Mock vulnerable app for PenScan's sample run.

Serves on localhost only. Simulates a vibe-coded app with two real
failure modes baked in:
  - /rest/v1/users returns rows with only the anon key  (check 2 FAIL)
  - /.env is served with HTTP 200                      (check 5 FAIL)
Everything else passes, so the expected verdict is DO NOT SHIP.

Run:  python3 mock_target.py   (serves http://127.0.0.1:8765)
"""

import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

FAKE_ANON_JWT = f"{b64url({'alg': 'HS256', 'typ': 'JWT'})}.{b64url({'role': 'anon', 'iss': 'supabase'})}.fakesignature"

APP_JS = f"""
// mock bundle for the PenScan sample run
const SUPABASE_URL = "https://demoproj123.supabase.co";
const SUPABASE_ANON_KEY = "{FAKE_ANON_JWT}";
async function loadNotes() {{
  const r = await fetch(`${{SUPABASE_URL}}/rest/v1/notes?select=*`, {{
    headers: {{ apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${{SUPABASE_ANON_KEY}}` }}
  }});
  return r.json();
}}
"""

INDEX_HTML = """<!doctype html><html><head><title>Demo Notes App</title>
<script src="/app.js"></script></head>
<body><h1>Demo notes app (mock target for PenScan sample run)</h1></body></html>"""

FAKE_ENV = "SUPABASE_URL=https://demoproj123.supabase.co\nSUPABASE_SERVICE_KEY=REDACTED-IN-MOCK\nSTRIPE_SECRET=REDACTED-IN-MOCK\n"

OPENAPI = {"paths": {"/users": {}, "/notes": {}}}

FAKE_USERS = [
    {"id": 1, "name": "REDACTED", "email": "REDACTED"},
    {"id": 2, "name": "REDACTED", "email": "REDACTED"},
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            self._send(200, INDEX_HTML, "text/html")
        elif p == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif p == "/rest/v1/":
            self._send(200, json.dumps(OPENAPI), "application/json")
        elif p.startswith("/rest/v1/users"):
            # RLS off: anyone with the anon key reads every row
            self._send(200, json.dumps(FAKE_USERS), "application/json")
        elif p.startswith("/rest/v1/notes"):
            self._send(200, json.dumps([]), "application/json")
        elif p == "/.env":
            self._send(200, FAKE_ENV)
        else:
            self._send(404, json.dumps({"error": "not found"}), "application/json")

    def do_POST(self):
        self._send(404, json.dumps({"error": "not found"}), "application/json")


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 8765), Handler)
    print("mock target on http://127.0.0.1:8765  (Ctrl+C to stop)")
    srv.serve_forever()
