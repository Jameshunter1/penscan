#!/usr/bin/env python3
"""
Acme VibeCRM — DELIBERATELY VULNERABLE sample app for PenScan.

*** DO NOT DEPLOY. DO NOT POINT AT REAL DATA. TEST TARGET ONLY. ***

This is a throwaway localhost app that replays the two documented 2026
vibe-coded-app breach patterns, so the PenScan five-check scanner has a
known-bad target to prove itself against:

  Pattern A (Moltbook shape — exposed client-side key, no row-level
  security): a service_role JWT is embedded in the public JavaScript
  bundle, and the users table returns every row to the bare anon key.
  Expected: PenScan checks 1 and 2 FAIL.

  Pattern B (Lovable shape — CVE-2025-48757, broken object-level
  authorization): GET /api/users/<id> returns any user's full record
  with no login and no ownership check (BOLA/IDOR).
  Expected: PenScan check 4 FAILS.

Everything else is clean on purpose (no open storage, no /.env, no
verbose errors), so checks 3 and 5 PASS — proving the scanner
discriminates instead of failing everything.

Expected verdict: DO NOT SHIP (exit code 2).

All keys, rows, and names here are FAKE. No real credentials exist
anywhere in this file.

Run:  python3 known_bad_app.py   (serves http://127.0.0.1:8766)
Scan: python3 penscan.py --site http://127.0.0.1:8766 \
          --supabase-url http://127.0.0.1:8766 --anon-key demo
"""

import base64
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8766


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# --- FAKE keys. Not real. Never were. -------------------------------------
FAKE_ANON_JWT = (
    f"{b64url({'alg': 'HS256', 'typ': 'JWT'})}."
    f"{b64url({'role': 'anon', 'iss': 'supabase'})}."
    "fakesignature"
)
# Pattern A, part 1: a PRIVILEGED key sitting in public client code.
# In the real 2026 incident this shape exposed ~1.5M API tokens.
FAKE_SERVICE_JWT = (
    f"{b64url({'alg': 'HS256', 'typ': 'JWT'})}."
    f"{b64url({'role': 'service_role', 'iss': 'supabase'})}."
    "fakesignature"
)

APP_JS = f"""
// Acme VibeCRM — client bundle (DELIBERATELY VULNERABLE test target)
const SUPABASE_URL = "https://acme-vibecrm.supabase.co";
const SUPABASE_ANON_KEY = "{FAKE_ANON_JWT}";
// TODO: move this to the server before launch  <-- never happened
const ADMIN_KEY = "{FAKE_SERVICE_JWT}";

async function loadUsers() {{
  // Pattern A, part 2: the table has no row-level security, so the
  // bare anon key reads every row.
  const r = await fetch(`${{SUPABASE_URL}}/rest/v1/users?select=*`, {{
    headers: {{ apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${{SUPABASE_ANON_KEY}}` }}
  }});
  return r.json();
}}

async function getUserProfile(userId) {{
  // Pattern B: broken object-level authorization (BOLA). The endpoint
  // trusts the id in the URL — no login, no "is this your record?" check.
  const r = await fetch(`/api/users/${{userId}}`);
  return r.json();
}}
"""

INDEX_HTML = """<!doctype html><html><head><title>Acme VibeCRM</title>
<script src="/app.js"></script></head>
<body>
<h1>Acme VibeCRM (DELIBERATELY VULNERABLE — PenScan test target, localhost only)</h1>
<p>Do not deploy. Do not point at real data.</p>
</body></html>"""

OPENAPI = {"paths": {"/users": {}, "/profiles": {}}}

# Fake rows. Shapes only — no real people, no real data.
FAKE_USERS = [
    {"id": 1, "name": "REDACTED", "email": "REDACTED",
     "phone": "REDACTED", "plan": "pro", "stripe_customer": "REDACTED"},
    {"id": 2, "name": "REDACTED", "email": "REDACTED",
     "phone": "REDACTED", "plan": "team", "stripe_customer": "REDACTED"},
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
        path = self.path.split("?")[0]

        if path == "/":
            self._send(200, INDEX_HTML, "text/html")
        elif path == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif path == "/rest/v1/":
            self._send(200, json.dumps(OPENAPI), "application/json")
        elif path.startswith("/rest/v1/users"):
            # Pattern A, part 2: no RLS — anon key reads every row.
            self._send(200, json.dumps(FAKE_USERS), "application/json")
        elif path.startswith("/rest/v1/profiles"):
            self._send(200, json.dumps([]), "application/json")
        elif path.startswith("/api/users/"):
            # Pattern B: BOLA — any id returns that user's full record,
            # no login, no ownership check. (Lovable shape, CVE-2025-48757.)
            m = re.fullmatch(r"/api/users/(\d+)", path)
            if m:
                uid = int(m.group(1))
                row = next((u for u in FAKE_USERS if u["id"] == uid), None)
                if row:
                    self._send(200, json.dumps(row), "application/json")
                    return
            self._send(404, json.dumps({"error": "not found"}), "application/json")
        elif path == "/api/users":
            # Check 4 probes this exact route: 200 + body => FAIL.
            self._send(200, json.dumps(FAKE_USERS), "application/json")
        else:
            # Clean 404s everywhere else: no /.env, no /admin, no stack traces.
            self._send(404, json.dumps({"error": "not found"}), "application/json")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path.startswith("/storage/v1/object/list/"):
            # Check 3: buckets exist but list nothing to the open web.
            self._send(200, json.dumps([]), "application/json")
        else:
            self._send(404, json.dumps({"error": "not found"}), "application/json")


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Acme VibeCRM (DELIBERATELY VULNERABLE test target) on "
          f"http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    srv.serve_forever()
