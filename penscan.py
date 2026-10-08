#!/usr/bin/env python3
"""
PenScan — five black-box pre-launch security checks for vibe-coded apps.

Only scan an app whose owner asked you to. This tool makes real HTTP
requests against the target you point it at; never aim it at someone
else's live app.

Usage:
    python3 penscan.py --site https://my-app.lovable.app
    python3 penscan.py --site https://my-app.lovable.app \
        --supabase-url https://xyzcompany.supabase.co \
        --anon-key eyJhbGciOi...

If --supabase-url / --anon-key are omitted, check 1 tries to discover
them from the site's JavaScript bundles.

Exit code: 0 = SHIP, 1 = SHIP WITH FIXES, 2 = DO NOT SHIP.
"""

import argparse
import base64
import json
import re
import sys
import urllib.request
import urllib.error
from html.parser import HTMLParser

TIMEOUT = 15

# ---------------------------------------------------------------- helpers

def fetch(url, headers=None, method="GET", data=None):
    """GET/POST a URL, return (status, body_text). Never raises."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return -1, f"request failed: {e}"


def b64url_decode(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg).decode("utf-8", "replace")


def decode_jwt(token):
    """Return the payload dict of a JWT, or None if it isn't one."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(b64url_decode(parts[1]))
    except Exception:
        return None


class ScriptSrcParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for k, v in attrs:
                if k == "src" and v:
                    self.srcs.append(v)


def join_url(site, src):
    if src.startswith("http://") or src.startswith("https://"):
        return src
    return site.rstrip("/") + "/" + src.lstrip("/")


# ---------------------------------------------------------------- checks

def check1_secrets_in_bundle(site):
    """Secrets hiding in the site's JavaScript bundles."""
    name = "1. Secrets in the site's JavaScript"
    findings = []
    status, html = fetch(site)
    if status != 200:
        return name, "error", [f"could not load site (HTTP {status})"], {}, {}

    parser = ScriptSrcParser()
    parser.feed(html)
    js = ""
    for src in parser.srcs:
        if not src.endswith(".js") and ".js?" not in src:
            continue
        _, body = fetch(join_url(site, src))
        if body and not body.startswith("request failed"):
            js += "\n" + body

    if not js.strip():
        return name, "pass", ["no JavaScript bundles found to inspect"], {}, {}

    proj = sorted(set(re.findall(r"https://[a-z0-9-]+\.supabase\.co", js)))
    jwts = sorted(set(re.findall(
        r"sb_publishable_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", js)))
    hard_keys = sorted(set(re.findall(
        r"sk_live_[A-Za-z0-9_-]+|xox[bap]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9]{20,}"
        r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}", js)))

    failed = False
    anon_key = None
    for token in jwts:
        payload = decode_jwt(token)
        if not payload:
            continue
        role = payload.get("role", "")
        if role == "service_role":
            failed = True
            findings.append("JWT with role=service_role found in bundle — "
                            "bypasses ALL database security (token redacted)")
        elif role == "anon" and anon_key is None:
            anon_key = token
            findings.append("anon key present in bundle (normal for Supabase apps)")
    for k in hard_keys:
        failed = True
        findings.append(f"hard secret found in bundle: {k[:8]}... (redacted)")

    if not findings:
        findings.append("no service_role keys or cloud secrets in bundles")
    discovered = {"supabase_url": proj[0] if proj else None, "anon_key": anon_key}
    return name, ("fail" if failed else "pass"), findings, discovered, {}


def check2_open_database(proj, anon):
    """Supabase tables readable without login."""
    name = "2. Database readable without login"
    if not proj or not anon:
        return name, "skip", ["need --supabase-url and --anon-key (not found in bundle)"], {}, {}
    headers = {"apikey": anon, "Authorization": f"Bearer {anon}"}
    findings = []
    status, body = fetch(f"{proj}/rest/v1/", headers=headers)
    tables = []
    if status == 200:
        try:
            paths = json.loads(body).get("paths", {})
            tables = [p.strip("/") for p in paths if p.strip("/")]
            findings.append(f"API spec lists tables: {', '.join(sorted(tables)[:8])}")
        except Exception:
            findings.append("API spec unreadable")
    candidates = ["users", "profiles", "orders", "payments", "messages", "transactions"]
    failed = False
    for t in candidates:
        if tables and t not in tables:
            continue
        status, body = fetch(f"{proj}/rest/v1/{t}?select=*&limit=3", headers=headers)
        if status == 200:
            try:
                rows = json.loads(body)
            except Exception:
                rows = None
            if isinstance(rows, list) and rows:
                failed = True
                keys = list(rows[0].keys())[:5] if isinstance(rows[0], dict) else []
                findings.append(f"table '{t}' returned {len(rows)} row(s) with anon key only "
                                f"(columns like: {keys}) — data redacted")
    if not failed:
        findings.append("no tables returned rows with the anon key alone")
    return name, ("fail" if failed else "pass"), findings, {}, {}


def check3_open_storage(proj, anon, js_bundle_text=""):
    """Open storage buckets."""
    name = "3. File storage open to the public"
    if not proj or not anon:
        return name, "skip", ["need --supabase-url and --anon-key (not found in bundle)"], {}, {}
    headers = {"apikey": anon, "Authorization": f"Bearer {anon}",
               "Content-Type": "application/json"}
    buckets = sorted(set(re.findall(
        r"storage/v1/object/(?:public/)?([a-z0-9_-]+)", js_bundle_text or "")))
    findings = []
    if not buckets:
        findings.append("no bucket names found in client code; trying common names")
        buckets = ["avatars", "uploads", "images", "public"]
    failed = False
    for b in buckets:
        status, body = fetch(f"{proj}/storage/v1/object/list/{b}", headers=headers,
                             method="POST", data=b'{"prefix":"","limit":10}')
        if status == 200:
            try:
                items = json.loads(body)
            except Exception:
                items = None
            if isinstance(items, list) and items:
                failed = True
                findings.append(f"bucket '{b}' lists files to the open web ({len(items)} shown)")
        status, _ = fetch(f"{proj}/storage/v1/object/public/{b}/test.jpg",
                          headers={"apikey": anon})
        if status == 200:
            failed = True
            findings.append(f"bucket '{b}' serves files directly (HTTP 200, no login)")
    if not failed:
        findings.append("no buckets leaked file listings or direct downloads")
    return name, ("fail" if failed else "pass"), findings, {}, {}


def check4_open_functions(site, proj, anon, js_bundle_text=""):
    """API routes and edge functions callable with no login."""
    name = "4. API routes callable with no login"
    findings = []
    failed = False
    if proj and anon:
        fns = sorted(set(re.findall(r"functions/v1/([a-z0-9_-]+)", js_bundle_text or "")))
        headers = {"apikey": anon, "Authorization": f"Bearer {anon}"}
        for fn in fns:
            status, body = fetch(f"{proj}/functions/v1/{fn}", headers=headers)
            if status == 200 or (400 <= status < 500 and len(body) > 50):
                failed = True
                findings.append(f"edge function '{fn}' responded (HTTP {status}) with no user login")
        if not fns:
            findings.append("no edge function names found in client code")
    for p in ["/api/admin", "/api/debug", "/api/users", "/api/webhook", "/api/stripe/webhook"]:
        status, body = fetch(site.rstrip("/") + p)
        if status == 200 and len(body) > 50:
            failed = True
            findings.append(f"route {p} returned HTTP 200 with no login")
    if not failed:
        findings.append("no API routes or functions executed without a login")
    return name, ("fail" if failed else "pass"), findings, {}, {}


def check5_debug_exposure(site):
    """Exposed admin/debug pages and verbose errors."""
    name = "5. Admin/debug pages and error leaks"
    findings = []
    failed = False
    for p in ["/.env", "/.env.local", "/admin", "/debug", "/_next/static/BUILD_ID"]:
        status, body = fetch(site.rstrip("/") + p)
        if p in ("/.env", "/.env.local"):
            if status == 200 and ("=" in body or "KEY" in body.upper()):
                failed = True
                findings.append(f"{p} served with HTTP 200 — credentials on disk, public")
        elif p in ("/admin", "/debug"):
            if status == 200 and len(body) > 200:
                failed = True
                findings.append(f"{p} loads without login (HTTP 200)")
        elif status == 200:
            findings.append(f"{p} exists (informational)")
    status, body = fetch(site.rstrip("/") + "/api/does-not-exist-12345")
    low = body.lower()
    if any(s in low for s in ["traceback", "stack trace", "at java.", "at node:", ".py\", line",
                              "node_modules", "sql syntax", "pg::", "sequelize"]):
        failed = True
        findings.append("error pages leak stack traces / file paths / SQL")
    else:
        findings.append("error pages do not leak stack traces")
    if not failed and not any("served" in f or "loads" in f or "leak" in f for f in findings):
        findings.append("no exposed env files, admin pages, or verbose errors")
    return name, ("fail" if failed else "pass"), findings, {}, {}


# ---------------------------------------------------------------- main

VERDICT_RULES = (
    "any FAIL on checks 1-3 -> DO NOT SHIP | "
    "FAILs only on 4-5 -> SHIP WITH FIXES | "
    "all pass -> SHIP"
)

def main():
    ap = argparse.ArgumentParser(description="PenScan: five pre-launch security checks.")
    ap.add_argument("--site", required=True, help="live app URL, e.g. https://my-app.lovable.app")
    ap.add_argument("--supabase-url", default=None)
    ap.add_argument("--anon-key", default=None)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    site = args.site.rstrip("/")
    results = []

    n1, s1, f1, disc, _ = check1_secrets_in_bundle(site)
    results.append((n1, s1, f1))
    proj = args.supabase_url or disc.get("supabase_url")
    anon = args.anon_key or disc.get("anon_key")

    # re-fetch bundle text for bucket/function name mining
    bundle_text = ""
    _, html = fetch(site)
    if html and not html.startswith("request failed"):
        p = ScriptSrcParser(); p.feed(html)
        for src in p.srcs:
            if ".js" in src:
                _, body = fetch(join_url(site, src))
                if body and not body.startswith("request failed"):
                    bundle_text += "\n" + body

    for fn in (lambda: check2_open_database(proj, anon),
               lambda: check3_open_storage(proj, anon, bundle_text),
               lambda: check4_open_functions(site, proj, anon, bundle_text),
               lambda: check5_debug_exposure(site)):
        n, s, f, _, _ = fn()
        results.append((n, s, f))

    fails = {i + 1 for i, (_, s, _) in enumerate(results) if s == "fail"}
    if fails & {1, 2, 3}:
        verdict = "DO NOT SHIP"
        code = 2
    elif fails:
        verdict = "SHIP WITH FIXES"
        code = 1
    else:
        verdict = "SHIP"
        code = 0

    if args.json:
        print(json.dumps({
            "site": site, "verdict": verdict,
            "checks": [{"name": n, "result": s, "findings": f} for n, s, f in results],
        }, indent=2))
    else:
        print(f"PenScan — {site}\n")
        for n, s, f in results:
            icon = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP", "error": "ERROR"}[s]
            print(f"[{icon}] {n}")
            for line in f:
                print(f"       - {line}")
            print()
        print(f"Verdict: {verdict}")
        print(f"Rules: {VERDICT_RULES}")
    return code


if __name__ == "__main__":
    sys.exit(main())
