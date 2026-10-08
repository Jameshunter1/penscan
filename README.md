# PenScan

Five black-box security checks for apps built with AI tools (Lovable, Bolt, v0, …) before they launch.

It tests a live app the way a stranger on the internet would: can anyone read the database, find secrets in the site's code, download private files, call APIs without logging in, or open admin pages? Each check ends in a plain verdict: **SHIP**, **SHIP WITH FIXES**, or **DO NOT SHIP**.

## The five checks

| # | Check | Fails when |
|---|-------|-----------|
| 1 | Secrets in the site's JavaScript | A `service_role` key or cloud secret (Stripe, AWS, …) is sitting in the downloaded code |
| 2 | Database readable without login | A table returns real rows using only the public anon key |
| 3 | File storage open to the public | A storage bucket lists files or serves downloads with no login |
| 4 | API routes callable with no login | An edge function or API route runs without a user token |
| 5 | Admin/debug pages and error leaks | `/.env` is served, `/admin` loads without login, or errors leak stack traces |

**Verdict rules:** any fail on checks 1–3 → **DO NOT SHIP**. Fails only on 4–5 → **SHIP WITH FIXES**. All pass → **SHIP**.

## Run it

Python 3, no dependencies.

```bash
python3 penscan.py --site https://my-app.lovable.app
```

If the scanner can't find your database URL and anon key in the site's code, pass them directly:

```bash
python3 penscan.py --site https://my-app.lovable.app \
  --supabase-url https://xyzcompany.supabase.co \
  --anon-key eyJhbGciOi...
```

Exit codes: `0` = SHIP, `1` = SHIP WITH FIXES, `2` = DO NOT SHIP. Add `--json` for machine-readable output.

## Try it on the mock app

`examples/mock_target.py` is a tiny local app with two deliberate flaws (open database table, exposed `/.env`). Run it, scan it, watch the verdict land on DO NOT SHIP:

```bash
python3 examples/mock_target.py &   # serves http://127.0.0.1:8765
python3 penscan.py --site http://127.0.0.1:8765 \
  --supabase-url http://127.0.0.1:8765 --anon-key demo
```

## Rules

- **Only scan an app whose owner asked you to.** Never point this at someone else's live app.
- Findings are shown redacted: shapes, not data. Never paste real rows, emails, or keys into a report.

## What this is and isn't

This runs 5 high-signal checks against the failure modes behind the documented vibe-coded-app breaches (exposed databases, leaked keys, open storage). It is not a full penetration test: it doesn't review source code, test logged-in roles against each other, or cover anything added after the scan date. No scan makes an app "unhackable."

See [report-template.md](report-template.md) for the write-up format, and [sample-report.md](sample-report.md) for a filled example from the mock run.
