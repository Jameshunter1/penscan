# PenScan

Five black-box security checks for apps built with AI tools (Lovable, Bolt, v0, …). Point it at a live app and it tells you **SHIP**, **SHIP WITH FIXES**, or **DO NOT SHIP**.

It caught this on the demo app included below:

```
[FAIL] 2. Database readable without login
       - table 'users' returned 2 row(s) with anon key only — data redacted
[FAIL] 5. Admin/debug pages and error leaks
       - /.env served with HTTP 200 — credentials on disk, public

Verdict: DO NOT SHIP
```

## Try it in one line

```bash
git clone https://github.com/Jameshunter1/penscan.git && cd penscan && bash sample-scan.sh
```

No dependencies — Python 3 only. That starts a deliberately vulnerable demo app on your own machine, scans it, and prints the verdict above. (Expected result: DO NOT SHIP. The demo is vulnerable on purpose.)

## Scan your own app

```bash
python3 penscan.py --site https://my-app.lovable.app
```

Add `--supabase-url` and `--anon-key` if they can't be found in your site's code. `--json` for machine-readable output. Exit codes: 0 = SHIP, 1 = SHIP WITH FIXES, 2 = DO NOT SHIP.

## The five checks

| # | Check | Fails when |
|---|---|---|
| 1 | Secrets in the site's JavaScript | A `service_role` key or cloud secret sits in the downloaded code |
| 2 | Database readable without login | A table returns rows using only the public anon key |
| 3 | File storage open to the public | A bucket lists files or serves downloads with no login |
| 4 | API routes callable with no login | A function or route runs without a user token |
| 5 | Admin pages and error leaks | `/.env` is served, `/admin` loads open, or errors leak stack traces |

**Verdict rules:** any fail on 1–3 → DO NOT SHIP. Fails only on 4–5 → SHIP WITH FIXES. All pass → SHIP.

Only scan apps whose owner asked you to. See [report-template.md](report-template.md) for the write-up format and [sample-report.md](sample-report.md) for a filled example. This is not a full penetration test — no scan makes an app "unhackable."
