# Pre-launch security report — Demo Notes App (mock target)

**Scan date:** 2026-10-08
**Scanned by:** PenScan (five black-box checks)
**Scope:** the mock app at `http://127.0.0.1:8765` (`examples/mock_target.py`). A local demo with two deliberate flaws, built to show what a failing scan looks like.

## The verdict

> # ⛔ DO NOT SHIP

**One line:** The database answers strangers, and the server's secret file is public. Fix both, redeploy, re-scan.

| Check | Result |
|---|---|
| 1. Secrets in the site's code | ✅ Pass |
| 2. Database readable without login | ❌ Fail |
| 3. File storage open to the public | ✅ Pass |
| 4. API routes callable with no login | ✅ Pass |
| 5. Admin/debug pages & error leaks | ❌ Fail |

Verdict rules: **any fail on checks 1–3 → DO NOT SHIP.** Fails only on 4–5 → SHIP WITH FIXES. All pass → SHIP.

---

## Findings

### Finding 1 — Anyone on the internet can read the users table

**What was tested:** Asked the database for the users table using only the public anon key — no login, the way any visitor's browser can.

**What came back:** 2 rows returned, shaped like `{id, name, email}` — data was not kept.

**Why it matters:** Every person who opens the site can download every user's name and email.

**How to fix:**

```
In Supabase, turn on Row Level Security for the users table and add a
policy so users can only read their own row:
create policy "users read own" on users for select using (auth.uid() = id).
Re-run check 2 with the anon key and confirm it returns zero rows.
```

**Severity:** 🔴 launch-blocker

### Finding 2 — The server's secret file is public

**What was tested:** Requested `/.env` the way any visitor can.

**What came back:** HTTP 200 with secret-shaped contents (redacted in this report).

**Why it matters:** Anyone can read the app's private keys straight off the web server.

**How to fix:**

```
Never serve dotfiles. In your hosting config, block /.env (and /.env.local).
Move secrets into the host's environment variables instead of a file on disk.
Re-run check 5 and confirm /.env returns 404.
```

**Severity:** 🔴 launch-blocker

---

## What this scan does and doesn't claim

- **Does:** 5 high-signal black-box checks against the failure modes behind the documented vibe-coded-app breaches (exposed databases, leaked keys, open storage).
- **Doesn't:** a full penetration test. It doesn't review source code, test logged-in user roles against each other, or cover anything added after the scan date. No scan makes an app "unhackable."
- **Re-scan:** fix the findings, redeploy, and re-run the failed checks to confirm before launch.

---

*Raw scanner output for this run is in `examples/sample-output.txt`.*
