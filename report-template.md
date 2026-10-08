# Pre-launch security report — [APP NAME]

**Scan date:** [YYYY-MM-DD]
**Scanned by:** PenScan (five black-box checks)
**Scope:** the live app at [SITE] plus its connected database, file storage, and API. Tested the way a stranger on the internet would — no access to your code.

## The verdict

> # ⛔ DO NOT SHIP / ⚠️ SHIP WITH FIXES / ✅ SHIP

**One line:** [e.g. "Your database is readable by anyone on the internet. Fix the items below, then re-scan before launch."]

| Check | Result |
|---|---|
| 1. Secrets in the site's code | ✅ Pass / ❌ Fail |
| 2. Database readable without login | ✅ Pass / ❌ Fail |
| 3. File storage open to the public | ✅ Pass / ❌ Fail |
| 4. API routes callable with no login | ✅ Pass / ❌ Fail |
| 5. Admin/debug pages & error leaks | ✅ Pass / ❌ Fail |

Verdict rules: **any fail on checks 1–3 → DO NOT SHIP.** Fails only on 4–5 → SHIP WITH FIXES. All pass → SHIP.

---

## Findings

One block per finding. Delete this section entirely if everything passed.

### Finding 1 — [short title, e.g. "Anyone can read your users table"]

**What was tested:** [plain words — e.g. "Asked your database for the users table the way any visitor's browser can."]

**What came back:** [redacted sample — e.g. "Rows returned, shaped like {name, email} — data was not kept."]

**Why it matters:** [one line, plain words — e.g. "Everyone who opens your site can download every user's name and email."]

**How to fix:**

```
[concrete fix — e.g. "In Supabase, turn on Row Level Security for the users
table and add a policy so users can only read their own row:
create policy "users read own" on users for select using (auth.uid() = id).
Re-run check 2 with the anon key and confirm it returns zero rows."]
```

**Severity:** 🔴 launch-blocker / 🟡 fix before scaling

### Finding 2 — …

---

## What this scan does and doesn't claim

- **Does:** 5 high-signal black-box checks against the failure modes behind the documented vibe-coded-app breaches (exposed databases, leaked keys, open storage).
- **Doesn't:** a full penetration test. It doesn't review source code, test logged-in user roles against each other, or cover anything added after the scan date. No scan makes an app "unhackable."
- **Re-scan:** fix the findings, redeploy, and re-run the failed checks to confirm before launch.
