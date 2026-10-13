# Pre-launch security report — Acme VibeCRM (known-bad sample app)

**Scan date:** 2026-10-12
**Scanned by:** PenScan five-check scanner (black-box, localhost test target)
**Scope:** the deliberately vulnerable sample app at `http://127.0.0.1:8766`
(`examples/known_bad_app.py` in this repo). It replays two documented 2026
breach patterns and nothing else. It was never deployed and never touched
real data — every key, row, and name in it is fake.

## The verdict

> # ⛔ DO NOT SHIP

**One line:** Your admin database key is sitting in your public website code,
your users table is readable by anyone on the internet, and your user API
hands out any customer's full record to strangers. Fix the three items below
before this goes anywhere near real users.

| Check | Result |
|---|---|
| 1. Secrets in the site's code | ❌ Fail |
| 2. Database readable without login | ❌ Fail |
| 3. File storage open to the public | ✅ Pass |
| 4. API routes callable with no login | ❌ Fail |
| 5. Admin/debug pages & error leaks | ✅ Pass |

Verdict rules: **any fail on checks 1–3 → DO NOT SHIP.** Fails only on 4–5 → SHIP WITH FIXES. All pass → SHIP.

---

## Findings

### Finding 1 — Admin database key in your public website code

**What I ran:** I downloaded your site's JavaScript the way any visitor's
browser does and searched it for keys.

**What came back:** A JWT with `role=service_role` sitting in `app.js`
(token redacted — I did not keep it). That key bypasses **all** database
security. This is the shape behind the 2026 incident where ~1.5M API tokens
leaked out of a vibe-coded app's client bundle.

**Why it matters:** Anyone who opens your site can copy that key and read,
change, or delete everything in your database. Row-level security does not
apply to it. Nothing is private while this key is public.

**Fix it — paste this into your coding agent:**

```
The Supabase service_role key is embedded in the public client JavaScript
bundle (app.js, variable ADMIN_KEY). 1) Delete it from all client-side code
and from git history. 2) Rotate the key immediately in the Supabase
dashboard so the leaked one stops working. 3) Move every privileged
operation to server-side code (edge function / API route) that reads the
key from an environment variable, never from shipped JavaScript. 4) Re-run
PenScan check 1 and confirm no service_role token appears in any bundle
before redeploying.
```

**Severity:** 🔴 launch-blocker

### Finding 2 — Anyone on the internet can read your users table

**What I ran:** I asked your database for the users table using only the
public anon key — no login, no account, the way a stranger's browser can.

**What came back:** 2 rows returned, shaped like:
`{id, name: '•••', email: '•••', phone: '•••', plan: '•••'}` — I did not keep
the data. The table has no row-level security.

**Why it matters:** Every person who opens your site can download every
user's name, email, phone number, and plan. Combined with Finding 1, there
is currently no access control on your customer data at all.

**Fix it — paste this into your coding agent:**

```
In Supabase, turn on Row Level Security for the users table and add a
policy so users can only read their own row:
create policy "users read own" on users for select using (auth.uid() = id).
Then verify with ONLY the anon key that
GET /rest/v1/users?select=* returns zero rows before redeploying.
```

**Severity:** 🔴 launch-blocker

### Finding 3 — Your user API gives away any customer's record (broken object-level authorization)

**What I ran:** I called `GET /api/users/2` with no login and no token —
asking for a user who is not me.

**What came back:** The full record for user id 2, shaped like:
`{id: 2, name: '•••', email: '•••', phone: '•••', plan: '•••',
stripe_customer: '•••'}` — I did not keep the data. The endpoint trusts
the id in the URL and never checks who is asking. This is the broken
object-level authorization pattern behind CVE-2025-48757, where 170+
vibe-coded apps leaked other users' data.

**Why it matters:** Anyone can enumerate `/api/users/1`, `/api/users/2`,
`/api/users/3`… and harvest every customer's personal details and billing
references, no account needed.

**Fix it — paste this into your coding agent:**

```
The GET /api/users/<id> endpoint returns any user's full record with no
authentication and no ownership check. 1) Require a valid user session on
every /api/users/* route — return 401 with no token. 2) Add an ownership
check: the requested id must equal the logged-in user's id (or the caller
must have an admin role checked server-side), otherwise return 403.
3) Stop returning sensitive fields (phone, stripe_customer) from this
endpoint — return only what the profile screen needs. 4) Re-run PenScan
check 4 and confirm /api/users returns 401 with no login before
redeploying.
```

**Severity:** 🔴 launch-blocker

---

## What this scan does and doesn't claim

- **Does:** 5 high-signal black-box checks against the exact failure modes behind the documented vibe-coded-app breaches (exposed databases, leaked keys, open storage).
- **Doesn't:** a full penetration test. It doesn't review your source code, test logged-in user roles against each other, or cover anything added after this scan date. No scan makes an app "unhackable" — anyone who tells you that is selling something.
- **Re-scan:** fix the findings, redeploy, and re-run the failed checks to confirm the fix before you announce the launch.

---

*PenScan — five pre-launch security checks for apps built with AI. Open source.*
*This report was generated against a deliberately vulnerable localhost sample.
No real app, data, or credentials were involved.*
