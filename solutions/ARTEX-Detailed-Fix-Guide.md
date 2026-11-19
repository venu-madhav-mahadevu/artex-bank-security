# ARTEX Bank Attacks — Detailed Fix Guide

*Expanded companion to the ARTEX attack report (research 16–17 Nov 2026) and to the condensed "ARTEX-Solutions-Code-Examples" guide. Defensive guidance only: every example below is a fix pattern for your own applications.*

> **Standing clarification:** No ARTEX run was performed against BofA CashPro or any live site. The findings table referenced in earlier material was an example from ARTEX's public demo against a test website. This guide maps fixes to attack methods documented in public reporting — FBI FLASH-20261113-001, Microsoft, AWS, CrowdStrike, CERT-In CIAD-2026-0046/0058, and the Korea Financial Security Institute (KFSI) — not to any scan of a real bank system.

## The one-line lesson from every incident

ARTEX used **no zero-days**. It chained known, preventable weaknesses — default/weak credentials, no rate limit / no MFA, SQL injection, missing API authentication, exposed admin/debug pages, secrets left in code/JS/public repos, over-privileged vendor OAuth apps — at machine speed, in parallel, with little human supervision. Speed, scale and a lower skill floor are what changed. Every fix below closes one of those weaknesses, and every fix must now *hold at machine speed, every time*.

**Confidence key (same as the report):** **Confirmed** = a named primary investigator / victim / regulator states it on the record. **Assessed** = that investigator's attribution or judgement, usually at stated "moderate confidence." **Alleged / reported** = press, anonymous sourcing, an agent's own unverified records, or an extortion claim. ARTEX use by one actor does **not** attribute another actor.

## Attack → Fix summary

| # | Attack / finding | Documented anchor incident | Fix | Section |
|---|---|---|---|---|
| 1 | Password spraying / credential stuffing | Storm-0940 spray: 151,000+ failed logons, peak 2,900/min (Microsoft) | Rate limiting + breached-password screening + MFA / WebAuthn step-up | §1 |
| 2 | SQL injection in search parameters | South Korean banks' entry point via peripheral systems (KFSI) | Parameterised queries everywhere + least-privilege DB accounts | §2 |
| 3 | Unsigned SAML assertions accepted; auth bypass | VAPOR PANDA vs US pharma (CrowdStrike) | Strict SAML signature validation, in order, reject on any failure | §3 |
| 4 | IDOR / authorisation bypass on APIs | "Acme" demo engagement order API; Check Point console records | Object-level authorisation on every request | §4 |
| 5 | SSRF / XXE → cloud metadata (IMDS) theft | VAPOR PANDA pharma #1; Storm-3358 (Microsoft/Talos) | URL allow-listing, IMDSv2 required, XXE disabled | §5 |
| 6 | Anonymous file upload → web shell | Storm-3358; AhnLab controlled lab run | Upload validation + no-execute storage + AV scan | §6 |
| 7 | API keys / secrets in JS bundles, .env, repos | GitHub search → Azure Key Vault exfiltration in 5 minutes (Microsoft) | Vault + short-lived credentials + continuous scanning | §7 |
| 8 | Exposed admin / debug pages, default credentials | Chainstack test Grafana, default admin creds (first-party) | SSO-gate or remove; deny rules; surface inventory | §8 |
| 9 | Weak session tokens | ARTEX demo findings; Greek gov forged admin token (VAPOR PANDA) | Secure session configuration + rotation + server-side invalidation | §9 |
| 10 | Payment-API abuse (disbursal without KYC/limits) | CERT-In CIAD-2026-0046 / 0058, CRAFTY FALCON | Stage-bound state machine + maker-checker + API-layer ceilings | §10 |
| 11 | Over-privileged vendor OAuth apps | ConnectWise Cloud Backup (Storm-0940); Salesloft Drift precedent | Least-privilege consent + service-principal monitoring | §11 |
| 12 | Deepfake liveness attempts | AWS MadPot Campaign 2 (rejected); MEXC takeover (victim-reported) | Server-side verdict + injection detection + recovery-session key audit | §12 |
| 13 | Slow detection | Intrusions reached privilege in <3 hours (FBI / Microsoft) | Detection queries tuned for machine-speed bursts + automated containment | §13 |
| 14 | Missing security headers / verbose errors | ARTEX demo + FBI mitigation guidance | Security headers + generic error responses | §14 |

---

## §1 Login attacks — rate limiting, breached passwords, MFA

### In simple words

Imagine a thief standing outside a row of houses, trying the same few common keys — "1234", "password", a key copied from an old burglary — on every door, thousands of times a minute, hoping one opens. That is password spraying and credential stuffing: not picking one lock expertly, but trying cheap keys everywhere at machine speed. In the Storm-0940 case the thief tried over 151,000 times in a few days and every door's lock jammed shut after a few wrong tries — which is why the spray itself failed.

### What happened

Microsoft's Storm-0940 investigation documents the largest credential attack in the record: on 10–14 October 2026, spraying from a single source (`144.172.64[.]99`) produced **151,000+ failed logons across 327 accounts in 8 organisations, peaking at 2,900 attempts per minute on 11 Oct, with 111,000+ attempts in one day and 48 accounts each absorbing more than 1,000 failures**. The outcome is the instructive part: **~98% of attempts ended in account lockout, and Microsoft observed no successful authentication, token issuance, Graph call or directory change from the spray** — lockouts held, but only just (Microsoft, 21 Oct 2026 — mechanics **Confirmed**; attribution of the campaign to Storm-0940 **Assessed** by Microsoft). A second, smaller data point comes from Lendsqr's first-party advisory on the November 2026 Nigerian wave: one server cycled admin accounts across many organisations every few seconds, and lockout stopped it in the observed case (60 attempts / 11 admin accounts / 48 minutes on 3 Nov). The WorkOS case (see §8) shows the opposite failure mode: an internal tool with **no rate limit at all** let an agent pull CRM records in bulk. ARTEX's own demo findings likewise call out "login page with no limit on tries" as one of its ten weak spots. The spray itself *failed* — what succeeded in the ConnectWise chain was the vendor-app step (§11) — which is why this section and §11 must be read together.

### Why it worked (root cause)

- No per-account, per-IP or per-device attempt limits tuned for bursts — limits (where present) were calibrated to human pace, not thousands of attempts per minute.
- No progressive lockout or escalating delay, so an agent could iterate at full speed indefinitely.
- Passwords were not screened against known-breached lists, so passwords already in public dumps remained valid targets for stuffing.
- MFA absent or not phishing-resistant on some paths; legacy authentication protocols that bypass MFA remained enabled.
- Peripheral systems (partner portals, employee tools) had weaker login controls than customer-facing banking — the FBI's guidance specifically calls out abnormal records-per-session and sequential lookups on exactly those portals.
- No alerting on the spray pattern itself (many accounts, one source, high failure rate), so detection depended on someone noticing.

### Vulnerable code

```python
# VULNERABLE — illustrative. No limits, no lockout, no MFA, password never screened.
@app.post("/login")
def login(username: str, password: str):
    user = db.find_user(username)
    if user and user.password_hash == hash(password):   # unlimited retries allowed
        return create_session(user)
    return {"error": "invalid credentials"}             # attacker retries forever
```

### Why the fix works, in simple words

The door now counts tries — per visitor, per house, per key-ring — and jams quickly, so thousands of attempts become a few. Keys that are already known to be stolen are banned outright. And important doors need a second proof you physically hold (a security key or your phone's fingerprint), so even a copied key alone gets nobody in.

### The fix, step by step

1. Add a sliding-window rate limiter in front of the login endpoint with **three independent dimensions**: per IP, per account, per device fingerprint. Tune for bursts in seconds (e.g. 5/min/IP, 20/hour/account, 100/day/device) — not human pace.
2. On limit breach, return HTTP 429 and raise a detection event (§13); do not silently drop — the burst *is* the signal.
3. Add progressive account lockout with escalating back-off, and alert when a single account crosses 1,000 failures (48 Storm-0940 accounts did — that should page someone).
4. Screen every password at set/reset time against a breached-password corpus using the k-anonymity range API (only a hash prefix leaves your server); reject passwords found in breaches.
5. Require MFA for all users; require **phishing-resistant** MFA (WebAuthn/passkeys) for administrators, approvers, and any step-up before irreversible actions.
6. Disable legacy authentication protocols that cannot enforce MFA.
7. Apply the *same* limits to partner, employee and peripheral portals — not just the customer login.
8. Log every failure with source IP, account, device and timestamp in a form the §13 spray query can consume.

### Fixed code

**1a. Rate limit per account + per IP + per device (Python / Redis)**

```python
import time
import redis
from fastapi import HTTPException, Request

r = redis.Redis(decode_responses=True)

LIMITS = [  # (window_seconds, max_attempts, key_template)
    (60,    5,    "rl:ip:{ip}"),        # 5 tries / minute / IP
    (3600,  20,   "rl:acct:{user}"),    # 20 tries / hour / account
    (86400, 100,  "rl:device:{dev}"),   # 100 tries / day / device
]

def check_login_rate_limit(request: Request, username: str):
    ip = request.client.host
    device = request.headers.get("x-device-id", "unknown")
    now = int(time.time())
    for window, max_attempts, template in LIMITS:
        key = template.format(ip=ip, user=username.lower(), dev=device)
        pipe = r.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zcard(key)
        _, count = pipe.execute()
        if count >= max_attempts:
            # Progressive delay + alert: bursts at machine speed are the signal
            raise HTTPException(status_code=429,
                                detail="Too many attempts. Try again later.")
        r.zadd(key, {f"{now}:{ip}": now})
        r.expire(key, window)
```

Key point from the Storm-0940 case: the spray hit **2,900 attempts/minute** and still failed because lockouts held — but only just. Limits must be tuned for *bursts in seconds*, not human pace.

**1b. Screen new passwords against breached-password lists (k-anonymity)**

```python
import hashlib
import requests

def is_breached_password(password: str) -> bool:
    """Have I Been Pwned range API — only the first 5 hash chars leave your server."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
    return any(line.split(":")[0] == suffix for line in resp.text.splitlines())

# At password set/reset:
# if is_breached_password(new_password): reject with "choose a password not seen in breaches"
```

**1c. Phishing-resistant MFA for high-risk actions (WebAuthn step-up)**

```javascript
// Browser: step-up before payments, beneficiary creation, limit changes
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: Uint8Array.from(atob(serverChallenge), c => c.charCodeAt(0)),
    rpId: "bank.example.com",
    userVerification: "required",          // biometrics/PIN, not just presence
    timeout: 60000,
  },
});
// Send assertion to server; server verifies signature + challenge + origin
// BEFORE executing the irreversible action. A stolen password alone is not enough.
```

Rule: **step-up + explicit human confirmation for irreversible actions** (payments, new beneficiaries, contact-detail changes). This is also what stops a rogue agent operating with valid credentials.

**1d. Second variant — rate limiting in Java / Spring Boot (Bucket4j + Redis)**

```java
// Java — same three-dimension policy, enforced as a servlet filter before the
// authentication provider ever sees the request.
@Component
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private final StringRedisTemplate redis;

    // windows: {seconds, maxAttempts}
    private static final long[][] LIMITS = { {60, 5}, {3600, 20}, {86400, 100} };

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        if (!req.getRequestURI().equals("/login")) { chain.doFilter(req, res); return; }

        String ip     = req.getRemoteAddr();
        String user   = Optional.ofNullable(req.getParameter("username")).orElse("").toLowerCase();
        String device = Optional.ofNullable(req.getHeader("X-Device-Id")).orElse("unknown");
        long now = System.currentTimeMillis() / 1000;

        for (String key : List.of("rl:ip:" + ip, "rl:acct:" + user, "rl:device:" + device)) {
            // pick the matching window for this key type in real code; shown compactly
            long window = key.startsWith("rl:ip") ? 60 : key.startsWith("rl:acct") ? 3600 : 86400;
            long max    = key.startsWith("rl:ip") ? 5  : key.startsWith("rl:acct") ? 20   : 100;
            var zset = redis.opsForZSet();
            zset.removeRangeByScore(key, 0, now - window);
            Long count = zset.zCard(key);
            if (count != null && count >= max) {
                res.setStatus(429);                       // Too Many Requests
                res.getWriter().write("Too many attempts. Try again later.");
                return;                                   // auth provider never runs
            }
            zset.add(key, now + ":" + ip, now);
            redis.expire(key, Duration.ofSeconds(window));
        }
        chain.doFilter(req, res);
    }
}
```

**More languages — the same rate limit in TypeScript, C# and Go:**

```typescript
// TypeScript / Node (Express) — Redis-backed, same three dimensions
import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";

export const loginLimiter = rateLimit({
  windowMs: 60_000, limit: 5,                       // 5 / minute / IP
  standardHeaders: true, legacyHeaders: false,
  store: new RedisStore({ sendCommand: (...a) => redis.sendCommand(a) }),
  message: { error: "Too many attempts. Try again later." },
});
// Add a second, per-account limiter keyed on req.body.username (20/hour)
// and a per-device limiter (100/day) — the dimensions, not the library, matter.
```

```csharp
// C# — ASP.NET Core built-in rate limiting (per-IP shown; add per-account
// and per-device partitions the same way)
builder.Services.AddRateLimiter(o =>
{
    o.AddPolicy("login", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(1) }));
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});
app.MapPost("/login", Login).RequireRateLimiting("login");
```

```go
// Go — net/http middleware with a Redis sliding window (per-IP key shown)
func loginRateLimit(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := clientIP(r)
        key := "rl:ip:" + ip
        now := time.Now().Unix()
        pipe := rdb.TxPipeline()
        pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(now-60, 10))
        count := pipe.ZCard(ctx, key)
        pipe.Exec(ctx)
        if count.Val() >= 5 {
            http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
            return
        }
        rdb.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
        rdb.Expire(ctx, key, time.Minute)
        next.ServeHTTP(w, r)
    })
}
```

### How to test the fix

1. **Given** a test account, **when** a script submits 6 login attempts from one IP within 60 seconds, **then** the 6th returns HTTP 429 and the authentication provider is never invoked (assert via auth-service mock call count = 5).
2. **Given** the Storm-0940 pattern replayed at low scale (e.g. 25 distinct test accounts × 10 failures from one source IP in 15 minutes), **when** the §13 Splunk spray query runs, **then** exactly one alert fires with distinct_users > 20 and failures > 200.
3. **Given** password reset, **when** a user submits a password known to appear in the breached corpus (use a test-only entry seeded in a stubbed range-API response), **then** the reset is rejected and the old password remains active.
4. **Given** a payment above the step-up threshold, **when** the user authenticates with password only (no WebAuthn assertion), **then** the payment is held and a WebAuthn challenge is issued; **and when** a valid assertion with `userVerification` is returned, **then** the payment proceeds.
5. **Given** a locked account after the hourly limit, **when** the correct password is submitted from a *different* IP inside the lockout window, **then** login is still refused (per-account limit is IP-independent).

---

## §2 SQL injection — parameterised queries, always

### In simple words

Think of a shop assistant who takes the note you hand them and reads it out loud to the stockroom as an instruction. If your note says "one red shirt — and also empty the safe into my bag," a careless assistant reads that too, and the stockroom obeys. SQL injection is exactly that: the visitor's typing is glued into the question the website asks its database (the stockroom), so the visitor can smuggle in extra instructions. The Korean banks were entered this way — not through the front-door banking app, but through side-door systems for loan agents and employees.

### What happened

The South Korean bank breaches of 27 September – 1 October 2026 are the anchor case. KFSI findings, as reported, are explicit about the entry point: **no successful attack touched customer-facing internet or mobile banking**; the breaches came through peripheral systems — Shinhan Bank's **loan-broker / loan-agent inquiry service**, KB Kookmin's **employee mobile work-support system**, and Hana Bank's **sales-support system "ODS"** — using **SQL injection plus authentication bypass** (Zscaler's technique summary). The exposure was material: Shinhan **25,729 people** (names, phones, annual income, loan/borrowing limits, resident registration numbers for some), KB Kookmin **119 records**, Hana **89 records**, BNK Busan **11 contract workers**, Yegaram Savings Bank **~40,000 people**; seven firms breached, roughly **66,000–68,000 individuals** in total, with **no money taken and no accounts taken over** — the risk is downstream voice-phishing and fraud from leaked PII (breaches **Confirmed** by banks/regulators; the ARTEX link and single-operator picture **Assessed** by CrowdStrike at moderate confidence). ARTEX's own "Acme" demo engagement shows the same shape in miniature: an **error-based SQL injection in a search parameter** recorded as database-read access. A KFSI official summarised the defensive gap: security on customer-facing services was strong; employee/partner systems were not.

### Why it worked (root cause)

- User input concatenated directly into SQL strings in search/inquiry parameters.
- Error-based injection was possible because database error messages were returned (or inferable) — see §14.
- The vulnerable systems were peripheral (loan-agent, employee, sales-support), so they escaped the hardening applied to core banking channels.
- Application DB accounts held broader privileges than the feature needed, letting a read primitive escalate (in other documented cases, SQLi chains into web shells via DB file writes).
- WAF coverage treated as the primary control rather than a safety net.
- No automated regression tests for injection on the peripheral apps' search endpoints.

### Vulnerable code

```python
# VULNERABLE — illustrative. String concatenation + raw DB errors surfaced.
@app.get("/loan-inquiries")
def search(agent_id: str):
    sql = f"SELECT * FROM loans WHERE agent_id = '{agent_id}'"   # injectable
    return db.execute(sql).fetchall()
# Try:  agent_id = ' OR '1'='1' --     → returns every loan record
# Try:  agent_id = ' AND (SELECT 1 FROM nonexistent) --  → error-based extraction
```

### Why the fix works, in simple words

The assistant stops reading your note as instructions. Your words are handed over in a sealed envelope clearly marked "this is data, never an order" — the database treats it only as the thing to look up, never as something to obey. On top of that, the assistant's own stockroom key only opens the shelves their job needs.

### The fix, step by step

1. Replace **every** string-built query with parameterised queries / prepared statements — no exceptions for "internal" or "trusted" parameters; peripheral systems are the documented target.
2. Where dynamic SQL is unavoidable (sort columns, table names), use a strict server-side allow-list of identifiers — parameters cannot bind identifiers.
3. Give each application a **least-privilege DB account**: read/write only its own tables; **no file-write, no OS-command functions** (this breaks the SQLi → web-shell chain), no access to other applications' schemas.
4. Return generic errors to clients (§14); log the full DB error server-side only, so error-based extraction has nothing to read.
5. Add a WAF/reverse-proxy SQLi rule set as a safety net only — never as the primary fix.
6. Inventory *all* applications with search/inquiry parameters, including partner and employee tools, and add them to the injection test suite.
7. Add the regression tests below to CI so a future refactor cannot silently reintroduce concatenation.

### Fixed code

```python
# Python (psycopg) — WRONG vs RIGHT
# WRONG:  cursor.execute(f"SELECT * FROM loans WHERE agent_id = '{agent_id}'")
cursor.execute("SELECT * FROM loans WHERE agent_id = %s", (agent_id,))
```

```java
// Java (JDBC)
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM loans WHERE agent_id = ?");
ps.setString(1, agentId);
```

```typescript
// Node (pg)
await pool.query("SELECT * FROM loans WHERE agent_id = $1", [agentId]);
```

**Allow-list for the one thing parameters can't bind — identifiers (Python):**

```python
# Sort/order clauses cannot be bound parameters. Allow-list them instead.
ALLOWED_SORTS = {"created_at": "created_at", "amount": "amount", "name": "borrower_name"}
ALLOWED_DIRS  = {"asc": "ASC", "desc": "DESC"}

def list_loans(sort: str, direction: str, agent_id: str):
    sort_col = ALLOWED_SORTS[sort]          # KeyError → 400 on anything else
    sort_dir = ALLOWED_DIRS[direction.lower()]
    sql = f"SELECT * FROM loans WHERE agent_id = %s ORDER BY {sort_col} {sort_dir}"
    return db.execute(sql, (agent_id,)).fetchall()   # value still parameterised
```

Plus defence in depth: the web app's DB account should be **least-privilege** (no file-write, no OS-command functions — ARTEX chains SQLi into web shells via DB file writes), and WAF rules are a safety net, never the primary fix.

**Least-privilege DB account (PostgreSQL example):**

```sql
-- One account per application; only the tables it owns; no dangerous functions.
CREATE ROLE loan_inquiry_app LOGIN PASSWORD '...from vault...';
GRANT SELECT, INSERT, UPDATE ON loans, loan_agents TO loan_inquiry_app;
REVOKE ALL ON pg_catalog.pg_user FROM loan_inquiry_app;
-- Deliberately NOT granted: COPY ... TO (file write), dblink, untrusted languages.
```

**More languages — parameterised queries in C#, Go, PHP and Ruby:**

```csharp
// C# (.NET / ADO.NET) — parameters, never string building
using var cmd = new SqlCommand(
    "SELECT * FROM loans WHERE agent_id = @agentId", conn);
cmd.Parameters.AddWithValue("@agentId", agentId);
```

```go
// Go (database/sql) — placeholders are driver-specific (? for MySQL, $1 for Postgres)
rows, err := db.Query("SELECT * FROM loans WHERE agent_id = $1", agentID)
```

```php
<?php
// PHP (PDO) — prepared statement with a bound parameter
$stmt = $pdo->prepare("SELECT * FROM loans WHERE agent_id = :agentId");
$stmt->execute(["agentId" => $agentId]);
```

```ruby
# Ruby (Rails / ActiveRecord) — bind variables; never interpolate into SQL strings
Loan.where(agent_id: agent_id)                       # preferred, hash form
Loan.where("agent_id = ?", agent_id)                 # bind-parameter form
```

### How to test the fix

1. **Given** the search endpoint, **when** `agent_id` is submitted as `' OR '1'='1' --`, **then** the response contains zero rows (the string is treated as a literal ID) and no SQL error is logged as an exception.
2. **Given** an error-based payload (`' AND (SELECT 1 FROM nonexistent_table) --`), **when** it is submitted, **then** the client receives the generic error body from §14 with a reference number, and the response contains no table name, SQLSTATE or stack text.
3. **Given** a CI static-analysis gate, **when** a developer commits a query built with string formatting/concatenation, **then** the build fails (e.g. bandit/semgrep rule for SQL string building) before merge.
4. **Given** the app's DB credentials extracted from staging config, **when** a test attempts `COPY (SELECT 1) TO '/tmp/x'` or an OS-command function, **then** the database denies it (permission error), proving the SQLi → file-write chain is broken.
5. **Given** the sort parameter, **when** `sort` is set to `(CASE WHEN 1=1 THEN amount END)`, **then** the API returns 400 from the allow-list check and executes no query.

---

## §3 SAML / SSO — reject unsigned or badly-signed assertions

### In simple words

Single sign-on (SSO) means one trusted office — your identity provider — checks who you are and stamps a pass that other systems accept: "this is Priya, she works here." SAML is just the standard format of that pass. The flaw: some systems accepted passes with **no stamp at all** — a handwritten note saying "I am the chief executive" would get you through the door. That is how one VAPOR PANDA victim was entered.

### What happened

In CrowdStrike's VAPOR PANDA reporting (29 Oct 2026), the entry into a US pharmaceutical company began with an **unsigned SAML assertion combined with XXE**: the service provider accepted an assertion carrying no valid signature, after which the attacker queried the cloud Instance Metadata Service and reached a role able to issue admin commands to thousands of instances, ending as enterprise administrator. CrowdStrike **confirmed** post-compromise activity at 9 organisations in the campaign; attribution of VAPOR PANDA as a China-nexus espionage actor is CrowdStrike's **assessment**. The FBI's TTP table lists the same technique formally — unsigned SAML assertions, MITRE T1606.002 (Forge Web Credentials: SAML Tokens). The failure is a one-line configuration class: a service provider that treats the assertion's *claims* as trustworthy without verifying the IdP's *signature* over them lets anyone mint an identity, including an administrator's, with a text editor.

### Why it worked (root cause)

- The SP accepted assertions with no signature, or with a signature it did not actually verify.
- Where signatures were checked, one or more of the surrounding conditions were not: audience, recipient, validity window, replay.
- Signing keys were not rotated after suspected export (the same campaign's Greek-government case used auth keys from a 2022 export that were apparently never rotated, letting the attacker forge an administrator token).
- Assertions accepted over plain HTTP in some deployments.
- No alerting on assertion-validation failures, so probing was invisible.

### Vulnerable code

```python
# VULNERABLE — illustrative. Parses claims, never verifies the signature.
def handle_saml_response(response_xml):
    assertion = parse(response_xml)
    user = assertion.subject            # attacker-controlled: anyone can write this XML
    return establish_session(user)      # full login as any user, incl. admins
```

### Why the fix works, in simple words

Every pass is now checked properly before the door opens: Is the stamp really from the trusted office? Is it within its valid hours? Was it made out for *this* building? Has this exact pass already been used once? If any answer is no, the door stays shut — no exceptions, no "let them in anyway".

### The fix, step by step

1. Require a signature on every assertion; **reject unsigned assertions outright** — no fallback path.
2. Verify the signature against the IdP's pinned certificate fingerprint from metadata you control (not a certificate supplied inside the message).
3. Enforce, in order: signature → validity window (`NotBefore`/`NotOnOrAfter`) → audience == your SP entity ID → recipient == your ACS URL → assertion ID not seen before (replay cache).
4. Reject on **any** failure; do not log-and-continue.
5. Accept assertions only over HTTPS.
6. Rotate IdP/SP signing keys on any suspected export or leak, and on a schedule; treat old keys as compromised (the Greek-government lesson).
7. Alert on validation failures — a burst of bad assertions is an attack in progress.

### Fixed code

```python
# Pseudocode for the SP assertion handler (any SAML library — python3-saml, Spring Security SAML)
def handle_saml_response(response_xml):
    assertion = parse(response_xml)
    assert assertion.signature is not None, "REJECT: unsigned assertion"
    assert verify_signature(assertion, idp_cert_fingerprint), "REJECT: bad signature"
    assert assertion.conditions.not_before <= now() < assertion.conditions.not_on_or_after
    assert assertion.audience == MY_SP_ENTITY_ID, "REJECT: wrong audience"
    assert assertion.recipient == MY_ACS_URL, "REJECT: wrong recipient"
    assert not replay_cache.seen(assertion.id), "REJECT: replay"
    replay_cache.add(assertion.id)
    return establish_session(assertion.subject)
```

**Second variant — Spring Security SAML (Java) configuration sketch:**

```java
// Java — Spring Security SAML2: rely on the framework's validator, and make
// sure every check is switched ON. The bug in the field is usually a custom
// handler that skips one of these.
@Bean
SecurityFilterChain samlChain(HttpSecurity http) throws Exception {
    http.saml2Login(saml -> saml
        .relyingPartyRegistrationRepository(registrations())
        // Default OpenSaml4AuthenticationProvider validates: signature against
        // the IdP cert in the registration, InResponseTo, audience, recipient,
        // and conditions window. Do NOT replace it with a claims-only converter.
        .authenticationManager(authentication ->
            new ProviderManager(new StrictSamlProvider()))  // rejects unsigned
    );
    return http.build();
}
// Operational rules alongside the code:
//  - IdP cert fingerprint pinned in the registration, never taken from the message
//  - clockSkew set small (e.g. 60s); assertions over HTTPS only
//  - signing-key rotation runbook executed on any suspected export
```

Also rotate signing keys on any suspected export, and never accept assertions over plain HTTP.

**More languages — SAML validation in TypeScript, C# and PHP:**

```typescript
// TypeScript (@node-saml/node-saml) — the library validates the signature
// against YOUR pinned IdP certificate; keep every check switched on.
import { SAML } from "@node-saml/node-saml";
const saml = new SAML({
  entryPoint: "https://idp.example.com/sso",
  cert: IDP_CERT_FINGERPRINT_PINNED,        // from your metadata, never from the message
  issuer: "https://bank.example.com/sp",
  callbackUrl: "https://bank.example.com/login/callback",
  wantAssertionsSigned: true,               // unsigned assertion → reject
  validateInResponseTo: "always",           // replay protection
  acceptedClockSkewMs: 60_000,
});
const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: body });
// Audience/recipient are validated against issuer/callbackUrl above; any
// failure throws BEFORE a session exists.
```

```csharp
// C# (.NET, e.g. Sustainsys.Saml2 / ITfoxtec) — configuration rules that matter
services.AddAuthentication()
    .AddSaml2(options =>
    {
        options.SPOptions.EntityId = new EntityId("https://bank.example.com/sp");
        // Signing validation is on by default — the field failures come from
        // custom code that disables it. Never set:
        //   WantAssertionsSigned = false, or a permissive signature validator.
    });
// Operational rules: IdP cert pinned in configuration, HTTPS only,
// signing keys rotated on any suspected export (the Greek-government lesson).
```

```php
<?php
// PHP (OneLogin php-saml) — strict mode is the fix; lax settings are the bug
$settings = [
    "strict" => true,                          // reject on ANY validation failure
    "sp" => ["entityId" => "https://bank.example.com/sp",
             "assertionConsumerService" => ["url" => "https://bank.example.com/acs"]],
    "idp" => ["entityId" => "https://idp.example.com",
              "x509cert" => $PINNED_IDP_CERT], // pinned, not taken from the message
    "security" => ["wantAssertionsSigned" => true,
                   "wantMessagesSigned" => true,
                   "requestedAuthnContext" => false],
];
```

### How to test the fix

1. **Given** a captured valid assertion from a staging login, **when** the signature element is deleted and the XML is re-posted to the ACS URL, **then** the SP returns 401/403, creates no session, and logs a `REJECT: unsigned assertion` event.
2. **Given** a validly signed assertion, **when** the `NameID` is edited to an administrator's ID (invalidating the signature), **then** the SP rejects it with a signature-validation failure.
3. **Given** a valid assertion, **when** the identical assertion is posted a second time, **then** the replay cache rejects it and no second session is created.
4. **Given** a valid assertion for a *different* SP (audience mismatch, e.g. from a partner test IdP), **when** it is posted to this SP, **then** it is rejected on audience/recipient before any session exists.
5. **Given** an assertion whose `NotOnOrAfter` is in the past, **when** it is posted, **then** it is rejected on the validity-window check even though the signature verifies.

---

## §4 IDOR — check ownership on every object access

### In simple words

When you're logged in, websites show your things at addresses like "…/orders/1001". An IDOR flaw means changing that number to 1002 shows you *someone else's* order — the website never checked the order was yours. It's a hotel front desk that hands over any room key to anyone who just says a room number. A human might try a few numbers; an automated attacker tries **all** of them, one after another, and copies the whole hotel register.

### What happened

IDOR (insecure direct object reference) appears in the record at every scale. In the "Acme" demo engagement transcribed by Tonic from ARTEX's shipped Global Edition sample, one of the recorded findings is an **IDOR / authorisation bypass on the order API** — the agent changed an object identifier and read data that belonged to someone else. Check Point's read of ten misconfigured ARTEX operator consoles (5 Nov 2026) lists IDOR among the weaknesses the agents abused in live criminal operations (console records **Confirmed** as read by Check Point; individual outcomes partly agent-reported). The pattern matters for banks specifically because ARTEX-class agents enumerate identifiers *sequentially and exhaustively* — the FBI mitigation guidance calls out alerting on sequential lookups and abnormal records-per-session — so an IDOR that a human might never notice is, to an agent, a full database extract at machine speed. No customer action is required for the attack: the attacker uses their *own* valid session and simply walks the ID space.

### Why it worked (root cause)

- Handlers fetched objects by ID and returned them without checking that the object belongs to the caller.
- Authorisation was assumed from the UI ("the button isn't shown") instead of enforced in the API handler.
- Sequential, guessable identifiers made enumeration trivial.
- Responses used 403 for other people's objects, confirming the object exists and inviting further probing (a 404 reveals nothing).
- No per-session velocity limits or alerts on sequential ID access, so bulk extraction looked like normal traffic.

### Vulnerable code

```python
# VULNERABLE — illustrative. Any logged-in user can read any order.
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user = Depends(current_user)):
    return db.get_order(order_id)          # no ownership check at all
```

### Why the fix works, in simple words

The front desk now checks the name on the booking against your ID before handing over anything. And if the room isn't yours, they say "no such room" rather than "that's someone else's room" — so an attacker can't even learn which numbers are worth attacking.

### The fix, step by step

1. In **every** handler that takes an object identifier, load the object and compare its owner/tenant to the authenticated principal — in the handler, on every request.
2. Return **404, not 403**, when the object exists but is not the caller's: don't confirm existence.
3. Centralise the check (a dependency/decorator or a data-access layer that always filters by tenant) so a new endpoint cannot forget it.
4. Scope every query by tenant/customer at the SQL level as defence in depth, not only in Python/Java code.
5. Add rate/velocity controls and alerting on sequential identifier access per session (§13).
6. Keep unguessable IDs if you like — as a speed bump only, never as the control.

### Fixed code

```python
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user = Depends(current_user)):
    order = db.get_order(order_id)
    if order is None or order.customer_id != user.customer_id:
        raise HTTPException(404)   # 404, not 403 — don't confirm the object exists
    return order
```

Rule: **the authorisation check lives in the handler, on every request** — never rely on "the UI doesn't show that button" or on unguessable IDs alone.

**Second variant — tenant-scoped data access in Java / Spring (the check can't be forgotten):**

```java
// Java — push the tenant filter into the repository query itself, so every
// caller gets scoping by construction rather than by remembering a check.
public interface OrderRepository extends JpaRepository<Order, Long> {
    // Spring Data derives: WHERE id = ? AND customer_id = ?
    Optional<Order> findByIdAndCustomerId(Long id, Long customerId);
}

@GetMapping("/api/orders/{id}")
public Order getOrder(@PathVariable Long id, @AuthenticationPrincipal AppUser user) {
    return orders.findByIdAndCustomerId(id, user.customerId())
                 .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    // Same 404 for "doesn't exist" and "not yours" — no existence oracle.
}
```

**More languages — the ownership check in TypeScript, C#, Go and Ruby:**

```typescript
// TypeScript / Node (Express) — same rule: load, compare owner, 404 if not yours
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await db.orders.findById(Number(req.params.id));
  if (!order || order.customerId !== req.user.customerId) {
    return res.status(404).end();            // 404, not 403
  }
  res.json(order);
});
```

```csharp
// C# (ASP.NET Core) — scope the query by the caller's customer id
[HttpGet("/api/orders/{id:int}")]
public async Task<IActionResult> GetOrder(int id)
{
    var customerId = User.CustomerId();
    var order = await _db.Orders
        .FirstOrDefaultAsync(o => o.Id == id && o.CustomerId == customerId);
    return order is null ? NotFound() : Ok(order);   // same 404 either way
}
```

```go
// Go — ownership enforced in the query itself
func getOrder(w http.ResponseWriter, r *http.Request) {
    user := userFromContext(r.Context())
    order, err := store.OrderByIDAndCustomer(r.Context(), idParam(r), user.CustomerID)
    if err == sql.ErrNoRows {           // covers "missing" AND "not yours"
        http.NotFound(w, r)
        return
    }
    writeJSON(w, order)
}
```

```ruby
# Ruby (Rails) — association scoping makes the check structural
def show
  order = current_user.orders.find(params[:id])   # raises 404 for others' orders
  render json: order
end
```

### How to test the fix

1. **Given** user A owns order 1001 and user B is authenticated, **when** B requests `/api/orders/1001`, **then** the response is 404 and the body contains none of A's data.
2. **Given** user B, **when** B requests a genuinely non-existent order ID (e.g. 999999999), **then** the response status and body shape are **identical** to the not-yours case (no existence oracle).
3. **Given** an automated sweep test, **when** a script walks order IDs 1–500 under one session, **then** it receives only that session's own orders, and the sequential-access detector (§13) raises an event.
4. **Given** a new endpoint added without the ownership dependency, **when** the CI authorisation test-suite runs (it enumerates all routes with object IDs and cross-accesses them), **then** the build fails until the check is present.

---

## §5 SSRF and XXE — the road to cloud credentials

### In simple words

Some features ask your server to fetch a web address for you — a link preview, an image import. SSRF means tricking that fetch into visiting an *internal* address that outsiders should never reach — above all a special address (the "metadata service") where a cloud server keeps its own keys, like a master key hanging just inside the staff door. XXE is the document version: a file that secretly instructs the reader "also go and fetch these other files and show me". Together they turned small web flaws into full cloud control in the documented cases.

### What happened

SSRF and XXE are the bridge from a web flaw to cloud control in this record. In the VAPOR PANDA campaign, the US pharma #1 intrusion chained **unsigned SAML + XXE → a query to the cloud Instance Metadata Service → a role able to issue admin commands to thousands of instances** → enterprise administrator (CrowdStrike — post-compromise **Confirmed** at the victim; campaign attribution **Assessed**). Microsoft's Storm-3358 reporting describes a Cambodia-based, financially motivated actor using ARTEX against financial organisations mainly in Southeast Asia from October 2026, with **anonymous file upload + SSRF** as the entry pair, then downloading the WISP/VShell/AdaptixC2 tooling via curl/netcat (Microsoft, via Talos/FBI — **Assessed/reported**). AWS's MadPot Campaign 1 playbook likewise lists **SSRF → metadata** as one of the codified routes to extract upstream provider keys from exposed AI applications (agent records **Confirmed** as captured; theft outcomes **not verified** by Amazon). The common thread: a server that can be told what URL to fetch will eventually be told to fetch `169.254.169.254` — the link-local metadata address — and hand back cloud credentials.

### Why it worked (root cause)

- Server-side URL fetching accepted arbitrary user-supplied URLs with no allow-list.
- The metadata service answered over IMDSv1 (a plain GET, no token), so any SSRF became credential theft.
- Redirects were followed without re-validating the destination, and DNS names were not checked against the IPs they resolved to (rebinding).
- XML parsers processed DTDs and external entities (XXE), giving a second path to internal files and internal HTTP services.
- Egress from application servers to internal/link-local ranges was not blocked at the network layer.

### Vulnerable code

```python
# VULNERABLE — illustrative. Fetches anything the caller asks for.
@app.get("/fetch-preview")
def fetch_preview(url: str):
    return requests.get(url).content
# Try: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
#      → the instance's cloud credentials, returned to the attacker.
```

### Why the fix works, in simple words

The fetcher may now visit only a short approved list of outside addresses, and it checks where an address *actually leads* before going — internal and key-drawer addresses are refused outright. The key drawer itself is upgraded so a simple knock gets nothing (it now demands a token the fetcher can't obtain). And documents are read with the "fetch extra files" feature permanently switched off.

### The fix, step by step

1. **Allow-list** outbound destinations by hostname; reject everything else. If a feature doesn't need arbitrary URLs, remove the fetch capability entirely.
2. Resolve the hostname and check **every resolved IP** against blocked ranges (link-local `169.254.0.0/16`, loopback, RFC-1918) before connecting — this defeats DNS rebinding.
3. Disable redirects, or re-run steps 1–2 on every redirect hop.
4. Require **IMDSv2** (token-required) on every instance and set the metadata hop limit to 1, so even a successful SSRF GET returns nothing.
5. Disable DTDs/external entities in **every** XML parser; use defused parsers for untrusted input.
6. Add network egress rules: application subnets cannot reach the metadata address or internal ranges except through approved proxies.
7. Give instances least-privilege IAM roles, so a stolen metadata credential is a small key, not an admin one (VAPOR PANDA's role could command thousands of instances — that is an IAM failure on top of the SSRF).

### Fixed code

**5a. SSRF: allow-list outbound URLs, block metadata ranges**

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.partner.example.com", "images.vendor.example.com"}
BLOCKED_NETS = [ipaddress.ip_network(n) for n in
                ("169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128")]

def safe_fetch(url: str) -> bytes:
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allow-listed")
    # Resolve and check the actual IP (defeats DNS-rebinding to internal addresses)
    for ip in {info[4][0] for info in socket.getaddrinfo(host, 443)}:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in BLOCKED_NETS):
            raise ValueError("blocked destination")
    # ... fetch with redirects disabled or re-validated per hop
```

**5b. Require IMDSv2 on every EC2 instance (Terraform)**

```hcl
resource "aws_instance" "app" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 only — kills SSRF token theft
    http_put_response_hop_limit = 1
  }
}
```

**Second variant — the same control as AWS CLI / CloudFormation:**

```bash
# CLI: enforce IMDSv2 on an existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```

```yaml
# CloudFormation equivalent
AppInstance:
  Type: AWS::EC2::Instance
  MetadataOptions:
    HttpEndpoint: enabled
    HttpTokens: required          # IMDSv2 only
    HttpPutResponseHopLimit: 1
```

**5c. XXE: disable DTDs in every XML parser**

```java
// Java
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setFeature("http://xml.org/sax/features/external-general-entities", false);
f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
f.setXIncludeAware(false);
f.setExpandEntityReferences(false);
```

```python
# Python — use defusedxml instead of xml.etree for untrusted input
from defusedxml.ElementTree import fromstring
```

**More languages — SSRF/XXE hardening in TypeScript, C# and PHP:**

```typescript
// TypeScript / Node — allow-list + resolved-IP check before fetching
import { lookup } from "node:dns/promises";
import ipaddr from "ipaddr.js";

const ALLOWED = new Set(["api.partner.example.com", "images.vendor.example.com"]);
const BLOCKED = ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"]
  .map(c => ipaddr.parseCIDR(c));

export async function assertSafeUrl(raw: string) {
  const host = new URL(raw).hostname;
  if (!ALLOWED.has(host)) throw new Error("host not allow-listed");
  for (const { address } of await lookup(host, { all: true })) {
    const ip = ipaddr.parse(address);
    if (BLOCKED.some(net => ip.match(net))) throw new Error("blocked destination");
  }
  // fetch with redirect: "manual" and re-run this check on every hop
}
```

```csharp
// C# (.NET) — XXE off: DTDs prohibited, no external resolver
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,   // any DOCTYPE → exception
    XmlResolver = null,                        // nothing external is ever fetched
};
using var reader = XmlReader.Create(stream, settings);
```

```php
<?php
// PHP — XXE off: never expand external entities (libxml2 >= 2.9 is safe by
// default; be explicit anyway, and prefer simplexml_load_string with flags)
libxml_use_internal_errors(true);
$xml = simplexml_load_string($input, "SimpleXMLElement", LIBXML_NONET);
// The rules that matter: never pass LIBXML_NOENT for untrusted input (it
// expands entities), and never re-enable external entity loading.
```

### How to test the fix

1. **Given** the URL-fetch feature, **when** a test submits `http://169.254.169.254/latest/meta-data/`, **then** the request is rejected before any outbound connection (assert no socket opened, e.g. via egress-proxy log) and a generic error is returned.
2. **Given** a test hostname whose DNS is controlled by the test (rebinding fixture resolving first to a public IP, then to `10.0.0.5`), **when** the feature fetches it, **then** the resolved-IP check blocks the second resolution and the fetch fails closed.
3. **Given** an instance launched from the Terraform/CloudFormation templates, **when** a plain IMDSv1 `GET` (no token) is issued from the instance itself in a staging check, **then** it returns 401, and a token-required IMDSv2 flow succeeds.
4. **Given** an XML upload/parse endpoint, **when** a document containing `<!ENTITY xxe SYSTEM "file:///etc/passwd">` is submitted, **then** parsing fails or the entity is not expanded, and the response contains no file content.
5. **Given** an allow-listed host that returns a 302 redirect to an internal address, **when** the feature fetches it, **then** the redirect target is re-validated and blocked.

---

## §6 File upload — never let an upload become code

### In simple words

Many sites let visitors upload files — a photo, a CV, a document. The flaw is storing that file, under its own name, in a place the web server also *runs programs from*. It's a cloakroom that lets a stranger leave a "coat" which is actually a working remote control for the building, then lets them walk back in and press the buttons. Attackers upload a small program (a "web shell") and from then on they operate the server as if they owned it — and when the first trick fails, the automated attacker patiently tries variations until one works.

### What happened

Anonymous file upload → web shell is one of the most repeated primitives in the record. Microsoft's Storm-3358 reporting has it as half of the entry pair (with SSRF) against financial organisations in Southeast Asia, after which the actor downloaded WISP/VShell/AdaptixC2 remote-access tooling (Microsoft — **Assessed/reported**). CERT-In's CIAD-2026-0046 lists "deprecated/unauthenticated APIs with unrestricted upload" among the entry vectors for the Indian payment-API campaign (**Confirmed** as issued by the regulator). The clearest step-by-step is defensive, from AhnLab's controlled lab evaluation: given only a target, objective and scope — no vulnerabilities or procedures specified — ARTEX took a **web-app file-upload flaw to a web shell and a Calculator execution on one host, without further human intervention**, and separately turned an exposed ActiveMQ into RCE on four internal hosts (lab results **Confirmed** under those test conditions). Mandiant's Weaver OA case adds the persistence detail: when the first web-shell attempts failed, the agent **revised them iteratively until a working shell resulted** — a control that merely blocks the *first* upload trick will be probed until it yields.

### Why it worked (root cause)

- Upload endpoints were anonymous or weakly authenticated, and accepted any file type.
- The declared `Content-Type` was trusted instead of the file's actual content.
- Uploads were stored under the web root (or a path the server would execute), keeping the original filename/extension — so `shell.jsp` stayed `shell.jsp`.
- No malware scanning before the file became reachable.
- Upload and execution lived on the same host/domain, so a stored file was immediately a running program.

### Vulnerable code

```python
# VULNERABLE — illustrative. Saves whatever arrives, under its own name, in web root.
@app.post("/upload")
def upload(file: UploadFile):
    path = f"/var/www/uploads/{file.filename}"   # attacker picks name AND extension
    open(path, "wb").write(file.file.read())
    return {"url": f"/uploads/{file.filename}"}  # …and the server will execute it
```

### Why the fix works, in simple words

Uploads are treated like parcels at a secure mailroom: the sender must be known, the contents are checked for what they *really* are (not what the label claims), the parcel is renamed, scanned, and locked in a room where nothing can run. When someone later collects it, it's handed over as a plain download — never as a program that executes.

### The fix, step by step

1. Require authentication and authorisation on every upload endpoint; no anonymous uploads.
2. Allow-list content types (e.g. PDF/JPEG/PNG only) and enforce a size cap.
3. Verify the file's **actual content** (magic bytes) against the declared type — a renamed executable must fail.
4. Store under a **random name with no original extension**, outside the web root, in quarantine storage that executes nothing.
5. Scan with AV/malware tooling before the file is released to any consumer.
6. Serve files back only through a download handler with `Content-Disposition: attachment`, from a separate domain/bucket that cannot execute code.
7. Re-test with the iterative mindset from the Weaver OA case: double extensions, null bytes, content-type spoofing, polyglot files — the fix must hold for all of them, not the first attempt.

### Fixed code

```python
ALLOWED = {"application/pdf", "image/jpeg", "image/png"}
MAX_BYTES = 10 * 1024 * 1024

def store_upload(file, data: bytes) -> str:
    if file.content_type not in ALLOWED or len(data) > MAX_BYTES:
        raise ValueError("file type or size not allowed")
    # Verify content, not just the declared type (magic bytes)
    if not magic_matches(data, file.content_type):
        raise ValueError("content does not match declared type")
    stored_name = f"{uuid.uuid4().hex}"          # random name, NO original extension
    s3.put_object(Bucket="uploads-quarantine", Key=stored_name, Body=data)
    return stored_name
    # Serve later via a download handler with Content-Disposition: attachment,
    # from a bucket/domain that executes nothing. Scan with AV before release.
```

**Second variant — Java / Spring Boot upload handler with content sniffing (Apache Tika):**

```java
// Java — same policy: authenticate, allow-list, sniff real content, random name,
// quarantine bucket, nothing executable anywhere near the upload path.
@PostMapping("/upload")
public UploadReceipt upload(@RequestParam("file") MultipartFile file,
                            @AuthenticationPrincipal AppUser user) throws IOException {
    if (file.getSize() > 10 * 1024 * 1024) throw new ResponseStatusException(BAD_REQUEST);

    byte[] data = file.getBytes();
    String detected = new Tika().detect(data);            // content, not the header
    if (!Set.of("application/pdf", "image/jpeg", "image/png").contains(detected)) {
        throw new ResponseStatusException(BAD_REQUEST, "file type not allowed");
    }
    String key = UUID.randomUUID().toString().replace("-", "");   // no extension kept
    s3.putObject(b -> b.bucket("uploads-quarantine").key(key), RequestBody.fromBytes(data));
    avScan.enqueue(key);                                  // released only after a clean scan
    return new UploadReceipt(key, ScanStatus.PENDING);
}
```

**More languages — upload validation in TypeScript, PHP and Go:**

```typescript
// TypeScript / Node — multer for transport, file-type for the REAL content
import multer from "multer";
import { fileTypeFromBuffer } from "file-type";

const ALLOWED = new Set(["application/pdf", "image/jpeg", "image/png"]);
export const upload = multer({ storage: multer.memoryStorage(),
                               limits: { fileSize: 10 * 1024 * 1024 } });

export async function storeUpload(file: Express.Multer.File): Promise<string> {
  const detected = await fileTypeFromBuffer(file.buffer);
  if (!detected || !ALLOWED.has(detected.mime)) throw new Error("type not allowed");
  const key = randomUUID().replaceAll("-", "");       // no original name/extension
  await s3.send(new PutObjectCommand({ Bucket: "uploads-quarantine", Key: key, Body: file.buffer }));
  await avScan.enqueue(key);                          // released only after clean scan
  return key;
}
```

```php
<?php
// PHP — verify with finfo (content), random name, store OUTSIDE the web root
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($_FILES["doc"]["tmp_name"]);
if (!in_array($mime, ["application/pdf", "image/jpeg", "image/png"], true)
    || $_FILES["doc"]["size"] > 10 * 1024 * 1024) {
    throw new Exception("file type or size not allowed");
}
$stored = bin2hex(random_bytes(16));                  // no extension kept
move_uploaded_file($_FILES["doc"]["tmp_name"], "/var/quarantine/" . $stored);
```

```go
// Go — sniff the first 512 bytes, random name, quarantine directory/bucket
func storeUpload(data []byte) (string, error) {
    if len(data) > 10*1024*1024 { return "", errors.New("too large") }
    switch http.DetectContentType(data) {             // content, not the header
    case "application/pdf", "image/jpeg", "image/png":
    default:
        return "", errors.New("type not allowed")
    }
    name := hex.EncodeToString(randBytes(16))         // no original extension
    return name, putToQuarantineBucket(name, data)    // AV scan before release
}
```

### How to test the fix

1. **Given** an authenticated session, **when** a JSP/PHP web-shell file is uploaded with its real content type, **then** it is rejected at the allow-list check and nothing is written to storage.
2. **Given** the same shell renamed to `photo.jpg` with a spoofed `image/jpeg` header, **when** it is uploaded, **then** the magic-byte/Tika check detects the mismatch and rejects it.
3. **Given** a valid PDF upload, **when** the test requests the stored object directly from the serving domain, **then** it is returned with `Content-Disposition: attachment`, a random extensionless name, and is never executed (response is the raw bytes, status 200, no server-side processing).
4. **Given** an EICAR test file (standard AV test string) uploaded as a PDF, **when** the scan completes, **then** the object stays quarantined, is marked infected, and the download handler returns 404/410 for it.
5. **Given** no session, **when** an upload is attempted anonymously, **then** the endpoint returns 401 before reading the file body.

---

## §7 Secrets — the 5-minute Key Vault lesson

### In simple words

Applications need keys and passwords to talk to databases and cloud services. Teams too often write those secrets directly into the program code, into files the website itself serves, or into shared code folders anyone can read. It's taping the vault combination to the vault door — and photocopying it into the lobby brochure. In Microsoft's documented case, an attacker went from finding one exposed key in a public code search to emptying a vault of secrets in **five minutes**. Deleting the note afterwards doesn't help: the combination is already copied, and one lab test even recovered a secret that had been deleted from the code history earlier.

### What happened

Microsoft documented the fastest path in the whole record: on 5 November 2026 it reported an agent going from a **GitHub search to Azure Key Vault exfiltration in five minutes** in one case — find an exposed secret in a public artefact, use it, empty the vault — with retries correcting API versions in 30–80 seconds, and follow-on service-principal sign-ins from 28 Oct across dozens of apps in multiple tenants (Microsoft telemetry — activity **Confirmed**). AWS's MadPot Campaign 1 codified the same playbook per product: target key-aggregators and AI builders (One API, New API, LiteLLM — including its default master key — Dify, Langflow, RAGFlow and others), extract upstream provider keys via default credentials, unauthenticated admin/config endpoints, CVEs, SSRF, and **secrets in client-side JS, source maps, debug routes and .env files**, then validate, pool and grade the keys — and feed stolen keys back into ARTEX's own model gateway to power the next round of hunting, a self-funding loop (agent records **Confirmed** as captured; outcomes **not verified** by Amazon). GitGuardian's sealed lab test removes any comfort that this needs special tooling: ARTEX shipped with **no built-in secret scanner**, yet improvised with `git` + `grep` and found **8 of 9 planted canary secrets**, including one deleted a commit earlier (**Confirmed** as a lab result). Lendsqr's November advisory adds the industrial-scale version: dozens of cloud servers hourly requesting `.env`/`.git`/cloud-credential files from every public site (213 blocked on 5–6 Nov alone).

### Why it worked (root cause)

- Secrets committed to repos, shipped in JS bundles and source maps, or left in `.env` files on web-accessible paths.
- Long-lived static tokens — Cloudflare found static, non-expiring tokens with no IP restriction were the common root cause in its ARTEX cases.
- Deleting a secret from code treated as remediation — it is not; anything that ever shipped must be considered compromised and **rotated** (GitGuardian's lab recovered a secret deleted one commit earlier).
- CI/CD pipelines holding standing credentials instead of short-lived, workload-bound (OIDC/managed-identity) ones.
- No continuous scanning of repos, container images, build artefacts and deployed JS, so exposure was discovered by attackers first.
- Vault access not monitored, so an exfiltration looked like a normal read until it was over — in five minutes.

### Vulnerable code

```python
# VULNERABLE — illustrative. A long-lived secret in source / shipped to clients.
AZURE_KEY = "sk-live-…"                    # committed to the repo, in the JS bundle,
DB_PASSWORD = "Prod!2024"                  # and in .env on a web-accessible path
def get_db():
    return connect(host="db.internal", user="app", password=DB_PASSWORD)
# Deleting these lines later does NOT fix anything — the values are already out.
```

### Why the fix works, in simple words

Keys stop being written down anywhere in the open. They live in a dedicated locked manager (a "vault"), and the application proves who it is and is handed a key that works only briefly — like a hotel keycard that expires at checkout. Anything that was ever taped up is treated as stolen and changed immediately, and automated scanners check the code folders continuously so the next slip is caught by you, not by an attacker.

### The fix, step by step

1. **No secrets in code, JS bundles, source maps, .env files, or repos. Ever.** Inventory where secrets currently live; assume anything that ever shipped is compromised.
2. **Rotate first, then remove.** Rotation is the remediation; deletion from the repo is housekeeping.
3. Replace static keys with **short-lived, workload-bound credentials** (OIDC / managed identity), especially in CI/CD.
4. Fetch the secrets that remain from a vault at runtime, using the workload's identity — no stored credential anywhere in the app.
5. Scan continuously: repos (including history), container layers, build artefacts, pipelines and deployed JS/source maps — in CI as a merge blocker and as a scheduled sweep.
6. IP-restrict any long-lived token that cannot yet be eliminated, and give it an expiry.
7. Alert on vault reads outside expected workload patterns (§13) — a five-minute exfiltration must trip an alarm in minute one.
8. Block web access to `.env`, `.git` and credential-file paths at the edge (the Lendsqr hunting pattern).

### Fixed code

1. **No secrets in code, JS bundles, source maps, .env files, or repos. Ever.** Anything that ever shipped is compromised — rotate it; deleting it from the repo does not revoke it.
2. **Short-lived, workload-bound credentials** (OIDC / managed identity) instead of static keys, especially in CI/CD.
3. Fetch secrets from the vault at runtime:

```python
# Python — Azure Key Vault with managed identity (no stored credential anywhere)
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

client = SecretClient(vault_url="https://my-vault.vault.azure.net/",
                      credential=DefaultAzureCredential())
db_password = client.get_secret("prod-db-password").value
```

4. Scan continuously in CI:

```yaml
# GitHub Actions — block the merge if a secret is detected
- name: Secret scan
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

5. IP-restrict any long-lived token that cannot be eliminated yet.

**Second variant — AWS: short-lived role credentials via OIDC in GitHub Actions (no stored AWS keys at all):**

```yaml
# .github/workflows/deploy.yml — the workflow exchanges a GitHub OIDC token for
# a ~1-hour AWS role session. There is no AKIA key to find in the repo, ever.
permissions:
  id-token: write          # required for the OIDC exchange
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
          aws-region: us-east-1
      # At runtime in app code, read remaining secrets from Secrets Manager with
      # that role — the application also holds no static credential.
```

**More languages — vault access with workload identity in TypeScript, Java and C#:**

```typescript
// TypeScript — Azure Key Vault via DefaultAzureCredential (managed identity;
// the app itself holds no credential to steal)
import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

const client = new SecretClient("https://my-vault.vault.azure.net/",
                                new DefaultAzureCredential());
const dbPassword = (await client.getSecret("prod-db-password")).value;
```

```java
// Java — same pattern, Azure SDK for Java
SecretClient client = new SecretClientBuilder()
    .vaultUrl("https://my-vault.vault.azure.net/")
    .credential(new DefaultAzureCredentialBuilder().build())  // managed identity
    .buildClient();
String dbPassword = client.getSecret("prod-db-password").getValue();
```

```csharp
// C# (.NET) — Azure.Security.KeyVault.Secrets with DefaultAzureCredential
var client = new SecretClient(new Uri("https://my-vault.vault.azure.net/"),
                              new DefaultAzureCredential());
KeyVaultSecret dbPassword = await client.GetSecretAsync("prod-db-password");
```

```go
// Go — AWS Secrets Manager with the workload's IAM role (no static keys)
cfg, _ := config.LoadDefaultConfig(ctx)               // role from the environment
sm := secretsmanager.NewFromConfig(cfg)
out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
    SecretId: aws.String("prod/db-password"),
})
```

### How to test the fix

1. **Given** a test repo, **when** a canary secret is committed (including in a commit that is later "removed"), **then** the CI secret scan fails the build and an alert names the file and commit — proving history is scanned, not just the working tree.
2. **Given** the rotated-credential runbook, **when** the old (planted) key is used against the staging API after rotation, **then** it is rejected, and the attempt is logged with the key's ID.
3. **Given** the production JS bundle and source maps from a staging build, **when** an automated check greps them for key patterns (`AKIA…`, `sk-…`, vault URLs with tokens), **then** zero matches are found.
4. **Given** a request to `/.env` and `/.git/config` on the staging site, **when** it is issued from an external test client, **then** both return 404/403 from the edge, matching the blocked Lendsqr pattern.
5. **Given** the CI deploy workflow, **when** its AWS session is inspected, **then** credentials are role-session credentials expiring in ≤1 hour and no long-lived access key exists in the repo's secrets store.

---

## §8 Admin / debug surface — remove it or put it behind SSO

### In simple words

Every system has control panels — dashboards and admin pages meant for staff. The flaw is leaving one of those panels reachable from the public internet, still using the installer's factory password ("admin"), like Chainstack's test dashboard. It's leaving the building's control room with a door onto the street and never changing the lock from the one the installer used on every building. The attacker didn't break anything — they simply logged in, then walked from the test panel to internal tools and on to the production database.

### What happened

Chainstack's first-party incident report (disclosed 3 Nov, technical details 10 Nov 2026) is the cleanest step-by-step in the record. On **26 Oct at 19:26**, the attacker logged into an **internet-exposed test Grafana** — deployed in July in a dev Kubernetes cluster — with **unchanged default admin credentials** and no SSO or basic-auth layer in front of it. From there: Grafana's **data-source proxy** pivoted to internal services; an **unauthenticated MCP tool server whose service account held cluster-admin** was reached; machine credentials were harvested (artefacts carried `artx`/`artex` markers; Chainstack states *high confidence* ARTEX was used); by **29 Oct** the attacker reached the **production database network**; detection and cut-off came on **31 Oct**. Impact: the customer account DB was accessed (organisation names, account-holder names, member emails, **password hashes**); node-credential systems were accessible but there is **no evidence they were read**. Chainstack's own summary is the lesson: **no software vulnerability was exploited** — the chain was default creds + exposed admin + missing auth + over-broad permissions + long-lived creds (**Confirmed**, first-party). The same shape opens ARTEX's own demo (a hidden/forgotten admin page; default admin password) and the WorkOS case, where an internet-facing internal sales tool accepted a *predictable dev credential*.

### Why it worked (root cause)

- A test/dev instance was reachable from the internet at all.
- Default vendor credentials were never changed before (or after) deployment.
- No SSO/auth layer in front of the admin UI — the app's own login was the only gate.
- The admin tool could proxy to internal services, and an internal tool server had **no authentication** with a **cluster-admin** service account — one hop turned a dashboard login into infrastructure control.
- No inventory of internet-facing applications, so the test instance was invisible to the security team.
- Detection took five days (26 → 31 Oct) — see §13.

### Vulnerable code

```text
# VULNERABLE — illustrative deployment state, the Chainstack shape:
#   grafana.test.example.com  →  reachable from 0.0.0.0/0
#   admin user                →  vendor default password, never rotated
#   SSO / IP allow-list       →  none
#   internal tool server      →  no auth, service account = cluster-admin
```

### Why the fix works, in simple words

Control rooms come off the street: panels are reachable only from inside the company network or after proper staff sign-in, every factory lock is changed before a system goes live, and someone keeps a complete list of every door the building actually has — including the test and side doors everyone forgot.

### The fix, step by step

1. **Inventory every internet-facing application** — including peripheral ones: partner portals, employee tools, test/dev instances, per-business-unit apps. The FBI lists this as its #1 action; Chainstack's instance was a *test* deployment.
2. Remove public exposure by default: admin/debug/test surfaces bind to internal networks or sit behind SSO with MFA — never the app's own login alone.
3. Change **every default credential before first deploy**, enforced in the deployment pipeline (deploy fails if a default is detected).
4. Disable debug endpoints (`/actuator`, `/debug`, consoles) in production builds.
5. Authenticate internal tool servers too, and strip their service accounts to least privilege — no cluster-admin for a tool server (Chainstack's step 3 is the force multiplier).
6. Add edge deny rules for admin/debug paths as defence in depth (below).
7. Run continuous external attack-surface scanning so the next forgotten instance is found by you first.
8. Restrict management interfaces (Kudu/SCM, cloud admin, backup, hypervisor, publishing) to trusted networks/private paths and disable basic publishing auth.

### Fixed code

```nginx
# nginx — admin/debug paths: internal network or SSO only, never public
location ~ ^/(admin|debug|actuator|console|grafana) {
    allow 10.0.0.0/8;          # corporate / VPN range
    deny  all;
    # plus SSO auth_request in front — see your IdP module
}
```

Checklist: inventory **every** internet-facing app including peripheral ones (partner portals, employee tools, test instances); change every default credential before first deploy; disable debug endpoints in production builds; continuous external attack-surface scanning.

**Second variant — the same gate at the application layer (Python / FastAPI SSO dependency):**

```python
# Python — defence in depth behind the edge rule: admin routes require an SSO
# identity with the admin group claim, verified on every request.
from fastapi import Depends, HTTPException, Request

def require_sso_admin(request: Request):
    claims = verify_sso_token(request.headers.get("authorization", ""))
    # verify_sso_token validates the IdP signature/expiry — see §3 for the pattern.
    if claims is None or "app-admins" not in claims.get("groups", []):
        raise HTTPException(403)

@app.get("/admin/health-detail", dependencies=[Depends(require_sso_admin)])
def admin_health_detail():
    return internal_diagnostics()   # unreachable without SSO + group membership
```

**More platforms — the same admin gate in Apache and IIS:**

```apache
# Apache — admin/debug paths restricted to the corporate range (SSO in front
# of this as well; this is the edge layer, not the only layer)
<LocationMatch "^/(admin|debug|actuator|console|grafana)">
    Require ip 10.0.0.0/8
</LocationMatch>
```

```xml
<!-- IIS — IP restrictions for admin paths (plus SSO module in front) -->
<location path="admin">
  <system.webServer>
    <security>
      <ipSecurity allowUnlisted="false">
        <add ipAddress="10.0.0.0" subnetMask="255.0.0.0" allowed="true" />
      </ipSecurity>
    </security>
  </system.webServer>
</location>
```

### How to test the fix

1. **Given** an external test client (no VPN), **when** it requests `/grafana`, `/admin`, `/actuator/env` and `/debug` on the staging domain, **then** every path returns 403/404 from the edge and none returns an application login page.
2. **Given** a fresh staging deployment, **when** the pipeline's default-credential check runs (attempting vendor defaults against each deployed app in an isolated namespace), **then** all default logins fail; if any succeeds, the deploy is blocked and an alert fires.
3. **Given** the internal tool server, **when** an unauthenticated request is made from another pod/namespace, **then** it is rejected with 401, and its service account's permissions test shows no cluster-admin binding.
4. **Given** the attack-surface scanner's latest report, **when** it is compared with the application inventory, **then** every externally reachable host maps to an inventory entry — an unmapped host fails the check.
5. **Given** an SSO session *without* the admin group, **when** it calls `/admin/health-detail`, **then** the response is 403 and the attempt is logged.

---

## §9 Sessions — strong tokens, safe cookies

### In simple words

After you log in, a website gives your browser a token — think of it as a wristband at an event: show the wristband, and staff don't ask for your ID again. Weak session tokens are wristbands that are easy to photocopy, never expire, and were printed with a stamp that leaked years ago and was never replaced. In the VAPOR PANDA case, attackers used authentication keys from a **2022** export that had never been changed to print themselves an administrator's wristband.

### What happened

"Weak login (session) token" is one of the three findings named clearly from ARTEX's own demo material (via Frank on Fraud's reproduction of the demo screenshots), alongside the hidden admin page and the unlimited login. The record's most consequential token failure is VAPOR PANDA's Greek-government case: the operator fed the agent a **2022 mail-server directory export whose authentication keys were apparently never rotated**, and from those stale keys **forged an administrator token**, then read mailboxes and recovered a VPN configuration and client key from users' mail (CrowdStrike — post-compromise **Confirmed** at victims in the campaign; the "apparently never rotated" detail is as reported). The lesson generalises: a session or token system is only as strong as its key hygiene — a token signed with an old, exported, or predictable key is forgeable no matter how good the cookie flags are, and a token that is never rotated or invalidated server-side stays valid for whoever holds a copy. ARTEX's recording-proxy design (capturing authenticated browser traffic so agents can work behind logins a human already passed) makes the same point from the other side: a stolen session token *is* the login.

### Why it worked (root cause)

- Session/token signing keys never rotated — including after exports, leaks, or staff changes.
- Tokens with long or no expiry; no idle timeout on sensitive applications.
- Session IDs not rotated at login or at privilege changes (fixation/replay risk).
- Cookies missing `Secure`, `HttpOnly`, `SameSite`, or the `__Host-` protections.
- Logout/password-change not invalidating tokens server-side, so copied tokens kept working.
- Predictable or low-entropy token generation in home-grown session code.

### Vulnerable code

```python
# VULNERABLE — illustrative. One static signing key since 2022, week-long tokens,
# no rotation at login, logout that only clears the browser cookie.
app.secret_key = "changeme-2022"          # exported in a directory dump; never rotated
SESSION_LIFETIME = timedelta(days=7)

@app.route("/logout")
def logout():
    resp.delete_cookie("session")          # server still honours the copied token
    return resp
```

### Why the fix works, in simple words

Wristbands are now printed with a secret stamp that is replaced regularly — replacing it instantly invalidates every old copy. Each band expires quickly, you get a fresh one when you move into a higher-security area, and when you leave (log out) or staff get suspicious, your band is cancelled on their list, not just taken off your wrist — so a photocopy stops working too.

### The fix, step by step

1. Generate session IDs with a CSPRNG (≥128 bits of entropy); never roll your own token format.
2. Store the signing key in a vault (§7) and **rotate it on a schedule and immediately on any suspected export** — rotation invalidates every token signed with the old key, which is the point.
3. Set banking-appropriate lifetimes: short idle timeout (e.g. 30 minutes), absolute cap, `Secure` + `HttpOnly` + `SameSite` cookies, `__Host-` prefix.
4. **Rotate the session ID at login and at every privilege change** (step-up, role change).
5. Invalidate sessions **server-side** on logout, password change, and risk events — a copied token must die with the session.
6. Bind high-risk sessions to device signals where feasible, and re-authenticate (step-up, §1) for irreversible actions rather than trusting the session alone.
7. Audit token/key age: alert on any signing key older than policy (the Greek case ran ~4 years).

### Fixed code

```python
# FastAPI/Starlette session cookie settings (same ideas in every framework)
SessionMiddleware(
    app,
    secret_key=load_from_vault("session-signing-key"),
    session_cookie="__Host-session",   # __Host- prefix: Secure + host-locked
    max_age=30 * 60,                   # 30-minute idle lifetime for banking
    same_site="strict",
    https_only=True,
)
# Rotate the session ID at login and at every privilege change.
# Invalidate server-side on logout, password change, and risk events.
```

**Second variant — server-side session store with rotation and revocation (Python / Redis):**

```python
import secrets

IDLE_SECONDS = 30 * 60

def create_session(user_id: str) -> str:
    sid = secrets.token_urlsafe(32)                    # 256-bit CSPRNG token
    r.setex(f"sess:{sid}", IDLE_SECONDS, user_id)
    return sid

def rotate_session(old_sid: str) -> str:
    """Call at login and at every privilege change — kills fixation and replay
    of any copied pre-auth token."""
    user_id = r.get(f"sess:{old_sid}")
    r.delete(f"sess:{old_sid}")                        # old token dies immediately
    return create_session(user_id)

def revoke_all_sessions(user_id: str):
    """Call on password change / risk event — a stolen token stops working."""
    for key in r.scan_iter(f"sess:*"):
        if r.get(key) == user_id:
            r.delete(key)
```

**More languages — session configuration in TypeScript, Java, C# and Ruby:**

```typescript
// TypeScript / Node (express-session + Redis store) — same policy values
app.use(session({
  name: "__Host-session",
  secret: await vault.get("session-signing-key"),     // from the vault, rotated (§7)
  store: redisStore,                                  // server-side: revocable
  cookie: { httpOnly: true, secure: true, sameSite: "strict", maxAge: 30 * 60 * 1000 },
  resave: false, saveUninitialized: false,
}));
// Regenerate the session ID at login and at privilege change:
//   req.session.regenerate(...)  — and destroy server-side on logout.
```

```java
// Java — Spring Session (Redis) + cookie policy
@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 30 * 60)   // 30-min idle
class SessionConfig {
    @Bean CookieSerializer cookieSerializer() {
        DefaultCookieSerializer s = new DefaultCookieSerializer();
        s.setCookieName("__Host-session");
        s.setUseSecureCookie(true);
        s.setSameSite("Strict");
        return s;
    }
    // Session ID rotates automatically on authentication in Spring Security;
    // invalidate server-side on logout / password change.
}
```

```csharp
// C# — ASP.NET Core cookie authentication with the same lifetimes
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.Name = "__Host-session";
        o.Cookie.HttpOnly = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(30);  // idle timeout via sliding expiration
        o.SlidingExpiration = true;
    });
```

```ruby
# Ruby (Rails) — session cookie policy in config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store,
  key: "__Host-session",
  expire_after: 30.minutes,
  secure: true, httponly: true, same_site: :strict
# Rotate on login: reset_session — and prefer a server-side store
# (redis_store) for banking so sessions can be revoked centrally.
```

### How to test the fix

1. **Given** a session cookie captured before login (fixation fixture), **when** the user logs in, **then** the session ID changes and the pre-login ID is rejected on the next request.
2. **Given** an authenticated session, **when** the user logs out and the test replays the pre-logout cookie, **then** the server returns 401 — server-side invalidation, not just cookie deletion.
3. **Given** a token signed with the *old* signing key (fixture from the staging vault's previous version), **when** it is presented after a key rotation, **then** it is rejected and the rejection is logged.
4. **Given** the login response, **when** its `Set-Cookie` header is inspected, **then** it carries `Secure`, `HttpOnly`, `SameSite=Strict` (or Lax where justified) and the `__Host-` prefix.
5. **Given** an idle session, **when** a request arrives after 31 minutes of inactivity, **then** the session is expired and the user is returned to login.

---

## §10 Payment APIs — bind the stages so they can't be skipped (CERT-In pattern)

### In simple words

In a lending office, staff at the front desk are supposed to check everything in order — application, identity (KYC), approval, verified recipient — before money moves. In the CERT-In cases, those checks existed only at the front desk, while the vault at the back (the "disbursal API" — the machine-to-machine door used to actually send money) opened for anyone holding a staff key who walked around the side. Attackers stole a staff key, skipped every front-desk check, invented reference numbers, and sent money straight to accomplice ("mule") accounts.

### What happened

CERT-In's advisory **CIAD-2026-0046** (9 Oct 2026, Critical, issued with CSIRT-Fin) documents actors exploiting payment and disbursement APIs for unauthorised fund transfers across Indian BFSI entities — NBFCs, digital lenders, fintechs, payment aggregators/PSPs, wallet and crypto operators. The method, step by step: steal payment-gateway/aggregator/partner-bank API credentials (long-lived tokens hardcoded in source, plaintext credentials in configs/DBs, forged commits); then invoke the **disbursal APIs directly, from the victim's own whitelisted infrastructure**, so the checks that live in the application layer — **loan creation, KYC, sanction, beneficiary, balance and per-transaction-limit checks — never run**; use dummy reference numbers; route funds to mule accounts via IMPS/NEFT and withdraw rapidly. The follow-on **CIAD-2026-0058** (4 Nov 2026, Critical) names the actor **CRAFTY FALCON** and the tool family — ARTEX, PentAGI, Cairn, CyberStrikeAI — probing payment APIs, running **small test transactions** first, deleting records, timing attacks for weekends/holidays, and re-targeting entities after incomplete remediation. CERT-In names **no victims and no loss total** (press claims of "~20 institutions" are not in the advisory); the campaign pattern is **Confirmed** by the regulator, while ARTEX's role in any *specific* transfer is **not established** — 0046 flagged only the "possible use of AI-assisted offensive tooling," and the tool naming belongs to 0058.

### Why it worked (root cause)

- The stage checks (creation → KYC → sanction → beneficiary → limits) existed only in the application/UI layer; the disbursal API itself enforced none of them.
- Direct API invocation with stolen credentials was indistinguishable from legitimate traffic — it came from the victim's own whitelisted infrastructure.
- No maker-checker separation at the API layer: one identity could create and execute.
- Amounts and references were not validated against an approved record, so dummy reference numbers passed.
- Per-transaction and daily ceilings were not enforced in the API itself.
- No idempotency protection, so replays/duplicates were possible.
- Long-lived API credentials were stealable from source/configs (see §7), and UAT was not fully separated from production.
- Monitoring was weakest exactly when attacks were timed: weekends and holidays.

### Vulnerable code

```java
// VULNERABLE — illustrative. The endpoint trusts the caller completely: no state,
// no approval record, no maker-checker, no ceiling. Whoever holds the API key
// can disburse to anyone, any amount, immediately.
@PostMapping("/api/disburse")
public Receipt disburse(@RequestBody DisburseRequest req, @RequestHeader("X-Api-Key") String key) {
    requireValidApiKey(key);
    return gateway.transfer(req.account(), req.ifsc(), req.amount());  // done. That's the bug.
}
```

### Why the fix works, in simple words

The vault itself now refuses to open unless the full trail of stamps is present and in order — application, identity check, sanction, verified recipient, approval — and the person turning the key cannot be the same person who approved the payment. The amount must match the approved paperwork exactly, daily totals are capped at the vault, and each payment can only ever be executed once.

### The fix, step by step

1. Model every payout as a **state machine** in the API itself: `CREATED → KYC_VERIFIED → SANCTIONED → BENEFICIARY_VERIFIED → APPROVED → EXECUTED`, with transitions enforced server-side. A payout can only execute from `APPROVED`.
2. Enforce **maker-checker**: the identity that created/approved a payout cannot execute it.
3. Validate the execution request **against the approved record**: amount, beneficiary and reference must match exactly; reject dummy or altered references.
4. Verify the beneficiary independently (penny-drop + name matching) before the `BENEFICIARY_VERIFIED` state is reachable.
5. Enforce **per-transaction and daily ceilings at the API layer**, not in the UI.
6. Require an **idempotency key** per payout; a duplicate submission returns the original result instead of paying twice.
7. Short-lived, scoped API credentials (§7); MFA on the payment platform; UAT fully separated from production.
8. Heightened monitoring and alerting on weekends/holidays and on small "test transaction" patterns (0058's signature).

### Fixed code

**Java — the state machine guard at execution time:**

```java
// Java — a payout can only execute from state APPROVED, and only with maker != checker
public Payout executePayout(String payoutId, User actor) {
    Payout p = repo.findByIdForUpdate(payoutId);

    require(p.getState() == State.APPROVED,
            "Payout must pass creation → KYC → sanction → beneficiary → approval first");
    require(p.getBeneficiary().isPennyDropVerified(),
            "Beneficiary not verified");
    require(!p.getMakerId().equals(actor.getId()),
            "Maker-checker: approver cannot execute own payout");
    require(p.getAmount().compareTo(p.getApprovedAmount()) == 0,
            "Amount differs from approved record — reject dummy/altered references");
    require(limitService.withinCeilings(p), "Per-transaction or daily ceiling exceeded");
    require(idempotencyStore.claim(p.getIdempotencyKey()),
            "Duplicate submission");

    p.setState(State.EXECUTED);
    return gateway.transfer(p);
}
```

Add: per-transaction and daily ceilings **at the API layer**, beneficiary penny-drop + name matching, MFA on the payment platform, UAT fully separated from production, and heightened monitoring on weekends/holidays (the attackers' preferred window).

**Python — the same guard as an explicit transition table:**

```python
# Python — legal transitions only; execute_payout() re-checks everything the
# Java version does. The state machine is the control, not the caller's honesty.
TRANSITIONS = {
    "CREATED":              {"KYC_VERIFIED"},
    "KYC_VERIFIED":         {"SANCTIONED"},
    "SANCTIONED":           {"BENEFICIARY_VERIFIED"},
    "BENEFICIARY_VERIFIED": {"APPROVED"},
    "APPROVED":             {"EXECUTED"},
    "EXECUTED":             set(),
}

def transition(payout, to_state: str):
    if to_state not in TRANSITIONS[payout.state]:
        raise DomainError(f"illegal transition {payout.state} -> {to_state}")
    payout.state = to_state

def execute_payout(payout_id: str, actor) -> Receipt:
    with db.transaction():
        p = db.get_payout_for_update(payout_id)
        require(p.state == "APPROVED", "stages cannot be skipped")
        require(p.beneficiary.penny_drop_verified, "beneficiary not verified")
        require(p.maker_id != actor.id, "maker-checker violation")
        require(p.amount == p.approved_amount, "amount differs from approved record")
        require(within_ceilings(p), "ceiling exceeded")
        require(idempotency.claim(p.idempotency_key), "duplicate submission")
        transition(p, "EXECUTED")
        return gateway.transfer(p)
```

**C# (.NET) — guard clauses in the disbursement service:**

```csharp
// C# — ASP.NET Core service layer. Same invariants, enforced before the
// gateway call, inside a serialisable transaction.
public async Task<Receipt> ExecutePayoutAsync(Guid payoutId, Guid actorId)
{
    var p = await _repo.GetForUpdateAsync(payoutId);

    if (p.State != PayoutState.Approved)
        throw new DomainException("Payout must pass creation → KYC → sanction → beneficiary → approval first");
    if (!p.Beneficiary.PennyDropVerified)
        throw new DomainException("Beneficiary not verified");
    if (p.MakerId == actorId)
        throw new DomainException("Maker-checker: approver cannot execute own payout");
    if (p.Amount != p.ApprovedAmount)
        throw new DomainException("Amount differs from approved record");
    if (!await _limits.WithinCeilingsAsync(p))
        throw new DomainException("Per-transaction or daily ceiling exceeded");
    if (!await _idempotency.TryClaimAsync(p.IdempotencyKey))
        throw new DomainException("Duplicate submission");

    p.State = PayoutState.Executed;
    await _repo.SaveAsync(p);
    return await _gateway.TransferAsync(p);
}
```

**TypeScript / Node — state guard middleware for the disburse route:**

```typescript
// TypeScript — Express/Nest style. The route cannot be reached in the wrong
// state; the guard runs before the handler, on every call.
async function requireExecutablePayout(req, res, next) {
  const p = await payouts.findByIdForUpdate(req.params.id);
  if (!p) return res.status(404).end();
  if (p.state !== "APPROVED")            return res.status(409).json({ error: "stages cannot be skipped" });
  if (!p.beneficiary.pennyDropVerified)  return res.status(409).json({ error: "beneficiary not verified" });
  if (p.makerId === req.user.id)         return res.status(403).json({ error: "maker-checker violation" });
  if (p.amount !== p.approvedAmount)     return res.status(409).json({ error: "amount differs from approved record" });
  if (!(await limits.withinCeilings(p))) return res.status(409).json({ error: "ceiling exceeded" });
  if (!(await idempotency.claim(p.idempotencyKey)))
    return res.status(200).json(await receipts.forPayout(p.id));  // duplicate → original receipt
  req.payout = p;
  next();
}
app.post("/api/payouts/:id/execute", requireExecutablePayout, async (req, res) => {
  req.payout.state = "EXECUTED";
  await payouts.save(req.payout);
  res.json(await gateway.transfer(req.payout));
});
```

**Go — the guard as a plain function (no framework magic to bypass):**

```go
// Go — every precondition is an explicit check before the transfer call.
func ExecutePayout(ctx context.Context, repo Repo, gw Gateway, id string, actor User) (Receipt, error) {
    p, err := repo.GetForUpdate(ctx, id)
    if err != nil { return Receipt{}, err }

    switch {
    case p.State != Approved:
        return Receipt{}, errors.New("payout must pass creation → KYC → sanction → beneficiary → approval first")
    case !p.Beneficiary.PennyDropVerified:
        return Receipt{}, errors.New("beneficiary not verified")
    case p.MakerID == actor.ID:
        return Receipt{}, errors.New("maker-checker: approver cannot execute own payout")
    case p.Amount != p.ApprovedAmount:
        return Receipt{}, errors.New("amount differs from approved record")
    case !repo.WithinCeilings(ctx, p):
        return Receipt{}, errors.New("per-transaction or daily ceiling exceeded")
    case !repo.ClaimIdempotency(ctx, p.IdempotencyKey):
        return Receipt{}, errors.New("duplicate submission")
    }
    p.State = Executed
    if err := repo.Save(ctx, p); err != nil { return Receipt{}, err }
    return gw.Transfer(ctx, p)
}
```

### How to test the fix

1. **Given** a payout in state `CREATED` (no KYC, no sanction), **when** the execute endpoint is called directly with valid API credentials — the CERT-In move — **then** it returns 409 and no gateway call is made (assert gateway mock count = 0).
2. **Given** an `APPROVED` payout created by maker M, **when** M (same identity) calls execute, **then** the call is rejected on maker-checker; **and when** a different checker identity calls it, **then** it executes exactly once.
3. **Given** an approved amount of 50,000, **when** execute is called with the amount field altered to 500,000 (or a dummy reference number), **then** it is rejected as differing from the approved record.
4. **Given** a successful execution, **when** the identical request (same idempotency key) is replayed, **then** the original receipt is returned and the gateway is not called a second time.
5. **Given** the daily ceiling is reached by prior payouts in the test fixture, **when** one more in-state payout is executed, **then** it is rejected on ceilings even though every other check passes.
6. **Given** a small-value "test transaction" pattern (0058's signature: tiny payout to a new beneficiary), **when** it is submitted, **then** it follows the identical state machine — no fast path exists for small amounts — and the monitoring alert fires.

---

## §11 Vendor / OAuth apps — least privilege + watch the service principals

### In simple words

Companies hire outside software services — backup tools, chat widgets — and give them a key to their systems so the service can do its job. The danger: that key often opens far more than the job needs, and it works *without* the usual ID check at the door (no MFA — the extra "prove it's you" step — because software, not a person, is signing in). In the ConnectWise case, thieves stole the vendor's keys and walked into more than 2,250 customer organisations in minutes, in one place even promoting themselves to full administrator.

### What happened

The spray failed; the vendor app succeeded. On **15 October 2026**, Storm-0940 authenticated **as the ConnectWise applications themselves** (Cloud Backup, formerly SkyKick, plus Cloud Management) using **four stolen app credentials / client assertions** — no user sign-in and no MFA prompt, because tenants already trusted the apps. The actor attempted sign-ins to **more than 2,250 tenants, with over 200 sign-ins in under 4 minutes**; Huntress confirmed unauthorised sign-ins in **162 tenants** by the next day. In follow-on activity in some tenants: Graph reconnaissance, **adding app credentials for persistence** (surviving vendor cleanup), changing users/groups/privileged roles — **in one case the app gave itself Global Administrator** — and reading Azure Key Vault secrets; some intrusions went from initial targeting to privileged access in **under 3 hours**. Microsoft is careful about the boundary: attempted ≠ compromised, presence of an affected app does not necessarily mean data was accessed, and Microsoft has **not** confirmed exfiltration in this campaign (mechanics **Confirmed** by Microsoft/ConnectWise/Huntress; Storm-0940 attribution **Assessed** by Microsoft). The late-2025 precedent rhymes exactly: in the Salesloft Drift case, OAuth tokens a vendor held for customer integrations were used via Salesforce's Bulk API across **700+ organisations**, looking like legitimate vendor calls and bypassing MFA (chain **Confirmed** by GTIG/Mandiant).

### Why it worked (root cause)

- Multi-tenant vendor apps were consented with far more privilege than their function needed (directory write, role management).
- App-only (service-principal) authentication bypasses user MFA by design — a stolen app credential is a standing, MFA-free login.
- Tenants inventoried vendor apps by display name (spoofable) rather than application ID.
- Users could self-consent to multi-tenant apps without an admin-consent workflow.
- Service-principal sign-ins, credential additions and role assignments were not monitored — the persistence move (adding credentials to the app) was invisible.
- Vendor credential hygiene was taken on trust, with no rotation attestation.

### Vulnerable code

```text
# VULNERABLE — illustrative tenant state, the ConnectWise shape:
#   Vendor backup app consented with: Directory.ReadWrite.All,
#   RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All
#   User self-consent: ALLOWED for multi-tenant apps
#   Service-principal sign-in logs: not reviewed; credential-add events: no alert
#   → one stolen app credential = MFA-free access + self-granted Global Admin
```

### Why the fix works, in simple words

Each vendor gets keys only to the exact rooms their job needs — a backup service has no business holding the key to the manager's office. A named person reviews and approves every new vendor key, the company keeps a list keyed to the vendor's true ID (not just its name), and alarms ring the moment a vendor key is copied or used to touch staff roles — the exact moves the attackers made.

### The fix, step by step

1. Turn on an **admin-consent workflow**: no user self-consent for multi-tenant apps; every consent reviewed.
2. Inventory vendor apps by **application ID**, not display name; record owner, permissions, and business justification for each.
3. Strip permissions to least privilege: a backup app does not need directory write or role management. Deny `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` and equivalents unless proven necessary — and re-prove quarterly.
4. Alert on the incident's exact behaviours: service principal adding credentials, app-role assignment grants, members added to privileged roles by a service principal (KQL below).
5. Review service-principal sign-ins daily — successes and failures **separately** (a failure burst is probing; a success from a new geography is worse).
6. Require vendors to attest credential rotation, and rotate your own grants on any vendor incident; remember persistence: check for credentials added to apps *before* the incident window.
7. Segment the vendor/supply-chain plane from identity, admin networks and core ledgers (Mandiant layer framing), and preserve Entra/Purview/SIEM evidence before deleting apps.

### Fixed code

- Admin-consent workflow: no user self-consent for multi-tenant apps; review by **application ID**, not display name.
- Least privilege: a backup app does not need directory write or role management. Deny `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` etc. unless proven necessary.
- Alert on the exact behaviours from the incident (KQL, Microsoft Sentinel):

```kusto
// Service-principal credential added — persistence behaviour from the ConnectWise case
AuditLogs
| where OperationName in ("Add service principal credentials",
                          "Add app role assignment grant to user",
                          "Add member to role")
| where InitiatedBy has "servicePrincipal"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

Review service-principal sign-ins (success and failure separately) daily; require vendors to attest credential rotation.

**Second platform — the same hunt in Splunk SPL (for non-Sentinel estates):**

```spl
| ``` Splunk — service-principal persistence behaviours, Entra audit via add-on ```
index=azure_audit OperationName IN ("Add service principal credentials",
    "Add app role assignment grant to user", "Add member to role")
    InitiatedBy.appId=*
| stats count BY OperationName, InitiatedBy.appId, _time
| where count > 0
```

**Third platform — a scheduled Python audit of consented apps against a permission allow-list (Microsoft Graph):**

```python
# Python — nightly job: any service principal holding a denied permission, or
# not present in the reviewed inventory (keyed by appId), pages the on-call.
DENIED = {"RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All",
          "Directory.ReadWrite.All"}

def audit_service_principals(graph, reviewed_inventory: dict[str, set[str]]):
    findings = []
    for sp in graph.get("/servicePrincipals").json()["value"]:
        granted = {g["permission"] for g in graph.app_role_assignments(sp["id"])}
        if sp["appId"] not in reviewed_inventory:
            findings.append((sp["appId"], sp.get("displayName"), "UNREVIEWED APP"))
        elif granted & DENIED - reviewed_inventory[sp["appId"]]:
            findings.append((sp["appId"], sp.get("displayName"),
                             f"denied permissions held: {granted & DENIED}"))
    return findings   # non-empty → alert; displayName is shown but appId is the key
```

### How to test the fix

1. **Given** a test tenant, **when** a standard user attempts to consent to an unreviewed multi-tenant app, **then** the consent is blocked and routed to the admin-consent queue.
2. **Given** the KQL/SPL hunts running against a staging tenant, **when** a test service principal adds a credential to itself (the persistence move), **then** an alert fires within the detection window naming the appId and operation.
3. **Given** the nightly Python audit, **when** a fixture service principal is granted `RoleManagement.ReadWrite.Directory` outside the reviewed inventory, **then** the audit reports it as a finding; **and when** the grant is removed, **then** the next run is clean.
4. **Given** the vendor inventory, **when** it is exported, **then** every entry is keyed by application ID with an owner and a permission justification — an entry keyed only by display name fails the review check.
5. **Given** a simulated vendor incident, **when** the rotation runbook runs, **then** all app credentials are rotated *and* a query for credentials added during the incident window returns a reviewed, empty-after-action list (persistence check).

---

## §12 Liveness / KYC — server-side verdict is what held

### In simple words

Signing up or recovering an account sometimes asks you to prove you're a real, live person by looking into your phone camera. Attackers now hold up a fake, computer-generated face — a "deepfake" — or feed the fake video in through a pretend camera. It's like wearing a very good mask to fool the security guard at the door. In the AWS-recorded attempts the guard still said no every time, because the *guard* (the bank's server), not the visitor's own phone, made the final decision. In the MEXC case the fake face was accepted at the account-recovery desk — and while staff later changed the locks, they forgot a spare key (an API key, i.e. a password for software) that the attacker had made during the visit, and the money left through that key.

### What happened

AWS's MadPot Campaign 2 (3 Oct – 5 Nov 2026) targeted **2 cryptocurrency exchanges**. The operators reverse-engineered one vendor's liveness protocol (the face-detection event stream, position tracking, movement-prompt coordinates), built a real-time deepfake pipeline on **one consumer GPU at 11.5 fps**, and got their best attempt through the full movement sequence with the face **within 7 pixels** of the target — and the **server-side verdict rejected the deepfake in every recorded attempt**. In parallel they forged ID photos with synthetic camera metadata matching real JPEG dimensions and preserved original compression tables, and ran four parallel sessions (cash-out search, balance clearing, pipeline-building, bypass). Amazon **cannot verify** theft outcomes from these campaigns; the KYC record is one of *attempts that failed* (agent records **Confirmed** as captured; outcomes **not verified**). The contrast case is MEXC (victim-reported, Sept 2026): an AI face-swap "handheld" video was **accepted** by KYC review during an account-info change; the attacker changed email + phone and **created an API key with withdrawal permission**; MEXC froze the account and restored password/email/phone/2FA — **but missed the API key** — and 24 hours later, 27 minutes after the withdrawal cooldown expired, **~$340,000 was drained via that key** (figures victim-reported via TechFlow; **Alleged** in its particulars, not an exchange forensic report). Market context is confirmed reporting: MIT Technology Review found virtual-camera/hooking bypass kits and stolen biometrics on sale in 22 Telegram channels.

### Why it worked (root cause)

- In the failure case, the liveness/KYC review accepted a client-presented video at face value — the verdict effectively trusted what the attacker's device submitted.
- No (or weak) injection-attack detection: virtual cameras and hooking frameworks were not screened for.
- Account recovery was treated as *lower* risk than onboarding, when it is higher: it changes the very contacts and credentials that protect the account.
- API keys created during the recovery session were not inventoried or revoked when the account was restored — the spare key survived the lock change.
- KYC retries were not velocity-limited, letting agents iterate hundreds of attempts (in the AWS case, iteration still failed — because the verdict was server-side).

### Vulnerable code

```python
# VULNERABLE — illustrative. Trusts a client-side "passed" flag, and the
# recovery flow restores credentials but never audits keys made in-session.
def liveness_callback(session, client_says_passed: bool):
    if client_says_passed:                 # the mask grades itself
        session.kyc_verified = True

def restore_account(user):
    reset_password(user); restore_email(user); restore_phone(user); reset_2fa(user)
    # ...and every API key created during the takeover stays live. (MEXC)
```


### Why the fix works, in simple words

The decision "is this a live person?" is made on the bank's own computers, never trusted from the visitor's phone — a mask can't grade itself. The system also checks whether the "camera" is even a real camera, and account recovery is treated as *more* dangerous than sign-up, with every spare key made during a recovery visit listed and cancelled afterwards.

### The fix, step by step

1. Compute the liveness verdict **server-side**, from signed capture data; never accept a client-side "passed" flag.
2. Require device attestation (Play Integrity / App Attest) and reject sessions with virtual-camera or hooking-framework signals — the injection-attack indicators.
3. Verify the movement challenge against the challenge *you issued* for that session, and check depth/3D consistency so a flat replayed video fails.
4. Bind the document check to file forensics (camera metadata, JPEG compression tables) **and** authoritative document verification — the AWS attackers forged both metadata and compression tables, so either check alone is insufficient.
5. Velocity-limit KYC attempts per account, device and IP so an agent cannot iterate hundreds of times.
6. Treat **account recovery as higher-risk than onboarding**: step-up verification (§1c) before changing email/phone/credentials.
7. On any recovery or takeover response, **list and revoke every API key and session created during the recovery window** — close the MEXC gap explicitly in the runbook and in code.

### Fixed code

```python
# Server-side liveness decision — never trust a client-side "passed" flag
def verify_liveness(session) -> bool:
    frames = session.captured_frames               # signed by the capture SDK
    if session.device_attestation != "valid":      # Play Integrity / App Attest
        return False
    if session.virtual_camera_detected or session.hooking_framework_detected:
        return False                               # injection-attack signals
    challenge_ok = check_movement_challenge(frames, session.issued_challenge)
    depth_ok     = check_depth_consistency(frames) # not a flat replayed video
    return challenge_ok and depth_ok               # verdict computed HERE, server-side
```

Plus: bind the document check to file forensics (camera metadata, JPEG compression tables) **and** authoritative document verification; velocity-limit KYC retries so an agent cannot iterate hundreds of times; treat **account recovery as higher-risk than onboarding** — step-up verification, and **audit/revoke every API key created during a recovery session**.

**Java — the recovery-session key audit (the MEXC fix) as an explicit step:**

```java
// Java — restoring an account is not complete until every credential created
// during the recovery window has been revoked. Make it part of the same
// transaction/runbook, not a follow-up ticket.
public void restoreAccount(User user, Instant recoveryStartedAt) {
    resetPassword(user);
    restoreEmail(user);
    restorePhone(user);
    resetSecondFactor(user);

    // The step MEXC missed:
    List<ApiKey> keysCreatedDuringRecovery =
        apiKeys.findByUserAndCreatedAtAfter(user, recoveryStartedAt);
    keysCreatedDuringRecovery.forEach(k -> apiKeys.revoke(k.getId(), "account-recovery"));
    sessions.revokeAllFor(user);                    // see §9
    audit.log("recovery complete; revoked {} api keys", keysCreatedDuringRecovery.size());
}
```

**TypeScript / Node — the verdict endpoint shape (decision server-side, signals in, boolean out):**

```typescript
// TypeScript — the client uploads signed capture data; it never sends a verdict.
app.post("/kyc/liveness/verdict", async (req, res) => {
  const s = await kycSessions.get(req.body.sessionId);
  if (!s || s.userId !== req.user.id) return res.status(404).end();

  if (s.deviceAttestation !== "valid")            return res.json({ passed: false });
  if (s.virtualCameraDetected || s.hookingDetected) return res.json({ passed: false });
  if (!checkMovementChallenge(s.frames, s.issuedChallenge)) return res.json({ passed: false });
  if (!checkDepthConsistency(s.frames))           return res.json({ passed: false });

  await rateLimitKyc.assertWithinVelocity(s.userId, s.deviceId, req.ip);
  return res.json({ passed: true });   // computed here, from server-held evidence
});
```

**C# (.NET) — velocity limit on KYC retries:**

```csharp
// C# — an agent iterating hundreds of liveness attempts must hit a wall.
// Sliding-window counter per user+device, enforced before the verdict runs.
public async Task AssertKycVelocityAsync(string userId, string deviceId)
{
    var key = $"kyc:{userId}:{deviceId}";
    var attempts = await _cache.IncrementAsync(key);
    if (attempts == 1) await _cache.KeyExpireAsync(key, TimeSpan.FromHours(1));
    if (attempts > 5)   // 5 attempts per hour is generous for a human
        throw new TooManyRequestsException("KYC attempt limit reached");
}
```

### How to test the fix

1. **Given** a liveness session, **when** the client submits `passed: true` without signed capture frames, **then** the verdict endpoint ignores the flag and returns `passed: false`.
2. **Given** a test harness presenting a virtual-camera device (emulator/injection fixture), **when** a liveness attempt runs, **then** attestation/injection checks reject it before the movement challenge is evaluated.
3. **Given** a replayed recording of a *previous* session's movement sequence, **when** it is submitted against a new session with a different issued challenge, **then** the challenge check fails (the movements don't match this session's prompts).
4. **Given** a restored account (recovery drill in staging), **when** an API key created during the recovery window is used afterwards, **then** it is rejected as revoked, and the audit log lists it.
5. **Given** six KYC attempts for the same user+device within an hour, **when** the sixth is submitted, **then** it is refused with a rate-limit response before any verdict computation.

---

## §13 Detection — tune for machine speed, not human speed

### In simple words

These attackers don't move like people — they can go from knocking on the door to sitting in the manager's office in under three hours. Checking the security tapes once a day is like reviewing yesterday's film of a burglary that finished this morning. The fix is alarms that watch for *impossibly fast* behaviour — thousands of failed logins in minutes, one visitor reading records one-after-another like a barcode scanner — and that can lock a door automatically instead of waiting for a person to notice.

### What happened

The timelines are the finding. Microsoft reports some Storm-0940 intrusions going from **initial targeting to privileged access in under 3 hours**, and the FBI's FLASH-20261113-001 repeats the figure — while the spray phase alone generated **151,000+ failed logons** that had to be visible in someone's logs. Chainstack took **five days** to detect (26 → 31 Oct 2026) an intrusion that began with a default-password login. GTIG documented the volumetric signature from the other side: directory fuzzing of 500+ requests, bursts of 2–25 seconds, **27 events in 23 seconds** in one case, and command output staged to **491 rotating webhook endpoints**. ARTEX also leaves softer fingerprints: distinctive user-agent strings (`artex-enrich`, `artex-pentest`, `artex-audit`, `artex-verify`, `ARTEX-worker`, `norma/0.4` — a supporting indicator only, easily changed), placeholder probes (`/zzz-nonexistent-…`) immediately before fuzz bursts, and — for corporate networks — **unexpected egress to public LLM APIs** from servers that should never call them, plus token-spend/billing anomalies. Every primary source converges on the same conclusion: response latency is now the constraint, and daily log review misses a sub-3-hour intrusion entirely.

### Why it worked (root cause)

- Detection content tuned for human-speed patterns (a handful of failed logins, business-hours review).
- Logs reviewed on a daily cycle while intrusions complete in under 3 hours.
- No alerting on the specific burst shapes: spray (many accounts, one source), sequential object access, placeholder-probe → fuzz-burst.
- Egress to LLM APIs and token-spend not monitored, so agent infrastructure ran unnoticed.
- Containment manual and slow — even a fired alert waited for a human to act.

### Vulnerable code

```text
# VULNERABLE — illustrative detection posture:
#   - auth logs shipped to a dashboard a person reads each morning
#   - alert rule: "more than 10 failed logins for one user in a day"
#   - no egress monitoring; no automated response
# A 2,900-attempts-per-minute spray finishes before the dashboard is opened.
```


### Why the fix works, in simple words

Machines leave machine-shaped footprints: bursts in seconds, thousands of tries, perfectly sequential reading. Alarms tuned to those shapes fire in minutes, while the attack is still happening, and automatic responses (lock the account, kill the session) shrink the attacker's head start from hours to minutes.

### The fix, step by step

1. Alert on **burst shapes in short windows** (5–15 minutes), not daily totals: many distinct accounts + one source + high failure count (spray); sequential object IDs per session (§4); placeholder-probe followed by a fuzz burst.
2. Add the ARTEX user-agent hunt as a **supporting** indicator — never the only one; user agents are trivially changed.
3. Alert on unexpected egress to public LLM API endpoints from servers, and on LLM token-spend/billing anomalies.
4. Review service-principal sign-ins (§11) and vault reads (§7) as streaming alerts, not reports.
5. **Automate containment**: on a high-confidence spray or burst alert, lock the targeted accounts, revoke sessions (§9), and block the source — then page a human. Response latency is the constraint.
6. Measure yourself: run tabletop/game-day replays of the Storm-0940 and Chainstack timelines and record time-to-detect and time-to-contain.

### Fixed code

```spl
| ``` Splunk — password-spray pattern: many accounts, one source, high failure rate ```
index=auth action=failure earliest=-15m
| stats dc(user) AS distinct_users, count AS failures BY src_ip
| where distinct_users > 20 AND failures > 200
```

```kusto
// KQL — ARTEX user agents (supporting indicator only; easily changed)
W3CIISLog
| where csUserAgent has_any ("artex-enrich", "artex-pentest", "artex-audit",
                             "artex-verify", "ARTEX-worker", "norma/0.4")
| summarize count() by csUserAgent, cIP, bin(TimeGenerated, 5m)
```

Also alert on: unexpected egress to public LLM APIs from servers that should never call them, token-spend/billing anomalies, and the placeholder-probe → fuzz-burst pattern (`/zzz-nonexistent-…` followed by hundreds of requests in seconds). Automate containment — response latency is now the constraint.

**Second platform — the spray hunt in Elastic (EQL/KQL-style, for Elastic estates):**

```text
# Elastic — same spray shape, 15-minute window, authentication logs
sequence by source.ip with maxspan=15m
  [authentication where event.outcome == "failure"] by user.name
| stats distinct_users = count_distinct(user.name), failures = count()
  by source.ip
| filter distinct_users > 20 and failures > 200
```

**Automated containment — Python responder wired to the spray alert:**

```python
# Python — when the spray hunt fires at high confidence, act first, page second:
# lock targeted accounts, revoke their sessions, block the source at the edge.
def on_spray_alert(alert):
    src_ip, users = alert["src_ip"], alert["distinct_users_list"]
    waf.block_ip(src_ip, ttl_minutes=60)                 # stop the burst now
    for username in users:
        accounts.lock(username, reason="spray-target")   # §1 lockout, forced
        sessions.revoke_all_for(username)                # §9 server-side kill
    pager.page_oncall(f"Spray contained: {len(users)} accounts locked, "
                      f"source {src_ip} blocked — review and unlock via runbook")
    audit.log("spray containment executed", alert_id=alert["id"])
```

### How to test the fix

1. **Given** the §1 spray replay fixture (25 accounts × 10 failures, one source, 15 minutes) run against staging logs, **when** the Splunk/KQL hunt runs, **then** exactly one alert fires and the containment responder locks the fixture accounts and blocks the fixture IP.
2. **Given** a single user mistyping their password 5 times, **when** the hunt runs, **then** no alert fires (distinct_users threshold not met) — the control distinguishes a spray from a forgetful human.
3. **Given** a request sequence containing `/zzz-nonexistent-test123` followed by 300 path probes in 30 seconds from one client, **when** the probe→burst rule evaluates, **then** an event is raised naming the client and the burst size.
4. **Given** a staging server with no LLM business need, **when** a test process makes an HTTPS request to a public LLM API endpoint, **then** the egress alert fires with the server identity and destination.
5. **Given** the Chainstack timeline replayed as log fixtures (default-cred login → internal pivot → DB network), **when** the detection suite runs end-to-end, **then** time-to-detect is measured and is under 15 minutes — versus the five days in the real incident.

---

## §14 Headers and errors — stop leaking the map

### In simple words

When something goes wrong, many websites helpfully explain exactly what went wrong — which file, which database table, which line of code. To an attacker (especially a tireless automated one) that's a free map of the building. Error messages should be like a polite front desk: "Something went wrong — your reference number is 12345," with the details written down privately for staff. Security headers are the standard safety notices your site hands to visitors' browsers — "only load content from us," "never show this page inside someone else's frame" — which browsers then enforce automatically.

### What happened

This block rests on the report's demo and mitigation evidence rather than a single named breach. ARTEX's demo engagements profited from exactly this leakage: the "Acme" demo's database access began with **error-based SQL injection in a search parameter** — the application's own error responses told the agent what it needed to extract data (§2). The report's wider findings list includes "**detailed errors/stack traces returned to unauthenticated users**," with the FBI's mitigation guidance implying agents use them as recon material. The mechanism is scale: a human skims an error page; an agent parses every stack trace, framework version, file path and table name across thousands of responses and feeds them straight back into its attack plan. Missing headers compound it — no HSTS means downgrade paths stay open, no CSP/`frame-ancestors` means the login page can be framed for clickjacking, and a verbose server banner advertises the exact stack to match against known CVEs (the report documents ARTEX exploiting known CVEs such as CVE-2025-3248 Langflow and CVE-2026-28797 RAGFlow).

### Why it worked (root cause)

- Framework debug modes and default error handlers left enabled in production.
- Database and framework exceptions propagated to the client body.
- No central error-handling layer mapping exceptions to generic responses with correlation IDs.
- Security headers never configured (or configured on the app but stripped at a proxy).
- Server/version banners (`server_tokens`, `X-Powered-By`) advertising the stack.

### Vulnerable code

```python
# VULNERABLE — illustrative. The exception IS the response.
@app.get("/search")
def search(q: str):
    try:
        return run_query(q)
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}, 500
# → "relation \"loan_applications\" does not exist… File \"/srv/app/queries.py\", line 42"
#   is a free schema + filesystem map for the next injection attempt.
```


### Why the fix works, in simple words

Attackers plan with whatever you show them. Generic errors show them nothing to plan with, while your own team keeps the full details in private logs. Headers close whole side doors (clickjacking, content sniffing, forced downgrade to unencrypted connections) with a few lines that every browser already knows how to obey.

### The fix, step by step

1. Add the standard security headers at the edge **and** verify they survive to the client (check the final response, not just the config).
2. Turn off version banners (`server_tokens off`, remove `X-Powered-By`).
3. Install one central error handler: clients get a generic message + a correlation/reference ID; the full stack trace goes to server-side logs keyed by that ID.
4. Disable framework debug modes in production builds and gate the change in the deployment pipeline.
5. Apply the same generic-error rule to API responses, including validation errors — no table names, no SQLSTATE, no file paths (§2's error-based injection depends on this).

### Fixed code

```nginx
# nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'" always;
server_tokens off;
```

Return generic errors to unauthenticated users (`"Something went wrong — reference #12345"`), log the stack trace server-side only. Detailed errors are recon material for an agent that reads them at machine speed.

**Second platform — Apache httpd:**

```apache
# Apache — same header set + banner suppression
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "no-referrer"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
ServerTokens Prod
ServerSignature Off
TraceEnable off
```

**Third platform — IIS (web.config):**

```xml
<!-- IIS — headers via outbound rules / httpProtocol, banner removal -->
<configuration>
  <system.webServer>
    <security><requestFiltering removeServerHeader="true" /></security>
    <httpProtocol>
      <customHeaders>
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="Referrer-Policy" value="no-referrer" />
        <add name="Content-Security-Policy" value="default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'" />
        <remove name="X-Powered-By" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

**Application layer — TypeScript / Express (helmet) and the generic error handler:**

```typescript
// TypeScript — helmet sets the same headers in-app (defence in depth behind
// the edge), and the error middleware is the ONLY place errors leave the app.
import helmet from "helmet";
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: "no-referrer" },
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"],
    objectSrc: ["'none'"], frameAncestors: ["'none'"] } },
}));

app.use((err, req, res, next) => {
  const ref = randomUUID();
  logger.error({ ref, err });                       // full trace: server-side only
  res.status(500).json({ error: `Something went wrong — reference #${ref}` });
});
```

**Application layer — Java / Spring Security headers:**

```java
// Java — Spring Security's header writer, same policy in framework config.
http.headers(headers -> headers
    .httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true))
    .contentTypeOptions(Customizer.withDefaults())                    // nosniff
    .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
    .frameOptions(frame -> frame.deny())
    .contentSecurityPolicy(csp -> csp.policyDirectives(
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'")));
```

### How to test the fix

1. **Given** any page on the staging site, **when** its response headers are inspected, **then** HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy` and the CSP are all present, and neither `Server` nor `X-Powered-By` reveals a version.
2. **Given** an endpoint forced to throw (bad ID format, DB down fixture), **when** the error response is inspected, **then** it contains only the generic message and a reference ID — no stack frames, file paths, table names or SQLSTATE strings (assert by regex blocklist).
3. **Given** the reference ID from a client-visible error, **when** support searches the server logs, **then** the full stack trace is found under that ID — proving detail is kept, just moved.
4. **Given** the login page, **when** a test page attempts to frame it from another origin, **then** the browser blocks framing (`frame-ancestors 'none'` / `X-Frame-Options`) — verified via a headless-browser test.
5. **Given** the error-based SQLi payload from §2, **when** it is submitted, **then** the response is the generic error body, identical in shape to any other 500 — the extraction channel is closed.

---

## Fix-first priority order

1. **MFA + rate limiting on every login** (incl. peripheral/partner/employee systems — that is where the Korean banks were hit).
2. **Rotate and vault every secret; scan repos, JS bundles and pipelines** (§7).
3. **Inventory the external surface; kill default credentials and exposed admin/debug** (§8).
4. **Parameterised queries + least-privilege DB accounts** (§2).
5. **Payment-API state machine + maker-checker + ceilings** (§10).
6. **Vendor-app consent review + service-principal monitoring** (§11).
7. **IMDSv2, SSRF allow-listing, XXE off** (§5).
8. **Server-side liveness verdict + recovery-session API-key audit** (§12).
9. **Burst-tuned detection + automated containment** (§13).

*Prepared 19 Nov 2026 as the expanded companion to the ARTEX report and the condensed solutions guide. Code is illustrative reference code in Python, Java, TypeScript/Node, C# (.NET), Go, PHP, Ruby, nginx, Apache, IIS, Terraform, KQL and Splunk SPL — adapt to your stack and test in staging before production use.*
