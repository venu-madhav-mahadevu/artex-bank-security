# Secure Starter — a baseline that resists the 12 ARTEX attacks

Reference implementations of the **safe** control for each ARTEX weakness class.
Use these patterns as the baseline for new services, and check existing code against them.

> These are teaching snippets, not a drop-in framework. Copy the *pattern*, adapt it to
> your stack, and keep the guarantee each one makes.

## Map: attack → control → file

| # | Attack | Safe control | File |
|---|--------|--------------|------|
| A1 | No rate limit / no MFA | throttle + required MFA + step-up | `src/auth.js` |
| A2 | SQL injection | parameterized queries only | `src/db.js` |
| A3 | Auth / SAML bypass | role from server session, not headers | `src/auth.js` |
| A4 | IDOR | ownership check after lookup | `src/objects.js` |
| A5 | SSRF | host allow-list + block internal + IMDSv2 | `src/fetch.js` |
| A5 | XXE | DTDs / external entities disabled | `src/xml.js` |
| A6 | File upload → web shell | magic-byte + size check, random name, outside web root | `src/upload.js` |
| A7 | Secrets in code | from env/vault, never hardcoded | `src/config.js`, `.env.example` |
| A8 | Exposed admin/debug & weak sessions | debug off, hardened cookies | `src/config.js` |
| A9 | Payment API abuse | state machine + maker-checker + ceilings | `src/payments.js` |
| A10 | Over-privileged OAuth apps | least scope, alerting (IdP config) | `ops/oauth-and-detection.md` |
| A11 | Deepfake / liveness bypass | server-side verdict, never a client flag | `src/liveness.js` |
| A12 | No machine-speed detection | real-time alerts + auto-containment (ops) | `ops/oauth-and-detection.md` |

## Verify it yourself (locally — never upload code)

    bash ../check-code.sh .
    gitleaks detect --source .
    semgrep --config auto .

**How to read the scanner output here:** the grep scan flags *surfaces* for review, not
verdicts. It will surface the `fetch(...)` in `fetch.js`, the `disburse/transfer` in
`payments.js`, and the login route in `auth.js` — those are the risky areas, and in this
repo each one is implemented with its safe control (open the file to confirm). It should
find **no hardcoded secrets, no string-concatenated SQL, and no weak cookie flags**, which
are the things a scanner can actually judge.

See `SECURITY-CHECKLIST.md` for the fix-first order.
