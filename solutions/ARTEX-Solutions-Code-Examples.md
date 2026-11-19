# ARTEX Bank Attacks — Solutions with Code Examples

*Companion to the ARTEX report delivered 16–17 Nov 2026. Defensive guidance only: every example below is a fix pattern for your own applications. Note: no ARTEX run was performed against BofA CashPro or any live site — the earlier findings table was an example from ARTEX's public demo against a test website. These solutions map to the attack methods documented in the report (FBI FLASH-20261113-001, Microsoft, AWS, CERT-In CIAD-2026-0046/0058, KFSI).*

## The one-line lesson from every incident

ARTEX used **no zero-days**. It chained known, preventable weaknesses at machine speed. Every solution below closes one of those weaknesses.

## Attack → Fix map

| # | Attack / finding (from the report) | Fix | Section |
|---|---|---|---|
| 1 | Password spraying / credential stuffing (151,000+ failed logons, peak 2,900/min) | Rate limiting + breached-password screening + MFA | §1 |
| 2 | SQL injection in search parameters (Korean banks' entry point) | Parameterised queries everywhere | §2 |
| 3 | Unsigned SAML assertions accepted; auth bypass | Strict SAML signature validation | §3 |
| 4 | IDOR / authorisation bypass on APIs | Object-level authorisation on every request | §4 |
| 5 | SSRF / XXE → cloud metadata (IMDS) theft | URL allow-listing, IMDSv2, XXE disabled | §5 |
| 6 | Anonymous file upload → web shell | Upload validation + no-execute storage | §6 |
| 7 | API keys / secrets in JS bundles, .env, repos (Key Vault emptied in 5 min) | Vault + short-lived credentials + scanning | §7 |
| 8 | Exposed admin / debug pages, default credentials | SSO-gate or remove; deny rules | §8 |
| 9 | Weak session tokens | Secure session configuration | §9 |
| 10 | Payment-API abuse (disbursal without KYC/limits — CERT-In) | Stage-bound state machine + maker-checker | §10 |
| 11 | Over-privileged vendor OAuth apps (ConnectWise, Drift) | Least-privilege consent + sign-in monitoring | §11 |
| 12 | Deepfake liveness attempts (rejected server-side — the control that held) | Server-side verdict + injection detection | §12 |
| 13 | Slow detection (intrusions reached privilege in <3 hours) | Detection queries tuned for machine-speed bursts | §13 |
| 14 | Missing security headers / verbose errors | Headers + generic error responses | §14 |

---

## §1 Login attacks — rate limiting, breached passwords, MFA

### 1a. Rate limit per account + per IP + per device (Python / Redis)

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

### 1b. Screen new passwords against breached-password lists (k-anonymity)

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

### 1c. Phishing-resistant MFA for high-risk actions (WebAuthn step-up)

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

---

## §2 SQL injection — parameterised queries, always

The Korean bank breaches entered through SQL injection in peripheral systems (loan-agent, employee, sales-support apps). The fix is mechanical:

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

Plus defence in depth: the web app's DB account should be **least-privilege** (no file-write, no OS-command functions — ARTEX chains SQLi into web shells via DB file writes), and WAF rules are a safety net, never the primary fix.

---

## §3 SAML / SSO — reject unsigned or badly-signed assertions

VAPOR PANDA entered one victim with an **unsigned SAML assertion**. Your SP must verify, in this order, and reject on any failure:

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

Also rotate signing keys on any suspected export, and never accept assertions over plain HTTP.

---

## §4 IDOR — check ownership on every object access

```python
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user = Depends(current_user)):
    order = db.get_order(order_id)
    if order is None or order.customer_id != user.customer_id:
        raise HTTPException(404)   # 404, not 403 — don't confirm the object exists
    return order
```

Rule: **the authorisation check lives in the handler, on every request** — never rely on "the UI doesn't show that button" or on unguessable IDs alone.

---

## §5 SSRF and XXE — the road to cloud credentials

### 5a. SSRF: allow-list outbound URLs, block metadata ranges

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

### 5b. Require IMDSv2 on every EC2 instance (Terraform)

```hcl
resource "aws_instance" "app" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 only — kills SSRF token theft
    http_put_response_hop_limit = 1
  }
}
```

### 5c. XXE: disable DTDs in every XML parser

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

---

## §6 File upload — never let an upload become code

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

---

## §7 Secrets — the 5-minute Key Vault lesson

Microsoft documented an agent going from a GitHub search to **Azure Key Vault exfiltration in 5 minutes**. Rules:

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

---

## §8 Admin / debug surface — remove it or put it behind SSO

Chainstack fell through an internet-exposed test Grafana with **default admin credentials**. The demo findings start with a hidden admin page.

```nginx
# nginx — admin/debug paths: internal network or SSO only, never public
location ~ ^/(admin|debug|actuator|console|grafana) {
    allow 10.0.0.0/8;          # corporate / VPN range
    deny  all;
    # plus SSO auth_request in front — see your IdP module
}
```

Checklist: inventory **every** internet-facing app including peripheral ones (partner portals, employee tools, test instances); change every default credential before first deploy; disable debug endpoints in production builds; continuous external attack-surface scanning.

---

## §9 Sessions — strong tokens, safe cookies

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

---

## §10 Payment APIs — bind the stages so they can't be skipped (CERT-In pattern)

The CERT-In attacks invoked disbursal APIs directly, stepping around loan creation, KYC, sanction, beneficiary and limit checks that lived only in the application layer. Fix: **enforce the sequence in the API itself**, as a state machine.

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

---

## §11 Vendor / OAuth apps — least privilege + watch the service principals

Storm-0940 succeeded through **trusted vendor apps**: app-only sign-in bypasses user MFA, and in one tenant the app gave itself Global Administrator. Controls:

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

---

## §12 Liveness / KYC — server-side verdict is what held

In the AWS MadPot record, deepfake attempts were **rejected every time** because the verdict was server-side. The MEXC loss happened where review accepted a face-swap and a withdrawal API key created during recovery was missed.

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

---

## §13 Detection — tune for machine speed, not human speed

Intrusions reached privileged access in **under 3 hours**; daily log review misses that. Two starter hunts:

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

---

## §14 Headers and errors — stop leaking the map

```nginx
# nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'" always;
server_tokens off;
```

Return generic errors to unauthenticated users (`"Something went wrong — reference #12345"`), log the stack trace server-side only. Detailed errors are recon material for an agent that reads them at machine speed.

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

*Prepared 19 Nov 2026 as a companion to the ARTEX report. Code is illustrative reference code in Python/Java/TypeScript/nginx/KQL/Splunk SPL — adapt to your stack and test in staging before production use.*
