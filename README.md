# ARTEX Bank Security — Attack Report & Code-Level Solutions

How AI-agent penetration-testing framework **ARTEX** (Agentic Reconnaissance and Target Exploitation eXtension) was used against banks and major services in Oct–Nov 2026 — and the **code-level fixes** that stop each attack.

> **Headline finding:** No source reports a zero-day in any ARTEX attack. ARTEX chained *known, preventable* weaknesses — default/weak credentials, no rate limit / no MFA, SQL injection, missing API authentication, exposed admin/debug pages, secrets in code/JS/repos, over-privileged vendor OAuth apps — at machine speed, in parallel, with little human supervision.

## Contents

### 📄 [Report — ARTEX-Attack-Report.md](report/ARTEX-Attack-Report.md) ([PDF](report/ARTEX-Attack-Report.pdf))
Sourced research report (16–17 Nov 2026) covering:
- What ARTEX is: origin, architecture (planner/worker agents), LLM models, how an operator runs it
- All documented attack methods: recon, password spraying, vulnerability chaining, supply-chain abuse, API-key harvesting, deepfake liveness attempts, exfiltration, post-access operations
- Documented incidents, step by step: Storm-0940 → ConnectWise (2,250+ M365 tenants), South Korean banks (KFSI findings), AWS MadPot honeypot campaigns, CERT-In payment-API abuse (CIAD-2026-0046/0058), FBI flash alert FLASH-20261113-001
- Confirmed vs. assessed vs. alleged kept separate throughout

### 📘 [Detailed Fix Guide — ARTEX-Detailed-Fix-Guide.md](solutions/ARTEX-Detailed-Fix-Guide.md)
The full, easy-to-understand version. Every attack block explained **in simple words** (with a real-life analogy), what happened, why it worked, vulnerable code, why the fix works, step-by-step fix, **fixed code in all major languages** (Python, Java, TypeScript/Node, C#, Go, PHP, Ruby + configs), and how to test each fix.

### 🛡️ [Solutions — ARTEX-Solutions-Code-Examples.md](solutions/ARTEX-Solutions-Code-Examples.md) ([PDF](solutions/ARTEX-Solutions-Code-Examples.pdf))
Defensive companion: every attack mapped to a fix **with code examples** (Python, Java, TypeScript, nginx, Terraform, KQL, Splunk SPL):
1. Rate limiting + breached-password screening + WebAuthn step-up
2. Parameterised queries (SQL injection)
3. Strict SAML signature validation
4. Object-level authorisation (IDOR)
5. SSRF allow-listing, IMDSv2, XXE hardening
6. Safe file-upload handling
7. Secrets management — vault, short-lived credentials, CI scanning
8. Admin/debug surface removal, session hardening
9. Payment-API state machine + maker-checker (CERT-In pattern)
10. Vendor OAuth least privilege + service-principal monitoring
11. Server-side liveness verdict (deepfake defence)
12. Machine-speed detection queries + fix-first priority order

## Sources
FBI FLASH-20261113-001 · Microsoft Security (Storm-0940) · AWS Security Blog (MadPot) · CrowdStrike · Google GTIG / Mandiant · Korea Financial Security Institute · CERT-In CIAD-2026-0046 / 0058 · Datadog · Censys

## Disclaimer
Defensive security research compiled from public sources for education and defence. Confidence labels in the report (Confirmed / Assessed / Alleged) reflect the underlying sources. No testing was performed against any live system.
