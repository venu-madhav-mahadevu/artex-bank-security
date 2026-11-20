# Secure baseline — checklist (fix-first order)

Do these in order; the top ones block the most damage for the least effort.

1. MFA + rate limiting on **every** login (employee, partner and peripheral systems too).
2. Rotate and vault **every** secret; scan repos, JS bundles and CI for leaks.
3. Inventory the external surface; remove exposed admin/debug; change all default credentials.
4. Parameterized queries everywhere + least-privilege DB accounts.
5. Payment-API state machine + maker-checker + ceilings.
6. Review vendor OAuth app consents & scopes; alert on new app credentials.
7. SSRF allow-listing + IMDSv2; disable XXE.
8. Server-side liveness verdict; audit recovery/session API keys.
9. Burst-tuned, real-time detection + automated containment.

Verify with the scanner (run locally, never upload code):

    bash ../check-code.sh .
    gitleaks detect --source .
    semgrep --config auto .
