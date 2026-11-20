# Controls that live in config/ops, not in code

## A10 — Over-privileged OAuth / vendor apps
These are enforced in your identity provider (Entra ID / Okta / Google Workspace), not the codebase.
- Grant each app the **least scope** it needs; never "Global Admin" or tenant-wide read.
- **Alert** on any new app credential, client secret, or admin consent.
- Review consented third-party apps on a schedule; revoke anything unused.
- Monitor service-principal / workload-identity sign-ins for anomalies.

## A12 — Machine-speed detection & response
ARTEX attacks run in parallel at machine speed, so daily log review is too slow.
- **Real-time alerts** on: login bursts, sequential ID enumeration, new app credentials,
  sub-second permission probing, impossible-travel sign-ins.
- **Automated containment**: auto-disable a credential or session on a high-confidence hit.
- Tune thresholds for burst velocity, not just totals.
