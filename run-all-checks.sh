#!/usr/bin/env bash
# run-all-checks.sh — run every local ARTEX safety check against a project.
# Usage:  bash run-all-checks.sh [path-to-your-project]   (defaults to current dir)
# Runs 100% locally. Your code is never uploaded anywhere.

set -uo pipefail
TARGET="${1:-.}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$TARGET" ]; then echo "Not a directory: $TARGET"; exit 1; fi

line(){ printf '\n============================================================\n'; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo "ARTEX full local check"
echo "Target : $(cd "$TARGET" && pwd)"
echo "Note   : everything runs on this machine; nothing is uploaded."

MISSING=()

# 1) Pattern scan (always available — ships with this repo)
line; echo ">> 1/4  Pattern scan (check-code.sh)"; line
if [ -f "$HERE/check-code.sh" ]; then
  bash "$HERE/check-code.sh" "$TARGET"
else
  echo "check-code.sh not found next to this script — run from the cloned repo."
fi

# 2) Secret scan
line; echo ">> 2/4  Secret scan (gitleaks)"; line
if have gitleaks; then
  gitleaks detect --source "$TARGET" --no-banner || true
else
  echo "gitleaks not installed. Install: https://github.com/gitleaks/gitleaks"; MISSING+=("gitleaks")
fi

# 3) Code vulnerability scan
line; echo ">> 3/4  Code scan (semgrep)"; line
if have semgrep; then
  semgrep --config auto --error "$TARGET" || true
else
  echo "semgrep not installed. Install: pip install semgrep  (or: brew install semgrep)"; MISSING+=("semgrep")
fi

# 4) Dependency scan (auto-detect ecosystem)
line; echo ">> 4/4  Dependency scan"; line
if [ -f "$TARGET/package.json" ]; then
  if have npm; then ( cd "$TARGET" && npm audit ) || true; else echo "npm not found."; fi
fi
if ls "$TARGET"/requirements*.txt "$TARGET"/pyproject.toml >/dev/null 2>&1; then
  if have pip-audit; then pip-audit -r "$TARGET"/requirements*.txt 2>/dev/null || ( cd "$TARGET" && pip-audit ) || true
  else echo "pip-audit not installed. Install: pip install pip-audit"; MISSING+=("pip-audit"); fi
fi
if [ ! -f "$TARGET/package.json" ] && ! ls "$TARGET"/requirements*.txt "$TARGET"/pyproject.toml >/dev/null 2>&1; then
  echo "No package.json / requirements.txt / pyproject.toml found — skipping dependency scan."
fi

line
echo "DONE. This is a first-pass filter, not proof of safety."
echo "Still TEST BY HAND (no scanner finds these):"
echo "  IDOR, payment limits, OAuth scopes, liveness verdict, burst detection."
if [ "${#MISSING[@]}" -gt 0 ]; then
  echo
  echo "Optional tools not installed: ${MISSING[*]}"
  echo "The pattern scan still ran; installing the above makes the check deeper."
fi
line
