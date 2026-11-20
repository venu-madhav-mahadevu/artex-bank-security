#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# check-code.sh — quick local scan of YOUR codebase for the weakness classes
# ARTEX exploits. Runs entirely on your machine; nothing is uploaded anywhere.
#
# Usage:   bash check-code.sh [path]     (defaults to current directory)
# Needs:   grep (built in). Uses ripgrep (rg) automatically if installed.
#
# This is a pattern search, not a full scanner — it flags things to REVIEW,
# and some issues (IDOR, payment logic, OAuth scopes, liveness) need manual
# checks it cannot see. Treat every hit as "look at this", not "confirmed bug".
# ---------------------------------------------------------------------------
set -u
ROOT="${1:-.}"
EXCL='--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=dist --exclude-dir=build --exclude-dir=.venv'
HITS=0

BINEXCL="-g !.git -g !node_modules -g !vendor -g !dist -g !build -g !*.pdf -g !*.png -g !*.jpg -g !*.jpeg -g !*.gif -g !*.svg -g !*.ico -g !*.woff -g !*.woff2 -g !*.min.js -g !*.min.css -g !*.map -g !*.lock"
GREPEXCL="$EXCL --exclude=*.pdf --exclude=*.png --exclude=*.jpg --exclude=*.jpeg --exclude=*.gif --exclude=*.svg --exclude=*.ico --exclude=*.woff --exclude=*.woff2 --exclude=*.min.js --exclude=*.min.css --exclude=*.map --exclude=*.lock"
if command -v rg >/dev/null 2>&1; then
  SEARCH() { rg -n --no-heading $BINEXCL -e "$1" "$ROOT" 2>/dev/null; }
else
  # -I skips binary files
  SEARCH() { grep -rIEn $GREPEXCL -e "$1" "$ROOT" 2>/dev/null; }
fi

section () {
  local title="$1"; local pattern="$2"
  echo ""
  echo "=== $title ==="
  local out; out="$(SEARCH "$pattern")"
  if [ -n "$out" ]; then
    echo "$out" | head -n 40
    local n; n="$(printf '%s\n' "$out" | grep -c .)"
    HITS=$((HITS + n))
    echo "   -> $n line(s) to review"
  else
    echo "   (no obvious matches)"
  fi
}

echo "ARTEX code check — scanning: $ROOT"

section "SQL injection (A2) — string-built queries" \
  'execute\(.*\+|executeQuery\(.*\+|query\(.*\+|f"SELECT|f'"'"'SELECT|String\.format\(.*(SELECT|INSERT|UPDATE|DELETE)|"(SELECT|INSERT|UPDATE|DELETE).*"\s*\+'

section "Hardcoded secrets (A7) — keys/passwords in code" \
  '(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*["'"'"'][^"'"'"']{6,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{30}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE) '

section "SSRF (A5) — fetches that may use user input" \
  'requests\.(get|post)\(|urlopen\(|axios\.(get|post|request)\(|fetch\(|HttpClient|WebClient|URLConnection|file_get_contents\('

section "XXE (A5) — XML parsers to harden" \
  'DocumentBuilderFactory|SAXParserFactory|XMLReader|etree\.parse|lxml|libxml|SimpleXML|XmlReader'

section "Command injection — shell from code" \
  'os\.system\(|subprocess\.[A-Za-z]+\(.*shell\s*=\s*True|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\(|popen\('

section "Unsafe eval / deserialization" \
  '\beval\(|pickle\.loads|yaml\.load\((?!.*Loader)|ObjectInputStream|Marshal\.load|unserialize\('

section "Weak session / cookie flags (A8)" \
  'httpOnly\s*[:=]\s*false|secure\s*[:=]\s*false|sameSite\s*[:=]\s*[\x27"]?none|set_cookie|SESSION_COOKIE_SECURE\s*=\s*False'

section "Exposed admin / debug (A8)" \
  'DEBUG\s*=\s*True|app\.debug\s*=\s*True|/debug|/actuator|/console|NODE_ENV.*development'

section "File upload handling (A6) — review validation" \
  'multer|MultipartFile|request\.files|FileUpload|move_uploaded_file|save\(.*filename|originalname'

section "Trusting client for auth (A3) — headers/flags" \
  'headers\[["'"'"']?(x-)?(user|role|admin|is[_-]?admin)|req\.(user|role)\s*=\s*req\.(headers|query|body)|isAdmin\s*=\s*(req|request)'

echo ""
echo "============================================================"
echo "Done. Total lines to review: $HITS"
echo ""
echo "Each hit is a place to CHECK, not a confirmed bug. Compare against the"
echo "safe patterns on your Check-your-code page, and remember these need"
echo "MANUAL testing (no grep finds them):"
echo "  - IDOR (A4):           does every record fetch check ownership? -> 404 if not yours"
echo "  - Payment API (A9):    can a disbursal run while skipping KYC/limit checks?"
echo "  - OAuth scopes (A10):  are third-party app consents least-privilege?"
echo "  - Liveness (A11):      is the pass/fail decided server-side, not by the client?"
echo "  - Rate limit/MFA (A1): do rapid logins get locked out? is MFA enforced?"
echo "  - Detection (A12):     do your monitors alert on bursts and enumeration?"
echo "============================================================"
