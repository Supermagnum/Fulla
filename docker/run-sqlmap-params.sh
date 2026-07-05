#!/usr/bin/env bash
# sqlmap each GET /keys filter parameter individually (empirical SQLi check).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${FULLA_BASE_URL:-http://127.0.0.1:8080}/keys"
OUT="${SCANNER_LOG_DIR:-$ROOT/docker/scanner-output}/sqlmap-clean"
mkdir -p "$OUT"

if ! command -v sqlmap >/dev/null 2>&1; then
  echo "sqlmap not found (pip install sqlmap or use parrotsec/sqlmap container)" >&2
  exit 1
fi

run_one() {
  local param="$1" value="$2"
  local url="${BASE}?${param}=${value}"
  local file="$OUT/${param}.txt"
  echo "=== sqlmap param=${param} url=${url} ===" | tee "$file"
  sqlmap -u "$url" --batch --level=1 --risk=1 --timeout=10 --retries=1 \
    --threads=1 --flush-session --technique=BEUSTQ 2>&1 | tee -a "$file"
  echo "exit: $?" | tee -a "$file"
}

run_one email "test@example.com"
run_one fingerprint "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
run_one callsign "TEST"
run_one dmr_id "12345"
run_one discord_id "test123"
run_one irc_id "testnick"
run_one fluxer_id "fluxer1"
run_one first_name "Test"
run_one last_name "User"

echo "sqlmap per-parameter scans written to $OUT"
