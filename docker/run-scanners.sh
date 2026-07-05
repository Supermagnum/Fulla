#!/usr/bin/env bash
# Industry-standard scanners against the built Fulla Docker image and running instance.
# Requires: Docker (or Podman), stack reachable at FULLA_BASE_URL (default http://127.0.0.1:8080).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/docker"

FULLA_BASE_URL="${FULLA_BASE_URL:-http://127.0.0.1:8080}"
FULLA_IMAGE="${FULLA_IMAGE:-localhost/docker_fulla:latest}"
SCANNER_LOG_DIR="${SCANNER_LOG_DIR:-$ROOT/docker/scanner-output}"
mkdir -p "$SCANNER_LOG_DIR"

BLOCK=0
log() { echo "[scanners] $*"; }

run_docker() {
  docker "$@"
}

severity_blocks() {
  local logfile="$1"
  local tool="$2"
  if [[ ! -f "$logfile" ]]; then
    log "SKIP $tool (no output file)"
    return 0
  fi
  if grep -qiE '(CRITICAL|HIGH)' "$logfile" 2>/dev/null; then
    if grep -qiE 'CRITICAL|HIGH' "$logfile"; then
      log "BLOCKING: $tool reported HIGH/CRITICAL — see $logfile"
      BLOCK=1
    fi
  fi
}

# Resolve image name from compose if not set
if [[ "$FULLA_IMAGE" == "docker.io/library/docker-fulla:latest" ]]; then
  FULLA_IMAGE="$(docker compose images -q fulla 2>/dev/null | head -1 || true)"
  if [[ -n "$FULLA_IMAGE" ]]; then
    FULLA_IMAGE="$(docker inspect --format='{{.RepoTags}}' "$FULLA_IMAGE" 2>/dev/null | tr -d '[]' | cut -d' ' -f1 || echo "$FULLA_IMAGE")"
  fi
fi

log "Target URL: $FULLA_BASE_URL"
log "Scanner logs: $SCANNER_LOG_DIR"

# --- Trivy (container image CVEs) ---
TRIVY_LOG="$SCANNER_LOG_DIR/trivy.txt"
if command -v trivy >/dev/null 2>&1; then
  log "Running trivy (host binary)..."
  trivy image --severity HIGH,CRITICAL --ignore-unfixed "$FULLA_IMAGE" 2>&1 | tee "$TRIVY_LOG" || true
elif run_docker info >/dev/null 2>&1; then
  log "Running trivy via container (Podman/Docker socket)..."
  SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  if [[ -S "$SOCK" ]]; then
    run_docker run --rm \
      -v "${SOCK}:/var/run/docker.sock" \
      docker.io/aquasec/trivy:latest image --severity HIGH,CRITICAL --ignore-unfixed "$FULLA_IMAGE" \
      2>&1 | tee "$TRIVY_LOG" || true
  else
    run_docker run --rm docker.io/aquasec/trivy:latest image --severity HIGH,CRITICAL --ignore-unfixed "$FULLA_IMAGE" \
      2>&1 | tee "$TRIVY_LOG" || true
  fi
else
  log "SKIP trivy (not installed and Docker unavailable)"
  echo "SKIP: trivy not available" >"$TRIVY_LOG"
fi
severity_blocks "$TRIVY_LOG" "trivy"

# --- Nikto (generic web server scan) ---
NIKTO_LOG="$SCANNER_LOG_DIR/nikto.txt"
HOST_PORT="${FULLA_BASE_URL#http://}"
HOST_PORT="${HOST_PORT#https://}"
if command -v nikto >/dev/null 2>&1; then
  log "Running nikto..."
  nikto -h "$FULLA_BASE_URL" -maxtime 120s 2>&1 | tee "$NIKTO_LOG" || true
elif run_docker info >/dev/null 2>&1; then
  log "Running nikto via container..."
  if run_docker run --rm --network host ghcr.io/sullo/nikto:latest \
    -h "$FULLA_BASE_URL" -maxtime 120s 2>&1 | tee "$NIKTO_LOG"; then
    :
  else
    run_docker run --rm --network host docker.io/securecodebox/nikto:latest \
      -h "$FULLA_BASE_URL" -maxtime 120s 2>&1 | tee "$NIKTO_LOG" || true
  fi
else
  log "SKIP nikto"
  echo "SKIP: nikto not available" >"$NIKTO_LOG"
fi

# --- Nuclei (default web templates) ---
NUCLEI_LOG="$SCANNER_LOG_DIR/nuclei.txt"
if command -v nuclei >/dev/null 2>&1; then
  log "Running nuclei..."
  nuclei -u "$FULLA_BASE_URL" -severity high,critical -silent 2>&1 | tee "$NUCLEI_LOG" || true
elif run_docker info >/dev/null 2>&1; then
  log "Running nuclei via Docker..."
  run_docker run --rm --network host docker.io/projectdiscovery/nuclei:latest \
    -u "$FULLA_BASE_URL" -severity high,critical -silent 2>&1 | tee "$NUCLEI_LOG" || true
else
  log "SKIP nuclei"
  echo "SKIP: nuclei not available" >"$NUCLEI_LOG"
fi
if [[ -s "$NUCLEI_LOG" ]] && ! grep -q '^SKIP:' "$NUCLEI_LOG"; then
  if grep -qiE '\[(high|critical)\]' "$NUCLEI_LOG"; then
    log "BLOCKING: nuclei findings — see $NUCLEI_LOG"
    BLOCK=1
  fi
fi

# --- sqlmap (each GET /keys filter parameter) ---
SQLMAP_DIR="$SCANNER_LOG_DIR/sqlmap-clean"
mkdir -p "$SQLMAP_DIR"
if command -v sqlmap >/dev/null 2>&1; then
  log "Running sqlmap per GET /keys parameter..."
  SCANNER_LOG_DIR="$SCANNER_LOG_DIR" FULLA_BASE_URL="$FULLA_BASE_URL" \
    "$ROOT/docker/run-sqlmap-params.sh" 2>&1 | tee "$SCANNER_LOG_DIR/sqlmap-all.txt" || true
elif run_docker info >/dev/null 2>&1; then
  log "Running sqlmap via parrotsec container (single-param smoke; use run-sqlmap-params.sh on host for full matrix)..."
  SQLMAP_URL="${FULLA_BASE_URL}/keys?email=test@example.com"
  run_docker run --rm --network host docker.io/parrotsec/sqlmap:latest \
    -u "$SQLMAP_URL" --batch --level=1 --risk=1 --timeout=10 --retries=1 \
    --threads=1 --flush-session 2>&1 | tee "$SCANNER_LOG_DIR/sqlmap.txt" || true
else
  log "SKIP sqlmap"
  echo "SKIP: sqlmap not available" >"$SCANNER_LOG_DIR/sqlmap.txt"
fi
if grep -rqi 'is vulnerable' "$SCANNER_LOG_DIR"/sqlmap*.txt "$SQLMAP_DIR" 2>/dev/null; then
  log "BLOCKING: sqlmap reported injection"
  BLOCK=1
fi

# --- OWASP ZAP baseline ---
ZAP_LOG="$SCANNER_LOG_DIR/zap-baseline.txt"
if run_docker info >/dev/null 2>&1; then
  log "Running OWASP ZAP baseline via Docker..."
  run_docker run --rm --network host -t docker.io/zaproxy/zap-stable zap-baseline.py \
    -t "$FULLA_BASE_URL" -I 2>&1 | tee "$ZAP_LOG" || true
  if grep -qiE 'FAIL-NEW|FAIL-INPROG' "$ZAP_LOG" 2>/dev/null; then
    if grep -qiE 'High|Critical' "$ZAP_LOG"; then
      log "BLOCKING: ZAP baseline High/Critical — see $ZAP_LOG"
      BLOCK=1
    fi
  fi
else
  log "SKIP zap-baseline (Docker unavailable)"
  echo "SKIP: zap-baseline requires Docker" >"$ZAP_LOG"
fi

if [[ "$BLOCK" -ne 0 ]]; then
  log "Scanner stage FAILED (HIGH/CRITICAL or sqlmap injection)"
  exit 1
fi

log "Scanner stage completed (no blocking findings)."
exit 0
