#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Stage 1: supply-chain (cargo audit / cargo deny) ==="
"$ROOT/docker/run-supply-chain.sh"

cd "$ROOT/docker"

# Podman rootless: use user socket when docker.sock is absent.
if [[ -z "${DOCKER_HOST:-}" ]] && [[ ! -S /var/run/docker.sock ]] && [[ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock" ]]; then
  export DOCKER_HOST="unix://${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  systemctl --user start podman.socket 2>/dev/null || true
fi

echo ""
echo "=== Stage 2: Docker stack (Fulla + MailHog) ==="
echo "Resetting Docker stack (fresh DB + MailHog)..."
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build

echo "Waiting for Fulla..."
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8080/ >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -sf http://127.0.0.1:8080/ >/dev/null || {
  echo "Fulla did not become ready on :8080" >&2
  exit 1
}

echo ""
echo "=== Stage 3: industry-standard scanners (trivy, nuclei, nikto, sqlmap, ZAP) ==="
export FULLA_BASE_URL="${FULLA_BASE_URL:-http://127.0.0.1:8080}"
if ! "$ROOT/docker/run-scanners.sh"; then
  echo "Scanner stage failed (blocking HIGH/CRITICAL or sqlmap injection)" >&2
  exit 1
fi

echo ""
echo "=== Stage 4: Fulla custom adversarial probes ==="
cd "$ROOT/adversarial-tests"
export MAILHOG_API="${MAILHOG_API:-http://127.0.0.1:8025}"
export FULLA_EXPECT_RATE_LIMIT="${FULLA_EXPECT_RATE_LIMIT:-50}"
export FULLA_EXPECT_READ_RATE_LIMIT="${FULLA_EXPECT_READ_RATE_LIMIT:-500}"
cargo run --release

echo ""
echo "Adversarial harness completed successfully."
