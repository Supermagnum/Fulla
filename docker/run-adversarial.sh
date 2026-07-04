#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/docker"

# Podman rootless: use user socket when docker.sock is absent.
if [[ -z "${DOCKER_HOST:-}" ]] && [[ ! -S /var/run/docker.sock ]] && [[ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock" ]]; then
  export DOCKER_HOST="unix://${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  systemctl --user start podman.socket 2>/dev/null || true
fi

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

cd "$ROOT/adversarial-tests"
export FULLA_BASE_URL="${FULLA_BASE_URL:-http://127.0.0.1:8080}"
export MAILHOG_API="${MAILHOG_API:-http://127.0.0.1:8025}"
export FULLA_EXPECT_RATE_LIMIT="${FULLA_EXPECT_RATE_LIMIT:-50}"
export FULLA_EXPECT_READ_RATE_LIMIT="${FULLA_EXPECT_READ_RATE_LIMIT:-500}"
cargo run --release
