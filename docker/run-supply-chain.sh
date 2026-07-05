#!/usr/bin/env bash
# Dependency supply-chain checks (RustSec + cargo-deny).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== cargo audit (RustSec) ==="
if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "Installing cargo-audit..."
  cargo install cargo-audit --locked
fi
cargo audit --deny warnings \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2025-0134 \
  --ignore RUSTSEC-2026-0190

echo ""
echo "=== cargo deny check ==="
if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "Installing cargo-deny..."
  cargo install cargo-deny --locked
fi
cargo deny check

echo ""
echo "Supply-chain checks passed."
