#!/usr/bin/env bash
# ============================================================================
# check_werror_build.sh — local mirror of the GitHub "Build with -Werror" gate
# ============================================================================
# WHY THIS EXISTS:
#   The GitHub Security Audit job ".github/workflows/security-audit.yml → Build
#   with -Werror" is the ONLY pipeline step that compiles the production library
#   with -DSECP256K1_WERROR=ON. ci_local.sh did not mirror it, so a warning-class
#   regression (e.g. a static function orphaned when its last caller is removed →
#   -Werror=unused-function) passed every local gate and only failed on CI —
#   exactly the "fix takes 2 days because we didn't check locally" loop the
#   project forbids. This script closes that gap.
#
# It reproduces the CI configure flags as closely as the host allows:
#   Release · g++-14 (CI compiler, falls back to g++/c++) · WERROR=ON ·
#   tests/bench/examples/java OFF (the CI gate intentionally excludes tests, which
#   use the deprecated variable-time ecdsa_sign() on purpose).
#   MARCH=x86-64-v3 only on x86_64 hosts (mirrors CI); omitted elsewhere so the
#   gate is still meaningful on arm64 dev machines.
#
# A persistent build dir (out/ci_werror) + ccache keep repeat runs fast
# (sub-30s warm); the first run pays a full compile.
#
# Exit codes: 0 = clean build (no warnings), 1 = warning/error (push should block).
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

if ! command -v cmake >/dev/null 2>&1 || ! command -v ninja >/dev/null 2>&1; then
  echo "check_werror_build: cmake/ninja not found — cannot run -Werror gate" >&2
  exit 1
fi

# Prefer the exact CI compiler (g++-14); fall back so the gate still runs locally.
CXX=""
for c in g++-14 g++ c++; do
  command -v "$c" >/dev/null 2>&1 && CXX="$(command -v "$c")" && break
done
if [[ -z "$CXX" ]]; then
  echo "check_werror_build: no C++ compiler found" >&2
  exit 1
fi

BUILD_DIR="$ROOT/out/ci_werror"
LOG="${TMPDIR:-/tmp}/ci_werror_$$.log"

CMAKE_ARGS=(
  -S . -B "$BUILD_DIR" -G Ninja
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_CXX_COMPILER="$CXX"
  -DSECP256K1_WERROR=ON
  -DSECP256K1_BUILD_BENCH=OFF
  -DSECP256K1_BUILD_TESTS=OFF
  -DSECP256K1_BUILD_EXAMPLES=OFF
  -DSECP256K1_BUILD_JAVA=OFF
)

# Mirror the CI march only on x86_64 (the CI runner arch); let other hosts default.
if [[ "$(uname -m)" == "x86_64" ]]; then
  CMAKE_ARGS+=(-DSECP256K1_MARCH=x86-64-v3)
fi

# ccache accelerates the repeat runs that matter for a pre-push gate.
if command -v ccache >/dev/null 2>&1; then
  CMAKE_ARGS+=(-DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache)
fi

echo "check_werror_build: $CXX | $(uname -m) | WERROR=ON | Release (mirrors Security Audit)"

if ! cmake "${CMAKE_ARGS[@]}" > "$LOG" 2>&1; then
  echo "check_werror_build: configure FAILED" >&2
  tail -20 "$LOG" >&2
  rm -f "$LOG"
  exit 1
fi

if ! cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 4)" >> "$LOG" 2>&1; then
  echo "check_werror_build: -Werror BUILD FAILED — a production-code warning is being treated as an error." >&2
  echo "  (this is the same gate as GitHub 'Build with -Werror'; fix the warning before pushing)" >&2
  # Surface only the real compiler diagnostics, not the benign LTO scheduling note.
  grep -E "error:|warning:" "$LOG" 2>/dev/null | grep -v "lto-wrapper" | head -20 >&2 || tail -20 "$LOG" >&2
  rm -f "$LOG"
  exit 1
fi

rm -f "$LOG"
echo "check_werror_build: OK — production library builds clean under -Werror"
exit 0
