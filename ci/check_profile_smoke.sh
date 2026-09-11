#!/usr/bin/env bash
# ============================================================================
# ci/check_profile_smoke.sh — configure-stage smoke test for deployment profiles
# ============================================================================
#
# Verifies every chain-specific / wallet CMakePresets entry configures cleanly
# without an actual full build. Catches the class of bug where a base preset
# disables an optional module (e.g. BIP-352) but leaves a dependent module
# (e.g. LTC-SP) implicitly ON, which makes `cmake --preset <name>` fail with a
# fatal_error inside src/cpu/CMakeLists.txt.
#
# Why configure-only and not build-only:
#   * Build time for all profiles ≥ 5–7 min on a CI runner; configure is < 5s.
#   * The configure stage already exercises the dependency-flag matrix that
#     causes 90% of profile breakage — link/library issues are caught later
#     by the per-profile Linux/Windows/macOS jobs anyway.
#   * One profile (bitcoin-core) IS built end-to-end below so the static
#     library actually links; the other profiles are config-only here.
#
# Exit codes:
#   0 — every profile configures cleanly and bitcoin-core links.
#   1 — at least one profile failed.
# ============================================================================
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Profiles to validate. Keep the list aligned with CMakePresets.json
# "chain-specific" + "wallet" deployment profiles. Audit / sanitizer presets
# are exercised by their own dedicated jobs and are intentionally excluded.
PROFILES=(
  bitcoin-core
  litecoin
  dogecoin
  bch-wallet
  wallet
  audit
)

PASS=0
FAIL=0
FAILED_NAMES=()
BUILD_DIR="${TMPDIR:-/tmp}/ufsecp_profile_smoke"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "── profile configure smoke ──"
for p in "${PROFILES[@]}"; do
  PRESET_DIR="$BUILD_DIR/$p"
  LOG="$BUILD_DIR/$p.log"
  printf "  %-14s ... " "$p"
  if cmake --preset "$p" -B "$PRESET_DIR" > "$LOG" 2>&1 \
     && grep -q "Configuring done" "$LOG"; then
    echo "OK"
    PASS=$((PASS + 1))
  else
    echo "FAIL  (log: $LOG)"
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("$p")
  fi
done

echo
echo "── bitcoin-core link smoke ──"
printf "  bitcoin-core build fastsecp256k1 ... "
LINK_LOG="$BUILD_DIR/bitcoin-core.build.log"
if cmake --build "$BUILD_DIR/bitcoin-core" --target fastsecp256k1 \
   -j "$(nproc 2>/dev/null || echo 4)" > "$LINK_LOG" 2>&1 \
   && [ -f "$BUILD_DIR/bitcoin-core/src/cpu/libfastsecp256k1.a" ]; then
  SIZE=$(stat -c '%s' "$BUILD_DIR/bitcoin-core/src/cpu/libfastsecp256k1.a" 2>/dev/null || \
         stat -f '%z' "$BUILD_DIR/bitcoin-core/src/cpu/libfastsecp256k1.a" 2>/dev/null)
  echo "OK ($((SIZE / 1024)) KB static lib)"
  PASS=$((PASS + 1))
else
  echo "FAIL  (log: $LINK_LOG)"
  FAIL=$((FAIL + 1))
  FAILED_NAMES+=("bitcoin-core-link")
fi

echo
echo "── summary ──"
TOTAL=$((PASS + FAIL))
echo "  passed: $PASS / $TOTAL"
if [ "$FAIL" -gt 0 ]; then
  echo "  failed profiles: ${FAILED_NAMES[*]}"
  echo "  full logs in: $BUILD_DIR"
  exit 1
fi
echo "  all deployment profiles configure cleanly + bitcoin-core links."
