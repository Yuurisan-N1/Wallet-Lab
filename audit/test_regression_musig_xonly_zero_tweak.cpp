// ============================================================================
// test_regression_musig_xonly_zero_tweak.cpp
// ============================================================================
// Regression for SHIM-001: secp256k1_musig_pubkey_xonly_tweak_add incorrectly
// rejected a zero tweak32 (parse_bytes_strict_nonzero). libsecp256k1 accepts
// zero tweak (result: key unchanged). The fix changes to parse_bytes_strict.
//
// Tests (MXT-1..3):
//   MXT-1  zero tweak returns 1 (was returning 0 before fix)
//   MXT-2  non-zero tweak still works (no regression)
//   MXT-3  out-of-range tweak (>= n) still rejected
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#include <cstdio>
#define STANDALONE_TEST
#endif

#include <cstdio>
#include <cstring>
#include <cstdint>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#if __has_include("secp256k1_musig.h")
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_musig.h"

// Secp256k1 order n (for out-of-range test)
static const uint8_t kOrderN[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

// privkey = 1
static const uint8_t kSk1[32] = {
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1
};

// Build a single-signer keyagg_cache as setup for tweak tests.
// Returns 0 on setup failure.
static int setup_keyagg(secp256k1_context* ctx, secp256k1_musig_keyagg_cache* cache) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, kSk1)) return 0;
    const secp256k1_pubkey* pks[1] = {&pk};
    secp256k1_xonly_pubkey agg_pk;
    return secp256k1_musig_pubkey_agg(ctx, &agg_pk, cache, pks, 1);
}

// ─── MXT-1: zero tweak must succeed ─────────────────────────────────────────
static void test_mxt1_zero_tweak_accepted() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_musig_keyagg_cache cache;
    CHECK(setup_keyagg(ctx, &cache), "[MXT-1] setup_keyagg");

    uint8_t zero_tweak[32] = {};  // all-zero tweak
    secp256k1_pubkey out_pk;
    int rc = secp256k1_musig_pubkey_xonly_tweak_add(ctx, &out_pk, &cache, zero_tweak);
    CHECK(rc == 1, "[MXT-1] zero tweak must return 1 (SHIM-001 regression)");

    secp256k1_context_destroy(ctx);
}

// ─── MXT-2: small non-zero tweak still works ────────────────────────────────
static void test_mxt2_nonzero_tweak_works() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_musig_keyagg_cache cache;
    CHECK(setup_keyagg(ctx, &cache), "[MXT-2] setup_keyagg");

    uint8_t tweak[32] = {};
    tweak[31] = 7;  // tweak = 7
    secp256k1_pubkey out_pk;
    int rc = secp256k1_musig_pubkey_xonly_tweak_add(ctx, &out_pk, &cache, tweak);
    CHECK(rc == 1, "[MXT-2] non-zero tweak must return 1");

    secp256k1_context_destroy(ctx);
}

// ─── MXT-3: tweak >= n must be rejected ─────────────────────────────────────
static void test_mxt3_overflow_tweak_rejected() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_musig_keyagg_cache cache;
    CHECK(setup_keyagg(ctx, &cache), "[MXT-3] setup_keyagg");

    secp256k1_pubkey out_pk;
    int rc = secp256k1_musig_pubkey_xonly_tweak_add(ctx, &out_pk, &cache, kOrderN);
    CHECK(rc == 0, "[MXT-3] tweak == n must be rejected");

    secp256k1_context_destroy(ctx);
}

static bool shim_available = true;

#else  // secp256k1_musig.h not found

static bool shim_available = false;

#endif // __has_include("secp256k1_musig.h")

int test_regression_musig_xonly_zero_tweak_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_musig_xonly_zero_tweak] SHIM-001: zero tweak accepted by xonly_tweak_add\n");

    if (!shim_available) {
        std::printf("  (shim not linked — skipping)\n");
        return 77;  // ADVISORY_SKIP_CODE
    }

#if __has_include("secp256k1_musig.h")
    test_mxt1_zero_tweak_accepted();
    test_mxt2_nonzero_tweak_works();
    test_mxt3_overflow_tweak_rejected();
#endif

    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_musig_xonly_zero_tweak_run(); }
#endif
