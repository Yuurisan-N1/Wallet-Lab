// ============================================================================
// REGRESSION TEST: MuSig2 v1 ABI partial_sign disabled (v9 RT-001 / TASK-001)
// ============================================================================
// Track: SECURITY — MuSig2 partial_sign v1 ABI signer-index bypass closure.
//
// BACKGROUND:
//   Prior revisions kept ufsecp_musig2_partial_sign() (v1) functional for
//   non-migrated callers. v9 RT-001 (adversarial review, 2026-05-24) found
//   that v1 still routed to musig2_partial_sign_core() with an empty
//   MuSig2KeyAggCtx::individual_pubkeys vector, which silently disarmed the
//   Rule-13 (privkey <-> signer_index) defense-in-depth check at
//   src/cpu/src/musig2.cpp:musig2_partial_sign. v1 therefore produced valid
//   partial signatures for arbitrary (sk, signer_index) pairs — a malicious
//   coordinator could elicit a sign-as-someone-else partial sig.
//
// FIX (v9 TASK-001):
//   ufsecp_musig2_partial_sign (v1) now fail-closes on every call with
//   UFSECP_ERR_DEPRECATED_API. The output buffer is zeroed and the secnonce
//   is securely erased before return, protecting callers that ignore the
//   return code from accidental nonce reuse.
//
// THIS TEST verifies:
//   1. v1 with valid inputs returns UFSECP_ERR_DEPRECATED_API (not UFSECP_OK,
//      not UFSECP_ERR_BAD_KEY, not any other code).
//   2. v1 output buffer is all-zero on return.
//   3. v1 secnonce buffer is securely erased (all-zero) on return.
//   4. v1 with NULL args still returns UFSECP_ERR_NULL_ARG (NULL check fires
//      before the deprecation reject — argument validation discipline).
//   5. v2 is unaffected and still produces valid partial signatures.
//
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>

#include "ufsecp.h"

static int g_pass = 0, g_fail = 0;

static void check(bool cond, const char* msg) {
    if (cond) { ++g_pass; std::printf("    [OK] %s\n", msg); }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", msg); }
    std::fflush(stdout);
}

// Fixed valid scalars (same family as test_regression_musig2_abi_signer_index).
static const uint8_t SK0[32] = {
    0x3B,0x91,0x8F,0xC2,0x3A,0xA4,0x77,0xD8,
    0xDE,0x9B,0x28,0x12,0xF3,0xBE,0x60,0xCE,
    0x8B,0x7E,0x45,0x26,0xA3,0x81,0x25,0x60,
    0xB9,0x92,0x21,0x3F,0x19,0x33,0xAE,0x71
};
static const uint8_t SK1[32] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28
};
static const uint8_t MSG32[32] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE
};

// Suppress the [[deprecated]] warning on the v1 entry point so the test
// compiles clean under -Werror=deprecated-declarations.
#if defined(__GNUC__) || defined(__clang__)
#  define V1_CALL_BEGIN _Pragma("GCC diagnostic push") \
                       _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#  define V1_CALL_END   _Pragma("GCC diagnostic pop")
#elif defined(_MSC_VER)
#  define V1_CALL_BEGIN __pragma(warning(push)) __pragma(warning(disable: 4996))
#  define V1_CALL_END   __pragma(warning(pop))
#else
#  define V1_CALL_BEGIN
#  define V1_CALL_END
#endif

// ─── test_v1_returns_deprecated ──────────────────────────────────────────────
static void test_v1_returns_deprecated() {
    std::printf("  [v1_returns_deprecated]\n");

    ufsecp_ctx* ctx = nullptr;
    check(ufsecp_ctx_create(&ctx) == UFSECP_OK, "ctx create");

    // Build a real 2-of-2 keyagg + session so we drive v1 with otherwise-valid
    // inputs — proving that the deprecation reject fires before any signing,
    // not because of a malformed input.
    uint8_t pk0[33], pk1[33];
    check(ufsecp_pubkey_create(ctx, SK0, pk0) == UFSECP_OK, "pubkey0");
    check(ufsecp_pubkey_create(ctx, SK1, pk1) == UFSECP_OK, "pubkey1");

    uint8_t pubkeys_buf[66];
    std::memcpy(pubkeys_buf,      pk0, 33);
    std::memcpy(pubkeys_buf + 33, pk1, 33);

    uint8_t keyagg[UFSECP_MUSIG2_KEYAGG_LEN];
    uint8_t agg_pk32[32];
    check(ufsecp_musig2_key_agg(ctx, pubkeys_buf, 2, keyagg, agg_pk32) == UFSECP_OK,
          "key_agg");

    uint8_t secnonce0[UFSECP_MUSIG2_SECNONCE_LEN];
    uint8_t pubnonce0[UFSECP_MUSIG2_PUBNONCE_LEN];
    uint8_t secnonce1[UFSECP_MUSIG2_SECNONCE_LEN];
    uint8_t pubnonce1[UFSECP_MUSIG2_PUBNONCE_LEN];
    static const uint8_t EA[32] = {0xAA};
    static const uint8_t EB[32] = {0xBB};
    check(ufsecp_musig2_nonce_gen(ctx, SK0, pk0, agg_pk32, MSG32, EA,
                                  secnonce0, pubnonce0) == UFSECP_OK, "nonce_gen0");
    check(ufsecp_musig2_nonce_gen(ctx, SK1, pk1, agg_pk32, MSG32, EB,
                                  secnonce1, pubnonce1) == UFSECP_OK, "nonce_gen1");

    uint8_t pubnonces_buf[132];
    std::memcpy(pubnonces_buf,      pubnonce0, 66);
    std::memcpy(pubnonces_buf + 66, pubnonce1, 66);
    uint8_t aggnonce[UFSECP_MUSIG2_AGGNONCE_LEN];
    check(ufsecp_musig2_nonce_agg(ctx, pubnonces_buf, 2, aggnonce) == UFSECP_OK,
          "nonce_agg");

    uint8_t session[UFSECP_MUSIG2_SESSION_LEN];
    check(ufsecp_musig2_start_sign_session(ctx, aggnonce, keyagg, MSG32, session) == UFSECP_OK,
          "start_sign_session");

    // Seed the partial_sig buffer with a known sentinel; after v1 returns it
    // must be all zero (fail-closed Rule 3). Use 0xA5 so any single byte left
    // unmodified is detectable.
    uint8_t psig[32];
    std::memset(psig, 0xA5, sizeof(psig));

    // Take a copy of secnonce0 since v1 securely-erases it; we want to verify
    // that erasure even on the deprecation path.
    uint8_t secnonce0_copy[UFSECP_MUSIG2_SECNONCE_LEN];
    std::memcpy(secnonce0_copy, secnonce0, UFSECP_MUSIG2_SECNONCE_LEN);

    ufsecp_error_t rc;
    V1_CALL_BEGIN
    rc = ufsecp_musig2_partial_sign(ctx, secnonce0_copy, SK0, keyagg, session,
                                    /*signer_index=*/0, psig);
    V1_CALL_END

    // Core v9 RT-001 assertion: v1 must hard-fail with the new code.
    check(rc == UFSECP_ERR_DEPRECATED_API,
          "v1 partial_sign returns UFSECP_ERR_DEPRECATED_API");
    check(rc != UFSECP_OK,
          "v1 partial_sign does NOT return UFSECP_OK (was: bypass-allowing)");

    // Output buffer must be fully zeroed.
    bool psig_zero = true;
    for (size_t i = 0; i < sizeof(psig); ++i) {
        if (psig[i] != 0) { psig_zero = false; break; }
    }
    check(psig_zero, "v1: partial_sig output buffer zeroed on deprecation");

    // Secnonce must be securely erased even though v1 rejected the call —
    // a caller that mistakenly ignored the rc must not be able to reuse the
    // nonce in another call.
    bool secnonce_zero = true;
    for (size_t i = 0; i < UFSECP_MUSIG2_SECNONCE_LEN; ++i) {
        if (secnonce0_copy[i] != 0) { secnonce_zero = false; break; }
    }
    check(secnonce_zero, "v1: secnonce securely erased on deprecation reject");

    // NULL-arg validation must still take precedence over the deprecation
    // reject (argument discipline preserved). Use a fresh sentinel buffer.
    uint8_t psig_null[32];
    std::memset(psig_null, 0xBE, sizeof(psig_null));
    V1_CALL_BEGIN
    ufsecp_error_t rc_null = ufsecp_musig2_partial_sign(
        nullptr, secnonce1, SK1, keyagg, session, 1, psig_null);
    V1_CALL_END
    check(rc_null == UFSECP_ERR_NULL_ARG,
          "v1: NULL ctx still returns UFSECP_ERR_NULL_ARG (not DEPRECATED_API)");

    ufsecp_ctx_destroy(ctx);
    std::printf("\n");
}

// ─── test_v2_still_works ─────────────────────────────────────────────────────
// Sanity-check that v2 is not affected by the v1 hard-fail.
static void test_v2_still_works() {
    std::printf("  [v2_still_works]\n");

    ufsecp_ctx* ctx = nullptr;
    check(ufsecp_ctx_create(&ctx) == UFSECP_OK, "ctx create");

    uint8_t pk0[33], pk1[33];
    check(ufsecp_pubkey_create(ctx, SK0, pk0) == UFSECP_OK, "pubkey0");
    check(ufsecp_pubkey_create(ctx, SK1, pk1) == UFSECP_OK, "pubkey1");

    uint8_t pubkeys_buf[66];
    std::memcpy(pubkeys_buf,      pk0, 33);
    std::memcpy(pubkeys_buf + 33, pk1, 33);

    uint8_t keyagg[UFSECP_MUSIG2_KEYAGG_LEN];
    uint8_t agg_pk32[32];
    check(ufsecp_musig2_key_agg(ctx, pubkeys_buf, 2, keyagg, agg_pk32) == UFSECP_OK,
          "key_agg");

    uint8_t sn0[UFSECP_MUSIG2_SECNONCE_LEN], pn0[UFSECP_MUSIG2_PUBNONCE_LEN];
    uint8_t sn1[UFSECP_MUSIG2_SECNONCE_LEN], pn1[UFSECP_MUSIG2_PUBNONCE_LEN];
    static const uint8_t EA[32] = {0xC0};
    static const uint8_t EB[32] = {0xC1};
    check(ufsecp_musig2_nonce_gen(ctx, SK0, pk0, agg_pk32, MSG32, EA, sn0, pn0) == UFSECP_OK,
          "nonce_gen0");
    check(ufsecp_musig2_nonce_gen(ctx, SK1, pk1, agg_pk32, MSG32, EB, sn1, pn1) == UFSECP_OK,
          "nonce_gen1");

    uint8_t pubnonces_buf[132];
    std::memcpy(pubnonces_buf,      pn0, 66);
    std::memcpy(pubnonces_buf + 66, pn1, 66);
    uint8_t aggnonce[UFSECP_MUSIG2_AGGNONCE_LEN];
    check(ufsecp_musig2_nonce_agg(ctx, pubnonces_buf, 2, aggnonce) == UFSECP_OK,
          "nonce_agg");

    uint8_t session[UFSECP_MUSIG2_SESSION_LEN];
    check(ufsecp_musig2_start_sign_session(ctx, aggnonce, keyagg, MSG32, session) == UFSECP_OK,
          "start_sign_session");

    uint8_t psig0[32];
    ufsecp_error_t rc = ufsecp_musig2_partial_sign_v2(
        ctx, sn0, SK0, pubkeys_buf, keyagg, session, /*signer_index=*/0, psig0);
    check(rc == UFSECP_OK, "v2 partial_sign (correct index) still returns UFSECP_OK");

    ufsecp_ctx_destroy(ctx);
    std::printf("\n");
}

int test_regression_musig2_v1_partial_sign_deprecated_run() {
    std::printf("====================================================================\n");
    std::printf("REGRESSION: MuSig2 v1 partial_sign disabled (v9 RT-001 / TASK-001)\n");
    std::printf("====================================================================\n\n");
    std::printf("Verifies that ufsecp_musig2_partial_sign (v1) fail-closes with\n");
    std::printf("UFSECP_ERR_DEPRECATED_API on every call, and that v2 is unaffected.\n\n");

    test_v1_returns_deprecated();
    test_v2_still_works();

    std::printf("====================================================================\n");
    std::printf("Result: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("====================================================================\n");

    return (g_fail > 0) ? 1 : 0;
}

#if defined(STANDALONE_TEST)
int main() {
    return test_regression_musig2_v1_partial_sign_deprecated_run();
}
#endif
