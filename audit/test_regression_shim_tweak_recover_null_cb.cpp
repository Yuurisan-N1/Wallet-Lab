// ============================================================================
// test_regression_shim_tweak_recover_null_cb.cpp
// ============================================================================
// Regression tests for NULL non-ctx arg illegal_callback in:
//   TRNC-1: secp256k1_xonly_pubkey_tweak_add     (shim_extrakeys.cpp)
//   TRNC-2: secp256k1_xonly_pubkey_tweak_add_check (shim_extrakeys.cpp)
//   TRNC-3: secp256k1_keypair_xonly_tweak_add    (shim_extrakeys.cpp)
//   TRNC-4: secp256k1_ecdsa_recoverable_signature_convert (shim_recovery.cpp)
//
// All four functions previously returned 0 silently on NULL non-ctx args
// without firing secp256k1_shim_call_illegal_cb. This diverged from the
// upstream libsecp256k1 ARG_CHECK contract (SHIM-NULL-CB-2026).
// ============================================================================

#if !defined(UNIFIED_AUDIT_RUNNER) && !defined(STANDALONE_TEST)
#define STANDALONE_TEST
#endif

#include <cstdio>
#include <cstring>
#include <array>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_recovery.h"

// ─── Illegal-callback trap ────────────────────────────────────────────────────

static int g_illegal_cb_fired = 0;
static void illegal_cb(const char* /*msg*/, void* /*data*/) {
    g_illegal_cb_fired = 1;
}

static secp256k1_context* make_ctx() {
    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_illegal_callback(ctx, illegal_cb, nullptr);
    return ctx;
}

// ─── TRNC-1: secp256k1_xonly_pubkey_tweak_add NULL non-ctx args ───────────────
static void test_xonly_pubkey_tweak_add_null_args() {
    auto* ctx = make_ctx();

    static const unsigned char kTweak[32] = {1};
    secp256k1_xonly_pubkey xpub{};
    secp256k1_pubkey outpub{};

    // NULL output_pubkey
    g_illegal_cb_fired = 0;
    int r = secp256k1_xonly_pubkey_tweak_add(ctx, nullptr, &xpub, kTweak);
    CHECK(r == 0, "[TRNC-1] tweak_add NULL output_pubkey returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-1] tweak_add NULL output_pubkey fires callback");

    // NULL internal_pubkey
    g_illegal_cb_fired = 0;
    r = secp256k1_xonly_pubkey_tweak_add(ctx, &outpub, nullptr, kTweak);
    CHECK(r == 0, "[TRNC-1] tweak_add NULL internal_pubkey returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-1] tweak_add NULL internal_pubkey fires callback");

    // NULL tweak32
    g_illegal_cb_fired = 0;
    r = secp256k1_xonly_pubkey_tweak_add(ctx, &outpub, &xpub, nullptr);
    CHECK(r == 0, "[TRNC-1] tweak_add NULL tweak32 returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-1] tweak_add NULL tweak32 fires callback");

    secp256k1_context_destroy(ctx);
}

// ─── TRNC-2: secp256k1_xonly_pubkey_tweak_add_check NULL non-ctx args ─────────
static void test_xonly_pubkey_tweak_add_check_null_args() {
    auto* ctx = make_ctx();

    static const unsigned char kX32[32] = {2};
    static const unsigned char kTweak[32] = {1};
    secp256k1_xonly_pubkey xpub{};

    // NULL tweaked_pubkey32
    g_illegal_cb_fired = 0;
    int r = secp256k1_xonly_pubkey_tweak_add_check(ctx, nullptr, 0, &xpub, kTweak);
    CHECK(r == 0, "[TRNC-2] tweak_add_check NULL tweaked_pubkey32 returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-2] tweak_add_check NULL tweaked_pubkey32 fires callback");

    // NULL internal_pubkey
    g_illegal_cb_fired = 0;
    r = secp256k1_xonly_pubkey_tweak_add_check(ctx, kX32, 0, nullptr, kTweak);
    CHECK(r == 0, "[TRNC-2] tweak_add_check NULL internal_pubkey returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-2] tweak_add_check NULL internal_pubkey fires callback");

    // NULL tweak32
    g_illegal_cb_fired = 0;
    r = secp256k1_xonly_pubkey_tweak_add_check(ctx, kX32, 0, &xpub, nullptr);
    CHECK(r == 0, "[TRNC-2] tweak_add_check NULL tweak32 returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-2] tweak_add_check NULL tweak32 fires callback");

    secp256k1_context_destroy(ctx);
}

// ─── TRNC-3: secp256k1_keypair_xonly_tweak_add NULL non-ctx args ──────────────
static void test_keypair_xonly_tweak_add_null_args() {
    auto* ctx = make_ctx();

    static const unsigned char kTweak[32] = {1};
    secp256k1_keypair kp{};

    // NULL keypair
    g_illegal_cb_fired = 0;
    int r = secp256k1_keypair_xonly_tweak_add(ctx, nullptr, kTweak);
    CHECK(r == 0, "[TRNC-3] keypair_xonly_tweak_add NULL keypair returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-3] keypair_xonly_tweak_add NULL keypair fires callback");

    // NULL tweak32
    g_illegal_cb_fired = 0;
    r = secp256k1_keypair_xonly_tweak_add(ctx, &kp, nullptr);
    CHECK(r == 0, "[TRNC-3] keypair_xonly_tweak_add NULL tweak32 returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-3] keypair_xonly_tweak_add NULL tweak32 fires callback");

    secp256k1_context_destroy(ctx);
}

// ─── TRNC-4: secp256k1_ecdsa_recoverable_signature_convert NULL non-ctx args ──
static void test_ecdsa_recoverable_signature_convert_null_args() {
    auto* ctx = make_ctx();

    secp256k1_ecdsa_signature sig{};
    secp256k1_ecdsa_recoverable_signature rsig{};

    // NULL sig (output)
    g_illegal_cb_fired = 0;
    int r = secp256k1_ecdsa_recoverable_signature_convert(ctx, nullptr, &rsig);
    CHECK(r == 0, "[TRNC-4] recoverable_sig_convert NULL sig returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-4] recoverable_sig_convert NULL sig fires callback");

    // NULL sigin
    g_illegal_cb_fired = 0;
    r = secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, nullptr);
    CHECK(r == 0, "[TRNC-4] recoverable_sig_convert NULL sigin returns 0");
    CHECK(g_illegal_cb_fired, "[TRNC-4] recoverable_sig_convert NULL sigin fires callback");

    secp256k1_context_destroy(ctx);
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
int main() {
#else
int test_regression_shim_tweak_recover_null_cb_run() {
#endif
    printf("[shim_tweak_recover_null_cb] TRNC-1..4: NULL non-ctx arg illegal_callback\n");

    test_xonly_pubkey_tweak_add_null_args();
    test_xonly_pubkey_tweak_add_check_null_args();
    test_keypair_xonly_tweak_add_null_args();
    test_ecdsa_recoverable_signature_convert_null_args();

    printf("[shim_tweak_recover_null_cb] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
