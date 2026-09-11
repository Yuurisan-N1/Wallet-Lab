// ============================================================================
// test_regression_shim_keypair_null_cb.cpp
// ============================================================================
// Regression: several shim functions silently returned 0 on NULL pointer
// arguments instead of firing the illegal_callback, diverging from upstream
// libsecp256k1 behaviour (ARG_CHECK → abort / callback).
//
// Fix (2026-05-25):
//   shim_extrakeys.cpp: keypair_create, keypair_sec, keypair_pub,
//                       keypair_xonly_pub — split combined NULL checks into
//                       per-argument guards that call secp256k1_shim_call_illegal_cb.
//   shim_ecdsa.cpp:     signature_parse_compact, signature_parse_der — same fix.
//
// Tests:
//   NCA-1: keypair_create(ctx, NULL, seckey) → callback + return 0
//   NCA-2: keypair_create(ctx, keypair, NULL) → callback + return 0
//   NCA-3: keypair_sec(ctx, NULL, keypair) → callback + return 0
//   NCA-4: keypair_pub(ctx, NULL, keypair) → callback + return 0
//   NCA-5: keypair_xonly_pub(ctx, NULL, keypair) → callback + return 0
//   NCA-6: signature_parse_compact(ctx, NULL, input64) → callback + return 0
//   NCA-7: signature_parse_compact(ctx, sig, NULL) → callback + return 0
//   NCA-8: signature_parse_der(ctx, NULL, input, len) → callback + return 0
//   NCA-9: signature_parse_der(ctx, sig, NULL, len) → callback + return 0
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <atomic>
#include <array>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#if __has_include("secp256k1.h")
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

static std::atomic<int> g_cb_count{0};

static void counting_illegal_cb(const char* /*msg*/, void* /*data*/) {
    ++g_cb_count;
}

static secp256k1_context* make_ctx() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_illegal_callback(ctx, counting_illegal_cb, nullptr);
    return ctx;
}

// A valid secret key (scalar 1..n-1)
static const unsigned char g_seckey[32] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
};

// ─── NCA-1: keypair_create NULL keypair ──────────────────────────────────────
static void test_nca1_keypair_create_null_keypair() {
    secp256k1_context* ctx = make_ctx();
    int before = g_cb_count.load();
    int rc = secp256k1_keypair_create(ctx, nullptr, g_seckey);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-1] keypair_create(NULL keypair) must return 0");
    CHECK(after > before,  "[NCA-1] keypair_create(NULL keypair) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-2: keypair_create NULL seckey ───────────────────────────────────────
static void test_nca2_keypair_create_null_seckey() {
    secp256k1_context* ctx = make_ctx();
    secp256k1_keypair kp{};
    int before = g_cb_count.load();
    int rc = secp256k1_keypair_create(ctx, &kp, nullptr);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-2] keypair_create(NULL seckey) must return 0");
    CHECK(after > before,  "[NCA-2] keypair_create(NULL seckey) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-3: keypair_sec NULL output seckey ───────────────────────────────────
static void test_nca3_keypair_sec_null_out() {
    secp256k1_context* ctx = make_ctx();
    secp256k1_keypair kp{};
    secp256k1_keypair_create(ctx, &kp, g_seckey);
    int before = g_cb_count.load();
    int rc = secp256k1_keypair_sec(ctx, nullptr, &kp);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-3] keypair_sec(NULL seckey_out) must return 0");
    CHECK(after > before,  "[NCA-3] keypair_sec(NULL seckey_out) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-4: keypair_pub NULL output pubkey ────────────────────────────────────
static void test_nca4_keypair_pub_null_out() {
    secp256k1_context* ctx = make_ctx();
    secp256k1_keypair kp{};
    secp256k1_keypair_create(ctx, &kp, g_seckey);
    int before = g_cb_count.load();
    int rc = secp256k1_keypair_pub(ctx, nullptr, &kp);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-4] keypair_pub(NULL pubkey_out) must return 0");
    CHECK(after > before,  "[NCA-4] keypair_pub(NULL pubkey_out) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-5: keypair_xonly_pub NULL output pubkey ──────────────────────────────
static void test_nca5_keypair_xonly_pub_null_out() {
    secp256k1_context* ctx = make_ctx();
    secp256k1_keypair kp{};
    secp256k1_keypair_create(ctx, &kp, g_seckey);
    int before = g_cb_count.load();
    int rc = secp256k1_keypair_xonly_pub(ctx, nullptr, nullptr, &kp);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-5] keypair_xonly_pub(NULL pubkey_out) must return 0");
    CHECK(after > before,  "[NCA-5] keypair_xonly_pub(NULL pubkey_out) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-6: signature_parse_compact NULL sig output ──────────────────────────
static void test_nca6_parse_compact_null_sig() {
    secp256k1_context* ctx = make_ctx();
    unsigned char input64[64]{};
    int before = g_cb_count.load();
    int rc = secp256k1_ecdsa_signature_parse_compact(ctx, nullptr, input64);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-6] parse_compact(NULL sig) must return 0");
    CHECK(after > before,  "[NCA-6] parse_compact(NULL sig) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-7: signature_parse_compact NULL input64 ─────────────────────────────
static void test_nca7_parse_compact_null_input() {
    secp256k1_context* ctx = make_ctx();
    secp256k1_ecdsa_signature sig{};
    int before = g_cb_count.load();
    int rc = secp256k1_ecdsa_signature_parse_compact(ctx, &sig, nullptr);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-7] parse_compact(NULL input64) must return 0");
    CHECK(after > before,  "[NCA-7] parse_compact(NULL input64) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-8: signature_parse_der NULL sig output ───────────────────────────────
static void test_nca8_parse_der_null_sig() {
    secp256k1_context* ctx = make_ctx();
    // Minimal valid DER envelope (just enough bytes for inputlen >= 8)
    static const unsigned char der[8] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    int before = g_cb_count.load();
    int rc = secp256k1_ecdsa_signature_parse_der(ctx, nullptr, der, sizeof(der));
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-8] parse_der(NULL sig) must return 0");
    CHECK(after > before,  "[NCA-8] parse_der(NULL sig) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

// ─── NCA-9: signature_parse_der NULL input ────────────────────────────────────
static void test_nca9_parse_der_null_input() {
    secp256k1_context* ctx = make_ctx();
    secp256k1_ecdsa_signature sig{};
    int before = g_cb_count.load();
    int rc = secp256k1_ecdsa_signature_parse_der(ctx, &sig, nullptr, 64);
    int after = g_cb_count.load();
    CHECK(rc == 0,         "[NCA-9] parse_der(NULL input) must return 0");
    CHECK(after > before,  "[NCA-9] parse_der(NULL input) must fire illegal_callback");
    secp256k1_context_destroy(ctx);
}

#else
// Shim not available — advisory skip
static void test_nca_shim_not_available() {
    printf("  [NCA] shim not available — advisory skip\n");
}
#endif // __has_include("secp256k1.h")

// ─── Entry point ─────────────────────────────────────────────────────────────

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
int main() {
#else
int test_regression_shim_keypair_null_cb_run() {
#endif
    printf("[shim_keypair_null_cb] 2026-05-25: NULL-arg illegal_callback fix — extrakeys + ecdsa parse\n");

#if __has_include("secp256k1.h")
    test_nca1_keypair_create_null_keypair();
    test_nca2_keypair_create_null_seckey();
    test_nca3_keypair_sec_null_out();
    test_nca4_keypair_pub_null_out();
    test_nca5_keypair_xonly_pub_null_out();
    test_nca6_parse_compact_null_sig();
    test_nca7_parse_compact_null_input();
    test_nca8_parse_der_null_sig();
    test_nca9_parse_der_null_input();
#else
    test_nca_shim_not_available();
    return ADVISORY_SKIP_CODE;
#endif

    printf("[shim_keypair_null_cb] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
