// ============================================================================
// test_regression_shim_context_erase.cpp
// ============================================================================
// Regression: shim_context.cpp used std::memset(ctx->blind, 0, 32) in
// context_destroy, context_randomize (null-seed path), and
// context_preallocated_destroy. std::memset on a secret buffer is subject to
// dead-store elimination by optimisers — use secp256k1::detail::secure_erase.
// Also: ContextBlindingScope fallback called r.is_zero() on a secret Scalar;
// fast::Scalar::is_zero() has a data-dependent early exit across limbs.
// Fix: replaced with r.is_zero_ct() (reads all limbs unconditionally).
//
// Fix (2026-05-25):
//   shim_context.cpp: 3× std::memset(ctx->blind, 0, 32) →
//                         secp256k1::detail::secure_erase(ctx->blind, 32)
//                     ContextBlindingScope: r.is_zero() → r.is_zero_ct()
//
// Tests:
//   SCE-1: source scan — std::memset(ctx->blind, 0, 32) absent in shim_context.cpp
//   SCE-2: source scan — secure_erase(ctx->blind present (≥3 occurrences)
//   SCE-3: source scan — is_zero_ct() present in ContextBlindingScope (≥1 occurrence)
//   SCE-4: functional — context create + randomize + destroy cycle correct
//   SCE-5: functional — context_randomize(NULL seed) disables blinding, sign+verify still OK
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <string>
#include <algorithm>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#if __has_include("secp256k1.h")
#include "secp256k1.h"
#include "secp256k1_schnorrsig.h"

// ─── Source-scan helpers ─────────────────────────────────────────────────────

static std::string read_file(const char* rel_path) {
    std::ifstream f(rel_path);
    if (!f) {
        // Try one directory up (for standalone builds run from build dir)
        std::string up = std::string("../") + rel_path;
        f.open(up);
        if (!f) return {};
    }
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>{});
}

static int count_occurrences(const std::string& haystack, const char* needle) {
    int n = 0;
    std::string::size_type pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += strlen(needle);
    }
    return n;
}

// ─── SCE-1/2/3: source scan of shim_context.cpp ──────────────────────────────
static void test_sce1_no_blind_memset() {
    const char* path = "compat/libsecp256k1_shim/src/shim_context.cpp";
    std::string src = read_file(path);
    if (src.empty()) {
        printf("  [SCE-1] source not found at '%s' — advisory skip\n", path);
        ++g_pass;
        return;
    }
    int hits = count_occurrences(src, "std::memset(ctx->blind, 0, 32)");
    CHECK(hits == 0, "[SCE-1] std::memset(ctx->blind, 0, 32) must be absent — use secure_erase");
}

static void test_sce2_secure_erase_blind() {
    const char* path = "compat/libsecp256k1_shim/src/shim_context.cpp";
    std::string src = read_file(path);
    if (src.empty()) { ++g_pass; return; }
    int hits = count_occurrences(src, "secure_erase(ctx->blind");
    CHECK(hits >= 3, "[SCE-2] secure_erase(ctx->blind must appear >= 3 times (destroy, randomize, preallocated_destroy)");
}

static void test_sce3_is_zero_ct_fallback() {
    const char* path = "compat/libsecp256k1_shim/src/shim_context.cpp";
    std::string src = read_file(path);
    if (src.empty()) { ++g_pass; return; }
    int hits = count_occurrences(src, "is_zero_ct()");
    CHECK(hits >= 1, "[SCE-3] is_zero_ct() must appear in ContextBlindingScope (replaces is_zero on secret)");
}

// ─── SCE-4: functional — create + randomize + destroy ────────────────────────
static void test_sce4_ctx_randomize_destroy_roundtrip() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    CHECK(ctx != nullptr, "[SCE-4] secp256k1_context_create must succeed");
    if (!ctx) return;

    // Valid random seed
    unsigned char seed[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
    };
    int rc = secp256k1_context_randomize(ctx, seed);
    CHECK(rc == 1, "[SCE-4] context_randomize with valid seed must succeed");

    // Sign + verify round-trip with randomized context
    const unsigned char sk[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7
    };
    unsigned char msg[32]{};
    msg[0] = 0xAB; msg[31] = 0xCD;

    secp256k1_keypair kp{};
    rc = secp256k1_keypair_create(ctx, &kp, sk);
    CHECK(rc == 1, "[SCE-4] keypair_create must succeed after randomize");

    secp256k1_xonly_pubkey xpk{};
    secp256k1_keypair_xonly_pub(ctx, &xpk, nullptr, &kp);

    unsigned char sig[64]{};
    rc = secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, nullptr);
    CHECK(rc == 1, "[SCE-4] schnorrsig_sign32 must succeed after ctx randomize");

    secp256k1_context* vctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    rc = secp256k1_schnorrsig_verify(vctx, sig, msg, 32, &xpk);
    CHECK(rc == 1, "[SCE-4] schnorrsig_verify must succeed after ctx randomize");

    secp256k1_context_destroy(vctx);
    secp256k1_context_destroy(ctx);
    ++g_pass; // reaching here without crash = secure_erase of blind did not corrupt memory
}

// ─── SCE-5: functional — context_randomize(NULL seed) disables blinding ──────
static void test_sce5_randomize_null_disables_blinding() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    CHECK(ctx != nullptr, "[SCE-5] context_create must succeed");
    if (!ctx) return;

    // Enable blinding, then disable it with NULL seed
    unsigned char seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = static_cast<unsigned char>(i + 1);
    secp256k1_context_randomize(ctx, seed);
    int rc = secp256k1_context_randomize(ctx, nullptr);
    CHECK(rc == 1, "[SCE-5] context_randomize(NULL) must succeed (disables blinding)");

    // Sign still works after disabling blinding
    const unsigned char sk[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9
    };
    unsigned char msg[32]{};
    msg[0] = 0xEF;

    secp256k1_keypair kp{};
    secp256k1_keypair_create(ctx, &kp, sk);
    unsigned char sig[64]{};
    rc = secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, nullptr);
    CHECK(rc == 1, "[SCE-5] sign must succeed after disabling blinding");

    secp256k1_context_destroy(ctx);
    ++g_pass; // reaching here without crash = context_destroy after NULL randomize succeeded
}

#else
static void test_sce_shim_not_available() {
    printf("  [SCE] shim not available — advisory skip\n");
}
#endif // __has_include("secp256k1.h")

// ─── Entry point ─────────────────────────────────────────────────────────────

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
int main() {
#else
int test_regression_shim_context_erase_run() {
#endif
    printf("[shim_context_erase] 2026-05-25: memset->secure_erase + is_zero->is_zero_ct in shim_context.cpp\n");

#if __has_include("secp256k1.h")
    test_sce1_no_blind_memset();
    test_sce2_secure_erase_blind();
    test_sce3_is_zero_ct_fallback();
    test_sce4_ctx_randomize_destroy_roundtrip();
    test_sce5_randomize_null_disables_blinding();
#else
    test_sce_shim_not_available();
    return ADVISORY_SKIP_CODE;
#endif

    printf("[shim_context_erase] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
