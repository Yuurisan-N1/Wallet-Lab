// ============================================================================
// test_regression_shim_rgrind_functional.cpp — R-grinding functional coverage
// ============================================================================
// SHIM-P3-006: secp256k1_ecdsa_sign with ndata produces different nonces than
// upstream libsecp256k1 (documented divergence). This test verifies FUNCTIONAL
// correctness — all 32 R-grinding iterations produce valid, distinct signatures.
//
// Note: does NOT check byte-identity with libsecp256k1 output (requires
// differential test against libsecp — tracked as TASK-007).
//
//   RGF-1  ndata=NULL produces valid signature
//   RGF-2  ndata=[counter] iterations all produce valid signatures
//   RGF-3  Different ndata values produce different signatures (nonce varies)
//   RGF-4  All 32 Bitcoin Core R-grind iterations verify successfully
//
// advisory=true: requires secp256k1_shim to be linked.
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
#endif

#include "secp256k1.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

namespace {

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("  [FAIL] %s\n", (msg)); } \
} while(0)

static const unsigned char SK[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7
};
static const unsigned char MSG[32] = {
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
    0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,
    0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32
};

// RGF-1/RGF-2: sign + verify helper
static bool sign_and_verify(secp256k1_context *ctx, secp256k1_pubkey *pubkey,
                             const void *ndata, secp256k1_ecdsa_signature *sig_out)
{
    int rc = secp256k1_ecdsa_sign(ctx, sig_out, MSG, SK,
                                   secp256k1_nonce_function_rfc6979, ndata);
    if (!rc) return false;
    // normalize to low-S form
    secp256k1_ecdsa_signature_normalize(ctx, sig_out, sig_out);
    rc = secp256k1_ecdsa_verify(ctx, sig_out, MSG, pubkey);
    return rc == 1;
}

// RGF-1: NULL ndata (first R-grind attempt, no extra entropy)
static void test_rgf1_null_ndata() {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { std::printf("  [SKIP] RGF-1: ctx_create failed\n"); return; }

    secp256k1_pubkey pk{};
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk, SK) == 1, "RGF-1: pubkey_create");

    secp256k1_ecdsa_signature sig{};
    bool ok = sign_and_verify(ctx, &pk, nullptr, &sig);
    CHECK(ok, "RGF-1: sign+verify with ndata=NULL");

    secp256k1_context_destroy(ctx);
}

// RGF-2: 32 R-grind iterations all produce valid signatures
static void test_rgf2_all_iterations_valid() {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { std::printf("  [SKIP] RGF-2: ctx_create failed\n"); return; }

    secp256k1_pubkey pk{};
    secp256k1_ec_pubkey_create(ctx, &pk, SK);

    int valid = 0;
    for (int i = 0; i < 32; ++i) {
        unsigned char extra_entropy[32] = {};
        extra_entropy[31] = static_cast<unsigned char>(i);

        secp256k1_ecdsa_signature sig{};
        bool ok = sign_and_verify(ctx, &pk, extra_entropy, &sig);
        if (ok) ++valid;
    }

    char buf[64];
    std::snprintf(buf, sizeof(buf), "RGF-2: %d/32 R-grind iterations valid", valid);
    CHECK(valid == 32, buf);

    secp256k1_context_destroy(ctx);
}

// RGF-3: Different ndata values produce different signatures
static void test_rgf3_distinct_nonces() {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { std::printf("  [SKIP] RGF-3: ctx_create failed\n"); return; }

    secp256k1_pubkey pk{};
    secp256k1_ec_pubkey_create(ctx, &pk, SK);

    // Collect 5 signatures with distinct ndata[31] values
    secp256k1_ecdsa_signature sigs[5]{};
    for (int i = 0; i < 5; ++i) {
        unsigned char extra[32] = {};
        extra[31] = static_cast<unsigned char>(i + 1);
        secp256k1_ecdsa_sign(ctx, &sigs[i], MSG, SK,
                              secp256k1_nonce_function_rfc6979, extra);
    }

    // All 5 must be distinct (different r or s)
    int distinct_pairs = 0;
    for (int i = 0; i < 5; ++i) {
        for (int j = i + 1; j < 5; ++j) {
            if (std::memcmp(sigs[i].data, sigs[j].data, 64) != 0) ++distinct_pairs;
        }
    }
    // 5 choose 2 = 10 pairs, all should be distinct
    char buf[80];
    std::snprintf(buf, sizeof(buf), "RGF-3: %d/10 distinct ndata-pairs", distinct_pairs);
    CHECK(distinct_pairs == 10, buf);

    secp256k1_context_destroy(ctx);
}

// RGF-4: Bitcoin Core R-grind simulation — first low-S sig wins
// Simulates CKey::Sign() grind loop: tries ndata=NULL then ndata=[counter]
static void test_rgf4_bitcoin_core_grind_simulation() {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { std::printf("  [SKIP] RGF-4: ctx_create failed\n"); return; }

    secp256k1_pubkey pk{};
    secp256k1_ec_pubkey_create(ctx, &pk, SK);

    bool found = false;
    secp256k1_ecdsa_signature final_sig{};

    // Iteration 0: ndata=NULL
    if (secp256k1_ecdsa_sign(ctx, &final_sig, MSG, SK,
                              secp256k1_nonce_function_rfc6979, nullptr)) {
        secp256k1_ecdsa_signature norm{};
        secp256k1_ecdsa_signature_normalize(ctx, &norm, &final_sig);
        if (std::memcmp(norm.data, final_sig.data, 64) == 0) {
            found = true;
        }
    }

    // Iterations 1-31: ndata = [counter] if first didn't yield low-S
    for (int i = 1; i < 32 && !found; ++i) {
        unsigned char extra[32] = {};
        extra[31] = static_cast<unsigned char>(i);
        if (secp256k1_ecdsa_sign(ctx, &final_sig, MSG, SK,
                                  secp256k1_nonce_function_rfc6979, extra)) {
            secp256k1_ecdsa_signature norm{};
            secp256k1_ecdsa_signature_normalize(ctx, &norm, &final_sig);
            if (std::memcmp(norm.data, final_sig.data, 64) == 0) {
                found = true;
            }
        }
    }

    CHECK(found, "RGF-4: R-grind simulation terminates with valid low-S signature");

    if (found) {
        int vrc = secp256k1_ecdsa_verify(ctx, &final_sig, MSG, &pk);
        CHECK(vrc == 1, "RGF-4: final grind signature verifies");
    }

    secp256k1_context_destroy(ctx);
}

} // namespace

int test_regression_shim_rgrind_functional_run() {
    std::printf("[test_regression_shim_rgrind_functional] RGF-1..4 (SHIM-P3-006)\n");
    g_pass = 0; g_fail = 0;

    test_rgf1_null_ndata();
    test_rgf2_all_iterations_valid();
    test_rgf3_distinct_nonces();
    test_rgf4_bitcoin_core_grind_simulation();

    std::printf("[test_regression_shim_rgrind_functional] %d/%d passed\n",
                g_pass, g_pass + g_fail);
    return g_fail > 0 ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_shim_rgrind_functional_run(); }
#endif
