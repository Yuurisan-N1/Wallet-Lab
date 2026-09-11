// ============================================================================
// REGRESSION: secp256k1_ecdsa_sign ndata (hedged) R-grinding bounded termination
//
// SHIM-010 (was SHIM-005): Bitcoin Core uses secp256k1_ecdsa_sign with a
// noncefp=NULL and a ndata counter byte to R-grind low-R signatures. The shim
// uses ct::ecdsa_sign_hedged (rfc6979_nonce_hedged) when ndata != NULL.
// Differences from libsecp nonce derivation: hedged variant uses a 129-byte
// HMAC input instead of libsecp's RFC6979 + extra_entropy (96+32 bytes).
//
// This test verifies:
//   NRG-1: ecdsa_sign with ndata produces a valid signature
//   NRG-2: different ndata produce different signatures (nonce varies)
//   NRG-3: same ndata + same (key, msg) produce identical signatures (deterministic)
//   NRG-4: Bitcoin Core R-grinding pattern terminates within 100 iterations
//   NRG-5: ecdsa_sign without ndata also produces valid signatures (regression)
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
#endif

#if defined(SECP256K1_BUILD_COMPAT_SHIM) || defined(UNIFIED_AUDIT_RUNNER)

#include "secp256k1.h"
#include <cstdio>
#include <cstring>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("  FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg); } \
} while(0)

static const secp256k1_context* sctx() {
    static secp256k1_context* s = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return s;
}

static const unsigned char kSk[32] = {
    0xB7,0xE1,0x51,0x62,0x8A,0xED,0x2A,0x6A,
    0xBF,0x71,0x58,0x80,0x9C,0xF4,0xF3,0xC7,
    0x62,0xE7,0x16,0x0F,0x38,0xB4,0xDA,0x56,
    0xA7,0x84,0xD9,0x04,0x51,0x90,0xCF,0xEF,
};
static const unsigned char kMsg[32] = {
    0x24,0x3F,0x6A,0x88,0x85,0xA3,0x08,0xD3,
    0x13,0x19,0x8A,0x2E,0x03,0x70,0x73,0x44,
    0xA4,0x09,0x38,0x22,0x29,0x9F,0x31,0xD0,
    0x08,0x2E,0xFA,0x98,0xEC,0x4E,0x6C,0x89,
};

// ── NRG-1: ecdsa_sign with ndata produces valid signature ─────────────────
static void test_ndata_sign_valid() {
    std::printf("  [NRG-1] secp256k1_ecdsa_sign with ndata produces valid signature\n");

    secp256k1_pubkey pk;
    CHECK(secp256k1_ec_pubkey_create(sctx(), &pk, kSk) == 1, "NRG-1: create pubkey");

    unsigned char ndata[32] = {0x01};
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_sign(sctx(), &sig, kMsg, kSk, nullptr, ndata);
    CHECK(rc == 1, "NRG-1: sign with ndata returns 1");
    CHECK(secp256k1_ecdsa_verify(sctx(), &sig, kMsg, &pk) == 1, "NRG-1: signature verifies");
}

// ── NRG-2: different ndata → different signatures ────────────────────────
static void test_ndata_different_nonce() {
    std::printf("  [NRG-2] different ndata produce different signatures\n");

    unsigned char nd1[32] = {0x01}, nd2[32] = {0x02};
    secp256k1_ecdsa_signature sig1, sig2;
    CHECK(secp256k1_ecdsa_sign(sctx(), &sig1, kMsg, kSk, nullptr, nd1) == 1, "NRG-2: sig1");
    CHECK(secp256k1_ecdsa_sign(sctx(), &sig2, kMsg, kSk, nullptr, nd2) == 1, "NRG-2: sig2");
    CHECK(memcmp(sig1.data, sig2.data, 64) != 0, "NRG-2: different ndata → different sigs");
}

// ── NRG-3: same inputs → identical signatures (deterministic) ────────────
static void test_ndata_deterministic() {
    std::printf("  [NRG-3] same (key, msg, ndata) → identical signature\n");

    unsigned char nd[32] = {0x42};
    secp256k1_ecdsa_signature s1, s2;
    CHECK(secp256k1_ecdsa_sign(sctx(), &s1, kMsg, kSk, nullptr, nd) == 1, "NRG-3: s1");
    CHECK(secp256k1_ecdsa_sign(sctx(), &s2, kMsg, kSk, nullptr, nd) == 1, "NRG-3: s2");
    CHECK(memcmp(s1.data, s2.data, 64) == 0, "NRG-3: deterministic with same ndata");
}

// ── NRG-4: Bitcoin Core R-grinding pattern terminates ────────────────────
// Bitcoin Core iterates ndata[0]++ to find low-R signatures (r < 0x80...).
// Low-R probability per attempt: ~50%. Expect termination in <100 iterations.
static void test_ndata_rgrind_terminates() {
    std::printf("  [NRG-4] Bitcoin Core R-grinding ndata pattern terminates\n");

    secp256k1_pubkey pk;
    CHECK(secp256k1_ec_pubkey_create(sctx(), &pk, kSk) == 1, "NRG-4: pubkey");

    unsigned char ndata[32] = {};
    secp256k1_ecdsa_signature sig;
    int found = 0;

    for (int attempt = 0; attempt < 100; ++attempt) {
        ndata[0] = static_cast<unsigned char>(attempt);
        if (secp256k1_ecdsa_sign(sctx(), &sig, kMsg, kSk, nullptr, ndata) != 1) continue;

        // Normalize to low-S
        secp256k1_ecdsa_signature_normalize(sctx(), &sig, &sig);

        // Check low-R: DER-encode and inspect r length
        unsigned char der[72]; size_t der_len = 72;
        secp256k1_ecdsa_signature_serialize_der(sctx(), der, &der_len, &sig);
        // DER: 30 [total_len] 02 [r_len] [r_bytes] 02 [s_len] [s_bytes]
        // Low-R: r_len <= 32 (no leading 0x00 padding byte needed)
        if (der[3] <= 32) { found = 1; break; }
    }

    CHECK(found, "NRG-4: R-grinding terminates within 100 iterations");
    // Verify the found signature
    if (found)
        CHECK(secp256k1_ecdsa_verify(sctx(), &sig, kMsg, &pk) == 1, "NRG-4: low-R sig verifies");
}

// ── NRG-5: ecdsa_sign without ndata (NULL) still works ───────────────────
static void test_no_ndata_still_works() {
    std::printf("  [NRG-5] secp256k1_ecdsa_sign with NULL ndata still produces valid sig\n");

    secp256k1_pubkey pk;
    CHECK(secp256k1_ec_pubkey_create(sctx(), &pk, kSk) == 1, "NRG-5: pubkey");
    secp256k1_ecdsa_signature sig;
    CHECK(secp256k1_ecdsa_sign(sctx(), &sig, kMsg, kSk, nullptr, nullptr) == 1, "NRG-5: sign");
    CHECK(secp256k1_ecdsa_verify(sctx(), &sig, kMsg, &pk) == 1, "NRG-5: verifies");
}

int test_regression_shim_ndata_rgrind_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_shim_ndata_rgrind] SHIM-010: ndata hedged nonce R-grind\n");
    test_ndata_sign_valid();
    test_ndata_different_nonce();
    test_ndata_deterministic();
    test_ndata_rgrind_terminates();
    test_no_ndata_still_works();
    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#else
int test_regression_shim_ndata_rgrind_run() { return 77; }
#endif

#ifdef STANDALONE_TEST
int main() { return test_regression_shim_ndata_rgrind_run(); }
#endif
