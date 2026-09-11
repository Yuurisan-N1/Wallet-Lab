// ============================================================================
// REGRESSION: secp256k1_musig_nonce_gen seckey handling (P2-SEC-002/003)
//
// P2-SEC-002: When seckey is NULL, the shim must NOT use session_id32 as a
//   private-key substitute in the HMAC-DRBG. Fixed: zero scalar used when
//   seckey is absent (nonce derived from session_id32+pubkey+msg only).
// P2-SEC-003: The sk Scalar parsed from seckey must be erased before return.
//   Verified indirectly: function must complete without crash or UB.
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
#endif

#if defined(SECP256K1_BUILD_COMPAT_SHIM) || defined(UNIFIED_AUDIT_RUNNER)

#include "secp256k1.h"
#include "secp256k1_musig.h"
#include "secp256k1_schnorrsig.h"  // secp256k1_schnorrsig_verify (MNG final-sig check)
#include <cstdio>
#include <cstring>
#include <array>

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

static const unsigned char kSk1[32] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
};
static const unsigned char kSk2[32] = {
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
};
static const unsigned char kSessionId[32] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
};

// ── MNG-1: nonce_gen with valid seckey succeeds ───────────────────────────
static void test_nonce_gen_with_seckey() {
    std::printf("  [MNG-1] secp256k1_musig_nonce_gen with seckey succeeds\n");

    secp256k1_pubkey pk1, pk2;
    CHECK(secp256k1_ec_pubkey_create(sctx(), &pk1, kSk1) == 1, "MNG-1: create pk1");
    CHECK(secp256k1_ec_pubkey_create(sctx(), &pk2, kSk2) == 1, "MNG-1: create pk2");

    const secp256k1_pubkey* pks[2] = {&pk1, &pk2};
    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey agg_pk;
    CHECK(secp256k1_musig_pubkey_agg(sctx(), &agg_pk, &cache, pks, 2) == 1,
          "MNG-1: pubkey_agg ok");

    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
    int rc = secp256k1_musig_nonce_gen(
        sctx(), &secnonce, &pubnonce, kSessionId,
        kSk1, &pk1, nullptr, &cache, nullptr);
    CHECK(rc == 1, "MNG-1: nonce_gen with seckey returns 1");

    // Pubnonce bytes must be non-zero
    bool pn_nonzero = false;
    for (int i = 0; i < 66; ++i) if (pubnonce.data[i]) { pn_nonzero = true; break; }
    CHECK(pn_nonzero, "MNG-1: pubnonce is non-zero");
}

// ── MNG-2: nonce_gen with NULL seckey succeeds (P2-SEC-002 regression) ──
static void test_nonce_gen_null_seckey() {
    std::printf("  [MNG-2] secp256k1_musig_nonce_gen with NULL seckey succeeds\n");

    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
    // NULL seckey: nonce derived from session_id32+msg+pubkey only (zero sk).
    // Must NOT crash, must NOT use session_id32 as a private key.
    int rc = secp256k1_musig_nonce_gen(
        sctx(), &secnonce, &pubnonce, kSessionId,
        nullptr, nullptr, nullptr, nullptr, nullptr);
    CHECK(rc == 1, "MNG-2: nonce_gen with NULL seckey returns 1");

    bool pn_nonzero = false;
    for (int i = 0; i < 66; ++i) if (pubnonce.data[i]) { pn_nonzero = true; break; }
    CHECK(pn_nonzero, "MNG-2: pubnonce is non-zero even with NULL seckey");
}

// ── MNG-3: different session_ids produce different nonces ────────────────
static void test_nonce_gen_different_sessions() {
    std::printf("  [MNG-3] different session_id32 produce different pubnonces\n");

    unsigned char sid1[32] = {0x01}, sid2[32] = {0x02};
    secp256k1_musig_secnonce sn1, sn2;
    secp256k1_musig_pubnonce pn1, pn2;

    CHECK(secp256k1_musig_nonce_gen(sctx(), &sn1, &pn1, sid1,
                                    nullptr, nullptr, nullptr, nullptr, nullptr) == 1,
          "MNG-3: gen session 1");
    CHECK(secp256k1_musig_nonce_gen(sctx(), &sn2, &pn2, sid2,
                                    nullptr, nullptr, nullptr, nullptr, nullptr) == 1,
          "MNG-3: gen session 2");

    bool different = (memcmp(pn1.data, pn2.data, 66) != 0);
    CHECK(different, "MNG-3: different session_ids produce different pubnonces");
}

// ── MNG-4: full 2-of-2 signing flow using nonce_gen ─────────────────────
static void test_nonce_gen_full_flow() {
    std::printf("  [MNG-4] full 2-of-2 signing flow through secp256k1_musig_nonce_gen\n");

    secp256k1_pubkey pk1, pk2;
    CHECK(secp256k1_ec_pubkey_create(sctx(), &pk1, kSk1) == 1, "MNG-4: pk1");
    CHECK(secp256k1_ec_pubkey_create(sctx(), &pk2, kSk2) == 1, "MNG-4: pk2");
    const secp256k1_pubkey* pks[2] = {&pk1, &pk2};

    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey agg_pk;
    CHECK(secp256k1_musig_pubkey_agg(sctx(), &agg_pk, &cache, pks, 2) == 1,
          "MNG-4: pubkey_agg");

    unsigned char sid1[32] = {0xAA}, sid2[32] = {0xBB};
    secp256k1_musig_secnonce sn1, sn2;
    secp256k1_musig_pubnonce pn1, pn2;
    CHECK(secp256k1_musig_nonce_gen(sctx(), &sn1, &pn1, sid1, kSk1, &pk1, nullptr, &cache, nullptr) == 1, "MNG-4: nonce1");
    CHECK(secp256k1_musig_nonce_gen(sctx(), &sn2, &pn2, sid2, kSk2, &pk2, nullptr, &cache, nullptr) == 1, "MNG-4: nonce2");

    const secp256k1_musig_pubnonce* pns[2] = {&pn1, &pn2};
    secp256k1_musig_aggnonce agg_nonce;
    CHECK(secp256k1_musig_nonce_agg(sctx(), &agg_nonce, pns, 2) == 1, "MNG-4: nonce_agg");

    unsigned char msg[32] = {0x42};
    secp256k1_musig_session session;
    CHECK(secp256k1_musig_nonce_process(sctx(), &session, &agg_nonce, msg, &cache) == 1, "MNG-4: nonce_process");

    secp256k1_keypair kp1, kp2;
    CHECK(secp256k1_keypair_create(sctx(), &kp1, kSk1) == 1, "MNG-4: kp1");
    CHECK(secp256k1_keypair_create(sctx(), &kp2, kSk2) == 1, "MNG-4: kp2");

    secp256k1_musig_partial_sig psig1, psig2;
    CHECK(secp256k1_musig_partial_sign(sctx(), &psig1, &sn1, &kp1, &cache, &session) == 1, "MNG-4: psig1");
    CHECK(secp256k1_musig_partial_sign(sctx(), &psig2, &sn2, &kp2, &cache, &session) == 1, "MNG-4: psig2");

    const secp256k1_musig_partial_sig* psigs[2] = {&psig1, &psig2};
    unsigned char sig[64];
    CHECK(secp256k1_musig_partial_sig_agg(sctx(), sig, &session, psigs, 2) == 1, "MNG-4: sig_agg");

    CHECK(secp256k1_schnorrsig_verify(sctx(), sig, msg, 32, &agg_pk) == 1, "MNG-4: verify");
}

int test_regression_musig2_nonce_gen_seckey_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_musig2_nonce_gen_seckey] P2-SEC-002/003: musig_nonce_gen seckey fix\n");
    test_nonce_gen_with_seckey();
    test_nonce_gen_null_seckey();
    test_nonce_gen_different_sessions();
    test_nonce_gen_full_flow();
    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#else

int test_regression_musig2_nonce_gen_seckey_run() { return 77; }  // ADVISORY_SKIP_CODE

#endif

#ifdef STANDALONE_TEST
int main() { return test_regression_musig2_nonce_gen_seckey_run(); }
#endif
