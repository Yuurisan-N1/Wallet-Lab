// ============================================================================
// test_nonce_uniqueness.cpp -- RFC 6979 Nonce Uniqueness & Determinism Monitor
// ============================================================================
//
// Verifies three orthogonal nonce-security properties:
//
//   A. DETERMINISM: same (privkey, msg) must always yield the same nonce k,
//      therefore the same signature. (RFC 6979 §3.2)
//
//   B. UNIQUENESS: different messages signed with the same key must yield
//      different nonces k₁ ≠ k₂ — equivalently, different r values.
//      A repeated r with the same key leaks the privkey (k-reuse attack).
//
//   C. KEY ISOLATION: different keys, same message → different r.
//      (Any fixed-nonce bias would collapse across keys.)
//
// Additional Schnorr-specific checks:
//   D. BIP-340 aux_rand=0 is deterministic (BIP-340 §default signing).
//   E. Different aux_rand bytes → different R commitment (hedged randomness).
//   F. ECDSA and Schnorr with the same (key, msg) produce DIFFERENT r values
//      (each has its own nonce derivation per RFC 6979 / BIP-340).
//
// Test numbering:
//   NU-1  … NU-6  : ECDSA determinism (6 distinct messages × 1 key)
//   NU-7  … NU-12 : ECDSA r-value uniqueness across messages (same key)
//   NU-13 … NU-17 : ECDSA r-value uniqueness across keys (same message)
//   NU-18 … NU-21 : Schnorr determinism (4 messages, aux_rand=0)
//   NU-22 … NU-25 : Schnorr r-value uniqueness across messages
//   NU-26 … NU-28 : Schnorr hedged: different aux_rand → different R
//   NU-29          : ECDSA vs Schnorr nonces differ for same (key, msg)
//   NU-30          : Multi-key round: 5 keys × 5 msgs → 25 distinct r values
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <array>
#include <vector>

#ifndef UFSECP_BUILDING
#define UFSECP_BUILDING
#endif
#include "ufsecp/ufsecp.h"

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Extract the 32-byte r value from a compact 64-byte ECDSA signature.
// In compact format: bytes [0..31] = r, bytes [32..63] = s.
static void ecdsa_r(const uint8_t sig64[64], uint8_t r32[32]) {
    std::memcpy(r32, sig64, 32);
}

// Extract the 32-byte R.x commitment from a BIP-340 Schnorr signature.
// Schnorr format: bytes [0..31] = R.x, bytes [32..63] = s.
static void schnorr_rx(const uint8_t sig64[64], uint8_t rx32[32]) {
    std::memcpy(rx32, sig64, 32);
}

// Returns true when two 32-byte values are identical.
static bool eq32(const uint8_t a[32], const uint8_t b[32]) {
    return std::memcmp(a, b, 32) == 0;
}

// Returns true when all 25 r values in a flat 25×32 array are pairwise distinct.
static bool all_distinct_32(const uint8_t* flat, int n) {
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            if (std::memcmp(flat + i * 32, flat + j * 32, 32) == 0) return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Test key material — chosen to be small, non-trivial, well-known
// ---------------------------------------------------------------------------

static constexpr uint8_t KEYS[5][32] = {
    { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1 }, // k=1
    { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,2 }, // k=2
    { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,3 }, // k=3
    { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,7 }, // k=7
    { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,11 }, // k=11
};

static constexpr uint8_t MSGS[6][32] = {
    // msg-0: sequential bytes
    { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
      0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
      0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
      0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20 },
    // msg-1: SHA-256("test") prefix
    { 0x9f,0x86,0xd0,0x81,0x88,0x4c,0x7d,0x65,
      0x9a,0x2f,0xea,0xa0,0xc5,0x5a,0xd0,0x15,
      0xa3,0xbf,0x4f,0x1b,0x2b,0x0b,0x82,0x2c,
      0xd1,0x5d,0x6c,0x15,0xb0,0xf0,0x0a,0x08 },
    // msg-2: SHA-256("abc")
    { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
      0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
      0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
      0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad },
    // msg-3: 0xdeadbeef pattern
    { 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
      0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
      0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef },
    // msg-4: high-byte pattern
    { 0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,
      0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0,
      0xef,0xee,0xed,0xec,0xeb,0xea,0xe9,0xe8,
      0xe7,0xe6,0xe5,0xe4,0xe3,0xe2,0xe1,0xe0 },
    // msg-5: near-zero (only last byte set)
    { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1 },
};

// ---------------------------------------------------------------------------
// NU-1 … NU-6 : ECDSA determinism (same (key, msg) → same sig, same r)
// ---------------------------------------------------------------------------

static void run_nu1_ecdsa_determinism(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-1..6] ECDSA RFC 6979 determinism (key=1, 6 messages)\n");

    for (int i = 0; i < 6; ++i) {
        uint8_t sig1[64] = {}, sig2[64] = {}, sig3[64] = {};
        ufsecp_error_t rc1 = ufsecp_ecdsa_sign(ctx, MSGS[i], KEYS[0], sig1);
        ufsecp_error_t rc2 = ufsecp_ecdsa_sign(ctx, MSGS[i], KEYS[0], sig2);
        ufsecp_error_t rc3 = ufsecp_ecdsa_sign(ctx, MSGS[i], KEYS[0], sig3);

        char msg[128];
        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: ECDSA msg[%d] three sign calls succeed", 1 + i, i);
        CHECK(rc1 == UFSECP_OK && rc2 == UFSECP_OK && rc3 == UFSECP_OK, msg);

        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: ECDSA msg[%d] all three sigs identical (RFC 6979 determinism)", 1 + i, i);
        CHECK(std::memcmp(sig1, sig2, 64) == 0 && std::memcmp(sig2, sig3, 64) == 0, msg);
    }
}

// ---------------------------------------------------------------------------
// NU-7 … NU-12 : ECDSA r-value uniqueness (same key, 6 distinct messages)
// Each pair of messages must produce a different r value.
// ---------------------------------------------------------------------------

static void run_nu7_ecdsa_r_uniqueness(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-7..12] ECDSA r-value uniqueness (key=1, 6 messages all differ)\n");

    uint8_t sigs[6][64] = {};
    uint8_t rs[6][32] = {};

    for (int i = 0; i < 6; ++i) {
        ufsecp_error_t rc = ufsecp_ecdsa_sign(ctx, MSGS[i], KEYS[0], sigs[i]);
        char msg[128];
        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: ECDSA sign msg[%d] with key=1 succeeds", 7 + i, i);
        CHECK(rc == UFSECP_OK, msg);
        ecdsa_r(sigs[i], rs[i]);
    }

    // Verify all 6 r values are pairwise distinct
    CHECK(all_distinct_32(rs[0], 6),
          "NU-12: all 6 ECDSA r values (6 distinct msgs, same key) are unique");
}

// ---------------------------------------------------------------------------
// NU-13 … NU-17 : ECDSA r-value uniqueness across 5 different keys (same msg)
// ---------------------------------------------------------------------------

static void run_nu13_ecdsa_key_isolation(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-13..17] ECDSA r-value uniqueness across 5 keys (same message)\n");

    uint8_t rs[5][32] = {};
    for (int k = 0; k < 5; ++k) {
        uint8_t sig[64] = {};
        ufsecp_error_t rc = ufsecp_ecdsa_sign(ctx, MSGS[0], KEYS[k], sig);
        char msg[128];
        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: ECDSA sign key[%d] with msg[0] succeeds", 13 + k, k);
        CHECK(rc == UFSECP_OK, msg);
        ecdsa_r(sig, rs[k]);
    }

    // Verify all 5 r values are pairwise distinct
    CHECK(all_distinct_32(rs[0], 5),
          "NU-17: all 5 ECDSA r values (5 keys, same msg) are unique");
}

// ---------------------------------------------------------------------------
// NU-18 … NU-21 : Schnorr BIP-340 determinism (aux_rand=0, 4 messages)
// ---------------------------------------------------------------------------

static void run_nu18_schnorr_determinism(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-18..21] Schnorr BIP-340 determinism (key=1, aux=0, 4 messages)\n");

    uint8_t aux[32] = {};  // all zeros → deterministic
    for (int i = 0; i < 4; ++i) {
        uint8_t sig1[64] = {}, sig2[64] = {}, sig3[64] = {};
        ufsecp_error_t rc1 = ufsecp_schnorr_sign(ctx, MSGS[i], KEYS[0], aux, sig1);
        ufsecp_error_t rc2 = ufsecp_schnorr_sign(ctx, MSGS[i], KEYS[0], aux, sig2);
        ufsecp_error_t rc3 = ufsecp_schnorr_sign(ctx, MSGS[i], KEYS[0], aux, sig3);

        char msg[128];
        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: Schnorr msg[%d] three sign calls succeed", 18 + i, i);
        CHECK(rc1 == UFSECP_OK && rc2 == UFSECP_OK && rc3 == UFSECP_OK, msg);

        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: Schnorr msg[%d] all three sigs identical (BIP-340 determinism)", 18 + i, i);
        CHECK(std::memcmp(sig1, sig2, 64) == 0 && std::memcmp(sig2, sig3, 64) == 0, msg);
    }
}

// ---------------------------------------------------------------------------
// NU-22 … NU-25 : Schnorr R.x uniqueness (same key, same aux, 4 distinct msgs)
// ---------------------------------------------------------------------------

static void run_nu22_schnorr_rx_uniqueness(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-22..25] Schnorr R.x uniqueness (key=1, aux=0, 4 messages all differ)\n");

    uint8_t aux[32] = {};
    uint8_t rxs[4][32] = {};

    for (int i = 0; i < 4; ++i) {
        uint8_t sig[64] = {};
        ufsecp_error_t rc = ufsecp_schnorr_sign(ctx, MSGS[i], KEYS[0], aux, sig);
        char msg[128];
        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: Schnorr sign msg[%d] with key=1 succeeds", 22 + i, i);
        CHECK(rc == UFSECP_OK, msg);
        schnorr_rx(sig, rxs[i]);
    }

    CHECK(all_distinct_32(rxs[0], 4),
          "NU-25: all 4 Schnorr R.x values (4 distinct msgs, same key+aux) are unique");
}

// ---------------------------------------------------------------------------
// NU-26 … NU-28 : Hedged Schnorr — different aux_rand → different R
// BIP-340 mixes aux_rand into nonce: same (key,msg) + different aux → different R
// ---------------------------------------------------------------------------

static void run_nu26_schnorr_hedged(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-26..28] Schnorr hedged: different aux_rand produces different R\n");

    // Three distinct aux_rand values (simulate OS entropy on each call)
    static constexpr uint8_t AUX[3][32] = {
        { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 }, // all-zero
        { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
          0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
          0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
          0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf },
        { 0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
          0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
          0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,
          0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0 },
    };

    uint8_t rxs[3][32] = {};
    uint8_t sigs[3][64] = {};
    for (int a = 0; a < 3; ++a) {
        ufsecp_error_t rc = ufsecp_schnorr_sign(ctx, MSGS[0], KEYS[0], AUX[a], sigs[a]);
        char msg[128];
        (void)std::snprintf(msg, sizeof(msg),
            "NU-%d: Schnorr hedged sign with aux[%d] succeeds", 26 + a, a);
        CHECK(rc == UFSECP_OK, msg);
        schnorr_rx(sigs[a], rxs[a]);
    }

    // aux[0] vs aux[1] must yield different R
    CHECK(!eq32(rxs[0], rxs[1]),
          "NU-26: Schnorr aux[0] vs aux[1] produce different R (hedged)");
    CHECK(!eq32(rxs[1], rxs[2]),
          "NU-27: Schnorr aux[1] vs aux[2] produce different R (hedged)");
    CHECK(!eq32(rxs[0], rxs[2]),
          "NU-28: Schnorr aux[0] vs aux[2] produce different R (hedged)");
}

// ---------------------------------------------------------------------------
// NU-29 : ECDSA vs Schnorr — different nonce derivation for same (key, msg)
// ECDSA uses RFC 6979 HMAC-DRBG; Schnorr uses BIP-340 tagged-hash.
// They MUST yield different r / R.x values.
// ---------------------------------------------------------------------------

static void run_nu29_ecdsa_vs_schnorr(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-29] ECDSA r vs Schnorr R.x differ for same (key, msg)\n");

    uint8_t aux[32] = {};  // deterministic Schnorr
    uint8_t sig_ecdsa[64] = {}, sig_schnorr[64] = {};
    ufsecp_error_t rc1 = ufsecp_ecdsa_sign(ctx, MSGS[0], KEYS[0], sig_ecdsa);
    ufsecp_error_t rc2 = ufsecp_schnorr_sign(ctx, MSGS[0], KEYS[0], aux, sig_schnorr);

    CHECK(rc1 == UFSECP_OK && rc2 == UFSECP_OK,
          "NU-29a: ECDSA and Schnorr sign calls both succeed");

    uint8_t r_ecdsa[32], rx_schnorr[32];
    ecdsa_r(sig_ecdsa, r_ecdsa);
    schnorr_rx(sig_schnorr, rx_schnorr);

    CHECK(!eq32(r_ecdsa, rx_schnorr),
          "NU-29: ECDSA r != Schnorr R.x for same (key=1, msg[0]) — different nonce paths");
}

// ---------------------------------------------------------------------------
// NU-30 : 5-key × 5-msg round — 25 (key, msg) pairs → 25 distinct r values
// This is a comprehensive k-reuse absence check over the test matrix.
// ---------------------------------------------------------------------------

static void run_nu30_matrix(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [NU-30] 5-key × 5-msg ECDSA matrix: 25 r values must all be distinct\n");

    // Collect 25 ECDSA r values
    uint8_t all_r[25][32] = {};
    bool all_ok = true;

    for (int k = 0; k < 5; ++k) {
        for (int m = 0; m < 5; ++m) {
            uint8_t sig[64] = {};
            ufsecp_error_t rc = ufsecp_ecdsa_sign(ctx, MSGS[m], KEYS[k], sig);
            if (rc != UFSECP_OK) { all_ok = false; continue; }
            ecdsa_r(sig, all_r[k * 5 + m]);
        }
    }

    CHECK(all_ok, "NU-30a: all 25 ECDSA sign calls in matrix succeed");

    CHECK(all_distinct_32(all_r[0], 25),
          "NU-30: all 25 r values (5-key × 5-msg ECDSA matrix) are pairwise distinct");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int test_nonce_uniqueness_run() {
    g_pass = 0; g_fail = 0;

    AUDIT_LOG("============================================================\n");
    AUDIT_LOG("  RFC 6979 Nonce Uniqueness & Determinism Monitor\n");
    AUDIT_LOG("  ECDSA + Schnorr nonce determinism, uniqueness, isolation\n");
    AUDIT_LOG("============================================================\n");

    ufsecp_ctx* ctx = nullptr;
    if (ufsecp_ctx_create(&ctx) != UFSECP_OK || ctx == nullptr) {
        CHECK(false, "NU-ctx: failed to create context");
        printf("[test_nonce_uniqueness] %d/%d checks passed (context creation failed)\n",
               g_pass, g_pass + g_fail);
        return 1;
    }

    run_nu1_ecdsa_determinism(ctx);
    run_nu7_ecdsa_r_uniqueness(ctx);
    run_nu13_ecdsa_key_isolation(ctx);
    run_nu18_schnorr_determinism(ctx);
    run_nu22_schnorr_rx_uniqueness(ctx);
    run_nu26_schnorr_hedged(ctx);
    run_nu29_ecdsa_vs_schnorr(ctx);
    run_nu30_matrix(ctx);

    ufsecp_ctx_destroy(ctx);

    printf("[test_nonce_uniqueness] %d/%d checks passed\n",
           g_pass, g_pass + g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#ifndef UNIFIED_AUDIT_RUNNER
int main() {
    return test_nonce_uniqueness_run();
}
#endif
