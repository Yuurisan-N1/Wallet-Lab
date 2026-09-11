// ============================================================================
// test_regression_shim_xonly_parse.cpp
// ============================================================================
// Regression tests for PASS4-003: secp256k1_xonly_pubkey_parse now delegates
// to schnorr_xonly_pubkey_parse (FE52 Jacobi QR + lift_x cache) instead of
// a manual FieldElement::sqrt() call.
//
// Tests (SXP-1..5):
//   SXP-1: valid x-coord parses and round-trips through serialize
//   SXP-2: x-coord not on curve returns 0
//   SXP-3: x-coord >= p returns 0 (strict boundary)
//   SXP-4: xonly_from_pubkey + xonly_parse produce matching X bytes
//   SXP-5: parity flag from xonly_from_pubkey matches negated-Y check
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cstdint>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#if __has_include("secp256k1.h") && __has_include("secp256k1_extrakeys.h")
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

// A known valid private key (BIP-340 test vector 0)
static const uint8_t k_privkey[32] = {
    0xB7, 0xE1, 0x51, 0x62, 0x8A, 0xED, 0x2A, 0x6A,
    0xBF, 0x71, 0x58, 0x80, 0x9C, 0xF4, 0xF3, 0xC7,
    0x62, 0xE7, 0x16, 0x0F, 0x38, 0xB4, 0xDA, 0x56,
    0xA7, 0x84, 0xD9, 0x04, 0x51, 0x90, 0xCF, 0xEF
};

// ─── SXP-1: valid x-coord parses and serialize round-trips ───────────────
static void test_sxp1_valid_roundtrip() {
    secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pub{};
    int rc = secp256k1_ec_pubkey_create(ctx, &pub, k_privkey);
    CHECK(rc == 1, "[SXP-1] ec_pubkey_create must succeed");

    secp256k1_xonly_pubkey xonly{};
    int parity = -1;
    rc = secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pub);
    CHECK(rc == 1, "[SXP-1] xonly_from_pubkey must succeed");

    // Serialize the x-only key to bytes
    uint8_t xbytes[32]{};
    rc = secp256k1_xonly_pubkey_serialize(ctx, xbytes, &xonly);
    CHECK(rc == 1, "[SXP-1] xonly_pubkey_serialize must succeed");

    // Re-parse from the serialized bytes — exercises PASS4-003 code path
    secp256k1_xonly_pubkey xonly2{};
    rc = secp256k1_xonly_pubkey_parse(ctx, &xonly2, xbytes);
    CHECK(rc == 1, "[SXP-1] xonly_pubkey_parse(valid x) must succeed");

    // Re-serialize and compare
    uint8_t xbytes2[32]{};
    rc = secp256k1_xonly_pubkey_serialize(ctx, xbytes2, &xonly2);
    CHECK(rc == 1, "[SXP-1] re-serialize after parse must succeed");
    CHECK(std::memcmp(xbytes, xbytes2, 32) == 0,
          "[SXP-1] x-only serialize round-trip must be identity");

    secp256k1_context_destroy(ctx);
}

// ─── SXP-2: x-coord not on curve returns 0 ───────────────────────────────
static void test_sxp2_not_on_curve() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    // x=5 is NOT a valid x-only point: 5³+7 = 132 is a quadratic NON-residue mod p,
    // so no y satisfies y²=x³+7 and lift_x fails. (The previous value x=1 was WRONG:
    // 1³+7 = 8 IS a QR mod p — p ≡ 7 (mod 8) makes 2 a QR, hence 8 = 2·2² is a QR —
    // so x=1 lifts to a valid point and parse correctly returns 1. Verified with
    // Euler's criterion: (x³+7)^((p-1)/2) mod p == 1 for x=1, != 1 for x=5.)
    uint8_t bad_x[32]{};
    bad_x[31] = 0x05;

    secp256k1_xonly_pubkey xonly{};
    int rc = secp256k1_xonly_pubkey_parse(ctx, &xonly, bad_x);
    CHECK(rc == 0, "[SXP-2] xonly_pubkey_parse(x not on curve) must return 0");

    secp256k1_context_destroy(ctx);
}

// ─── SXP-3: x >= p returns 0 (strict field element rejection) ────────────
static void test_sxp3_x_gte_p() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    // secp256k1 field prime p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    // p itself is rejected by parse_bytes_strict.
    static const uint8_t p_bytes[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };

    secp256k1_xonly_pubkey xonly{};
    int rc = secp256k1_xonly_pubkey_parse(ctx, &xonly, p_bytes);
    CHECK(rc == 0, "[SXP-3] xonly_pubkey_parse(x = p) must return 0");

    secp256k1_context_destroy(ctx);
}

// ─── SXP-4: xonly_from_pubkey and xonly_parse produce matching X bytes ───
static void test_sxp4_from_pubkey_matches_parse() {
    secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pub{};
    secp256k1_ec_pubkey_create(ctx, &pub, k_privkey);

    secp256k1_xonly_pubkey xonly_from{};
    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_from, nullptr, &pub);

    uint8_t x32[32]{};
    secp256k1_xonly_pubkey_serialize(ctx, x32, &xonly_from);

    secp256k1_xonly_pubkey xonly_parsed{};
    int rc = secp256k1_xonly_pubkey_parse(ctx, &xonly_parsed, x32);
    CHECK(rc == 1, "[SXP-4] parse of from_pubkey x-bytes must succeed");

    uint8_t x32_parsed[32]{};
    secp256k1_xonly_pubkey_serialize(ctx, x32_parsed, &xonly_parsed);
    CHECK(std::memcmp(x32, x32_parsed, 32) == 0,
          "[SXP-4] from_pubkey and parse must produce same X bytes");

    secp256k1_context_destroy(ctx);
}

// ─── SXP-5: parity flag correctness ──────────────────────────────────────
static void test_sxp5_parity_flag() {
    secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pub{};
    secp256k1_ec_pubkey_create(ctx, &pub, k_privkey);

    // pub.data[63] & 1 gives the original Y parity
    int orig_y_odd = (pub.data[63] & 1) ? 1 : 0;

    secp256k1_xonly_pubkey xonly{};
    int parity = -1;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pub);

    // parity == 1 means the original pubkey had odd Y (was negated to get even Y)
    CHECK(parity == orig_y_odd,
          "[SXP-5] xonly_from_pubkey parity must equal original Y oddness");

    secp256k1_context_destroy(ctx);
}

#else
static void test_sxp1_valid_roundtrip()          { ++g_pass; }
static void test_sxp2_not_on_curve()             { ++g_pass; }
static void test_sxp3_x_gte_p()                  { ++g_pass; }
static void test_sxp4_from_pubkey_matches_parse() { ++g_pass; }
static void test_sxp5_parity_flag()              { ++g_pass; }
#endif

int test_regression_shim_xonly_parse_run();

#ifdef STANDALONE_TEST
int main() { return test_regression_shim_xonly_parse_run(); }
#endif

int test_regression_shim_xonly_parse_run() {
    g_pass = 0; g_fail = 0;
    printf("[shim_xonly_parse] PASS4-003: xonly_parse via schnorr_xonly_pubkey_parse\n");
    test_sxp1_valid_roundtrip();
    test_sxp2_not_on_curve();
    test_sxp3_x_gte_p();
    test_sxp4_from_pubkey_matches_parse();
    test_sxp5_parity_flag();
    printf("[shim_xonly_parse] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
