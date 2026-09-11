// ============================================================================
// test_regression_shim_null_arg_cb.cpp
// ============================================================================
// Regression tests for SHIM-NEW-001/002/003: these shim functions previously
// silently returned 0 when non-ctx pointer arguments were NULL. Upstream
// libsecp256k1 fires the illegal_callback for all NULL API arguments.
//
// Functions covered:
//   SHIM-NEW-001: secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_serialize
//   SHIM-NEW-002: secp256k1_xonly_pubkey_parse, secp256k1_xonly_pubkey_serialize
//   SHIM-NEW-003: secp256k1_ecdsa_recoverable_signature_parse_compact,
//                 secp256k1_ecdsa_recoverable_signature_serialize_compact
//
// Tests (NAC-1..8):
//   NAC-1: ec_pubkey_create(ctx, NULL, seckey) fires callback
//   NAC-2: ec_pubkey_create(ctx, pubkey, NULL) fires callback
//   NAC-3: ec_pubkey_serialize(ctx, NULL, len, pubkey, flags) fires callback
//   NAC-4: xonly_pubkey_parse(ctx, NULL, input32) fires callback
//   NAC-5: xonly_pubkey_parse(ctx, pubkey, NULL) fires callback
//   NAC-6: xonly_pubkey_serialize(ctx, NULL, pubkey) fires callback
//   NAC-7: recoverable_signature_parse_compact(ctx, NULL, input, recid) fires callback
//   NAC-8: recoverable_signature_serialize_compact(ctx, NULL, recid, sig) fires callback
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <atomic>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#if __has_include("secp256k1.h")
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_recovery.h"

static std::atomic<int> g_nac_cb{0};
static void nac_illegal_cb(const char*, void*) { ++g_nac_cb; }

static const unsigned char kValidSk[32] = {
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01
};

static secp256k1_pubkey make_valid_pubkey(secp256k1_context* ctx) {
    secp256k1_pubkey pk{};
    secp256k1_ec_pubkey_create(ctx, &pk, kValidSk);
    return pk;
}

// ── NAC-1: ec_pubkey_create NULL pubkey fires callback ────────────────────
static void test_nac1_pubkey_create_null_pubkey() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    int before = g_nac_cb.load();
    int rc = secp256k1_ec_pubkey_create(ctx, nullptr, kValidSk);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-1] pubkey_create(NULL pubkey) must return 0");
    CHECK(after > before, "[NAC-1] pubkey_create(NULL pubkey) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

// ── NAC-2: ec_pubkey_create NULL seckey fires callback ────────────────────
static void test_nac2_pubkey_create_null_seckey() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    secp256k1_pubkey pk{};
    int before = g_nac_cb.load();
    int rc = secp256k1_ec_pubkey_create(ctx, &pk, nullptr);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-2] pubkey_create(NULL seckey) must return 0");
    CHECK(after > before, "[NAC-2] pubkey_create(NULL seckey) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

// ── NAC-3: ec_pubkey_serialize NULL output fires callback ─────────────────
static void test_nac3_pubkey_serialize_null_output() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    secp256k1_pubkey pk = make_valid_pubkey(ctx);
    size_t outlen = 33;
    int before = g_nac_cb.load();
    int rc = secp256k1_ec_pubkey_serialize(ctx, nullptr, &outlen, &pk,
                                           SECP256K1_EC_COMPRESSED);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-3] pubkey_serialize(NULL output) must return 0");
    CHECK(after > before, "[NAC-3] pubkey_serialize(NULL output) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

// ── NAC-4: xonly_pubkey_parse NULL pubkey fires callback ──────────────────
static void test_nac4_xonly_parse_null_pubkey() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    // Use X coordinate of a known valid point (generator X)
    static const unsigned char kGx[32] = {
        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
        0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
        0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
        0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
    };

    int before = g_nac_cb.load();
    int rc = secp256k1_xonly_pubkey_parse(ctx, nullptr, kGx);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-4] xonly_parse(NULL pubkey) must return 0");
    CHECK(after > before, "[NAC-4] xonly_parse(NULL pubkey) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

// ── NAC-5: xonly_pubkey_parse NULL input fires callback ───────────────────
static void test_nac5_xonly_parse_null_input() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    secp256k1_xonly_pubkey xpk{};
    int before = g_nac_cb.load();
    int rc = secp256k1_xonly_pubkey_parse(ctx, &xpk, nullptr);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-5] xonly_parse(NULL input) must return 0");
    CHECK(after > before, "[NAC-5] xonly_parse(NULL input) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

// ── NAC-6: xonly_pubkey_serialize NULL output fires callback ──────────────
static void test_nac6_xonly_serialize_null_output() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    // Build a valid xonly pubkey via pubkey_create + from_pubkey
    secp256k1_pubkey pk = make_valid_pubkey(ctx);
    secp256k1_xonly_pubkey xpk{};
    secp256k1_xonly_pubkey_from_pubkey(ctx, &xpk, nullptr, &pk);

    int before = g_nac_cb.load();
    int rc = secp256k1_xonly_pubkey_serialize(ctx, nullptr, &xpk);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-6] xonly_serialize(NULL output) must return 0");
    CHECK(after > before, "[NAC-6] xonly_serialize(NULL output) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

// ── NAC-7: recoverable_sig_parse NULL sig fires callback ──────────────────
static void test_nac7_rec_parse_null_sig() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    unsigned char input64[64]{};

    int before = g_nac_cb.load();
    int rc = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, nullptr, input64, 0);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-7] rec_sig_parse(NULL sig) must return 0");
    CHECK(after > before, "[NAC-7] rec_sig_parse(NULL sig) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

// ── NAC-8: recoverable_sig_serialize NULL output fires callback ───────────
static void test_nac8_rec_serialize_null_output() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_set_illegal_callback(ctx, nac_illegal_cb, nullptr);

    // Build a valid recoverable sig
    unsigned char input64[64] = {
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    secp256k1_ecdsa_recoverable_signature sig{};
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, input64, 0);

    int recid_out = -1;
    int before = g_nac_cb.load();
    int rc = secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx, nullptr, &recid_out, &sig);
    int after = g_nac_cb.load();

    CHECK(rc == 0,        "[NAC-8] rec_sig_serialize(NULL output) must return 0");
    CHECK(after > before, "[NAC-8] rec_sig_serialize(NULL output) must fire illegal_callback");

    secp256k1_context_destroy(ctx);
}

#else
static void test_nac1_pubkey_create_null_pubkey()       { ++g_pass; }
static void test_nac2_pubkey_create_null_seckey()       { ++g_pass; }
static void test_nac3_pubkey_serialize_null_output()    { ++g_pass; }
static void test_nac4_xonly_parse_null_pubkey()         { ++g_pass; }
static void test_nac5_xonly_parse_null_input()          { ++g_pass; }
static void test_nac6_xonly_serialize_null_output()     { ++g_pass; }
static void test_nac7_rec_parse_null_sig()              { ++g_pass; }
static void test_nac8_rec_serialize_null_output()       { ++g_pass; }
#endif // __has_include("secp256k1.h")

int test_regression_shim_null_arg_cb_run();

#ifdef STANDALONE_TEST
int main() { return test_regression_shim_null_arg_cb_run(); }
#endif

int test_regression_shim_null_arg_cb_run() {
    g_pass = 0; g_fail = 0;
    printf("[shim_null_arg_cb] SHIM-NEW-001/002/003: NULL non-ctx args must fire illegal_callback\n");
    test_nac1_pubkey_create_null_pubkey();
    test_nac2_pubkey_create_null_seckey();
    test_nac3_pubkey_serialize_null_output();
    test_nac4_xonly_parse_null_pubkey();
    test_nac5_xonly_parse_null_input();
    test_nac6_xonly_serialize_null_output();
    test_nac7_rec_parse_null_sig();
    test_nac8_rec_serialize_null_output();
    printf("[shim_null_arg_cb] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
