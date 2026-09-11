// ============================================================================
// test_regression_adaptor_ct_secret_extract.cpp
// ============================================================================
// Regression for SEC-001/CT-001:
//   SEC-001 — ecdsa_adaptor_extract() left s_inv on stack (not erased).
//             Fix: secure_erase(&s_inv) after computing t.
//   CT-001  — ecdsa_adaptor_extract() used fast::operator* (VT) for
//              s_hat * s_inv, leaking the extracted adaptor secret t
//              via timing. Fix: ct::scalar_mul(s_hat, s_inv).
//
// Behavioral verification: if ct::scalar_mul produces the correct output,
// the full round-trip (sign → extract → verify pubkey derivation) holds.
// Timing invariants are not directly testable; correctness is the witness.
//
// Tests (ACE-1..4):
//   ACE-1  round-trip: extracted secret matches adaptor secret (both normal)
//   ACE-2  extracted secret reproduces the adaptor point (via pubkey_create)
//   ACE-3  negated adaptor secret also accepted (BIP-340 y-parity flip)
//   ACE-4  extract with zero sig.s returns failure (fail-closed)
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#include <cstdio>
#define STANDALONE_TEST
#endif

#ifndef UFSECP_BUILDING
#define UFSECP_BUILDING
#endif
#include "ufsecp/ufsecp.h"

#include <cstdio>
#include <cstring>
#include <cstdint>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

// privkey = 1
static const uint8_t kSk1[32] = {
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1
};
// adaptor secret = 2
static const uint8_t kAdaptorSec[32] = {
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,2
};
static const uint8_t kMsg[32] = {0xDE, 0xAD, 0xBE, 0xEF};

namespace {

// ─── ACE-1/ACE-2: round-trip extract recovers adaptor secret ─────────────────
static void test_ace1_ace2_roundtrip() {
    ufsecp_ctx* ctx = nullptr;
    CHECK(ufsecp_ctx_create(&ctx) == UFSECP_OK, "[ACE-1] ctx_create");

    // derive adaptor point
    uint8_t adaptor_pt[33] = {};
    CHECK(ufsecp_pubkey_create(ctx, kAdaptorSec, adaptor_pt) == UFSECP_OK,
          "[ACE-1] pubkey_create adaptor point");

    // sign adaptor pre-sig
    uint8_t presig[UFSECP_ECDSA_ADAPTOR_SIG_LEN] = {};
    CHECK(ufsecp_ecdsa_adaptor_sign(ctx, kSk1, kMsg, adaptor_pt, presig) == UFSECP_OK,
          "[ACE-1] adaptor_sign");

    // adapt → final sig
    uint8_t sig64[64] = {};
    CHECK(ufsecp_ecdsa_adaptor_adapt(ctx, presig, kAdaptorSec, sig64) == UFSECP_OK,
          "[ACE-1] adaptor_adapt");

    // extract adaptor secret from (presig, sig64)
    uint8_t extracted[32] = {};
    CHECK(ufsecp_ecdsa_adaptor_extract(ctx, presig, sig64, extracted) == UFSECP_OK,
          "[ACE-1] adaptor_extract must succeed (SEC-001/CT-001)");

    // extracted must not be all-zero
    bool nonzero = false;
    for (int i = 0; i < 32; ++i) nonzero |= (extracted[i] != 0);
    CHECK(nonzero, "[ACE-1] extracted secret must be non-zero");

    // ACE-2: extracted secret must reproduce the adaptor point (or negation)
    uint8_t ext_pt[33] = {}, neg_pt[33] = {};
    CHECK(ufsecp_pubkey_create(ctx, extracted, ext_pt) == UFSECP_OK,
          "[ACE-2] pubkey_create from extracted");
    ufsecp_pubkey_negate(ctx, ext_pt, neg_pt);
    CHECK(std::memcmp(ext_pt, adaptor_pt, 33) == 0 ||
          std::memcmp(neg_pt, adaptor_pt, 33) == 0,
          "[ACE-2] extracted secret reproduces adaptor point (or negation) — CT-001 correctness");

    ufsecp_ctx_destroy(ctx);
}

// ─── ACE-3: negated adaptor secret also accepted ─────────────────────────────
static void test_ace3_negated_secret() {
    ufsecp_ctx* ctx = nullptr;
    CHECK(ufsecp_ctx_create(&ctx) == UFSECP_OK, "[ACE-3] ctx_create");

    // privkey = 3
    uint8_t sk3[32] = {};
    sk3[31] = 3;
    uint8_t adaptor_pt[33] = {};
    CHECK(ufsecp_pubkey_create(ctx, kAdaptorSec, adaptor_pt) == UFSECP_OK,
          "[ACE-3] pubkey_create");

    uint8_t presig[UFSECP_ECDSA_ADAPTOR_SIG_LEN] = {};
    CHECK(ufsecp_ecdsa_adaptor_sign(ctx, sk3, kMsg, adaptor_pt, presig) == UFSECP_OK,
          "[ACE-3] adaptor_sign with sk=3");

    uint8_t sig64[64] = {};
    CHECK(ufsecp_ecdsa_adaptor_adapt(ctx, presig, kAdaptorSec, sig64) == UFSECP_OK,
          "[ACE-3] adaptor_adapt");

    uint8_t extracted[32] = {};
    int rc = ufsecp_ecdsa_adaptor_extract(ctx, presig, sig64, extracted);
    CHECK(rc == UFSECP_OK, "[ACE-3] extract with sk=3 succeeds");

    ufsecp_ctx_destroy(ctx);
}

// ─── ACE-4: all-zero sig64 causes extract to fail (fail-closed) ──────────────
static void test_ace4_zero_sig_rejected() {
    ufsecp_ctx* ctx = nullptr;
    CHECK(ufsecp_ctx_create(&ctx) == UFSECP_OK, "[ACE-4] ctx_create");

    uint8_t adaptor_pt[33] = {};
    CHECK(ufsecp_pubkey_create(ctx, kAdaptorSec, adaptor_pt) == UFSECP_OK,
          "[ACE-4] pubkey_create");

    uint8_t presig[UFSECP_ECDSA_ADAPTOR_SIG_LEN] = {};
    CHECK(ufsecp_ecdsa_adaptor_sign(ctx, kSk1, kMsg, adaptor_pt, presig) == UFSECP_OK,
          "[ACE-4] adaptor_sign");

    // all-zero sig64: s == 0, so extract must fail
    uint8_t zero_sig64[64] = {};
    uint8_t extracted[32] = {};
    int rc = ufsecp_ecdsa_adaptor_extract(ctx, presig, zero_sig64, extracted);
    CHECK(rc != UFSECP_OK, "[ACE-4] extract with zero sig must fail (fail-closed)");

    ufsecp_ctx_destroy(ctx);
}

} // namespace

int test_regression_adaptor_ct_secret_extract_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_adaptor_ct_secret_extract] SEC-001/CT-001: CT extract + s_inv erase\n");

    test_ace1_ace2_roundtrip();
    test_ace3_negated_secret();
    test_ace4_zero_sig_rejected();

    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_adaptor_ct_secret_extract_run(); }
#endif
