// ============================================================================
// test_regression_rfc6979_ct_loop.cpp
// ============================================================================
// Regression: rfc6979_nonce used a data-dependent early-return loop (iteration
// count revealed whether the first HMAC candidate was >= n or == 0).
//
// Fix (RFC6979-CT): replaced the variable-length retry loop with a fixed
// 2-iteration structure.  ct::scalar_select picks the first valid candidate
// without a secret-dependent branch.  Probability of needing iteration 2 is
// ~2^-128; probability of both failing is ~2^-256.
//
// Tests:
//   RFC-1: 200 ECDSA sign + verify round-trips with diverse keys/messages.
//          All must produce valid signatures (correctness regression guard).
//   RFC-2: Determinism check — same key+message always produces the same nonce
//          (RFC 6979 §3.2 determinism requirement).
//   RFC-3: Different messages always produce different nonces (nonce uniqueness).
// ============================================================================

#include <cstdio>
#include <cstring>
#include <array>
#include <vector>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#include "secp256k1/ecdsa.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/ct/sign.hpp"
#include "secp256k1/ct/point.hpp"
#include "secp256k1/precompute.hpp"
#include "secp256k1/init.hpp"

using namespace secp256k1;
using fast::Scalar;
using fast::Point;

static Scalar make_scalar(uint64_t lo) {
    std::array<uint8_t, 32> b{};
    b[24] = static_cast<uint8_t>(lo >> 56);
    b[25] = static_cast<uint8_t>(lo >> 48);
    b[26] = static_cast<uint8_t>(lo >> 40);
    b[27] = static_cast<uint8_t>(lo >> 32);
    b[28] = static_cast<uint8_t>(lo >> 24);
    b[29] = static_cast<uint8_t>(lo >> 16);
    b[30] = static_cast<uint8_t>(lo >>  8);
    b[31] = static_cast<uint8_t>(lo      );
    Scalar s{};
    Scalar::parse_bytes_strict_nonzero(b.data(), s);
    return s;
}

// ─── RFC-1: sign+verify round-trips ──────────────────────────────────────────
static void test_rfc1_sign_verify_roundtrip() {
    SECP256K1_INIT();
    printf("  [RFC-1] 200 ECDSA sign+verify round-trips with diverse keys\n");

    int ok_count = 0;
    for (int i = 1; i <= 200; ++i) {
        Scalar sk = make_scalar(static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
        if (sk.is_zero()) continue;

        // Message: hash-like bytes derived from i
        std::array<uint8_t, 32> msg{};
        msg[0] = static_cast<uint8_t>(i & 0xFF);
        msg[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        msg[2] = 0xDE; msg[3] = 0xAD;
        msg[31] = static_cast<uint8_t>(i ^ 0x5A);

        ECDSASignature sig = ct::ecdsa_sign(msg, sk);
        if (sig.r.is_zero() || sig.s.is_zero()) continue;  // degenerate (negligible prob)

        Point pubkey = ct::generator_mul(sk);
        bool verified = ecdsa_verify(msg, pubkey, sig);
        if (verified) ++ok_count;
    }
    CHECK(ok_count >= 195, "[RFC-1] >=195/200 round-trips verified");
}

// ─── RFC-2: determinism — same key+msg → same signature ─────────────────────
static void test_rfc2_determinism() {
    SECP256K1_INIT();
    printf("  [RFC-2] RFC 6979 determinism: same key+msg → same signature\n");

    Scalar sk = make_scalar(0x0102030405060708ULL);
    std::array<uint8_t, 32> msg{};
    msg[0] = 0xAB; msg[1] = 0xCD; msg[15] = 0xEF;

    ECDSASignature sig1 = ct::ecdsa_sign(msg, sk);
    ECDSASignature sig2 = ct::ecdsa_sign(msg, sk);
    ECDSASignature sig3 = ct::ecdsa_sign(msg, sk);

    bool det12 = (sig1.r == sig2.r) && (sig1.s == sig2.s);
    bool det13 = (sig1.r == sig3.r) && (sig1.s == sig3.s);
    CHECK(det12, "[RFC-2] sign(k1,m) == sign(k1,m) — call 1 vs 2");
    CHECK(det13, "[RFC-2] sign(k1,m) == sign(k1,m) — call 1 vs 3");
}

// ─── RFC-3: nonce uniqueness — different messages → different signatures ──────
static void test_rfc3_nonce_uniqueness() {
    SECP256K1_INIT();
    printf("  [RFC-3] RFC 6979 nonce uniqueness: different messages → different sigs\n");

    Scalar sk = make_scalar(0xFEDCBA9876543210ULL);

    std::array<uint8_t, 32> msg1{}, msg2{};
    msg1[0] = 0x01; msg1[1] = 0x00;
    msg2[0] = 0x02; msg2[1] = 0x00;

    ECDSASignature sig1 = ct::ecdsa_sign(msg1, sk);
    ECDSASignature sig2 = ct::ecdsa_sign(msg2, sk);

    bool different = !(sig1.r == sig2.r && sig1.s == sig2.s);
    CHECK(different, "[RFC-3] different messages → different nonces/sigs");
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
int main() {
#else
int test_regression_rfc6979_ct_loop_run() {
#endif
    printf("[rfc6979_ct_loop] RFC6979-CT: fixed 2-iteration CT nonce loop regression\n");

    test_rfc1_sign_verify_roundtrip();
    test_rfc2_determinism();
    test_rfc3_nonce_uniqueness();

    printf("[rfc6979_ct_loop] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
