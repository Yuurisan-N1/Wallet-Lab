// ============================================================================
// test_regression_adaptor_ct_nonce.cpp
// ============================================================================
// Regression: adaptor_nonce() and ecdsa_adaptor_binding() used a
// data-dependent retry loop `for (ctr=0; !parse_strict_nonzero(...); ++ctr)`
// to handle the ~2^-128 probability that the hash output >= n or == 0.
// The loop iteration count leaks via timing whether the first candidate was
// valid — a secret-bearing branch on a private-key-derived hash.
//
// Fix (P2-CT-RT-004): Replace with a fixed 2-iteration CT select pattern
// identical to the rfc6979_nonce_hedged fix (CT-001).  Both iterations are
// always executed; ct::scalar_select picks the first valid candidate without
// any secret-dependent branch.
//
// Tests:
//   ACN-1: schnorr_adaptor_sign + schnorr_adaptor_verify correctness round-trip
//          (50 diverse keys/messages).
//   ACN-2: ecdsa_adaptor_sign + ecdsa_adaptor_verify correctness round-trip.
//   ACN-3: adapt + extract correctness (schnorr adaptor secret recovery).
//   ACN-4: Determinism — same inputs → same pre-signature.
//   ACN-5: Different inputs → different pre-signatures.
// ============================================================================

#include <cstdio>
#include <cstring>
#include <array>
#include <vector>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#include "secp256k1/adaptor.hpp"
#include "secp256k1/schnorr.hpp"
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

static Scalar make_scalar(std::uint64_t lo) {
    std::array<std::uint8_t, 32> b{};
    b[24] = static_cast<std::uint8_t>(lo >> 56);
    b[25] = static_cast<std::uint8_t>(lo >> 48);
    b[26] = static_cast<std::uint8_t>(lo >> 40);
    b[27] = static_cast<std::uint8_t>(lo >> 32);
    b[28] = static_cast<std::uint8_t>(lo >> 24);
    b[29] = static_cast<std::uint8_t>(lo >> 16);
    b[30] = static_cast<std::uint8_t>(lo >>  8);
    b[31] = static_cast<std::uint8_t>(lo      );
    Scalar s{};
    Scalar::parse_bytes_strict_nonzero(b.data(), s);
    return s;
}

// ─── ACN-1: schnorr adaptor sign + verify correctness ────────────────────────
static void test_acn1_schnorr_adaptor_roundtrip() {
    SECP256K1_INIT();
    printf("  [ACN-1] schnorr_adaptor_sign + verify: 50 round-trips (CT nonce fix correctness)\n");

    int ok = 0;
    for (int i = 1; i <= 50; ++i) {
        Scalar sk = make_scalar(static_cast<std::uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
        if (sk.is_zero()) continue;

        Scalar t_secret = make_scalar(static_cast<std::uint64_t>(i) * 0xDEADBEEFCAFEBABEULL);
        if (t_secret.is_zero()) continue;
        Point adaptor = ct::generator_mul(t_secret);

        std::array<std::uint8_t, 32> msg{};
        msg[0] = static_cast<std::uint8_t>(i & 0xFF);
        msg[1] = 0xAB; msg[31] = static_cast<std::uint8_t>(i ^ 0x5A);

        std::array<std::uint8_t, 32> aux{};
        aux[0] = static_cast<std::uint8_t>(i * 3);

        SchnorrAdaptorSig pre_sig = schnorr_adaptor_sign(sk, msg, adaptor, aux);
        if (pre_sig.s_hat.is_zero()) continue;

        Point P = ct::generator_mul(sk);
        auto P_x = P.x().to_bytes();

        bool v = schnorr_adaptor_verify(pre_sig, P_x, msg, adaptor);
        if (v) ++ok;
    }
    CHECK(ok >= 45, "[ACN-1] >=45/50 schnorr adaptor sign+verify round-trips passed");
}

// ─── ACN-2: ecdsa adaptor sign + verify correctness ──────────────────────────
static void test_acn2_ecdsa_adaptor_roundtrip() {
    SECP256K1_INIT();
    printf("  [ACN-2] ecdsa_adaptor_sign + verify: 50 round-trips (CT nonce fix correctness)\n");

    int ok = 0;
    for (int i = 1; i <= 50; ++i) {
        Scalar sk = make_scalar(static_cast<std::uint64_t>(i) * 0xFEDCBA9876543210ULL);
        if (sk.is_zero()) continue;

        Scalar t_secret = make_scalar(static_cast<std::uint64_t>(i) * 0x0102030405060708ULL);
        if (t_secret.is_zero()) continue;
        Point adaptor = ct::generator_mul(t_secret);

        std::array<std::uint8_t, 32> msg_hash{};
        msg_hash[0] = static_cast<std::uint8_t>(i & 0xFF);
        msg_hash[1] = 0xCC; msg_hash[31] = static_cast<std::uint8_t>(i ^ 0x77);

        ECDSAAdaptorSig pre_sig = ecdsa_adaptor_sign(sk, msg_hash, adaptor);
        if (pre_sig.r.is_zero() || pre_sig.s_hat.is_zero()) continue;

        Point pk = ct::generator_mul(sk);
        bool v = ecdsa_adaptor_verify(pre_sig, pk, msg_hash, adaptor);
        if (v) ++ok;
    }
    CHECK(ok >= 45, "[ACN-2] >=45/50 ecdsa adaptor sign+verify round-trips passed");
}

// ─── ACN-3: schnorr adapt + extract correctness ──────────────────────────────
static void test_acn3_schnorr_adapt_extract() {
    SECP256K1_INIT();
    printf("  [ACN-3] schnorr adaptor adapt + extract: adaptor secret recovery\n");

    Scalar sk = make_scalar(0xCAFEBABEDEADBEEFULL);
    if (sk.is_zero()) { CHECK(false, "[ACN-3] degenerate sk"); return; }

    Scalar t_secret = make_scalar(0x0102030405060708ULL);
    if (t_secret.is_zero()) { CHECK(false, "[ACN-3] degenerate t"); return; }
    Point adaptor = ct::generator_mul(t_secret);

    std::array<std::uint8_t, 32> msg{};
    msg[0] = 0xDE; msg[1] = 0xAD; msg[15] = 0xBE; msg[31] = 0xEF;
    std::array<std::uint8_t, 32> aux{};
    aux[0] = 0x42;

    SchnorrAdaptorSig pre_sig = schnorr_adaptor_sign(sk, msg, adaptor, aux);
    CHECK(!pre_sig.s_hat.is_zero(), "[ACN-3] pre_sig.s_hat non-zero");

    SchnorrSignature final_sig = schnorr_adaptor_adapt(pre_sig, t_secret);
    CHECK(!final_sig.s.is_zero(), "[ACN-3] final_sig.s non-zero");

    auto [extracted_t, ok] = schnorr_adaptor_extract(pre_sig, final_sig);
    CHECK(ok, "[ACN-3] adaptor secret extracted successfully");
    CHECK(extracted_t == t_secret, "[ACN-3] extracted adaptor secret == original t");
}

// ─── ACN-4: determinism — same inputs → same pre-signature ───────────────────
static void test_acn4_adaptor_nonce_determinism() {
    SECP256K1_INIT();
    printf("  [ACN-4] adaptor_nonce determinism: same key+msg+aux → same pre-sig\n");

    Scalar sk = make_scalar(0x1234567890ABCDEFULL);
    if (sk.is_zero()) { CHECK(false, "[ACN-4] degenerate sk"); return; }

    Scalar t_secret = make_scalar(0xFEDCBA9876543210ULL);
    if (t_secret.is_zero()) { CHECK(false, "[ACN-4] degenerate t"); return; }
    Point adaptor = ct::generator_mul(t_secret);

    std::array<std::uint8_t, 32> msg{};
    msg[0] = 0x01; msg[1] = 0x02; msg[31] = 0x03;
    std::array<std::uint8_t, 32> aux{};
    aux[0] = 0xFF;

    SchnorrAdaptorSig pre1 = schnorr_adaptor_sign(sk, msg, adaptor, aux);
    SchnorrAdaptorSig pre2 = schnorr_adaptor_sign(sk, msg, adaptor, aux);

    bool same_s = (pre1.s_hat == pre2.s_hat);
    CHECK(same_s, "[ACN-4] same key+msg+aux → same s_hat (adaptor nonce is deterministic)");
}

// ─── ACN-5: different messages → different pre-signatures ────────────────────
static void test_acn5_adaptor_nonce_uniqueness() {
    SECP256K1_INIT();
    printf("  [ACN-5] adaptor_nonce uniqueness: different messages → different pre-sigs\n");

    Scalar sk = make_scalar(0xAABBCCDDEEFF0011ULL);
    if (sk.is_zero()) { CHECK(false, "[ACN-5] degenerate sk"); return; }

    Scalar t_secret = make_scalar(0x1122334455667788ULL);
    if (t_secret.is_zero()) { CHECK(false, "[ACN-5] degenerate t"); return; }
    Point adaptor = ct::generator_mul(t_secret);

    std::array<std::uint8_t, 32> msg1{}, msg2{};
    msg1[0] = 0x01; msg1[31] = 0xAA;
    msg2[0] = 0x02; msg2[31] = 0xBB;
    std::array<std::uint8_t, 32> aux{};
    aux[0] = 0x00;

    SchnorrAdaptorSig pre1 = schnorr_adaptor_sign(sk, msg1, adaptor, aux);
    SchnorrAdaptorSig pre2 = schnorr_adaptor_sign(sk, msg2, adaptor, aux);

    bool different = !(pre1.s_hat == pre2.s_hat);
    CHECK(different, "[ACN-5] different messages → different s_hat (nonce uniqueness)");
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
int main() {
#else
int test_regression_adaptor_ct_nonce_run() {
#endif
    printf("[adaptor_ct_nonce] P2-CT-RT-004: adaptor nonce fixed 2-iteration CT regression\n");

    test_acn1_schnorr_adaptor_roundtrip();
    test_acn2_ecdsa_adaptor_roundtrip();
    test_acn3_schnorr_adapt_extract();
    test_acn4_adaptor_nonce_determinism();
    test_acn5_adaptor_nonce_uniqueness();

    printf("[adaptor_ct_nonce] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
