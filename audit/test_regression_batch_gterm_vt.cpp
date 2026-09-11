// ============================================================================
// test_regression_batch_gterm_vt.cpp
// ============================================================================
// Regression: schnorr_batch_verify (large-batch MSM path) previously used
// ct::generator_mul(g_coeff) to compute the generator term g_coeff * G.
// g_coeff = sum(weight_i * sig_i.s) — all inputs are public signature data;
// CT arithmetic here adds overhead with zero security benefit (PERF-008).
//
// Fix: replaced with Point::generator().scalar_mul(g_coeff) (variable-time).
// Result is algebraically identical; correctness is unchanged.
//
// Tests:
//   GTM-1: Correctness — large batch of valid Schnorr sigs returns true.
//   GTM-2: Fail-closed on corrupted s — a modified sig.s changes g_coeff,
//          causing the MSM equation to fail (batch verify returns false).
//   GTM-3: Fail-closed on corrupted pubkey — invalid pubkey term returns false.
// ============================================================================

#include <cstdio>
#include <cstring>
#include <array>
#include <vector>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#include "secp256k1/batch_verify.hpp"
#include "secp256k1/schnorr.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/ct/sign.hpp"
#include "secp256k1/init.hpp"

using namespace secp256k1;
using fast::Scalar;
using fast::Point;

static Scalar make_sk(std::uint64_t seed) {
    std::array<std::uint8_t, 32> b{};
    b[24] = static_cast<std::uint8_t>(seed >> 56);
    b[25] = static_cast<std::uint8_t>(seed >> 48);
    b[26] = static_cast<std::uint8_t>(seed >> 40);
    b[27] = static_cast<std::uint8_t>(seed >> 32);
    b[28] = static_cast<std::uint8_t>(seed >> 24);
    b[29] = static_cast<std::uint8_t>(seed >> 16);
    b[30] = static_cast<std::uint8_t>(seed >>  8);
    b[31] = static_cast<std::uint8_t>(seed      );
    Scalar s{};
    Scalar::parse_bytes_strict_nonzero(b.data(), s);
    return s;
}

static std::vector<SchnorrBatchEntry> make_valid_batch(int n) {
    std::vector<SchnorrBatchEntry> entries;
    entries.reserve(static_cast<std::size_t>(n));
    for (int i = 1; i <= n; ++i) {
        Scalar sk = make_sk(static_cast<std::uint64_t>(i) * 0xC0FFEE12345678ABULL);
        if (sk.is_zero()) continue;

        std::array<std::uint8_t, 32> msg{};
        msg[0] = static_cast<std::uint8_t>(i & 0xFF);
        msg[1] = 0xBB;
        msg[31] = static_cast<std::uint8_t>(i ^ 0x7F);

        std::array<std::uint8_t, 32> aux{};
        SchnorrSignature sig = schnorr_sign(sk, msg, aux);
        if (sig.s.is_zero()) continue;

        Point P = ct::generator_mul(sk);
        SchnorrBatchEntry e;
        e.pubkey_x = P.x().to_bytes();
        e.message  = msg;
        e.signature = sig;
        entries.push_back(e);
    }
    return entries;
}

// ─── GTM-1: large-batch correctness ──────────────────────────────────────────
static void test_gtm1_large_batch_correct() {
    SECP256K1_INIT();
    printf("  [GTM-1] batch_verify: 128 valid Schnorr sigs → true (VT g_coeff*G path)\n");
    auto entries = make_valid_batch(128);
    bool ok = schnorr_batch_verify(entries.data(), entries.size());
    CHECK(ok, "[GTM-1] 128 valid Schnorr sigs must verify (g_coeff*G VT path)");
}

// ─── GTM-2: corrupted s invalidates g_coeff term ─────────────────────────────
static void test_gtm2_corrupt_s_fails() {
    SECP256K1_INIT();
    printf("  [GTM-2] batch_verify: corrupted sig.s changes g_coeff → false\n");
    auto entries = make_valid_batch(128);
    if (entries.size() < 2) return;

    // Flip bit 0 of s in the middle entry — changes g_coeff * G ≠ rest.
    std::size_t mid = entries.size() / 2;
    std::array<uint8_t, 32> s_bytes{};
    entries[mid].signature.s.write_bytes(s_bytes.data());
    s_bytes[31] ^= 0x01;
    Scalar bad_s{};
    if (Scalar::parse_bytes_strict_nonzero(s_bytes.data(), bad_s)) {
        entries[mid].signature.s = bad_s;
    } else {
        // Fallback: flip a different bit if the result was >= n or zero.
        s_bytes[31] ^= 0x01;
        s_bytes[30] ^= 0x02;
        Scalar::parse_bytes_strict_nonzero(s_bytes.data(), bad_s);
        entries[mid].signature.s = bad_s;
    }

    bool ok = schnorr_batch_verify(entries.data(), entries.size());
    CHECK(!ok, "[GTM-2] corrupted sig.s must cause batch_verify false");
}

// ─── GTM-3: corrupted pubkey invalidates P term ───────────────────────────────
static void test_gtm3_corrupt_pubkey_fails() {
    SECP256K1_INIT();
    printf("  [GTM-3] batch_verify: corrupted pubkey_x → false\n");
    auto entries = make_valid_batch(128);
    if (entries.empty()) return;

    // Replace last entry's pubkey_x with a different valid pubkey.
    Scalar alt_sk = make_sk(0xDEADBEEFCAFEB0B0ULL);
    if (!alt_sk.is_zero()) {
        Point alt_P = ct::generator_mul(alt_sk);
        entries.back().pubkey_x = alt_P.x().to_bytes();
    } else {
        entries.back().pubkey_x[0] ^= 0xFF;
    }

    bool ok = schnorr_batch_verify(entries.data(), entries.size());
    CHECK(!ok, "[GTM-3] mismatched pubkey must cause batch_verify false");
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
int main() {
#else
int test_regression_batch_gterm_vt_run() {
#endif
    printf("[batch_gterm_vt] PERF-008: batch_verify g_coeff*G uses VT path (not CT)\n");

    test_gtm1_large_batch_correct();
    test_gtm2_corrupt_s_fails();
    test_gtm3_corrupt_pubkey_fails();

    printf("[batch_gterm_vt] %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
