// ============================================================================
// REGRESSION: schnorr_sign e_hash and e not erased (P1-SEC-002 / SEC-009)
//
// schnorr_sign computes:
//   e_hash = tagged_hash("BIP0340/challenge", R.x || P.x || msg)
//   e      = Scalar::from_bytes(e_hash)
//
// e_hash includes R.x which is derived from the secret nonce k.
// Before the fix, e_hash and e were NOT erased in the cleanup block,
// leaving nonce-derived material on the stack. After the fix, both are
// erased alongside d_bytes, t_hash, k_prime, k, etc.
//
// Correctness guard: sign+verify still works after the erasure fix.
// The erasure itself is validated by Valgrind/Tsan in the CI CT pipeline;
// this test guards functional correctness of the fix.
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
#endif

#include "secp256k1/schnorr.hpp"
#include <cstdio>
#include <cstring>
#include <array>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("  FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg); } \
} while(0)

static const uint8_t kPrivkey[32] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
};
static const uint8_t kAux[32] = {
    0xCA,0xFE,0xBA,0xBE,0xCA,0xFE,0xBA,0xBE,
    0xCA,0xFE,0xBA,0xBE,0xCA,0xFE,0xBA,0xBE,
    0xCA,0xFE,0xBA,0xBE,0xCA,0xFE,0xBA,0xBE,
    0xCA,0xFE,0xBA,0xBE,0xCA,0xFE,0xBA,0xBE,
};

// ── SHE-1: sign+verify round-trip still works after e_hash erasure fix ────
static void test_sign_verify_roundtrip() {
    std::printf("  [SHE-1] schnorr_sign+verify round-trip (e_hash erasure fix must not break correctness)\n");

    secp256k1::fast::Scalar sk{};
    CHECK(secp256k1::fast::Scalar::parse_bytes_strict_nonzero(kPrivkey, sk),
          "SHE-1: private key parse succeeds");

    auto kp = secp256k1::schnorr_keypair_create(sk);
    std::array<uint8_t,32> msg = {0xDE,0xAD,0xBE,0xEF};
    std::array<uint8_t,32> aux; std::memcpy(aux.data(), kAux, 32);

    auto sig = secp256k1::schnorr_sign(kp, msg, aux);
    CHECK(!sig.r.empty() && !sig.s.is_zero(), "SHE-1: signature is non-zero");

    // Build xonly pubkey for verification
    auto px = kp.px;
    bool ok = secp256k1::schnorr_verify(px, msg, sig);
    CHECK(ok, "SHE-1: verify succeeds after sign with e_hash erasure");
}

// ── SHE-2: 50 sign+verify round-trips with varied messages ───────────────
static void test_many_roundtrips() {
    std::printf("  [SHE-2] 50 sign+verify round-trips with varied messages\n");

    secp256k1::fast::Scalar sk{};
    secp256k1::fast::Scalar::parse_bytes_strict_nonzero(kPrivkey, sk);
    auto kp = secp256k1::schnorr_keypair_create(sk);
    auto px = kp.px;

    int ok_count = 0;
    for (int i = 0; i < 50; ++i) {
        std::array<uint8_t,32> msg = {};
        msg[0] = static_cast<uint8_t>(i);
        msg[1] = static_cast<uint8_t>(i >> 8);
        std::array<uint8_t,32> aux = {};
        aux[31] = static_cast<uint8_t>(i);

        auto sig = secp256k1::schnorr_sign(kp, msg, aux);
        if (!sig.s.is_zero() && secp256k1::schnorr_verify(px, msg, sig))
            ++ok_count;
    }
    CHECK(ok_count == 50, "SHE-2: all 50 sign+verify round-trips pass");
}

// ── SHE-3: deterministic output (same inputs → same signature) ────────────
static void test_deterministic_output() {
    std::printf("  [SHE-3] schnorr_sign is deterministic (e_hash erasure must not affect output)\n");

    secp256k1::fast::Scalar sk{};
    secp256k1::fast::Scalar::parse_bytes_strict_nonzero(kPrivkey, sk);
    auto kp = secp256k1::schnorr_keypair_create(sk);

    std::array<uint8_t,32> msg = {0x42};
    std::array<uint8_t,32> aux; std::memcpy(aux.data(), kAux, 32);

    auto sig1 = secp256k1::schnorr_sign(kp, msg, aux);
    auto sig2 = secp256k1::schnorr_sign(kp, msg, aux);

    // R.x must be equal
    CHECK(sig1.r == sig2.r, "SHE-3: R.x is deterministic");
    // s must be equal
    CHECK(sig1.s == sig2.s, "SHE-3: s is deterministic");
}

// ── SHE-4: different messages → different signatures ─────────────────────
static void test_different_messages_different_sigs() {
    std::printf("  [SHE-4] different messages produce different signatures\n");

    secp256k1::fast::Scalar sk{};
    secp256k1::fast::Scalar::parse_bytes_strict_nonzero(kPrivkey, sk);
    auto kp = secp256k1::schnorr_keypair_create(sk);
    std::array<uint8_t,32> aux; std::memcpy(aux.data(), kAux, 32);

    std::array<uint8_t,32> msg1 = {0x01};
    std::array<uint8_t,32> msg2 = {0x02};
    auto sig1 = secp256k1::schnorr_sign(kp, msg1, aux);
    auto sig2 = secp256k1::schnorr_sign(kp, msg2, aux);

    // Different messages produce different nonces (BIP-340 nonce derivation
    // includes the message, so R.x differs).
    bool r_different = (sig1.r != sig2.r);
    CHECK(r_different, "SHE-4: different messages produce different R.x (nonce derivation correct)");
}

int test_regression_schnorr_sign_e_hash_erased_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_schnorr_sign_e_hash_erased] P1-SEC-002: schnorr_sign e_hash + e erasure fix\n");
    test_sign_verify_roundtrip();
    test_many_roundtrips();
    test_deterministic_output();
    test_different_messages_different_sigs();
    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_schnorr_sign_e_hash_erased_run(); }
#endif
