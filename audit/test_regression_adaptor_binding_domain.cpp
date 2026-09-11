// ============================================================================
// test_regression_adaptor_binding_domain.cpp — adaptor soundness regression
// ============================================================================
// Schnorr adaptor binding (BIP-340 tagged challenge) + ECDSA adaptor DLEQ soundness.
//
// GHSA-c7q2-gv3g-rgxm: the ECDSA adaptor previously used a "binding" scalar that
// cancelled in verify and bound nothing — r (= x-coord of k*T) was NOT tied to the
// adaptor point T, so a malicious signer could substitute an arbitrary r' (adjusting
// s_hat) and still pass adaptor_verify, yet the pre-signature was not adaptable. The
// fix replaces the binding scalar with a Chaum-Pedersen DLEQ proof that R_hat = k*G
// and R = k*T share the same k; verify checks the DLEQ, r == R.x, and the ECDSA
// relation. These tests guard both the honest path and forgery rejection.
//
// TESTS:
//   ADB-1  Schnorr adaptor sign/verify round-trip succeeds
//   ADB-2  schnorr_adaptor_verify rejects flipped needs_negation flag
//   ADB-3  schnorr_adaptor_adapt produces a valid BIP-340 Schnorr signature
//   ADB-4  schnorr_adaptor_extract recovers the adaptor secret exactly
//   ADB-5  ECDSA adaptor full round-trip: sign→verify→adapt→ecdsa_verify→extract
//   ADB-6  GHSA-c7q2 forgery rejected: substituted r' / tampered DLEQ / swapped R
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <array>
#include <cstring>

#include "secp256k1/adaptor.hpp"
#include "secp256k1/schnorr.hpp"
#include "secp256k1/ecdsa.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/sha256.hpp"
#include "secp256k1/ct/point.hpp"

using namespace secp256k1;
using secp256k1::fast::Scalar;
using secp256k1::fast::Point;

static int g_pass = 0, g_fail = 0;
static void check(bool cond, const char* msg) {
    if (cond) { ++g_pass; printf("  [OK]   %s\n", msg); }
    else       { ++g_fail; printf("  [FAIL] %s\n", msg); }
    fflush(stdout);
}

// Fixed test vectors — deterministic, no randomness.
static Scalar make_sk(uint8_t byte31) {
    std::array<uint8_t, 32> b{};
    b[31] = byte31;
    Scalar s;
    Scalar::parse_bytes_strict_nonzero(b.data(), s);
    return s;
}

static std::array<uint8_t, 32> make_msg(uint8_t byte0) {
    std::array<uint8_t, 32> m{};
    m[0] = byte0;
    m[31] = 0xAA;
    return m;
}

static std::array<uint8_t, 32> zero_aux() { return {}; }

// ── ADB-1: Schnorr adaptor sign/verify round-trip ──────────────────────────
static void test_adb_1() {
    printf("  -- ADB-1: Schnorr adaptor sign/verify round-trip\n");

    Scalar sk    = make_sk(7);
    Scalar t     = make_sk(11);      // adaptor secret
    Point  T     = ct::generator_mul(t);
    auto   msg   = make_msg(0x01);
    auto   aux   = zero_aux();

    SchnorrAdaptorSig pre = schnorr_adaptor_sign(sk, msg, T, aux);

    // Derive x-only pubkey bytes
    Point P = ct::generator_mul(sk);
    auto [px_bytes, p_odd] = P.x_bytes_and_parity();
    if (p_odd) P = P.negate();  // even-Y convention

    bool ok = schnorr_adaptor_verify(pre, px_bytes, msg, T);
    check(ok, "[adb-1] schnorr_adaptor_verify(honest pre-sig) == true");
}

// ── ADB-2: Reject flipped needs_negation ───────────────────────────────────
static void test_adb_2() {
    printf("  -- ADB-2: needs_negation integrity check\n");

    Scalar sk = make_sk(5);
    Scalar t  = make_sk(9);
    Point  T  = ct::generator_mul(t);
    auto   msg = make_msg(0x02);
    auto   aux = zero_aux();

    SchnorrAdaptorSig pre = schnorr_adaptor_sign(sk, msg, T, aux);

    Point P = ct::generator_mul(sk);
    auto [px_bytes, p_odd] = P.x_bytes_and_parity();
    if (p_odd) P = P.negate();

    // Honest verify must pass
    bool honest = schnorr_adaptor_verify(pre, px_bytes, msg, T);
    check(honest, "[adb-2] honest pre-sig passes verify");

    // Tampered: flip needs_negation — must be rejected
    SchnorrAdaptorSig tampered = pre;
    tampered.needs_negation = !tampered.needs_negation;
    bool tampered_ok = schnorr_adaptor_verify(tampered, px_bytes, msg, T);
    check(!tampered_ok, "[adb-2] flipped needs_negation is rejected by verify");
}

// ── ADB-3: adapt → valid Schnorr sig ───────────────────────────────────────
static void test_adb_3() {
    printf("  -- ADB-3: adapt produces valid BIP-340 Schnorr signature\n");

    Scalar sk = make_sk(3);
    Scalar t  = make_sk(13);
    Point  T  = ct::generator_mul(t);
    auto   msg = make_msg(0x03);
    auto   aux = zero_aux();

    SchnorrAdaptorSig pre = schnorr_adaptor_sign(sk, msg, T, aux);

    Point P = ct::generator_mul(sk);
    auto [px_bytes, p_odd] = P.x_bytes_and_parity();
    if (p_odd) P = P.negate();

    SchnorrSignature final_sig = schnorr_adaptor_adapt(pre, t);

    bool verify_ok = schnorr_verify(px_bytes.data(), msg.data(), final_sig);
    check(verify_ok, "[adb-3] adapted signature passes schnorr_verify");
    check(!final_sig.s.is_zero(), "[adb-3] adapted signature has non-zero s");
}

// ── ADB-4: extract recovers adaptor secret exactly ─────────────────────────
static void test_adb_4() {
    printf("  -- ADB-4: extract recovers adaptor secret\n");

    Scalar sk = make_sk(17);
    Scalar t  = make_sk(23);
    Point  T  = ct::generator_mul(t);
    auto   msg = make_msg(0x04);
    auto   aux = zero_aux();

    SchnorrAdaptorSig pre       = schnorr_adaptor_sign(sk, msg, T, aux);
    SchnorrSignature  final_sig = schnorr_adaptor_adapt(pre, t);

    auto [t_recovered, ok] = schnorr_adaptor_extract(pre, final_sig);
    check(ok, "[adb-4] extract returns ok=true");

    // t_recovered must equal t (or -t if negation occurred)
    // The extract function handles the negation internally.
    Point T_check = ct::generator_mul(t_recovered);
    auto [T_x, T_odd] = T.x_bytes_and_parity();
    auto [Tc_x, Tc_odd] = T_check.x_bytes_and_parity();
    check(T_x == Tc_x, "[adb-4] extracted secret reproduces T x-coordinate");
}

// ── ADB-5: ECDSA adaptor full round-trip (sign→verify→adapt→ecdsa_verify→extract) ──
static void test_adb_5() {
    printf("  -- ADB-5: ECDSA adaptor full round-trip (DLEQ-bound)\n");

    Scalar sk = make_sk(19);
    Scalar t  = make_sk(29);
    Point  T  = ct::generator_mul(t);
    Point  P  = ct::generator_mul(sk);
    auto   msg = make_msg(0x05);

    ECDSAAdaptorSig pre = ecdsa_adaptor_sign(sk, msg, T);
    check(!pre.r.is_zero() && !pre.s_hat.is_zero(),
          "[adb-5] ECDSA adaptor pre-sig is non-degenerate");
    check(ecdsa_adaptor_verify(pre, P, msg, T),
          "[adb-5a] ecdsa_adaptor_verify(honest pre-sig) == true");

    // Adapt with the witness t → a standard ECDSA signature that verifies under P.
    // This proves the pre-signature was actually adaptable (the soundness property
    // GHSA-c7q2-gv3g-rgxm restored: adaptor_verify==OK ⇒ adaptable).
    ECDSASignature sig = ecdsa_adaptor_adapt(pre, t);
    check(ecdsa_verify(msg.data(), P, sig),
          "[adb-5b] adapted signature is a valid ECDSA signature");

    // Extract recovers the adaptor secret t from (pre-sig, completed sig).
    auto extracted = ecdsa_adaptor_extract(pre, sig);
    check(extracted.second && extracted.first.to_bytes() == t.to_bytes(),
          "[adb-5c] ecdsa_adaptor_extract recovers the adaptor secret t");
}

// ── ADB-6: GHSA-c7q2-gv3g-rgxm — forged / unbound pre-signatures are rejected ─────
static void test_adb_6() {
    printf("  -- ADB-6: GHSA-c7q2 forgery (substituted r' / tampered DLEQ / swapped R) rejected\n");

    Scalar sk = make_sk(41);
    Scalar t  = make_sk(43);
    Point  T  = ct::generator_mul(t);
    Point  P  = ct::generator_mul(sk);
    auto   msg = make_msg(0x06);

    ECDSAAdaptorSig pre = ecdsa_adaptor_sign(sk, msg, T);
    check(ecdsa_adaptor_verify(pre, P, msg, T),
          "[adb-6] honest pre-sig verifies (baseline)");

    // The advisory forgery: a malicious signer (knows sk) substitutes an arbitrary r'
    // NOT bound to T, and adjusts s_hat' = s_hat*(z + r'*x)*(z + r*x)^-1. The old verify
    // accepted this (r was unbound); the DLEQ-bound verify MUST reject it (r' != R.x).
    Scalar z = Scalar::from_bytes(msg);
    Scalar r_prime = make_sk(0x7b);
    check(r_prime.to_bytes() != pre.r.to_bytes(), "[adb-6] chosen r' differs from the honest r");
    Scalar s_forged = pre.s_hat * (z + (r_prime * sk)) * (z + (pre.r * sk)).inverse();
    ECDSAAdaptorSig forged = pre;
    forged.r = r_prime;
    forged.s_hat = s_forged;
    check(!ecdsa_adaptor_verify(forged, P, msg, T),
          "[adb-6] forged pre-sig with substituted r' is REJECTED (r bound to T via DLEQ)");

    // Tampering the DLEQ response must also be rejected.
    ECDSAAdaptorSig dleq_tamper = pre;
    dleq_tamper.dleq_s = pre.dleq_s + Scalar::one();
    check(!ecdsa_adaptor_verify(dleq_tamper, P, msg, T),
          "[adb-6] corrupted DLEQ response is REJECTED");

    // Swapping R (and its matching r) without a fresh DLEQ must be rejected.
    ECDSAAdaptorSig r_tamper = pre;
    r_tamper.R = ct::generator_mul(make_sk(0x55));
    r_tamper.r = Scalar::from_bytes(r_tamper.R.x().to_bytes());
    check(!ecdsa_adaptor_verify(r_tamper, P, msg, T),
          "[adb-6] swapped R with no valid DLEQ is REJECTED");
}

// ── Entry point ────────────────────────────────────────────────────────────

int test_regression_adaptor_binding_domain_run() {
    g_pass = 0; g_fail = 0;
    printf("[adaptor_binding] Schnorr adaptor binding + ECDSA adaptor DLEQ soundness (ADB-1..6)\n");
    printf("  ECDSA adaptor: DLEQ-bound (GHSA-c7q2-gv3g-rgxm); Schnorr adaptor: BIP-340 tagged challenge\n\n");

    test_adb_1();
    test_adb_2();
    test_adb_3();
    test_adb_4();
    test_adb_5();
    test_adb_6();

    printf("\n[adaptor_binding] %d/%d\n", g_pass, g_pass + g_fail);
    return g_fail > 0 ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_adaptor_binding_domain_run(); }
#endif
