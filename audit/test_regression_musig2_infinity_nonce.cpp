// ============================================================================
// test_regression_musig2_infinity_nonce.cpp
// Conformance: musig2_start_sign_session must handle an infinity aggregate-nonce
// component per BIP-327 §GetSessionValues (matches reference.py + libsecp256k1).
//
// BIP-327 does NOT abort when an individual aggregate-nonce half (R1 or R2) is the
// point at infinity — cpoint_ext accepts the 33-zero "ext" encoding. It computes the
// effective nonce R = R1 + b·R2 and, ONLY if that combined nonce is infinity, sets
// R = G. libsecp256k1 (secp256k1_musig_nonce_process) does exactly this: it never
// rejects on individual infinity halves; `if is_infinity(fin_nonce): fin_nonce = G`.
//
// (Earlier this file asserted the OPPOSITE — that R1/R2 infinity must be rejected —
//  citing a misreading of "SEC-005". That was a non-conformant divergence; corrected
//  here. Individual *pubnonces* are still rejected upstream in pubnonce_parse, which is
//  the correct BIP-327 cpoint rule — see test_exploit_musig2_infinity_pubnonce.)
//
// Tests:
//   MIN-1: musig2_nonce_agg with empty vector returns all-infinity struct
//   MIN-2: start_sign_session with R1=infinity, R2=G → VALID session, R = b·G
//   MIN-3: start_sign_session with R1=G, R2=infinity → VALID session, R = G
//   MIN-4: start_sign_session with both halves infinity (effective nonce = inf)
//          → VALID session, R = G  (BIP-327 R=G substitution)
//   MIN-5: Valid 2-of-2 nonce round-trip still works
// ============================================================================

#include <cstdio>
#include <cstring>
#include <array>
#include <vector>
static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"
#include "secp256k1/musig2.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/ct/point.hpp"

using namespace secp256k1;
using fast::Scalar;
using fast::Point;

static const unsigned char kSk1[32] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0A
};
static const unsigned char kSk2[32] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0B
};

static std::array<uint8_t, 33> pubkey_compressed(const unsigned char sk[32]) {
    Scalar s{};
    Scalar::parse_bytes_strict_nonzero(sk, s);
    auto P = ct::generator_mul(s);
    return P.to_compressed();
}

static MuSig2KeyAggCtx make_2party_keyagg() {
    auto pk1 = pubkey_compressed(kSk1);
    auto pk2 = pubkey_compressed(kSk2);
    std::vector<std::array<uint8_t, 33>> pks = {pk1, pk2};
    return musig2_key_agg(pks);
}

// A conformant session is usable: challenge e is non-zero and R is a real point.
static bool session_is_valid(const MuSig2Session& sess) {
    return !sess.e.is_zero() && !sess.R.is_infinity();
}
// x-only equality (parity-independent: R is normalized to even-Y internally).
static bool same_x_as_generator(const MuSig2Session& sess) {
    return sess.R.x().to_bytes() == Point::generator().x().to_bytes();
}

// ── MIN-1: nonce_agg empty vector returns infinity struct ─────────────────
static void test_nonce_agg_empty_vector() {
    MuSig2AggNonce agg = musig2_nonce_agg({});
    CHECK(agg.R1.is_infinity(), "[MIN-1a] musig2_nonce_agg({}) → R1 is infinity");
    CHECK(agg.R2.is_infinity(), "[MIN-1b] musig2_nonce_agg({}) → R2 is infinity");
}

// ── MIN-2: start_sign_session ACCEPTS R1=infinity → R = b·R2 (BIP-327) ─────
static void test_start_sign_session_r1_infinity() {
    auto kagg = make_2party_keyagg();
    std::array<uint8_t, 32> msg = {0x11, 0x22, 0x33};

    MuSig2AggNonce nonce{};
    nonce.R1 = Point::infinity();   // R1 cancelled to infinity (valid ext encoding)
    nonce.R2 = Point::generator();  // R2 a valid point

    MuSig2Session sess = musig2_start_sign_session(nonce, kagg, msg);
    // R = 0 + b·R2 = b·R2 (not infinity) → valid session; BIP-327 does NOT reject.
    CHECK(session_is_valid(sess),
          "[MIN-2] R1=infinity accepted: valid session (R = b*R2), not rejected");
    CHECK(!sess.R.is_infinity(),
          "[MIN-2b] R1=infinity: effective nonce R is a real point");
}

// ── MIN-3: start_sign_session ACCEPTS R2=infinity → R = G (BIP-327) ────────
static void test_start_sign_session_r2_infinity() {
    auto kagg = make_2party_keyagg();
    std::array<uint8_t, 32> msg = {0x44, 0x55, 0x66};

    MuSig2AggNonce nonce{};
    nonce.R1 = Point::generator();  // R1 a valid point
    nonce.R2 = Point::infinity();   // R2 cancelled to infinity

    MuSig2Session sess = musig2_start_sign_session(nonce, kagg, msg);
    // R = R1 + b·0 = G → valid session; effective nonce equals the generator.
    CHECK(session_is_valid(sess),
          "[MIN-3] R2=infinity accepted: valid session (R = G), not rejected");
    CHECK(same_x_as_generator(sess),
          "[MIN-3b] R2=infinity: effective nonce R == G");
}

// ── MIN-4: both halves infinity → effective nonce infinity → R = G ─────────
static void test_start_sign_session_from_empty_agg() {
    auto kagg = make_2party_keyagg();
    std::array<uint8_t, 32> msg = {0x77, 0x88, 0x99};

    // Both halves infinity (here via nonce_agg({})): effective nonce R1+b·R2 = infinity,
    // so BIP-327 §GetSessionValues substitutes R = G. This is the official
    // sign_verify_vectors "both halves at infinity" valid case at the unit level.
    MuSig2AggNonce agg = musig2_nonce_agg({});
    MuSig2Session sess = musig2_start_sign_session(agg, kagg, msg);
    CHECK(session_is_valid(sess),
          "[MIN-4] both halves infinity: valid session (BIP-327 R=G), not rejected");
    CHECK(same_x_as_generator(sess),
          "[MIN-4b] both halves infinity: effective nonce R == G");
}

// ── MIN-5: valid 2-of-2 round-trip still works after the fix ─────────────
static void test_valid_2of2_round_trip() {
    auto kagg = make_2party_keyagg();

    Scalar sk1{};
    Scalar::parse_bytes_strict_nonzero(kSk1, sk1);
    Scalar sk2{};
    Scalar::parse_bytes_strict_nonzero(kSk2, sk2);

    auto [sn1, pn1] = musig2_nonce_gen(sk1, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, nullptr);
    auto [sn2, pn2] = musig2_nonce_gen(sk2, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2}, nullptr);

    MuSig2AggNonce aggnonce = musig2_nonce_agg({pn1, pn2});
    // Valid aggregated nonce must NOT be infinity
    CHECK(!aggnonce.R1.is_infinity(), "[MIN-5a] valid nonce agg: R1 not infinity");
    CHECK(!aggnonce.R2.is_infinity(), "[MIN-5b] valid nonce agg: R2 not infinity");

    std::array<uint8_t, 32> msg = {0xAB, 0xCD, 0xEF};
    MuSig2Session sess = musig2_start_sign_session(aggnonce, kagg, msg);
    CHECK(session_is_valid(sess), "[MIN-5c] valid session: usable (e!=0, R!=infinity)");
    CHECK(!sess.e.is_zero(),         "[MIN-5d] valid session: challenge e is non-zero");
    CHECK(!sess.R.is_infinity(),     "[MIN-5e] valid session: nonce R is not infinity");

    MuSig2Session sess2 = sess;
    auto psig1 = musig2_partial_sign(sn1, sk1, kagg, sess, 0);
    auto psig2 = musig2_partial_sign(sn2, sk2, kagg, sess2, 1);
    CHECK(!psig1.is_zero(), "[MIN-5f] signer-0 partial sign succeeds");
    CHECK(!psig2.is_zero(), "[MIN-5g] signer-1 partial sign succeeds");

    auto final_sig = musig2_partial_sig_agg({psig1, psig2}, sess2);
    CHECK(final_sig[0] != 0 || final_sig[32] != 0,
          "[MIN-5h] aggregated signature non-zero");
}

// ── _run() ───────────────────────────────────────────────────────────────
int test_regression_musig2_infinity_nonce_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_musig2_infinity_nonce] BIP-327 infinity aggregate-nonce conformance (R=G)\n");

    test_nonce_agg_empty_vector();
    test_start_sign_session_r1_infinity();
    test_start_sign_session_r2_infinity();
    test_start_sign_session_from_empty_agg();
    test_valid_2of2_round_trip();

    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() {
    return test_regression_musig2_infinity_nonce_run();
}
#endif
