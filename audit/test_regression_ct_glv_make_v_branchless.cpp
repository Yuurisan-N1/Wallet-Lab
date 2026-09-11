// ============================================================================
// REGRESSION: ct::scalar_mul(Point,Scalar) uses the branchless ct_glv_make_v
// helper and stays numerically identical to the variable-time reference
// (CT-CRYPTO-001)
// ============================================================================
// The public variable-base CT scalar multiply secp256k1::ct::scalar_mul(p, k)
// (src/cpu/src/ct_point.cpp:3002) built its GLV "v" half-scalars with a local
// `make_v` lambda that branched on the SECRET GLV sign bit:
//     if (k_neg) { ...negate magnitude... } else { ...increment L[2]... }
// k_neg = ct_scalar_is_high(secret half-scalar); this path is reached from ECDH
// (ct::scalar_mul(pubkey, privkey)), ellswift XDH, and ec_seckey_tweak_mul with
// a SECRET scalar — so a data-dependent branch there is a constant-time hygiene
// gap (CT-CRYPTO-001). The fix makes the public scalar_mul build "v" with the
// SAME branchless masked computation as the ct_glv_make_v helper, INLINED into
// scalar_mul — the helper lives in a platform-guarded block not compiled on
// wasm/32-bit/MSVC, while this public scalar_mul is compiled everywhere, so it
// must not reference the helper directly (that broke the wasm/android/windows
// builds; the inline masked form is the same math and compiles on every target).
//
// This test proves the migration is numerically EXACT: for many random scalars
// (covering both GLV sign polarities ~50/50) and the k=1/k=2 edges,
//     ct::scalar_mul(P, k)  ==  P.scalar_mul(k)   (variable-time reference)
// on a non-generator base point P. If the branchless helper computed a different
// magnitude/offset than the old lambda, these would diverge.
// ============================================================================

#include <array>
#include <cstdint>
#include <cstdio>

#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/ct/point.hpp"

using secp256k1::fast::Scalar;
using secp256k1::fast::Point;

static int g_pass = 0, g_fail = 0;
static void check(bool cond, const char* msg) {
    if (cond) { ++g_pass; std::printf("    [OK] %s\n", msg); }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", msg); }
    std::fflush(stdout);
}

static bool points_equal(const Point& A, const Point& B) {
    if (A.is_infinity() && B.is_infinity()) return true;
    if (A.is_infinity() || B.is_infinity()) return false;
    return A.to_compressed() == B.to_compressed();
}

// Deterministic xorshift64 — no external entropy (reproducible test).
static uint64_t g_rng = 0x9e3779b97f4a7c15ULL;
static uint64_t next_rng() {
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}
static Scalar random_scalar() {
    std::array<uint8_t, 32> b{};
    for (int i = 0; i < 32; ++i) b[static_cast<unsigned>(i)] = static_cast<uint8_t>(next_rng() & 0xFFu);
    b[31] |= 0x01; // ensure non-zero
    return Scalar::from_bytes(b);
}

#ifndef UNIFIED_AUDIT_RUNNER
int main() {
#else
int test_regression_ct_glv_make_v_branchless_run() {
#endif
    std::printf("====================================================================\n");
    std::printf("REGRESSION: ct::scalar_mul branchless make_v correctness (CT-CRYPTO-001)\n");
    std::printf("====================================================================\n\n");

    // Non-generator base point P = 7*G (is_generator_ cleared after scalar_mul),
    // so P.scalar_mul(k) exercises the variable-base reference path.
    std::array<uint8_t, 32> seven{}; seven[31] = 0x07;
    Point P = Point::generator().scalar_mul(Scalar::from_bytes(seven));
    check(!P.is_infinity(), "setup: base point P = 7*G is valid");

    // Edge: k = 1 -> k*P == P ; k = 2 -> k*P == P+P
    {
        std::array<uint8_t, 32> one{}; one[31] = 0x01;
        Point a = secp256k1::ct::scalar_mul(P, Scalar::from_bytes(one));
        check(points_equal(a, P), "CT-GLV-1: ct::scalar_mul(P, 1) == P");

        std::array<uint8_t, 32> two{}; two[31] = 0x02;
        Point a2 = secp256k1::ct::scalar_mul(P, Scalar::from_bytes(two));
        Point ref2 = P.scalar_mul(Scalar::from_bytes(two));
        check(points_equal(a2, ref2), "CT-GLV-2: ct::scalar_mul(P, 2) == 2*P (vt ref)");
    }

    // Random scalars — both GLV sign polarities exercised across the sample.
    constexpr int N = 256;
    int mismatches = 0;
    for (int i = 0; i < N; ++i) {
        Scalar k = random_scalar();
        Point a = secp256k1::ct::scalar_mul(P, k);   // CT path (uses ct_glv_make_v)
        Point b = P.scalar_mul(k);                    // variable-time reference
        if (!points_equal(a, b)) ++mismatches;
    }
    check(mismatches == 0, "CT-GLV-3: ct::scalar_mul == vt scalar_mul for 256 random k");
    std::printf("    (random sample mismatches: %d / %d)\n", mismatches, N);

    std::printf("\n--- Result: %d passed, %d failed ---\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
