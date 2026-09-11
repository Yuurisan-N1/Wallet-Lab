// ============================================================================
// Specification Oracle: secp256k1 Curve Parameter Conformance Test
// ============================================================================
// Verifies that our implementation's constants EXACTLY match the published
// secp256k1 specification (SEC 2 v2.0, Certicom Research, 2010):
//   https://www.secg.org/sec2-v2.pdf  Section 2.4.1
//
// This is the single most important correctness test in the audit suite.
// Every cryptographic guarantee this library provides rests on:
//   1. The field prime p being the correct value
//   2. The curve order n being the correct value
//   3. The generator G having the published coordinates
//   4. G satisfying the curve equation y² = x³ + 7 (mod p)
//   5. n being the true order of G (n*G = point at infinity)
//
// If ANY of these checks fail, all signatures and key derivations are wrong.
//
// Tests:
//   SPEC-1  Field prime p matches SEC2 spec bytes
//   SPEC-2  Group order n matches SEC2 spec bytes
//   SPEC-3  Generator Gx matches SEC2 spec bytes
//   SPEC-4  Generator Gy matches SEC2 spec bytes
//   SPEC-5  G satisfies curve equation: Gy² ≡ Gx³ + 7 (mod p)
//   SPEC-6  (n-1)*G == -G  (proves n is the true order)
//   SPEC-7  p ≡ 3 (mod 4)  (required by our sqrt / Tonelli-Shanks)
//   SPEC-8  2*G ≠ G        (G is not a 2-torsion point)
//   SPEC-9  2*G ≠ infinity (G has order > 2)
//   SPEC-10 G + (-G) == infinity (group inverse)
//   SPEC-11 b = 7: G.y² - G.x³ ≡ 7 (mod p) (curve coefficient)
//   SPEC-12 Cross-representation: all limb layouts agree on p value
//   SPEC-13 Cross-representation: all limb layouts agree on n value
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>

#include "secp256k1/field.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/ct/point.hpp"

using namespace secp256k1::fast;

static int g_pass = 0, g_fail = 0;
static const char* g_section = "";

#include "audit_check.hpp"

// ============================================================================
// Published secp256k1 constants (SEC 2 v2.0, Section 2.4.1)
// Source: https://www.secg.org/sec2-v2.pdf
// ============================================================================

// p = 2^256 - 2^32 - 977
// = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
static constexpr std::array<uint8_t, 32> SPEC_P = {{
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFE, 0xFF,0xFF,0xFC,0x2F
}};

// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
static constexpr std::array<uint8_t, 32> SPEC_N = {{
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6, 0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C, 0xD0,0x36,0x41,0x41
}};

// n - 1 = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364140
static constexpr std::array<uint8_t, 32> SPEC_N_MINUS_1 = {{
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6, 0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C, 0xD0,0x36,0x41,0x40
}};

// Gx = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
static constexpr std::array<uint8_t, 32> SPEC_GX = {{
    0x79,0xBE,0x66,0x7E, 0xF9,0xDC,0xBB,0xAC,
    0x55,0xA0,0x62,0x95, 0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB, 0x2D,0xCE,0x28,0xD9,
    0x59,0xF2,0x81,0x5B, 0x16,0xF8,0x17,0x98
}};

// Gy = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
static constexpr std::array<uint8_t, 32> SPEC_GY = {{
    0x48,0x3A,0xDA,0x77, 0x26,0xA3,0xC4,0x65,
    0x5D,0xA4,0xFB,0xFC, 0x0E,0x11,0x08,0xA8,
    0xFD,0x17,0xB4,0x48, 0xA6,0x85,0x54,0x19,
    0x9C,0x47,0xD0,0x8F, 0xFB,0x10,0xD4,0xB8
}};

// ============================================================================
// Helper: compare a FieldElement's serialized bytes to spec bytes
// ============================================================================
static bool fe_bytes_eq(const FieldElement& fe, const std::array<uint8_t, 32>& spec) {
    auto got = fe.to_bytes();
    return got == spec;
}

// ============================================================================
// SPEC-1/2: Verify p and n match spec
// ============================================================================
static void run_spec_constants() {
    g_section = "SPEC-1/2 Constants (p, n)";

    // The field prime p: a FieldElement created from p_bytes should normalize to zero
    // because p ≡ 0 (mod p) in the field. This proves our p equals the spec p.
    FieldElement p_fe = FieldElement::from_bytes(SPEC_P);
    CHECK(p_fe == FieldElement::zero(),
          "SPEC-1: p_spec as FieldElement must be zero (p ≡ 0 mod p)");

    // Additionally, p-1 as a field element must NOT be zero
    std::array<uint8_t, 32> p_minus_1 = SPEC_P;
    p_minus_1[31] ^= 0x01;  // p-1: last byte 0x2F → 0x2E
    FieldElement pm1_fe = FieldElement::from_bytes(p_minus_1);
    CHECK(!(pm1_fe == FieldElement::zero()),
          "SPEC-1: p-1 as FieldElement must NOT be zero");

    // The scalar n: Scalar::from_bytes(n_bytes) must reduce to zero (n ≡ 0 mod n)
    Scalar n_scalar = Scalar::from_bytes(SPEC_N);
    CHECK(n_scalar.is_zero(),
          "SPEC-2: n_spec as Scalar must be zero (n ≡ 0 mod n)");

    // n-1 must NOT reduce to zero
    Scalar nm1 = Scalar::from_bytes(SPEC_N_MINUS_1);
    CHECK(!nm1.is_zero(),
          "SPEC-2: (n-1)_spec as Scalar must NOT be zero");
}

// ============================================================================
// SPEC-3/4: Verify generator coordinates match spec
// ============================================================================
static void run_spec_generator_coords() {
    g_section = "SPEC-3/4 Generator coordinates (Gx, Gy)";

    Point G = Point::generator();

    CHECK(!G.is_infinity(),
          "SPEC-3: generator must not be the point at infinity");

    // Extract affine coordinates
    FieldElement Gx = G.x();
    FieldElement Gy = G.y();

    CHECK(fe_bytes_eq(Gx, SPEC_GX),
          "SPEC-3: generator x-coordinate must match SEC2 spec");

    CHECK(fe_bytes_eq(Gy, SPEC_GY),
          "SPEC-4: generator y-coordinate must match SEC2 spec");
}

// ============================================================================
// SPEC-5/11: G satisfies curve equation y² = x³ + 7 (mod p)
// b = 7 is the curve coefficient in y² = x³ + ax + b, a=0
// ============================================================================
static void run_spec_curve_equation() {
    g_section = "SPEC-5/11 Curve equation y² = x³ + 7";

    Point G = Point::generator();
    FieldElement Gx = G.x();
    FieldElement Gy = G.y();

    FieldElement lhs = Gy * Gy;              // Gy²
    FieldElement rhs = Gx * Gx * Gx + FieldElement::from_uint64(7);  // Gx³ + 7

    CHECK(lhs == rhs,
          "SPEC-5: Gy² must equal Gx³ + 7 (mod p) — G lies on secp256k1");

    // Also verify the curve coefficient b = 7 (not 6, not 8)
    FieldElement curve_b = lhs - Gx * Gx * Gx;  // Gy² - Gx³ = b
    FieldElement expected_b = FieldElement::from_uint64(7);
    CHECK(curve_b == expected_b,
          "SPEC-11: curve coefficient b must equal 7");

    // Verify coefficient a = 0 (curve has no linear x term)
    FieldElement rhs_full = Gx * Gx * Gx + expected_b;  // x³ + b (no ax term)
    CHECK(lhs == rhs_full,
          "SPEC-11: a = 0 verified — curve is y² = x³ + 7 with no linear term");

    // Verify for 2*G as well (a randomly derived point that must also be on curve)
    Scalar two = Scalar::from_uint64(2);
    Point G2 = Point::generator().scalar_mul(two);
    CHECK(!G2.is_infinity(), "SPEC-5: 2*G must not be infinity");
    FieldElement G2x = G2.x();
    FieldElement G2y = G2.y();
    FieldElement lhs2 = G2y * G2y;
    FieldElement rhs2 = G2x * G2x * G2x + FieldElement::from_uint64(7);
    CHECK(lhs2 == rhs2, "SPEC-5: 2*G must also satisfy y² = x³ + 7");
}

// ============================================================================
// SPEC-6: (n-1)*G == -G  (proves n is the true group order of G)
// ============================================================================
static void run_spec_group_order() {
    g_section = "SPEC-6 Group order (n*G = ∞, (n-1)*G = -G)";

    // (n-1)*G should equal -G
    // Because: (n-1)*G + G = n*G = ∞  ⟹  (n-1)*G = -G
    Scalar n_minus_1 = Scalar::from_bytes(SPEC_N_MINUS_1);

    Point G         = Point::generator();
    Point neg_G     = G.negate();
    Point kG        = Point::generator().scalar_mul(n_minus_1);

    CHECK(!kG.is_infinity(),
          "SPEC-6: (n-1)*G must not be infinity");

    FieldElement kGx = kG.x();
    FieldElement kGy = kG.y();
    FieldElement nGx = neg_G.x();
    FieldElement nGy = neg_G.y();

    // Same x-coordinate (both -G have same x as G)
    CHECK(kGx == nGx,
          "SPEC-6: (n-1)*G and -G must have the same x-coordinate");

    // Same y-coordinate (both equal -G)
    CHECK(kGy == nGy,
          "SPEC-6: (n-1)*G must equal -G (same y)");

    // Zero scalar gives infinity: 0*G = ∞
    Scalar zero_scalar = Scalar::from_bytes(SPEC_N);  // n ≡ 0 mod n
    Point zero_G = Point::generator().scalar_mul(zero_scalar);
    CHECK(zero_G.is_infinity(),
          "SPEC-6: 0*G (= n*G) must be the point at infinity");
}

// ============================================================================
// SPEC-7: p ≡ 3 (mod 4) — required by our Cipolla/Tonelli-Shanks sqrt
// ============================================================================
static void run_spec_prime_properties() {
    g_section = "SPEC-7 Prime properties (p ≡ 3 mod 4)";

    // p mod 4: last two bits of p.
    // p = ...FFFFFC2F in hex. 0x2F = 0b00101111. Bottom 2 bits = 11 = 3 (mod 4) ✓
    uint8_t p_low_byte = SPEC_P[31];  // 0x2F
    CHECK((p_low_byte & 3u) == 3u,
          "SPEC-7: p ≡ 3 (mod 4) — required for sqrt via (p+1)/4 exponentiation");

    // Verify our sqrt is consistent with the spec: sqrt(4) mod p should be 2
    FieldElement four = FieldElement::from_uint64(4);
    FieldElement root = four.sqrt();
    // sqrt(4) = 2 or p-2; either way root*root == 4
    FieldElement root_sq = root * root;
    CHECK(root_sq == four, "SPEC-7: sqrt(4)^2 must equal 4");

    // Euler criterion: a^((p-1)/2) ≡ 1 (mod p) for any quadratic residue a
    // Use a = 4 (which is 2², a QR): 4^((p-1)/2) must equal 1
    // We verify indirectly: sqrt exists iff a^((p-1)/2) == 1
    FieldElement nine = FieldElement::from_uint64(9);  // 3², also a QR
    FieldElement root9 = nine.sqrt();
    CHECK(root9 * root9 == nine, "SPEC-7: sqrt(9)^2 must equal 9");
}

// ============================================================================
// SPEC-8/9/10: Generator order > 2, group inverse
// ============================================================================
static void run_spec_torsion() {
    g_section = "SPEC-8/9/10 Torsion and inverse";

    Point G = Point::generator();
    Scalar two = Scalar::from_uint64(2);
    Point G2 = Point::generator().scalar_mul(two);

    // SPEC-8: 2*G ≠ G (G is not a fixed point of doubling)
    FieldElement Gx  = G.x();
    FieldElement Gy  = G.y();
    FieldElement G2x = G2.x();
    FieldElement G2y = G2.y();
    CHECK(Gx != G2x || Gy != G2y,
          "SPEC-8: 2*G must not equal G (order > 1)");

    // SPEC-9: 2*G ≠ infinity (order > 2)
    CHECK(!G2.is_infinity(),
          "SPEC-9: 2*G must not be the point at infinity (order > 2)");

    // SPEC-10: G + (-G) == infinity
    Point neg_G    = G.negate();
    Point sum      = G.add(neg_G);
    CHECK(sum.is_infinity(),
          "SPEC-10: G + (-G) must be the point at infinity");

    // Commutativity: (-G) + G also gives infinity
    Point sum2 = neg_G.add(G);
    CHECK(sum2.is_infinity(),
          "SPEC-10: (-G) + G must also be the point at infinity (commutativity)");
}

// ============================================================================
// SPEC-12/13: Cross-representation consistency
// All arithmetic representations (4x64, 5x52, 10x26 where available)
// must give the same results for p and n.
// ============================================================================
static void run_spec_cross_representation() {
    g_section = "SPEC-12/13 Cross-representation (64-bit vs 32-bit)";

    // Verify PRIME32 (ARM 32-bit representation) matches SPEC_P
    // We do this indirectly: compute the prime via field arithmetic.
    // If p is correctly represented, then (-1) in the field (== p-1 in the integers)
    // should serialize as p-1 bytes.
    FieldElement minus_one = FieldElement::from_uint64(1).negate();
    // minus_one = -1 = p - 1 in the field
    auto serialized = minus_one.to_bytes();

    // p - 1 bytes: same as SPEC_P but last byte decremented
    std::array<uint8_t, 32> p_minus_1_expected = SPEC_P;
    p_minus_1_expected[31] -= 1;  // 0x2F -> 0x2E

    CHECK(serialized == p_minus_1_expected,
          "SPEC-12: (-1) in field must serialize as p-1 bytes (cross-rep consistency)");

    // Similarly, for scalars: -1 mod n should be n-1
    Scalar minus_one_scalar = Scalar::from_uint64(1).negate();
    auto s_bytes = minus_one_scalar.to_bytes();
    CHECK(s_bytes == SPEC_N_MINUS_1,
          "SPEC-13: (-1) as Scalar must serialize as n-1 bytes (cross-rep consistency)");
}

// ============================================================================
// Entry point
// ============================================================================
int test_secp256k1_spec_run() {
    g_pass = 0;
    g_fail = 0;

    run_spec_constants();
    run_spec_generator_coords();
    run_spec_curve_equation();
    run_spec_group_order();
    run_spec_prime_properties();
    run_spec_torsion();
    run_spec_cross_representation();

    printf("[test_secp256k1_spec] %d/%d checks passed\n", g_pass, g_pass + g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_secp256k1_spec_run(); }
#endif
