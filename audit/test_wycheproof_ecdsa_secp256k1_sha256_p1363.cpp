// ============================================================================
// C2SP Wycheproof ECDSA secp256k1 SHA-256 P1363 Test Vectors
// ============================================================================
// Source: ecdsa_secp256k1_sha256_p1363_test.json (Apache 2.0)
// Origin: https://github.com/C2SP/wycheproof
//
// IEEE P1363 encoding: fixed 64-byte raw r || s (no DER wrapping).
//
// Categories covered:
//   1. Valid P1363 signatures (baseline, signature malleability)
//   2. k*G large x-coordinate (r ≈ 2^128): valid
//   3. Boundary: small r=1,s=1 and r=1,s=2
//   4. s == 1 (min-s edge case)
//   5. Invalid: r=0, s=0, r=0+variants, r=n, s=0, etc.
//   6. Wrong size (not exactly 64 bytes)
//   7. Point-at-infinity during verification
//   8. Comparison-with-infinity edge case
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>

#include "secp256k1/field.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/ecdsa.hpp"
#include "secp256k1/sha256.hpp"

using namespace secp256k1;
using fast::Scalar;
using fast::Point;
using fast::FieldElement;

static int g_pass = 0, g_fail = 0;
static const char* g_section = "";

#include "audit_check.hpp"

// -- Hex helpers ---------------------------------------------------------------

static uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

static std::array<uint8_t, 32> hex32(const char* h) {
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < 32; ++i)
        out[i] = static_cast<uint8_t>(
            (hex_nibble(h[2*i]) << 4) | hex_nibble(h[2*i+1]));
    return out;
}

static size_t hex_decode(const char* hex, uint8_t* out, size_t max_out) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return 0;
    size_t n = hex_len / 2;
    if (n > max_out) return 0;
    for (size_t i = 0; i < n; ++i)
        out[i] = static_cast<uint8_t>(
            (hex_nibble(hex[2*i]) << 4) | hex_nibble(hex[2*i+1]));
    return n;
}

// -- P1363 parser: exactly 64 bytes, bytes[0..31]=r, bytes[32..63]=s ----------
static bool p1363_parse(const uint8_t* buf, size_t len,
                         std::array<uint8_t,32>& r_out,
                         std::array<uint8_t,32>& s_out) {
    if (len != 64) return false;
    std::memcpy(r_out.data(), buf,      32);
    std::memcpy(s_out.data(), buf + 32, 32);
    return true;
}

// -- Public key construction --------------------------------------------------
static Point make_pubkey(const char* wx_hex, const char* wy_hex) {
    auto x = FieldElement::from_bytes(hex32(wx_hex));
    auto y = FieldElement::from_bytes(hex32(wy_hex));
    return Point::from_affine(x, y);
}

// -- Strict non-zero scalar check (r, s must be in [1, n-1]) -----------------
// returns false when parse_bytes_strict_nonzero fails (value is 0 or >= n)
static bool parse_scalar_strict(const std::array<uint8_t,32>& bytes, Scalar& out) {
    return Scalar::parse_bytes_strict_nonzero(bytes, out);
}

// -- Standard hash: SHA-256("313233343030") -----------------------------------
// msg = hex "313233343030" = ASCII bytes [0x31,0x32,0x33,0x34,0x30,0x30]
// sha256 = bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023
static std::array<uint8_t,32> std_hash() {
    uint8_t msg[] = { 0x31, 0x32, 0x33, 0x34, 0x30, 0x30 };
    return SHA256::hash(msg, sizeof(msg));
}

// -- Verify helper using strict scalar parsing --------------------------------
// Returns true iff r & s parse cleanly into [1,n-1] and the ECDSA equation holds.
static bool p1363_verify(const uint8_t* sig64, size_t sig_len,
                          const std::array<uint8_t,32>& hash,
                          const Point& pk) {
    std::array<uint8_t,32> r_b{}, s_b{};
    if (!p1363_parse(sig64, sig_len, r_b, s_b)) return false;
    Scalar r_s{}, s_s{};
    if (!parse_scalar_strict(r_b, r_s)) return false;
    if (!parse_scalar_strict(s_b, s_s)) return false;
    ECDSASignature sig{ r_s, s_s };
    return ecdsa_verify(hash.data(), pk, sig);
}

// ============================================================================
// 1. Valid signatures – baseline + signature malleability (tcId 1)
// ============================================================================
// Group 1 pubkey (wx/wy decoded from P1363 JSON Group 1):
//   wx = b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f
//   wy = f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9
//
// tcId 1: "signature malleability" – high-S, but valid general ECDSA
//   r = 813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365
//   s = 900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87
static void test_valid_group1_sigs() {
    g_section = "p1363_valid_g1";
    std::printf("  [1] Valid P1363 signatures (Group 1, tcId 1)\n");

    auto pk = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    auto hash = std_hash();

    // tcId 1: valid sig (high-S but not Bitcoin – P1363 has no low-S rule)
    const char* sig_hex =
        "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87";
    uint8_t sig_buf[64];
    size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
    CHECK(sig_len == 64, "tcId 1: decoded 64 bytes");

    CHECK(p1363_verify(sig_buf, sig_len, hash, pk), "tcId 1: valid sig verifies");
}

// ============================================================================
// 2. Valid – k*G large x-coordinate (tcId 115, r ≈ 2^128)
// ============================================================================
// Group 2 pubkey:
//   wx = 07310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc362
//   wy = 26a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0
//
// tcId 115: r = 000000000000000000000000000000014551231950b75fc4402da1722fc9baeb
//           s = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e
static void test_valid_large_x_coord() {
    g_section = "p1363_large_x_tcid115";
    std::printf("  [2] Valid: k*G large x-coordinate (tcId 115)\n");

    auto pk = make_pubkey(
        "07310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc362",
        "26a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0");

    auto hash = std_hash();

    const char* sig_hex =
        "000000000000000000000000000000014551231950b75fc4402da1722fc9baeb"
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e";
    uint8_t sig_buf[64];
    size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
    CHECK(sig_len == 64, "tcId 115: decoded 64 bytes");
    CHECK(p1363_verify(sig_buf, sig_len, hash, pk), "tcId 115: large-x valid");
}

// ============================================================================
// 3. Valid – small r=1, s=1 and r=1, s=2 (tcId 120, 122)
// ============================================================================
// Group 5 pubkey (tcId 120, r=s=1):
//   wx = 1877045be25d34a1d0600f9d5c00d0645a2a54379b6ceefad2e6bf5c2a3352ce
//   wy = 821a532cc1751ee1d36d41c3d6ab4e9b143e44ec46d73478ea6a79a5c0e54159
//
// Group 6 pubkey (tcId 122, r=1, s=2):
//   wx = 455439fcc3d2deeceddeaece60e7bd17304f36ebb602adf5a22e0b8f1db46a50
//   wy = aec38fb2baf221e9a8d1887c7bf6222dd1834634e77263315af6d23609d04f77
static void test_valid_small_rs() {
    g_section = "p1363_small_rs";
    std::printf("  [3] Valid: small r=1,s=1 (tcId 120) and r=1,s=2 (tcId 122)\n");

    auto hash = std_hash();

    // tcId 120: r=1, s=1
    {
        auto pk = make_pubkey(
            "1877045be25d34a1d0600f9d5c00d0645a2a54379b6ceefad2e6bf5c2a3352ce",
            "821a532cc1751ee1d36d41c3d6ab4e9b143e44ec46d73478ea6a79a5c0e54159");

        const char* sig_hex =
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000001";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(sig_len == 64, "tcId 120: decoded 64 bytes");
        CHECK(p1363_verify(sig_buf, sig_len, hash, pk), "tcId 120: r=s=1 valid");
    }

    // tcId 122: r=1, s=2
    {
        auto pk = make_pubkey(
            "455439fcc3d2deeceddeaece60e7bd17304f36ebb602adf5a22e0b8f1db46a50",
            "aec38fb2baf221e9a8d1887c7bf6222dd1834634e77263315af6d23609d04f77");

        const char* sig_hex =
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(sig_len == 64, "tcId 122: decoded 64 bytes");
        CHECK(p1363_verify(sig_buf, sig_len, hash, pk), "tcId 122: r=1,s=2 valid");
    }
}

// ============================================================================
// 4. Valid – s == 1 edge case (tcId 148)
// ============================================================================
// Group 148 pubkey:
//   wx = bb79f61857f743bfa1b6e7111ce4094377256969e4e15159123d9548acc3be6c
//   wy = 1f9d9f8860dcffd3eb36dd6c31ff2e7226c2009c4c94d8d7d2b5686bf7abd677
//
// tcId 148: r = 55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1
//           s = 0000000000000000000000000000000000000000000000000000000000000001 (result=valid)
static void test_valid_s_equals_one() {
    g_section = "p1363_s_eq_one_tcid148";
    std::printf("  [4] Valid: s == 1 (tcId 148)\n");

    auto pk = make_pubkey(
        "bb79f61857f743bfa1b6e7111ce4094377256969e4e15159123d9548acc3be6c",
        "1f9d9f8860dcffd3eb36dd6c31ff2e7226c2009c4c94d8d7d2b5686bf7abd677");

    auto hash = std_hash();

    const char* sig_hex =
        "55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1"
        "0000000000000000000000000000000000000000000000000000000000000001";
    uint8_t sig_buf[64];
    size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
    CHECK(sig_len == 64, "tcId 148: decoded 64 bytes");
    CHECK(p1363_verify(sig_buf, sig_len, hash, pk), "tcId 148: s=1 valid");
}

// ============================================================================
// 5. Invalid – r = 0 variants (tcId 11–14)
// ============================================================================
// Group 1 pubkey used throughout (wx/wy from test #1 above).
// All must be REJECTED.
static void test_invalid_r_zero() {
    g_section = "p1363_invalid_r0";
    std::printf("  [5] Invalid: r == 0 variants (tcId 11-14)\n");

    auto pk = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    auto hash = std_hash();

    // tcId 11: r=0, s=0
    {
        const char* sig_hex =
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 11: r=s=0 rejected");
    }

    // tcId 12: r=0, s=1
    {
        const char* sig_hex =
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000001";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 12: r=0,s=1 rejected");
    }

    // tcId 13: r=0, s=n  (n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    {
        const char* sig_hex =
            "0000000000000000000000000000000000000000000000000000000000000000"
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 13: r=0,s=n rejected");
    }

    // tcId 14: r=0, s=n-1
    {
        const char* sig_hex =
            "0000000000000000000000000000000000000000000000000000000000000000"
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        // s=n-1 is in [1,n-1] but r=0 must reject
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 14: r=0,s=n-1 rejected");
    }
}

// ============================================================================
// 6. Invalid – s == 0 variants (tcId 18, 32, 149)
// ============================================================================
static void test_invalid_s_zero() {
    g_section = "p1363_invalid_s0";
    std::printf("  [6] Invalid: s == 0 variants (tcId 18, 32, 149)\n");

    auto hash = std_hash();

    // tcId 18: r=1, s=0 (Group 1 pk)
    {
        auto pk = make_pubkey(
            "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
            "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");
        const char* sig_hex =
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000000";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 18: r=1,s=0 rejected");
    }

    // tcId 32: r=n-1, s=0 (Group 1 pk)
    {
        auto pk = make_pubkey(
            "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
            "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");
        const char* sig_hex =
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
            "0000000000000000000000000000000000000000000000000000000000000000";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 32: r=n-1,s=0 rejected");
    }

    // tcId 149: s=0, r=valid (Group 148 pk) – corresponds to s==0 check
    {
        auto pk = make_pubkey(
            "bb79f61857f743bfa1b6e7111ce4094377256969e4e15159123d9548acc3be6c",
            "1f9d9f8860dcffd3eb36dd6c31ff2e7226c2009c4c94d8d7d2b5686bf7abd677");
        const char* sig_hex =
            "55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1"
            "0000000000000000000000000000000000000000000000000000000000000000";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 149: s=0 rejected");
    }
}

// ============================================================================
// 7. Invalid – r out of range (r >= n, r = n, r = n+1, r = p)
//    tcId 25, 26, 39, 46  (Group 1 pubkey)
// ============================================================================
static void test_invalid_r_out_of_range() {
    g_section = "p1363_invalid_r_range";
    std::printf("  [7] Invalid: r >= n (tcId 25, 26, 39, 46)\n");

    auto pk = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    auto hash = std_hash();

    // tcId 25: r=n, s=0  (r=n is out of range; s=0 also invalid)
    {
        const char* sig_hex =
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
            "0000000000000000000000000000000000000000000000000000000000000000";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 25: r=n,s=0 rejected");
    }

    // tcId 26: r=n, s=1
    {
        const char* sig_hex =
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
            "0000000000000000000000000000000000000000000000000000000000000001";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 26: r=n,s=1 rejected");
    }

    // tcId 39: r=n+1, s=0
    {
        const char* sig_hex =
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
            "0000000000000000000000000000000000000000000000000000000000000000";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 39: r=n+1,s=0 rejected");
    }

    // tcId 46: r=p, s=0  (p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    {
        const char* sig_hex =
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
            "0000000000000000000000000000000000000000000000000000000000000000";
        uint8_t sig_buf[64];
        size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
        CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 46: r=p,s=0 rejected");
    }
}

// ============================================================================
// 8. Invalid – r = p-3 (> n) with otherwise valid s (tcId 116)
// ============================================================================
// Group 2 pubkey, r = p-3 which is > n, so it must be rejected.
// r = fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c
// s = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e
static void test_invalid_r_p_minus_3() {
    g_section = "p1363_invalid_r_pmin3_tcid116";
    std::printf("  [8] Invalid: r = p-3 > n (tcId 116)\n");

    auto pk = make_pubkey(
        "07310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc362",
        "26a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0");

    auto hash = std_hash();

    const char* sig_hex =
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c"
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e";
    uint8_t sig_buf[64];
    size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
    CHECK(sig_len == 64, "tcId 116: decoded 64 bytes");
    CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 116: r=p-3 > n rejected");
}

// ============================================================================
// 9. Invalid – wrong size (not 64 bytes); tcId 121 ("0101")
// ============================================================================
static void test_invalid_wrong_size() {
    g_section = "p1363_invalid_size";
    std::printf("  [9] Invalid: wrong encoded size (tcId 121)\n");

    uint8_t sig_buf[64] = { 0x01, 0x01 };  // only 2 bytes

    auto pk = make_pubkey(
        "1877045be25d34a1d0600f9d5c00d0645a2a54379b6ceefad2e6bf5c2a3352ce",
        "821a532cc1751ee1d36d41c3d6ab4e9b143e44ec46d73478ea6a79a5c0e54159");

    auto hash = std_hash();

    // p1363_parse checks len == 64; 2 != 64 → rejects
    CHECK(!p1363_verify(sig_buf, 2, hash, pk), "tcId 121: 2-byte sig rejected");
    // Zero-length
    CHECK(!p1363_verify(sig_buf, 0, hash, pk), "zero-length sig rejected");
    // 63 bytes (truncated)
    CHECK(!p1363_verify(sig_buf, 63, hash, pk), "63-byte sig rejected");
}

// ============================================================================
// 10. Invalid – point at infinity during verification (tcId 165)
// ============================================================================
// Group 165 pubkey (chosen so the verification equation produces infinity):
//   wx = d533b789a4af890fa7a82a1fae58c404f9a62a50b49adafab349c513b4150874
//   wy = 01b4171b803e76b34a9861e10f7bc289a066fd01bd29f84c987a10a5fb18c2d4
// sig: r = 7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0  (= n/2)
//      s = 55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0
static void test_invalid_infinity_during_verify() {
    g_section = "p1363_invalid_infinity_tcid165";
    std::printf(" [10] Invalid: point at infinity during verify (tcId 165)\n");

    auto pk = make_pubkey(
        "d533b789a4af890fa7a82a1fae58c404f9a62a50b49adafab349c513b4150874",
        "01b4171b803e76b34a9861e10f7bc289a066fd01bd29f84c987a10a5fb18c2d4");

    auto hash = std_hash();

    const char* sig_hex =
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
        "55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0";
    uint8_t sig_buf[64];
    size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
    CHECK(sig_len == 64, "tcId 165: decoded 64 bytes");
    CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 165: infinity-result rejected");
}

// ============================================================================
// 11. Invalid – comparison with infinity (tcId 204)
// ============================================================================
// Group 204 pubkey:
//   wx = 8aa2c64fa9c6437563abfbcbd00b2048d48c18c152a2a6f49036de7647ebe82e
//   wy = 1ce64387995c68a060fa3bc0399b05cc06eec7d598f75041a4917e692b7f51ff
// sig: r = 55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0
//      s = 33333333333333333333333333333332f222f8faefdb533f265d461c29a47373
static void test_invalid_comparison_with_infinity() {
    g_section = "p1363_invalid_compare_inf_tcid204";
    std::printf(" [11] Invalid: comparison with infinity (tcId 204)\n");

    auto pk = make_pubkey(
        "8aa2c64fa9c6437563abfbcbd00b2048d48c18c152a2a6f49036de7647ebe82e",
        "1ce64387995c68a060fa3bc0399b05cc06eec7d598f75041a4917e692b7f51ff");

    auto hash = std_hash();

    const char* sig_hex =
        "55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c0"
        "33333333333333333333333333333332f222f8faefdb533f265d461c29a47373";
    uint8_t sig_buf[64];
    size_t sig_len = hex_decode(sig_hex, sig_buf, sizeof(sig_buf));
    CHECK(sig_len == 64, "tcId 204: decoded 64 bytes");
    CHECK(!p1363_verify(sig_buf, sig_len, hash, pk), "tcId 204: infinity-comparison rejected");
}

// ============================================================================
// 12. Wrong message/key cross-check
// ============================================================================
// Verify that a valid signature for Group 1 does NOT verify under Group 2 key
// and does NOT verify with a different message hash.
static void test_cross_checks() {
    g_section = "p1363_cross_check";
    std::printf(" [12] Cross-checks: wrong key / wrong message\n");

    // Valid sig for Group 1 (tcId 1)
    const char* sig_hex =
        "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87";
    uint8_t sig_buf[64];
    hex_decode(sig_hex, sig_buf, sizeof(sig_buf));

    auto hash = std_hash();

    // Wrong key (Group 2)
    auto pk_wrong = make_pubkey(
        "07310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc362",
        "26a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0");
    CHECK(!p1363_verify(sig_buf, 64, hash, pk_wrong), "wrong key rejects valid sig");

    // Wrong message
    auto pk_g1 = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");
    uint8_t bad_msg[] = { 0x00 };
    auto wrong_hash = SHA256::hash(bad_msg, sizeof(bad_msg));
    CHECK(!p1363_verify(sig_buf, 64, wrong_hash, pk_g1), "wrong message rejects valid sig");
}

// ============================================================================
// Entry point
// ============================================================================
int test_wycheproof_ecdsa_p1363_run() {
    std::printf("=== Wycheproof ECDSA secp256k1 SHA-256 P1363 ===\n");
    test_valid_group1_sigs();
    test_valid_large_x_coord();
    test_valid_small_rs();
    test_valid_s_equals_one();
    test_invalid_r_zero();
    test_invalid_s_zero();
    test_invalid_r_out_of_range();
    test_invalid_r_p_minus_3();
    test_invalid_wrong_size();
    test_invalid_infinity_during_verify();
    test_invalid_comparison_with_infinity();
    test_cross_checks();
    std::printf("--- Result: %d passed, %d failed ---\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() {
    return test_wycheproof_ecdsa_p1363_run();
}
#endif
