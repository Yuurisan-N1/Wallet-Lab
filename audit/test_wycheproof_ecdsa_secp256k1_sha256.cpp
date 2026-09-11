// ============================================================================
// C2SP Wycheproof ECDSA secp256k1 SHA-256 DER Test Vectors
// ============================================================================
// Source: ecdsa_secp256k1_sha256_test.json (Apache 2.0)
// Origin: https://github.com/C2SP/wycheproof
//
// DER encoding: standard ASN.1 SEQUENCE { INTEGER r, INTEGER s }.
//
// Categories covered:
//   1. Valid pseudorandom DER signatures (Group 1 tcId 1,3; Group 2 tcId 5)
//   2. Signature malleability – high-S is valid in non-Bitcoin ECDSA (tcId 5)
//   3. k*G large x-coordinate edge case (tcId 350, valid)
//   4. r=n-1, s=n-2 boundary (tcId 352, valid)
//   5. s=1 arithmetic edge (tcId 373, valid) and s=0 (tcId 374, invalid)
//   6. r=0 / s=0 edge cases (tcId 168, 169, 176)
//   7. r=n, r=p out-of-range rejects (tcId 192, 193, 216)
//   8. Structural rejects: empty, partial-tag, BER long-form, BER indefinite,
//      missing leading-zero (negative INTEGER), wrong outer tag, trailing bytes,
//      BER-encoded r-length
//   9. Cross-check: wrong key / wrong message
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

// -- Hex helpers --------------------------------------------------------------

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

// -- Strict DER ECDSA parser --------------------------------------------------
// Accepts only canonical DER: 0x30 <short-form len> 0x02 <rlen> <r> 0x02 <slen> <s>
// Rejects all BER extensions, negative integers, integers > 32 bytes, trailing bytes.
static bool der_parse_strict(const uint8_t* der, size_t len,
                              std::array<uint8_t,32>& r_out,
                              std::array<uint8_t,32>& s_out) {
    if (!der || len < 8) return false;
    size_t off = 0;
    if (der[off++] != 0x30) return false;

    // Short-form only (< 0x80)
    if (off >= len) return false;
    if (der[off] >= 0x80) return false;
    size_t seq_len = der[off++];
    if (off + seq_len != len) return false;

    auto read_int = [&](std::array<uint8_t,32>& out) -> bool {
        if (off >= len || der[off] != 0x02) return false;
        off++;
        if (off >= len) return false;
        if (der[off] >= 0x80) return false; // reject BER long-form
        size_t int_len = der[off++];
        if (int_len == 0 || off + int_len > len) return false;
        const uint8_t* p = der + off;
        size_t n = int_len;
        // Reject non-minimal leading zero (0x00 before a byte that doesn't need it)
        if (n > 1 && p[0] == 0x00 && p[1] < 0x80) return false;
        // Reject missing leading zero (high bit set with no preceding 0x00)
        if (n > 0 && p[0] >= 0x80) return false;
        // Strip canonical leading 0x00 (required for high-bit value bytes)
        if (n > 0 && p[0] == 0x00) { p++; n--; }
        if (n > 32) return false;
        out.fill(0);
        if (n > 0) std::memcpy(out.data() + 32 - n, p, n);
        off += int_len;
        return true;
    };

    if (!read_int(r_out)) return false;
    if (!read_int(s_out)) return false;
    if (off != len) return false; // no trailing bytes
    return true;
}

// -- Public key construction --------------------------------------------------
static Point make_pubkey(const char* wx_hex, const char* wy_hex) {
    auto x = FieldElement::from_bytes(hex32(wx_hex));
    auto y = FieldElement::from_bytes(hex32(wy_hex));
    return Point::from_affine(x, y);
}

// -- Strict scalar range check: [1, n-1] ------------------------------------
static bool parse_scalar_strict(const std::array<uint8_t,32>& bytes, Scalar& out) {
    return Scalar::parse_bytes_strict_nonzero(bytes, out);
}

// -- Full DER-verify: parse + scalar checks + ECDSA verify ------------------
static bool der_verify(const char* sig_hex,
                        const std::array<uint8_t,32>& hash,
                        const Point& pk) {
    uint8_t buf[300] = {};
    size_t len = (strlen(sig_hex) == 0) ? 0
                                        : hex_decode(sig_hex, buf, sizeof(buf));
    if (len == 0 && strlen(sig_hex) != 0) return false; // odd-length or overflow

    std::array<uint8_t,32> r_b{}, s_b{};
    if (!der_parse_strict(buf, len, r_b, s_b)) return false;

    Scalar r_s{}, s_s{};
    if (!parse_scalar_strict(r_b, r_s)) return false;
    if (!parse_scalar_strict(s_b, s_s)) return false;

    ECDSASignature sig{ r_s, s_s };
    return ecdsa_verify(hash.data(), pk, sig);
}

// -- Message hashes -----------------------------------------------------------
// msg = "" (empty)
static std::array<uint8_t,32> hash_empty() {
    uint8_t dummy[1] = {};
    return SHA256::hash(dummy, 0); // zero length, non-null pointer
}
// msg = hex("313233343030")
static std::array<uint8_t,32> hash_std() {
    uint8_t msg[] = { 0x31, 0x32, 0x33, 0x34, 0x30, 0x30 };
    return SHA256::hash(msg, sizeof(msg));
}

// ============================================================================
// 1. Valid DER signatures – Group 1 (tcId 1, 3)
// ============================================================================
// wx = 782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963
// wy = af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152
static void test_valid_group1() {
    g_section = "der_valid_g1";
    std::printf("  [1] Valid DER – Group 1 (tcId 1, 3)\n");

    auto pk = make_pubkey(
        "782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963",
        "af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152");

    // tcId 1: msg = "" (empty)
    CHECK(der_verify(
        "3046022100f80ae4f96cdbc9d853f83d47aae225bf407d51c56b7776cd67d0dc195d99a9dc"
        "022100b303e26be1f73465315221f0b331528807a1a9b6eb068ede6eebeaaa49af8a36",
        hash_empty(), pk), "tcId 1: valid empty-msg");

    // tcId 3: msg = "313233343030"
    CHECK(der_verify(
        "3045022100d035ee1f17fdb0b2681b163e33c359932659990af77dca632012b30b27a057b3"
        "02201939d9f3b2858bc13e3474cb50e6a82be44faa71940f876c1cba4c3e989202b6",
        hash_std(), pk), "tcId 3: valid std-msg");
}

// ============================================================================
// 2. Valid – Group 2, signature malleability (tcId 5)
// ============================================================================
// wx = b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f
// wy = f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9
// (JSON has leading 00 bytes; stripped to 32 bytes for FieldElement::from_bytes)
//
// High-S is valid in non-Bitcoin ECDSA.
static void test_valid_malleable() {
    g_section = "der_valid_malleable";
    std::printf("  [2] Valid: high-S malleability (tcId 5, Group 2)\n");

    auto pk = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    CHECK(der_verify(
        "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
        hash_std(), pk), "tcId 5: high-S valid");
}

// ============================================================================
// 3. Valid – k*G large x-coordinate (tcId 350)
// ============================================================================
// Same Group 2 pubkey. r ≈ 2^128 (k*G.x ≥ n → reduction gives small r).
static void test_valid_large_x() {
    g_section = "der_valid_large_x";
    std::printf("  [3] Valid: large k*G x-coord (tcId 350)\n");

    auto pk = make_pubkey(
        "07310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc362",
        "26a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0");

    // r = 014551231950b75fc4402da1722fc9baeb (17 bytes)
    // s = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e
    CHECK(der_verify(
        "30360211014551231950b75fc4402da1722fc9baeb"
        "022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
        hash_std(), pk), "tcId 350: large-x valid");
}

// ============================================================================
// 4. Valid – r=n-1, s=n-2 boundary (tcId 352)
// ============================================================================
// r = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f  (n-1)
// s = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e  (n-2)
// wx = bc97e7585eecad48e16683bc4091708e1a930c683fc47001d4b383594f2c4e22
// wy = 705989cf69daeadd4e4e4b8151ed888dfec20fb01728d89d56b3f38f2ae9c8c5
static void test_valid_large_rs() {
    g_section = "der_valid_large_rs";
    std::printf("  [4] Valid: r=n-1, s=n-2 (tcId 352)\n");

    auto pk = make_pubkey(
        "bc97e7585eecad48e16683bc4091708e1a930c683fc47001d4b383594f2c4e22",
        "705989cf69daeadd4e4e4b8151ed888dfec20fb01728d89d56b3f38f2ae9c8c5");

    CHECK(der_verify(
        "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f"
        "022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
        hash_std(), pk), "tcId 352: r=n-1,s=n-2 valid");
}

// ============================================================================
// 5. s=1 valid (tcId 373) and s=0 invalid (tcId 374)
// ============================================================================
// pubkey:
//   wx = bb79f61857f743bfa1b6e7111ce4094377256969e4e15159123d9548acc3be6c
//   wy = 1f9d9f8860dcffd3eb36dd6c31ff2e7226c2009c4c94d8d7d2b5686bf7abd677
// r  = 55555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1
static void test_s_one_and_zero() {
    g_section = "der_s_one_s_zero";
    std::printf("  [5] Arithmetic edge: s=1 valid (tcId 373), s=0 invalid (tcId 374)\n");

    auto pk = make_pubkey(
        "bb79f61857f743bfa1b6e7111ce4094377256969e4e15159123d9548acc3be6c",
        "1f9d9f8860dcffd3eb36dd6c31ff2e7226c2009c4c94d8d7d2b5686bf7abd677");

    auto h = hash_std();

    // tcId 373: s=1, valid
    CHECK(der_verify(
        "3025022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1"
        "020101",
        h, pk), "tcId 373: s=1 valid");

    // tcId 374: s=0, invalid (scalar range check rejects s=0)
    CHECK(!der_verify(
        "3025022055555555555555555555555555555554e8e4f44ce51835693ff0ca2ef01215c1"
        "020100",
        h, pk), "tcId 374: s=0 invalid");
}

// ============================================================================
// 6. r=0 and s=0 edge cases (tcId 168, 169, 176)
// ============================================================================
// These are well-formed DER SEQUENCE { INTEGER 0, INTEGER y } or similar.
// Scalar range [1, n-1] rejects 0 for either component.
static void test_r0_s0_edges() {
    g_section = "der_r0_s0";
    std::printf("  [6] Arithmetic edge: r=0 or s=0 rejected (tcId 168, 169, 176)\n");

    // Any pubkey – fails at scalar range check before verification
    auto pk = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    auto h = hash_std();

    // tcId 168: SEQUENCE { INTEGER 0, INTEGER 0 }
    CHECK(!der_verify("3006020100020100", h, pk), "tcId 168: r=0,s=0");
    // tcId 169: SEQUENCE { INTEGER 0, INTEGER 1 }
    CHECK(!der_verify("3006020100020101", h, pk), "tcId 169: r=0,s=1");
    // tcId 176: SEQUENCE { INTEGER 1, INTEGER 0 }
    CHECK(!der_verify("3006020101020100", h, pk), "tcId 176: r=1,s=0");
}

// ============================================================================
// 7. r out of [1, n-1]: r=n (tcId 192, 193) and r=p (tcId 216)
// ============================================================================
// n   = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
// p   = fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
// Both > n-1, so scalar range check fails.
static void test_r_out_of_range() {
    g_section = "der_r_oor";
    std::printf("  [7] r out-of-range: r=n (tcId 192,193) and r=p (tcId 216)\n");

    auto pk = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    auto h = hash_std();

    // tcId 192: r=n, s=0
    // SEQUENCE { INTEGER n, INTEGER 0 }
    // n as DER INTEGER (high bit 0xff → needs leading 0x00, 33 bytes)
    // r: 02 21 00 [n 32 bytes] = 35 bytes
    // s: 02 01 00 = 3 bytes
    // Total = 38 = 0x26
    CHECK(!der_verify(
        "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        "020100",
        h, pk), "tcId 192: r=n rejected");

    // tcId 193: r=n, s=1
    CHECK(!der_verify(
        "3026022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        "020101",
        h, pk), "tcId 193: r=n s=1 rejected");

    // tcId 216: r=p, s=0
    // p as DER INTEGER (high bit 0xff → needs leading 0x00, 33 bytes)
    CHECK(!der_verify(
        "3026022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        "020100",
        h, pk), "tcId 216: r=p rejected");
}

// ============================================================================
// 8. Structural rejects – must be rejected by strict DER parser
// ============================================================================
// All vectors derived from Group 2 valid sig (tcId 5) base values:
//   r = 813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365  (32 bytes, MSB 0x81)
//   s = 900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87  (32 bytes, MSB 0x90)
// Valid DER baseline (tcId 5):
//   3046 0221 00 [r32] 0221 00 [s32] = 72 bytes total
static void test_structural_rejects() {
    g_section = "der_structural";
    std::printf("  [8] Structural rejects\n");

    auto pk = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    auto h = hash_std();

    // (a) Empty sig
    CHECK(!der_verify("", h, pk), "empty sig rejected");

    // (b) Tag only (length byte missing)
    CHECK(!der_verify("30", h, pk), "tag-only rejected");

    // (c) SEQUENCE with zero-length content
    CHECK(!der_verify("3000", h, pk), "zero-length sequence rejected");

    // (d) Wrong outer tag (0x31 = SET)
    // 3146 0221 00 [r32] 0221 00 [s32]
    CHECK(!der_verify(
        "3146022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
        h, pk), "wrong outer tag 0x31 rejected");

    // (e) Wrong outer tag (0x05 = NULL)
    CHECK(!der_verify("0500", h, pk), "NULL tag rejected");

    // (f) BER: outer length in long form 0x81 0x46
    // 30 81 46 0221 00 [r32] 0221 00 [s32]
    CHECK(!der_verify(
        "3081460221"
        "00813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
        h, pk), "BER long-form outer length rejected");

    // (g) BER: indefinite length 0x30 0x80 ... 0x00 0x00
    // 30 80 0221 00 [r32] 0221 00 [s32] 00 00
    CHECK(!der_verify(
        "308002210"
        "0813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f870000",
        h, pk), "BER indefinite outer length rejected");

    // (h) Missing leading 0x00 on r (high bit 0x81 makes it look negative)
    // r without leading zero: 02 20 [r32] = 34 bytes
    // s with leading zero:    02 21 00 [s32] = 35 bytes
    // Total = 69 = 0x45 → outer 30 45
    CHECK(!der_verify(
        "3045"
        "0220813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
        h, pk), "r missing leading zero rejected");

    // (i) Missing leading 0x00 on s (high bit 0x90 makes it look negative)
    // r with leading zero:    02 21 00 [r32] = 35 bytes
    // s without leading zero: 02 20 [s32] = 34 bytes
    // Total = 69 = 0x45 → outer 30 45
    CHECK(!der_verify(
        "3045"
        "022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "0220900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
        h, pk), "s missing leading zero rejected");

    // (j) BER: r-length in long form 0x81 0x21
    // r: 02 81 21 00 [r32] = 37 bytes
    // s: 02 21 00 [s32] = 35 bytes
    // Total = 72 = 0x48 → outer 30 48
    CHECK(!der_verify(
        "304802812100"
        "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
        h, pk), "BER r-length long form rejected");

    // (k) Trailing byte appended to valid DER (tcId-5 baseline + 00)
    // Valid is 72 bytes; outer SEQUENCE claims 70 = 0x46 bytes of content.
    // With trailing 00, total is 73 but outer length still says 70 → off != len.
    CHECK(!der_verify(
        "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f8700",
        h, pk), "trailing byte rejected");
}

// ============================================================================
// 9. Cross-checks: wrong key / wrong message
// ============================================================================
static void test_cross_checks() {
    g_section = "der_cross";
    std::printf("  [9] Cross-checks\n");

    // tcId 3 valid sig: Group 1 key, std msg
    const char* valid_der =
        "3045022100d035ee1f17fdb0b2681b163e33c359932659990af77dca632012b30b27a057b3"
        "02201939d9f3b2858bc13e3474cb50e6a82be44faa71940f876c1cba4c3e989202b6";

    auto correct_hash = hash_std();

    auto pk_g1 = make_pubkey(
        "782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963",
        "af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152");
    auto pk_g2 = make_pubkey(
        "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f",
        "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9");

    // Correct key + msg → verifies
    CHECK(der_verify(valid_der, correct_hash, pk_g1),  "correct key+msg");
    // Wrong key → fails
    CHECK(!der_verify(valid_der, correct_hash, pk_g2), "wrong key fails");
    // Wrong msg → fails
    CHECK(!der_verify(valid_der, hash_empty(),  pk_g1), "wrong msg fails");
}

// ============================================================================
// Entry point
// ============================================================================
int test_wycheproof_ecdsa_sha256_run() {
    std::printf("=== Wycheproof ECDSA secp256k1 SHA-256 DER ===\n");
    test_valid_group1();
    test_valid_malleable();
    test_valid_large_x();
    test_valid_large_rs();
    test_s_one_and_zero();
    test_r0_s0_edges();
    test_r_out_of_range();
    test_structural_rejects();
    test_cross_checks();
    std::printf("--- Result: %d passed, %d failed ---\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() {
    return test_wycheproof_ecdsa_sha256_run();
}
#endif
