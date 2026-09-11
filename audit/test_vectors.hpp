// =============================================================================
// UltrafastSecp256k1 - Shared Test Vectors
// =============================================================================
// Single source of truth for test data used by CPU, CUDA, and OpenCL test suites.
// Include this header to get canonical K*G vectors + edge-case constants.
// =============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <array>

namespace secp256k1 {
namespace test_vectors {

// ============================================================================
// Canonical K*G test vectors (from Bitcoin/libsecp256k1 reference)
// ============================================================================

struct KGVector {
    const char* scalar_hex;
    const char* expected_x;
    const char* expected_y;
    const char* description;
};

// 1*G through 10*G + boundary scalars
inline constexpr KGVector KG_VECTORS[] = {
    // Small scalars: 1*G through 10*G
    {"0000000000000000000000000000000000000000000000000000000000000001",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", "1*G"},
    {"0000000000000000000000000000000000000000000000000000000000000002",
     "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
     "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a", "2*G"},
    {"0000000000000000000000000000000000000000000000000000000000000003",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672", "3*G"},
    {"0000000000000000000000000000000000000000000000000000000000000004",
     "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
     "51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922", "4*G"},
    {"0000000000000000000000000000000000000000000000000000000000000005",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
     "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6", "5*G"},

    // Random large scalars
    {"4727daf2986a9804b1117f8261aba645c34537e4474e19be58700792d501a591",
     "0566896db7cd8e47ceb5e4aefbcf4d46ec295a15acb089c4affa9fcdd44471ef",
     "1513fcc547db494641ee2f65926e56645ec68cceaccb278a486e68c39ee876c4", "Random k #1"},
    {"c77835cf72699d217c2bbe6c59811b7a599bb640f0a16b3a332ebe64f20b1afa",
     "510f6c70028903e8c0d6f7a156164b972cea569b5a29bb03ff7564dfea9e875a",
     "c02b5ff43ae3b46e281b618abb0cbdaabdd600fbd6f4b78af693dec77080ef56", "Random k #2"},
    {"c401899c059f1c624292fece1933c890ae4970abf56dd4d2c986a5b9d7c9aeb5",
     "8434cbaf8256a8399684ed2212afc204e2e536034612039177bba44e1ea0d1c6",
     "0c34841bd41b0d869b35cfc4be6d57f098ae4beca55dc244c762c3ca0fd56af3", "Random k #3"},

    // Boundary scalars
    {"000000000000000000000000000000000000000000000000000000000000000a",
     "a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
     "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7", "10*G"},
    {"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777", "(n-1)*G = -G"},
};

inline constexpr int KG_VECTOR_COUNT = sizeof(KG_VECTORS) / sizeof(KG_VECTORS[0]);

// ============================================================================
// Curve constants (hex strings)
// ============================================================================

// Generator point G
inline constexpr const char* GENERATOR_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
inline constexpr const char* GENERATOR_Y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

// Field prime p = 2^256 - 2^32 - 977
inline constexpr const char* FIELD_PRIME = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

// Curve order n
inline constexpr const char* CURVE_ORDER = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

// n-1
inline constexpr const char* ORDER_MINUS_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";

// n-2
inline constexpr const char* ORDER_MINUS_2 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f";

// ============================================================================
// Edge case scalars (for boundary testing)
// ============================================================================

inline constexpr const char* EDGE_SCALARS[] = {
    // Zero (should give point at infinity)
    "0000000000000000000000000000000000000000000000000000000000000000",
    // One
    "0000000000000000000000000000000000000000000000000000000000000001",
    // Two
    "0000000000000000000000000000000000000000000000000000000000000002",
    // n-1 (produces -G)
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    // n-2
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
    // n (should give infinity, equivalent to 0)
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    // All bits set (reduces mod n to some value)
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // High bit only
    "8000000000000000000000000000000000000000000000000000000000000000",
    // Alternating bits
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "5555555555555555555555555555555555555555555555555555555555555555",
};

inline constexpr int EDGE_SCALAR_COUNT = sizeof(EDGE_SCALARS) / sizeof(EDGE_SCALARS[0]);

// ============================================================================
// Large scalar pairs for cross-check (k1, k2: verify k2*(k1*G) = (k1*k2)*G)
// ============================================================================

inline constexpr const char* LARGE_SCALAR_PAIRS[][2] = {
    {"deadbeefcafebabef00dfeedfacefeed1234567890abcdef1122334455667788",
     "1111111111111111111111111111111111111111111111111111111111111111"},
    {"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
     "0000000000000000000000000000000000000000000000000000000000000002"},
    {"700a25ca2ae4eb40dfa74c9eda069be7e2fc9bfceabb13953ddedd33e1f03f2c",
     "489206bbfff1b2370619ba0e6a51b74251267e06d3abafb055464bb623d5057a"},
};

inline constexpr int LARGE_SCALAR_PAIR_COUNT =
    sizeof(LARGE_SCALAR_PAIRS) / sizeof(LARGE_SCALAR_PAIRS[0]);

// ============================================================================
// Hex conversion utilities
// ============================================================================

inline std::array<uint8_t, 32> hex_to_bytes_be(const char* hex) {
    std::array<uint8_t, 32> bytes{};
    for (size_t i = 0; i < 32; ++i) {
        auto nib = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        bytes[i] = static_cast<uint8_t>((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    }
    return bytes;
}

// Big-endian bytes to 4x uint64_t little-endian limbs
inline void bytes_be_to_limbs(const std::array<uint8_t, 32>& bytes, uint64_t limbs[4]) {
    for (size_t i = 0; i < 4; ++i) {
        uint64_t limb = 0;
        for (size_t j = 0; j < 8; ++j) {
            limb |= static_cast<uint64_t>(bytes[31 - (i * 8 + j)]) << (j * 8);
        }
        limbs[i] = limb;
    }
}

// 4x uint64_t little-endian limbs to hex string
inline std::string limbs_to_hex(const uint64_t limbs[4]) {
    uint8_t buf[32];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            buf[31 - (i * 8 + j)] = static_cast<uint8_t>(limbs[i] >> (j * 8));
        }
    }
    static const char* hc = "0123456789abcdef";
    std::string r;
    r.reserve(64);
    for (int i = 0; i < 32; ++i) {
        r += hc[(buf[i] >> 4) & 0xF];
        r += hc[buf[i] & 0xF];
    }
    return r;
}

// Case-insensitive hex comparison
inline bool hex_equal(const std::string& a, const char* b) {
    if (a.length() != std::strlen(b)) return false;
    for (size_t i = 0; i < a.length(); i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'F') ca += 32;
        if (cb >= 'A' && cb <= 'F') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

} // namespace test_vectors
} // namespace secp256k1
