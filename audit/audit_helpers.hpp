// ============================================================================
// audit/audit_helpers.hpp — Shared deterministic test helpers
// ============================================================================
// Include AFTER: the file-local `static std::mt19937_64 rng(SEED);` declaration.
// All random helpers take `rng` by reference so each audit file keeps its own
// deterministic seed while sharing one canonical implementation.
//
// SINGLE SOURCE OF TRUTH: fix here → fixed everywhere, no drift.
// ============================================================================
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <random>

#include "secp256k1/field.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"

// Fill a 32-byte array with deterministic pseudo-random bytes from rng.
inline std::array<uint8_t, 32> random_bytes32(std::mt19937_64& rng) {
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 4; ++i) {
        uint64_t v = rng();
        std::memcpy(out.data() + static_cast<std::size_t>(i) * 8, &v, 8);
    }
    return out;
}

// Return a non-zero scalar sampled uniformly from [1, n).
inline secp256k1::fast::Scalar random_scalar(std::mt19937_64& rng) {
    for (;;) {
        auto bytes = random_bytes32(rng);
        auto s = secp256k1::fast::Scalar::from_bytes(bytes);
        if (!s.is_zero()) return s;
    }
}

// Return a field element sampled uniformly from [0, p).
inline secp256k1::fast::FieldElement random_fe(std::mt19937_64& rng) {
    return secp256k1::fast::FieldElement::from_bytes(random_bytes32(rng));
}

// Point equality that correctly handles the point at infinity on both sides.
inline bool points_equal(const secp256k1::fast::Point& a,
                         const secp256k1::fast::Point& b) {
    if (a.is_infinity() && b.is_infinity()) return true;
    if (a.is_infinity() != b.is_infinity()) return false;
    return a.to_compressed() == b.to_compressed();
}
