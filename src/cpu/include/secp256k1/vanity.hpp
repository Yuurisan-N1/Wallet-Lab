#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "secp256k1/address.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/scalar.hpp"

namespace secp256k1 {

enum class VanityAddressType : std::uint8_t { P2PKH };

struct VanitySearchConfig {
    VanityAddressType type{VanityAddressType::P2PKH};
    std::string prefix;
    fast::Scalar start{fast::Scalar::one()};
    std::size_t max_attempts{0};
    Network network{Network::Mainnet};
};

struct VanityMatch {
    fast::Scalar private_key;
    fast::Point public_key;
    std::string address;
    std::size_t attempts{0};
};

bool valid_vanity_prefix(const VanitySearchConfig& config) noexcept;
std::pair<VanityMatch, bool> find_vanity(const VanitySearchConfig& config);

} // namespace secp256k1