#include "secp256k1/vanity.hpp"

#include <algorithm>
#include <array>
#include <string_view>

#include "secp256k1/address.hpp"

namespace secp256k1 {

namespace {
constexpr char kBase58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool is_base58_prefix(const std::string& prefix) noexcept {
    return !prefix.empty() && std::all_of(prefix.begin(), prefix.end(), [](char c) {
        return std::string_view(kBase58).find(c) != std::string_view::npos;
    });
}
}

bool valid_vanity_prefix(const VanitySearchConfig& config) noexcept {
    if (config.type != VanityAddressType::P2PKH || !is_base58_prefix(config.prefix))
        return false;
    if (config.network == Network::Mainnet && config.prefix.front() != '1') return false;
    if (config.network == Network::Testnet && config.prefix.front() != 'm' && config.prefix.front() != 'n')
        return false;
    return !config.start.is_zero() && config.max_attempts != 0;
}

std::pair<VanityMatch, bool> find_vanity(const VanitySearchConfig& config) {
    VanityMatch result;
    if (!valid_vanity_prefix(config)) return {result, false};

    auto key = config.start;
    const auto generator = fast::Point::generator();
    for (std::size_t i = 0; i < config.max_attempts; ++i) {
        result.attempts = i + 1;
        const auto pub = generator.scalar_mul(key);
        const auto address = address_p2pkh(pub, config.network);
        if (address.compare(0, config.prefix.size(), config.prefix) == 0) {
            result.private_key = key;
            result.public_key = pub;
            result.address = address;
            return {result, true};
        }
        key += fast::Scalar::one();
        if (key.is_zero()) break;
    }
    return {result, false};
}

} // namespace secp256k1