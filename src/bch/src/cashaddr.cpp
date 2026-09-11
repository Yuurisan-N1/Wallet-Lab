// ============================================================================
// cashaddr.cpp — CashAddr encode/decode implementation
// ============================================================================
#include "secp256k1/bch/cashaddr.hpp"
#include "secp256k1/sha256.hpp"
#include "secp256k1/address.hpp"
#include <cstring>
#include <cassert>
#include <vector>
#include <cctype>
#include <algorithm>

// CashAddr charset and polymod constants (from spec)
static constexpr char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static constexpr uint64_t GENERATOR[5] = {
    0x98f2bc8e61ULL, 0x79b76d99e2ULL, 0xf33e5fb3c4ULL,
    0xae2eabe2a8ULL, 0x1e4f43e470ULL
};

namespace secp256k1::bch {

namespace {

static std::string_view network_prefix(Network net) noexcept {
    switch (net) {
        case Network::Mainnet: return CASHADDR_PREFIX_MAINNET;
        case Network::Testnet: return CASHADDR_PREFIX_TESTNET;
        case Network::Chipnet: return CASHADDR_PREFIX_CHIPNET;
        case Network::Regtest: return CASHADDR_PREFIX_REGTEST;
    }
    return CASHADDR_PREFIX_MAINNET;
}

static uint64_t cashaddr_polymod(const uint8_t* data, size_t len) noexcept {
    uint64_t c = 1;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c0 = static_cast<uint8_t>(c >> 35);
        c = ((c & 0x07ffffffffULL) << 5) ^ data[i];
        for (int j = 0; j < 5; ++j)
            if ((c0 >> j) & 1) c ^= GENERATOR[j];
    }
    return c ^ 1;
}

// Convert 8-bit groups to 5-bit groups
static void convert_bits(std::vector<uint8_t>& out,
                         const uint8_t* in, size_t inlen,
                         int from_bits, int to_bits, bool pad) {
    int acc = 0, bits = 0;
    const int maxv = (1 << to_bits) - 1;
    for (size_t i = 0; i < inlen; ++i) {
        acc = (acc << from_bits) | in[i];
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad && bits > 0)
        out.push_back((acc << (to_bits - bits)) & maxv);
}

} // anonymous namespace

std::string cashaddr_encode(const uint8_t* hash, size_t hash_len,
                            AddrType type, Network network) noexcept {
    // Version byte: type in high bits, size in low bits
    uint8_t version = 0;
    switch (type) {
        case AddrType::P2PKH:  version = 0x00; break;
        case AddrType::P2SH:   version = 0x08; break;
        case AddrType::P2SH32: version = 0x28; break; // extended (32B)
    }
    // Size field (see spec Table 2)
    if      (hash_len == 20) version |= 0x00;
    else if (hash_len == 32) version |= 0x03;

    std::vector<uint8_t> payload;
    payload.push_back(version);
    payload.insert(payload.end(), hash, hash + hash_len);

    std::vector<uint8_t> data5;
    convert_bits(data5, payload.data(), payload.size(), 8, 5, true);

    // Build checksum input: prefix_bytes + 0x00 + data5 + 8 zeros
    std::string_view pfx = network_prefix(network);
    std::vector<uint8_t> chk_input;
    for (char c : pfx) chk_input.push_back(static_cast<uint8_t>(c) & 0x1f);
    chk_input.push_back(0);
    chk_input.insert(chk_input.end(), data5.begin(), data5.end());
    for (int i = 0; i < 8; ++i) chk_input.push_back(0);

    uint64_t checksum = cashaddr_polymod(chk_input.data(), chk_input.size());

    std::string result(pfx);
    result += ':';
    for (uint8_t v : data5) result += CHARSET[v];
    for (int i = 7; i >= 0; --i)
        result += CHARSET[(checksum >> (5 * i)) & 0x1f];
    return result;
}

std::optional<CashAddr> cashaddr_decode(std::string_view addr) noexcept {
    // Find the ':' separator
    size_t colon = addr.find(':');
    std::string_view prefix, payload_str;
    if (colon == std::string_view::npos) {
        // No prefix — assume mainnet
        prefix = CASHADDR_PREFIX_MAINNET;
        payload_str = addr;
    } else {
        prefix = addr.substr(0, colon);
        payload_str = addr.substr(colon + 1);
    }

    // Decode charset
    std::vector<uint8_t> data5;
    data5.reserve(payload_str.size());
    for (char c : payload_str) {
        const char* p = std::strchr(CHARSET, std::tolower(c));
        if (!p) return std::nullopt;
        data5.push_back(static_cast<uint8_t>(p - CHARSET));
    }
    if (data5.size() < 8) return std::nullopt;

    // Verify checksum
    std::vector<uint8_t> chk_input;
    for (char c : prefix) chk_input.push_back(static_cast<uint8_t>(c) & 0x1f);
    chk_input.push_back(0);
    chk_input.insert(chk_input.end(), data5.begin(), data5.end());
    if (cashaddr_polymod(chk_input.data(), chk_input.size()) != 0)
        return std::nullopt;

    // Strip checksum (last 8 5-bit groups)
    data5.resize(data5.size() - 8);

    // Convert 5-bit to 8-bit
    std::vector<uint8_t> decoded;
    convert_bits(decoded, data5.data(), data5.size(), 5, 8, false);
    if (decoded.empty()) return std::nullopt;

    uint8_t version = decoded[0];
    uint8_t type_bits = (version >> 3) & 0x1f;
    uint8_t size_bits = version & 0x07;

    CashAddr result{};
    result.hash_len = (size_bits < 3) ? 20 : 32;

    if      (type_bits == 0x00) result.type = AddrType::P2PKH;
    else if (type_bits == 0x01) result.type = AddrType::P2SH;
    else if (type_bits == 0x05) result.type = AddrType::P2SH32;
    else return std::nullopt;

    if (decoded.size() - 1 != result.hash_len) return std::nullopt;
    std::memcpy(result.hash.data(), decoded.data() + 1, result.hash_len);

    // Determine network from prefix
    if      (prefix == CASHADDR_PREFIX_MAINNET) result.network = Network::Mainnet;
    else if (prefix == CASHADDR_PREFIX_TESTNET) result.network = Network::Testnet;
    else if (prefix == CASHADDR_PREFIX_CHIPNET) result.network = Network::Chipnet;
    else if (prefix == CASHADDR_PREFIX_REGTEST) result.network = Network::Regtest;
    else return std::nullopt;

    return result;
}

std::string cashaddr_from_pubkey(const uint8_t* pubkey33,
                                 Network network) noexcept {
    // hash160 = RIPEMD160(SHA256(pubkey)) — real implementation via secp256k1::hash160
    auto h160 = secp256k1::hash160(pubkey33, 33);
    return cashaddr_encode(h160.data(), 20, AddrType::P2PKH, network);
}

std::string cashaddr_from_script_hash(const uint8_t* hash20,
                                      Network network) noexcept {
    return cashaddr_encode(hash20, 20, AddrType::P2SH, network);
}

bool cashaddr_is_valid(std::string_view addr) noexcept {
    return cashaddr_decode(addr).has_value();
}

} // namespace secp256k1::bch
