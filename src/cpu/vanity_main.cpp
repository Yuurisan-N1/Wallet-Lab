#include <cstdlib>
#include <iostream>
#include <string>

#include "secp256k1/vanity.hpp"

namespace {
void usage(const char* name) {
    std::cerr << "Usage: " << name << " --prefix PREFIX [--max-attempts N] [--start N] [--testnet]\n";
}
}

int main(int argc, char** argv) {
    secp256k1::VanitySearchConfig cfg;
    cfg.max_attempts = 100000;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--prefix" && i + 1 < argc) cfg.prefix = argv[++i];
        else if (arg == "--max-attempts" && i + 1 < argc) cfg.max_attempts = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--start" && i + 1 < argc) cfg.start = secp256k1::fast::Scalar::from_uint64(std::strtoull(argv[++i], nullptr, 10));
        else if (arg == "--testnet") cfg.network = secp256k1::Network::Testnet;
        else { usage(argv[0]); return 2; }
    }
    if (cfg.prefix.empty()) { usage(argv[0]); return 2; }
    const auto [match, found] = secp256k1::find_vanity(cfg);
    if (!found) {
        std::cout << "not found after " << match.attempts << " attempts\n";
        return 1;
    }
    std::cout << "address=" << match.address << "\n"
              << "private_key=" << match.private_key.to_hex() << "\n"
              << "public_key=";
    const auto pub = match.public_key.to_compressed();
    static constexpr char hex[] = "0123456789abcdef";
    for (auto byte : pub) std::cout << hex[byte >> 4] << hex[byte & 15];
    std::cout << "\nattempts=" << match.attempts << "\n";
    return 0;
}
