#include <cstdio>
#include <string>
#include "secp256k1/vanity.hpp"

using namespace secp256k1;

static int failed = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "FAIL: %s\n", #expr); ++failed; } } while (0)

int main() {
    {
        VanitySearchConfig cfg;
        cfg.type = VanityAddressType::P2PKH;
        cfg.prefix = "1BgGZ9";
        cfg.start = fast::Scalar::from_uint64(1);
        cfg.max_attempts = 1;
        auto [match, ok] = find_vanity(cfg);
        CHECK(ok);
        CHECK(match.attempts == 1);
        CHECK(match.private_key == fast::Scalar::one());
        CHECK(match.address == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }
    {
        VanitySearchConfig cfg;
        cfg.type = VanityAddressType::P2PKH;
        cfg.prefix = "1BgGZ9";
        cfg.start = fast::Scalar::from_uint64(2);
        cfg.max_attempts = 1;
        auto [match, ok] = find_vanity(cfg);
        CHECK(!ok);
        CHECK(match.attempts == 1);
        CHECK(match.address.empty());
    }
    {
        VanitySearchConfig cfg;
        cfg.type = VanityAddressType::P2PKH;
        cfg.prefix = "not-an-address";
        cfg.start = fast::Scalar::from_uint64(1);
        cfg.max_attempts = 10;
        auto [match, ok] = find_vanity(cfg);
        CHECK(!ok);
        CHECK(match.attempts == 0);
    }
    return failed == 0 ? 0 : 1;
}
