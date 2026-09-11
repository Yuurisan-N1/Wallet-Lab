// ============================================================================
// test_regression_segwit_hash160_decouple.cpp
// ----------------------------------------------------------------------------
// Regression: src/cpu/src/segwit.cpp::local_hash160 used to call the top-level
// secp256k1::hash160 (defined in address.cpp, gated behind SECP256K1_BUILD_BIP352).
// In a BIP-352-off profile — e.g. the Bitcoin Core backend — address.cpp is not
// compiled, so the symbol was undefined and the no-LTO link failed
// (validate_p2wpkh_witness -> hash160 -> unresolved). Under LTO the dead-code
// path was eliminated, hiding the bug.
//
// Fix: segwit.cpp now calls secp256k1::hash::hash160 (hash_accel.cpp, part of the
// always-on hash module), decoupling P2WPKH witness validation from BIP-352.
//
// This test exercises validate_p2wpkh_witness so the symbol is link-required in
// every profile (the test itself fails to link if hash160 is unresolved), and
// asserts the hash160-based program match is bit-correct.
// ============================================================================
#include "secp256k1/segwit.hpp"
#include "secp256k1/hash_accel.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <vector>

using namespace secp256k1;

static int g_fail = 0;
#define CHECK(cond, msg)                                                        \
    do { if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fail; }            \
         else         { std::printf("  ok  : %s\n", msg); } } while (0)

// Generator point G in compressed form (a known-valid 33-byte secp256k1 pubkey).
static const std::uint8_t G_COMPRESSED[33] = {
    0x02, 0x79,0xBE,0x66,0x7E, 0xF9,0xDC,0xBB,0xAC, 0x55,0xA0,0x62,0x95,
    0xCE,0x87,0x0B,0x07, 0x02,0x9B,0xFC,0xDB, 0x2D,0xCE,0x28,0xD9,
    0x59,0xF2,0x81,0x5B, 0x16,0xF8,0x17,0x98
};

int test_regression_segwit_hash160_decouple_run() {
    std::printf("segwit hash160 decouple (BIP-352-independent P2WPKH validation)\n");

    std::vector<std::uint8_t> pubkey(G_COMPRESSED, G_COMPRESSED + 33);

    // program = hash160(pubkey) via the always-on hash module (the fixed path).
    std::array<std::uint8_t, 20> program = hash::hash160(pubkey.data(), pubkey.size());

    // BIP-141 P2WPKH witness = [<sig>, <pubkey>]. The signature is not verified
    // by validate_p2wpkh_witness — only structure + hash160(pubkey) == program.
    std::vector<std::vector<std::uint8_t>> witness = {
        std::vector<std::uint8_t>(72, 0x01),   // dummy DER-sized sig
        pubkey
    };

    CHECK(validate_p2wpkh_witness(witness, program.data()),
          "matching hash160(pubkey) program is accepted");

    std::array<std::uint8_t, 20> bad = program;
    bad[0] ^= 0x01;
    CHECK(!validate_p2wpkh_witness(witness, bad.data()),
          "tampered program (1 bit flipped) is rejected");

    // Wrong-length pubkey must be rejected (structural BIP-141 check still holds).
    std::vector<std::vector<std::uint8_t>> bad_witness = {
        std::vector<std::uint8_t>(72, 0x01),
        std::vector<std::uint8_t>(32, 0x02)    // 32 bytes, not a 33-byte compressed key
    };
    CHECK(!validate_p2wpkh_witness(bad_witness, program.data()),
          "non-33-byte pubkey witness is rejected");

    std::printf("\n%s\n", g_fail == 0 ? "SEGWIT-HASH160-DECOUPLE OK"
                                      : "SEGWIT-HASH160-DECOUPLE FAILURES");
    return g_fail == 0 ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_segwit_hash160_decouple_run(); }
#endif
