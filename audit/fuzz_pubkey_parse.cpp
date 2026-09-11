// ============================================================================
// LibFuzzer harness: Public key parsing boundary fuzzer
// ============================================================================
//
// TARGET: ufsecp_pubkey_parse()           — compressed (33B), uncompressed (65B)
//         ufsecp_pubkey_xonly()            — x-only (32B)
//         ufsecp_pubkey_negate()           — unary on valid pubkey
//         ufsecp_pubkey_tweak_add()        — additive tweak on valid pubkey
//         ufsecp_pubkey_tweak_mul()        — multiplicative tweak on valid pubkey
//
// CONTRACT: no crash, no abort, no UB on ANY byte sequence.
//           A returned error code is always acceptable; a crash is never.
//
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "ufsecp/ufsecp.h"

static ufsecp_ctx* g_ctx = nullptr;

static void ensure_ctx() {
    if (!g_ctx) {
        if (ufsecp_ctx_create(&g_ctx) != UFSECP_OK) abort();
    }
}

// ---------------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ensure_ctx();

    if (size < 1) return 0;

    // Split fuzz input: first byte selects test variant, remainder is payload
    const uint8_t variant = data[0];
    const uint8_t* payload = data + 1;
    const size_t   plen    = size - 1;

    uint8_t pk33[33];
    uint8_t pk65[65];
    uint8_t xonly32[32];

    switch (variant & 0x07) {
        case 0:
        case 1: {
            // --- compressed pubkey parse -----------------------------------
            uint8_t  buf33[33] = {};
            size_t   copy = plen < 33 ? plen : 33;
            memcpy(buf33, payload, copy);
            uint8_t out33[33];
            (void)ufsecp_pubkey_parse(g_ctx, buf33, 33, out33);
            break;
        }
        case 2:
        case 3: {
            // --- uncompressed pubkey parse ---------------------------------
            uint8_t  buf65[65] = {};
            size_t   copy = plen < 65 ? plen : 65;
            memcpy(buf65, payload, copy);
            uint8_t out33[33];
            (void)ufsecp_pubkey_parse(g_ctx, buf65, 65, out33);
            break;
        }
        case 4: {
            // --- x-only parse (32 bytes) -----------------------------------
            uint8_t buf32[32] = {};
            size_t  copy = plen < 32 ? plen : 32;
            memcpy(buf32, payload, copy);
            // parse as if compressed with 02 prefix
            uint8_t buf33[33]; buf33[0] = 0x02;
            memcpy(buf33 + 1, buf32, 32);
            uint8_t out33[33];
            ufsecp_error_t rc = ufsecp_pubkey_parse(g_ctx, buf33, 33, out33);
            if (rc == UFSECP_OK) {
                // If valid, test xonly extraction
                (void)ufsecp_pubkey_xonly(g_ctx, out33, xonly32, nullptr);
            }
            break;
        }
        case 5: {
            // --- parse then negate ----------------------------------------
            if (plen < 33) break;
            uint8_t buf33[33]; memcpy(buf33, payload, 33);
            uint8_t out33[33];
            ufsecp_error_t rc = ufsecp_pubkey_parse(g_ctx, buf33, 33, out33);
            if (rc == UFSECP_OK) {
                uint8_t neg33[33];
                (void)ufsecp_pubkey_negate(g_ctx, out33, neg33);
            }
            break;
        }
        case 6: {
            // --- parse then tweak_add with fuzz tweak ---------------------
            if (plen < 33 + 32) break;
            uint8_t buf33[33]; memcpy(buf33, payload, 33);
            uint8_t tweak32[32]; memcpy(tweak32, payload + 33, 32);
            uint8_t out33[33];
            ufsecp_error_t rc = ufsecp_pubkey_parse(g_ctx, buf33, 33, out33);
            if (rc == UFSECP_OK) {
                uint8_t tweaked33[33];
                (void)ufsecp_pubkey_tweak_add(g_ctx, out33, tweak32, tweaked33);
            }
            break;
        }
        case 7: {
            // --- parse then tweak_mul with fuzz scalar --------------------
            if (plen < 33 + 32) break;
            uint8_t buf33[33]; memcpy(buf33, payload, 33);
            uint8_t scalar32[32]; memcpy(scalar32, payload + 33, 32);
            uint8_t out33[33];
            ufsecp_error_t rc = ufsecp_pubkey_parse(g_ctx, buf33, 33, out33);
            if (rc == UFSECP_OK) {
                uint8_t tweaked33[33];
                (void)ufsecp_pubkey_tweak_mul(g_ctx, out33, scalar32, tweaked33);
            }
            break;
        }
    }

    // Always-on: feed raw payload at every valid parse size (1..65) with prefix 02/03/04
    if (plen >= 32) {
        for (uint8_t prefix : {(uint8_t)0x02, (uint8_t)0x03}) {
            uint8_t buf33[33]; buf33[0] = prefix;
            memcpy(buf33 + 1, payload, 32);
            uint8_t out33[33];
            (void)ufsecp_pubkey_parse(g_ctx, buf33, 33, out33);
        }
    }
    if (plen >= 64) {
        uint8_t buf65[65]; buf65[0] = 0x04;
        memcpy(buf65 + 1, payload, 64);
        uint8_t out33[33];
        (void)ufsecp_pubkey_parse(g_ctx, buf65, 65, out33);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Standalone
// ---------------------------------------------------------------------------
#if defined(LIBFUZZER_STANDALONE) || defined(SECP256K1_STANDALONE_FUZZ)

#include <cstdio>
#include <random>

int main() {
    ensure_ctx();
    std::mt19937_64 rng(0xDEADBEEFCAFE0002ULL);
    constexpr int kIter = 100000;

    printf("fuzz_pubkey_parse: running %d iterations\n", kIter);

    // All-zeros 33B (invalid point)
    { uint8_t z[34] = {0x02}; LLVMFuzzerTestOneInput(z, 34); }
    // Generator (valid)
    {
        static const uint8_t G33[] = {
            0x03,
            0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
            0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
            0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
            0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98,
        };
        uint8_t buf[34]; buf[0] = 0x01; memcpy(buf+1, G33, 33);
        LLVMFuzzerTestOneInput(buf, 34);
    }

    for (int i = 0; i < kIter; ++i) {
        const size_t len = 1 + (rng() % 80);
        std::vector<uint8_t> buf(len);
        for (auto& b : buf) b = static_cast<uint8_t>(rng());
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    printf("fuzz_pubkey_parse: PASS\n");
    return 0;
}
#endif
