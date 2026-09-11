// ============================================================================
// LibFuzzer harness: BIP-32 path string parsing boundary fuzzer
// ============================================================================
//
// TARGET: ufsecp_bip32_derive_path()  — path parser ("m/44'/0'/0'/0/0")
//         ufsecp_bip32_master()       — seed parser (1–64 bytes)
//         ufsecp_bip32_derive()       — single index derivation
//
// CONTRACT: no crash on any path string or seed byte sequence.
//           Path strings can be arbitrarily malformed: empty, NUL-bytes,
//           negative indices, excessively deep, no leading "m", Unicode etc.
//
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

#include "ufsecp/ufsecp.h"

static ufsecp_ctx* g_ctx = nullptr;
static void ensure_ctx() {
    if (!g_ctx && ufsecp_ctx_create(&g_ctx) != UFSECP_OK) abort();
}

// A fixed master key derived from a known seed for path-fuzzing
static ufsecp_bip32_key g_master;
static bool             g_master_ready = false;

static void ensure_master() {
    if (g_master_ready) return;
    ensure_ctx();
    static const uint8_t seed[64] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,
    };
        if ((ufsecp_bip32_master(g_ctx, seed, sizeof(seed), &g_master)) != UFSECP_OK) abort();
    g_master_ready = true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ensure_ctx();
    ensure_master();

    if (size == 0) return 0;

    const uint8_t variant = data[0];
    const uint8_t* payload = data + 1;
    const size_t   plen    = size - 1;

    switch (variant & 0x03) {
        case 0: {
            // --- arbitrary path string (fuzz input used as NUL-terminated string)
            // Make sure string is NUL-terminated within a bounded buffer
            std::vector<char> path_str(plen + 1, '\0');
            memcpy(path_str.data(), payload, plen);
            // Do NOT strip embedded NULs — the parser must handle them gracefully.
            // (memcpy copies all bytes; the extra '\0' ensures C-string termination.)
            ufsecp_bip32_key child;
            (void)ufsecp_bip32_derive_path(g_ctx, &g_master, path_str.data(), &child);
            break;
        }
        case 1: {
            // --- seed parsing fuzz (ufsecp_bip32_master accepts 16..64 byte seeds)
            // Feed arbitrary length payload as seed — must not crash outside valid range,
            // and must not crash within range either.
            if (plen == 0) break;
            ufsecp_bip32_key master_out;
            (void)ufsecp_bip32_master(g_ctx, payload, plen, &master_out);
            break;
        }
        case 2: {
            // --- deep path fuzz: build path from fuzz bytes as index stream
            if (plen < 4) break;
            // interpret every 4 bytes as a derivation index
            size_t depth = plen / 4;
            if (depth > 20) depth = 20;  // cap at 20 levels (realistic wallet depth)
            ufsecp_bip32_key cur = g_master;
            for (size_t i = 0; i < depth; ++i) {
                uint32_t idx;
                memcpy(&idx, payload + i * 4, 4);
                ufsecp_bip32_key next;
                ufsecp_error_t rc = ufsecp_bip32_derive(g_ctx, &cur, idx, &next);
                if (rc != UFSECP_OK) break;
                cur = next;
            }
            break;
        }
        case 3: {
            // --- known-malformed path patterns
            static const char* const kPaths[] = {
                "",
                "m",
                "m/",
                "m/0/",
                "m//0",
                "m/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'",  // 16-deep
                "m/2147483648",     // hardened index boundary (2^31)
                "m/2147483647'",    // max hardened
                "m/4294967295",     // max uint32
                "m/4294967296",     // overflow
                "M/0/0/0",          // uppercase M
                "0/0/0",            // no leading m
                "m/0x10/0x20",      // hex notation
                "/0/0/0",           // leading slash
                "m/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0",  // 24 deep
                "m/\x00/0",         // embedded NUL
                "m/-1/0",           // negative
                "m/9999999999999999999999999999",  // huge number
                nullptr
            };
            for (int j = 0; kPaths[j] != nullptr; ++j) {
                ufsecp_bip32_key child;
                (void)ufsecp_bip32_derive_path(g_ctx, &g_master, kPaths[j], &child);
            }
            break;
        }
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
    ensure_master();
    printf("fuzz_bip32_path: running\n");

    // Trigger edge-case paths
    uint8_t trigger[1] = { 0x03 };
    LLVMFuzzerTestOneInput(trigger, 1);

    std::mt19937_64 rng(0xDEADBEEFCAFE0005ULL);
    constexpr int kIter = 30000;
    for (int i = 0; i < kIter; ++i) {
        const size_t len = 1 + (rng() % 128);
        std::vector<uint8_t> buf(len);
        for (auto& b : buf) b = static_cast<uint8_t>(rng());
        // Bias toward printable ASCII and path characters for variant 0
        buf[0] = buf[0] & 0x03;  // constrain variant byte
        if ((buf[0] & 0x03) == 0) {
            // Fill with plausible path chars
            static const char kPathChars[] = "m/0123456789'";
            for (size_t j = 1; j < buf.size(); ++j) {
                buf[j] = (uint8_t)kPathChars[rng() % (sizeof(kPathChars) - 1)];
            }
        }
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    printf("fuzz_bip32_path: PASS (%d iterations)\n", kIter);
    return 0;
}
#endif
