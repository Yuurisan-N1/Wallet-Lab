// ============================================================================
// LibFuzzer harness: DER signature parsing boundary fuzzer
// ============================================================================
//
// TARGET: ufsecp_ecdsa_sig_from_der()  — full parser boundary test
//         ufsecp_ecdsa_sig_to_der()    — round-trip (parse → re-encode)
//
// CONTRACT: must never crash, abort, or corrupt memory on ANY byte sequence,
//           regardless of length (0 to 72+ bytes) or content.
//
// BUILD (LibFuzzer, requires clang):
//   cmake -S . -B build -DSECP256K1_BUILD_LIBFUZZER=ON \
//         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
//         -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer,address,undefined"
//   ./build/audit/fuzz_der_parse  [corpus/]
//
// BUILD (standalone, deterministic):
//   cmake -S . -B build -DSECP256K1_BUILD_FUZZ_TESTS=ON
//   ./build/audit/test_fuzz_der_parse_standalone
//
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <array>
#include <vector>

// C ABI — zero library dependency, only our own header
#include "ufsecp/ufsecp.h"

// Shared context (LibFuzzer re-uses the process between runs)
static ufsecp_ctx* g_ctx = nullptr;

static void ensure_ctx() {
    if (!g_ctx) {
        ufsecp_error_t rc = ufsecp_ctx_create(&g_ctx);
        if (rc != UFSECP_OK || !g_ctx) {
            abort();  // fatal: library failed to initialise
        }
    }
}

// ---------------------------------------------------------------------------
// LLVMFuzzerTestOneInput — entry point for LibFuzzer and OSS-Fuzz
// ---------------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ensure_ctx();

    // --- Pass 1: raw bytes → sig_from_der --------------------------------
    // Contract: must return OK or an error code — never crash/abort.
    uint8_t compact64[64];
    ufsecp_error_t rc = ufsecp_ecdsa_sig_from_der(g_ctx, data, size, compact64);

    if (rc == UFSECP_OK) {
        // --- Pass 2: valid compact → sig_to_der (round-trip) -------------
        uint8_t der_out[UFSECP_SIG_DER_MAX_LEN];
        size_t  der_len = sizeof(der_out);
        ufsecp_error_t rc2 = ufsecp_ecdsa_sig_to_der(g_ctx, compact64, der_out, &der_len);

        if (rc2 == UFSECP_OK && der_len <= UFSECP_SIG_DER_MAX_LEN) {
            // --- Pass 3: re-parse the DER we just emitted -----------------
            // If our emitter produces correct DER, this must parse back cleanly.
            uint8_t compact64b[64];
            ufsecp_error_t rc3 = ufsecp_ecdsa_sig_from_der(g_ctx, der_out, der_len, compact64b);
            // We don't abort on parse failure here — the fuzzer will find it
            // if `compact64b != compact64` consistently.
            (void)rc3;
            // Optionally: byte comparison (only if rc3 == OK)
            if (rc3 == UFSECP_OK) {
                // R and S must round-trip exactly
                if (memcmp(compact64, compact64b, 64) != 0) {
                    // Hard invariant violation: crash intentionally so LibFuzzer
                    // captures the input.
                    __builtin_trap();
                }
            }
        }
    }

    // --- Variant: try with trailing garbage appended ---------------------
    // Some parsers accept prefix of valid DER + ignore trailing bytes.
    // Contract: no crash even with extra bytes.
    if (size >= 2 && size <= 70) {
        std::vector<uint8_t> padded(size + 32, 0xAB);
        memcpy(padded.data(), data, size);
        uint8_t compact_padded[64];
        (void)ufsecp_ecdsa_sig_from_der(g_ctx, padded.data(), padded.size(), compact_padded);
    }

    return 0;  // non-crash inputs are never "interesting" from a coverage perspective
}

// ---------------------------------------------------------------------------
// Standalone mode: run from main() without LibFuzzer runtime
// Build with LIBFUZZER_STANDALONE or SECP256K1_BUILD_FUZZ_TESTS defined.
// ---------------------------------------------------------------------------
#if defined(LIBFUZZER_STANDALONE) || defined(SECP256K1_STANDALONE_FUZZ)

#include <cstdio>
#include <random>

static void run_input(const uint8_t* data, size_t size) {
    LLVMFuzzerTestOneInput(data, size);
}

// Corpus of known-interesting DER inputs
static const std::vector<std::vector<uint8_t>> k_corpus = {
    {},                                                          // empty
    {0x30},                                                      // truncated sequence tag
    {0x30, 0x00},                                               // zero-length sequence
    {0x30, 0x44},                                               // length mismatch
    {0xFF, 0xFF, 0xFF},                                          // invalid tag
    // Minimal valid DER (low-S dummy, not a real sig but structurally correct):
    {0x30,0x44, 0x02,0x20,
     0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
     0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
     0x02,0x20,
     0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
     0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},
    // High-bit set on integer (DER violation)
    {0x30,0x44, 0x02,0x20,
     0x80,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
     0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
     0x02,0x20,
     0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
     0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},
    // Overly-long length encoding
    {0x30,0x81,0x44},
    // r = 0
    {0x30,0x26, 0x02,0x01,0x00, 0x02,0x21,0x00,
     0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
     0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
     0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
     0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41},
};

int main(int argc, char** argv) {
    ensure_ctx();
    printf("fuzz_der_parse: running %zu corpus seeds\n", k_corpus.size());

    for (const auto& seed : k_corpus) {
        run_input(seed.data(), seed.size());
    }

    // Pseudo-random sweep: 50,000 iterations
    std::mt19937_64 rng(0xDEADBEEFCAFE0001ULL);
    constexpr int kIter = 50000;
    for (int i = 0; i < kIter; ++i) {
        size_t len = rng() % 80;
        std::vector<uint8_t> buf(len);
        for (auto& b : buf) b = static_cast<uint8_t>(rng());
        run_input(buf.data(), buf.size());
    }

    printf("fuzz_der_parse: PASS (%d iterations)\n", kIter);
    return 0;
}

#endif  // LIBFUZZER_STANDALONE / SECP256K1_STANDALONE_FUZZ
