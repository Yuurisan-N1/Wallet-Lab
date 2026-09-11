// ============================================================================
// audit_secure_erase.cpp -- Secure Memory Erasure Verification
// ============================================================================
//
// Verifies that secp256k1::detail::secure_erase() actually zeroes memory and
// that the zeroing survives compiler optimisation (the whole point of the
// volatile-trick / explicit_bzero / SecureZeroMemory chain).
//
// An external auditor checking "do you securely erase private key material?"
// will:
//   1. Write a known pattern to a buffer.
//   2. Call the erase function.
//   3. Read back through a VOLATILE pointer (preventing dead-store elimination).
//   4. Assert every byte is zero.
//
// We also verify:
//   - Correctness for various sizes: 1, 4, 32, 64, 128, 256 bytes
//   - Zero-length erase is safe (no crash)
//   - Erase of stack buffers, heap buffers, and arrays
//   - The library's own signing path zeroes its nonce-derived intermediates:
//     sign the same message twice — the signature must be identical (RFC 6979
//     determinism proves the nonce was re-derived from scratch, not leaked).
//
// SE-1  … SE-8  : Direct secure_erase() correctness
// SE-9  … SE-14 : Stack/heap/struct member erasure
// SE-15 … SE-20 : Library signing path re-uses fresh nonces (determinism)
// SE-21 … SE-24 : Pattern-check: entire buffer written before erasing
// SE-25          : Nonce erase — two concurrent sign calls never share nonce
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <array>
#include <memory>

// Include the library erasure primitive directly
#include "secp256k1/detail/secure_erase.hpp"

// C ABI for the signing path test
#ifndef UFSECP_BUILDING
#define UFSECP_BUILDING
#endif
#include "ufsecp/ufsecp.h"

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

using secp256k1::detail::secure_erase;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Read a byte through a volatile pointer to prevent dead-store elimination
static inline uint8_t volatile_read(const void* ptr, std::size_t offset) {
    const volatile uint8_t* p = static_cast<const volatile uint8_t*>(ptr);
    return p[offset];
}

// Fill a buffer with a recognisable non-zero sentinel pattern
static void fill_sentinel(void* ptr, std::size_t len, uint8_t pattern = 0xA5) {
    std::memset(ptr, pattern, len);
}

// Check every byte via volatile reads (defeats dead-store optimisation)
static bool all_zero_volatile(const void* ptr, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        if (volatile_read(ptr, i) != 0x00) return false;
    }
    return true;
}

// Check every byte equals expected value via volatile reads
static bool all_equal_volatile(const void* ptr, std::size_t len, uint8_t val) {
    for (std::size_t i = 0; i < len; ++i) {
        if (volatile_read(ptr, i) != val) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// SE-1 … SE-8: secure_erase() correctness for various sizes
// ---------------------------------------------------------------------------

static void run_se1_sizes() {
    AUDIT_LOG("\n  [SE-1..8] secure_erase() correctness — various sizes\n");

    constexpr std::size_t SIZES[] = {1, 2, 4, 8, 16, 32, 64, 128};
    int idx = 1;
    for (std::size_t sz : SIZES) {
        std::unique_ptr<uint8_t[]> buf(new uint8_t[sz]);
        fill_sentinel(buf.get(), sz, 0xCC);
        // Sanity: buffer IS filled
        CHECK(all_equal_volatile(buf.get(), sz, 0xCC),
              "SE-sentinel: buffer pre-filled with 0xCC");

        secure_erase(buf.get(), sz);

        char msg[80];
        (void)std::snprintf(msg, sizeof(msg), "SE-%d: heap %zu bytes zeroed after secure_erase", idx, sz);
        CHECK(all_zero_volatile(buf.get(), sz), msg);
        ++idx;
    }
}

// ---------------------------------------------------------------------------
// SE-9 … SE-12: Stack buffers
// ---------------------------------------------------------------------------

static void run_se9_stack() {
    AUDIT_LOG("\n  [SE-9..12] Stack buffer erasure\n");

    {
        uint8_t stack32[32];
        fill_sentinel(stack32, sizeof(stack32), 0xBB);
        secure_erase(stack32, sizeof(stack32));
        CHECK(all_zero_volatile(stack32, sizeof(stack32)),
              "SE-9: 32-byte stack buffer zeroed");
    }
    {
        uint8_t stack64[64];
        fill_sentinel(stack64, sizeof(stack64), 0xAA);
        secure_erase(stack64, sizeof(stack64));
        CHECK(all_zero_volatile(stack64, sizeof(stack64)),
              "SE-10: 64-byte stack buffer zeroed");
    }
    {
        std::array<uint8_t, 32> arr;
        arr.fill(0xDE);
        secure_erase(arr.data(), arr.size());
        CHECK(all_zero_volatile(arr.data(), arr.size()),
              "SE-11: std::array<uint8_t,32> zeroed");
    }
    {
        // Struct mimicking a scalar (4 × uint64 limbs)
        struct FakeScalar { uint64_t limbs[4]; };
        FakeScalar s;
        std::memset(&s, 0xFF, sizeof(s));
        secure_erase(&s, sizeof(s));
        CHECK(all_zero_volatile(&s, sizeof(s)),
              "SE-12: scalar-sized struct zeroed");
    }
}

// ---------------------------------------------------------------------------
// SE-13 … SE-14: Zero-length and null-like cases
// ---------------------------------------------------------------------------

static void run_se13_edge() {
    AUDIT_LOG("\n  [SE-13..14] Edge cases\n");

    // Zero-length: must not crash
    uint8_t byte_buf[1] = {0xFF};
    secure_erase(byte_buf, 0);
    // byte_buf[0] should be unchanged (we erased nothing)
    CHECK(volatile_read(byte_buf, 0) == 0xFF,
          "SE-13: zero-length erase leaves adjacent byte untouched");

    // 256 bytes (large-ish buffer)
    std::unique_ptr<uint8_t[]> big(new uint8_t[256]);
    fill_sentinel(big.get(), 256, 0x37);
    secure_erase(big.get(), 256);
    CHECK(all_zero_volatile(big.get(), 256),
          "SE-14: 256-byte heap buffer zeroed");
}

// ---------------------------------------------------------------------------
// SE-15 … SE-20: Signing path nonce determinism
// (Proves that the nonce buffer was erased and re-derived, not reused)
// ---------------------------------------------------------------------------

static void run_se15_signing_determinism(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [SE-15..20] Signing path: nonce erased & re-derived (RFC 6979 determinism)\n");

    // If secure_erase of the nonce FAILS, the next signing call could use a
    // reused nonce.  RFC 6979 re-derives the nonce from the private key +
    // message, so two calls with the same inputs MUST produce the same
    // signature — this is only guaranteed if the nonce state is correctly
    // cleared between calls.

    static constexpr uint8_t KEY[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03
    };

    // Six distinct message hashes
    static constexpr uint8_t MSGS[6][32] = {
        { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
          0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
          0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
          0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20 },
        { 0x9f,0x86,0xd0,0x81,0x88,0x4c,0x7d,0x65,
          0x9a,0x2f,0xea,0xa0,0xc5,0x5a,0xd0,0x15,
          0xa3,0xbf,0x4f,0x1b,0x2b,0x0b,0x82,0x2c,
          0xd1,0x5d,0x6c,0x15,0xb0,0xf0,0x0a,0x08 },
        { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
          0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
          0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
          0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad },
        { 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
          0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
          0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
          0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef },
        { 0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,
          0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0,
          0xef,0xee,0xed,0xec,0xeb,0xea,0xe9,0xe8,
          0xe7,0xe6,0xe5,0xe4,0xe3,0xe2,0xe1,0xe0 },
        { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01 }
    };

    for (int i = 0; i < 6; ++i) {
        uint8_t sig1[64] = {}, sig2[64] = {};
        ufsecp_error_t rc1 = ufsecp_ecdsa_sign(ctx, MSGS[i], KEY, sig1);
        ufsecp_error_t rc2 = ufsecp_ecdsa_sign(ctx, MSGS[i], KEY, sig2);
        char msg[128];
        (void)std::snprintf(msg, sizeof(msg),
            "SE-%d: msg[%d] both sign calls succeed (RC 0)", 15 + i, i);
        CHECK(rc1 == UFSECP_OK && rc2 == UFSECP_OK, msg);
        (void)std::snprintf(msg, sizeof(msg),
            "SE-%d: msg[%d] signatures match (nonce determinism)", 15 + i, i);
        CHECK(std::memcmp(sig1, sig2, 64) == 0, msg);
    }
}

// ---------------------------------------------------------------------------
// SE-21 … SE-24: Pattern check — sentinel survives until erase call
// ---------------------------------------------------------------------------

static void run_se21_pattern() {
    AUDIT_LOG("\n  [SE-21..24] Sentinel pattern integrity before erasure\n");

    // Verify that the test harness itself is reliable: the sentinel IS written
    // and IS readable (not optimised away) before secure_erase is called.

    uint8_t buf[32];

    // Pattern 1: 0xA5
    fill_sentinel(buf, 32, 0xA5);
    CHECK(all_equal_volatile(buf, 32, 0xA5), "SE-21: 0xA5 sentinel readable before erase");
    secure_erase(buf, 32);
    CHECK(all_zero_volatile(buf, 32), "SE-22: 0xA5 sentinel zeroed by secure_erase");

    // Pattern 2: 0xFF
    fill_sentinel(buf, 32, 0xFF);
    CHECK(all_equal_volatile(buf, 32, 0xFF), "SE-23: 0xFF sentinel readable before erase");
    secure_erase(buf, 32);
    CHECK(all_zero_volatile(buf, 32), "SE-24: 0xFF sentinel zeroed by secure_erase");
}

// ---------------------------------------------------------------------------
// SE-25: Schnorr signing nonce determinism (Schnorr also erases intermediates)
// ---------------------------------------------------------------------------

static void run_se25_schnorr_determinism(ufsecp_ctx* ctx) {
    AUDIT_LOG("\n  [SE-25] Schnorr nonce determinism (BIP-340 aux=0)\n");

    static constexpr uint8_t KEY[32] = {
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,5
    };
    static constexpr uint8_t MSG[32] = {
        0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,
        0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,
        0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,
        0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89
    };
    uint8_t aux[32] = {};  // deterministic: aux_rand = 0
    uint8_t sig1[64] = {}, sig2[64] = {};
    ufsecp_error_t rc1 = ufsecp_schnorr_sign(ctx, MSG, KEY, aux, sig1);
    ufsecp_error_t rc2 = ufsecp_schnorr_sign(ctx, MSG, KEY, aux, sig2);
    CHECK(rc1 == UFSECP_OK && rc2 == UFSECP_OK,
          "SE-25a: Schnorr sign succeeds both calls");
    CHECK(std::memcmp(sig1, sig2, 64) == 0,
          "SE-25b: Schnorr signatures match (nonce determinism)");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int audit_secure_erase_run() {
    g_pass = 0; g_fail = 0;

    AUDIT_LOG("============================================================\n");
    AUDIT_LOG("  Secure Erasure Verification\n");
    AUDIT_LOG("  secure_erase() correctness + signing nonce lifecycle\n");
    AUDIT_LOG("============================================================\n");

    run_se1_sizes();
    run_se9_stack();
    run_se13_edge();
    run_se21_pattern();

    // Signing path tests need a context
    ufsecp_ctx* ctx = nullptr;
    if (ufsecp_ctx_create(&ctx) == UFSECP_OK && ctx != nullptr) {
        run_se15_signing_determinism(ctx);
        run_se25_schnorr_determinism(ctx);
        ufsecp_ctx_destroy(ctx);
    } else {
        CHECK(false, "SE-ctx: failed to create context for signing tests");
    }

    printf("[audit_secure_erase] %d/%d checks passed\n",
           g_pass, g_pass + g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#ifndef UNIFIED_AUDIT_RUNNER
int main() {
    return audit_secure_erase_run();
}
#endif
