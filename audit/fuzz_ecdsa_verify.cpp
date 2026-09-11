// ============================================================================
// LibFuzzer harness: ECDSA verify + ecrecover boundary fuzzer
// ============================================================================
//
// TARGET: ufsecp_ecdsa_verify()           — DER + compact path
//         ufsecp_ecdsa_sig_from_der()     — parser
//         ufsecp_ecdsa_recover()          — ecrecover (recid 0/1/2/3)
//         ufsecp_ecdsa_batch_verify()     — batch mode (single entry)
//
// INVARIANTS:
//   1. No crash/abort on any input.
//   2. If verify accepts, re-running accepts (determinism).
//   3. recover() on a valid sig + correct recid gives back the signing pubkey.
//      (Checked against a known sign-then-recover sequence below.)
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
    if (!g_ctx && ufsecp_ctx_create(&g_ctx) != UFSECP_OK) abort();
}

// Known-valid private key for the sign→recover self-test
static const uint8_t kTestSk[32] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ensure_ctx();

    uint8_t msg32[32]  = {};
    uint8_t sig64[64]  = {};
    uint8_t pk33[33]   = {};

    if (size > 0) { size_t m = size < 32 ? size : 32; memcpy(msg32, data, m); }
    if (size > 32){ size_t s = (size-32) < 64 ? (size-32) : 64; memcpy(sig64, data+32, s); }
    if (size > 96){ size_t p = (size-96) < 33 ? (size-96) : 33; memcpy(pk33,  data+96, p); }

    // --- compact verify ---------------------------------------------------
    (void)ufsecp_ecdsa_verify(g_ctx, msg32, sig64, pk33);

    // --- DER path: encode compact → DER → verify -------------------------
    {
        uint8_t der[UFSECP_SIG_DER_MAX_LEN];
        size_t  der_len = sizeof(der);
        ufsecp_error_t rc_der = ufsecp_ecdsa_sig_to_der(g_ctx, sig64, der, &der_len);
        if (rc_der == UFSECP_OK && der_len <= UFSECP_SIG_DER_MAX_LEN) {
            uint8_t compact_back[64];
            ufsecp_error_t rc_parse = ufsecp_ecdsa_sig_from_der(g_ctx, der, der_len, compact_back);
            if (rc_parse == UFSECP_OK) {
                (void)ufsecp_ecdsa_verify(g_ctx, msg32, compact_back, pk33);
            }
        }
    }

    // --- ecrecover fuzz (recid 0..3) -------------------------------------
    for (int recid = 0; recid < 4; ++recid) {
        uint8_t recovered_pk33[33];
        (void)ufsecp_ecdsa_recover(g_ctx, msg32, sig64, recid, recovered_pk33);
    }

    // --- batch verify (single entry) -------------------------------------
    {
        const uint8_t* msgs[1]  = { msg32 };
        const uint8_t* sigs[1]  = { sig64 };
        const uint8_t* pks[1]   = { pk33  };
        (void)ufsecp_ecdsa_batch_verify(g_ctx, 1, msgs, sigs, (const uint8_t (*)[33])pks, nullptr);
    }

    // --- determinism check on valid accepts --------------------------------
    {
        ufsecp_error_t r1 = ufsecp_ecdsa_verify(g_ctx, msg32, sig64, pk33);
        ufsecp_error_t r2 = ufsecp_ecdsa_verify(g_ctx, msg32, sig64, pk33);
        if (r1 != r2) __builtin_trap();
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Standalone
// ---------------------------------------------------------------------------
#if defined(LIBFUZZER_STANDALONE) || defined(SECP256K1_STANDALONE_FUZZ)

#include <cstdio>
#include <random>

// Self-test: sign with kTestSk → verify → recover
static void self_test_recover() {
    ensure_ctx();
    uint8_t pk33[33];
    if (ufsecp_pubkey_create(g_ctx, kTestSk, pk33) != UFSECP_OK) {
        printf("FAIL: pubkey_create\n"); abort();
    }
    uint8_t msg[32] = {0xDE,0xAD,0xBE,0xEF};
    uint8_t sig65[65];  // recoverable: 65 bytes (sig64 + recid byte)
    if (ufsecp_ecdsa_sign_recoverable(g_ctx, msg, kTestSk, sig65, &sig65[64]) != UFSECP_OK) {
        printf("FAIL: sign_recoverable\n"); abort();
    }
    uint8_t rpk33[33];
    int recid = (int)sig65[64];
    if (ufsecp_ecdsa_recover(g_ctx, msg, sig65, recid, rpk33) != UFSECP_OK) {
        printf("FAIL: recover returned error\n"); abort();
    }
    if (memcmp(pk33, rpk33, 33) != 0) {
        printf("FAIL: recovered pubkey != signing pubkey\n"); abort();
    }
    printf("  [OK] sign→recover self-test\n");
}

int main() {
    ensure_ctx();
    printf("fuzz_ecdsa_verify: running\n");
    self_test_recover();

    std::mt19937_64 rng(0xDEADBEEFCAFE0004ULL);
    constexpr int kIter = 50000;
    for (int i = 0; i < kIter; ++i) {
        const size_t len = rng() % 250;
        std::vector<uint8_t> buf(len);
        for (auto& b : buf) b = static_cast<uint8_t>(rng());
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
    printf("fuzz_ecdsa_verify: PASS (%d iterations)\n", kIter);
    return 0;
}
#endif
