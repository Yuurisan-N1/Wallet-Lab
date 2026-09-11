/* ============================================================================
 * UltrafastSecp256k1 — BIP-352 Silent Payment GPU Batch Scan Audit
 * ============================================================================
 * Audit coverage for ufsecp_bip352_prepare_scan_plan (CPU utility) and
 * ufsecp_gpu_bip352_scan_batch (GPU batch scan).
 *
 * BIP-352 pipeline per tweak t_i:
 *   1. shared = scan_privkey × t_i               (GLV wNAF)
 *   2. ser37  = [prefix_byte] || shared.x || [0,0,0,0]
 *   3. hash   = SHA256_tagged("BIP0352/SharedSecret", ser37)
 *   4. output = hash × G + spend_pubkey
 *   5. prefix = upper 64 bits of output.x
 *
 * TESTS:
 *   SW-BIP352-1 : UFSECP_BIP352_SCAN_PLAN_BYTES macro == 264
 *   SW-BIP352-2 : ufsecp_bip352_prepare_scan_plan null arg → error
 *   SW-BIP352-3 : ufsecp_bip352_prepare_scan_plan produces non-zero output
 *   SW-BIP352-4 : GPU scan: null ctx → error
 *   SW-BIP352-5 : GPU scan: null scan_privkey → error
 *   SW-BIP352-6 : GPU scan: null spend_pubkey → error
 *   SW-BIP352-7 : GPU scan: null tweak_pubkeys → error (when n_tweaks > 0)
 *   SW-BIP352-8 : GPU scan: null prefix64_out → error
 *   SW-BIP352-9 : GPU scan: n_tweaks == 0 → UFSECP_OK (no crash)
 *   SW-BIP352-10: GPU scan: single tweak → prefix is non-zero
 *   SW-BIP352-11: GPU scan: batch of 16 tweaks → all prefixes non-zero
 *   SW-BIP352-12: GPU scan: determinism — same inputs → same prefixes
 *   SW-BIP352-13: GPU scan: distinct tweaks → prefixes are not all identical
 *   SW-BIP352-14: GPU scan: invalid compressed tweak pubkey is rejected
 *
 * Compiles as standalone (define STANDALONE_TEST) or as part of the audit runner.
 * ============================================================================ */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "ufsecp/ufsecp.h"
#include "ufsecp/ufsecp_gpu.h"

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

#define CHECK(cond, id, msg)                                                    \
    do {                                                                        \
        if (cond) { ++g_pass; }                                                 \
        else { ++g_fail; std::printf("  FAIL %s: %s\n", (id), (msg)); }        \
    } while (0)

#define SKIP(id, msg)                                                           \
    do { ++g_skip; std::printf("  SKIP %s: %s\n", (id), (msg)); } while (0)

/* ---- deterministic test-vector data ------------------------------------- */
/* These constants match the benchmark in opencl/benchmarks/bench_bip352_opencl.cpp
 * so that audit and bench share the same reference scalars. */
static const uint8_t SCAN_KEY[32] = {
    0xc4,0x23,0x9f,0xd6,0xfc,0x3d,0xb6,0xe2,
    0x2b,0x8b,0xed,0x6a,0x49,0x21,0x9e,0x4e,
    0x30,0xd7,0xd6,0xa3,0xb9,0x82,0x94,0xb1,
    0x38,0xaf,0x4a,0xd3,0x00,0xda,0x1a,0x42
};

static const uint8_t ORDER_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static const uint8_t SPEND_PUBKEY[33] = {
    0x02,
    0xe2,0xed,0x4b,0x9c,0xe9,0x14,0x5e,0x17,
    0x21,0xf1,0x1f,0x99,0x5f,0x72,0x6e,0xf8,
    0xcf,0x50,0xfc,0x85,0x92,0x89,0xac,0x94,
    0x4b,0x2d,0xaf,0xe5,0x03,0xa3,0xc7,0x4c
};

/* Simple LCG to generate deterministic tweak compressed public keys.
 * We generate synthetic scalars, derive their public keys via CPU, and use
 * those as tweak inputs so the test is self-contained. */
static void fill_det(uint8_t* buf, size_t len, uint8_t seed) {
    uint32_t st = seed;
    for (size_t i = 0; i < len; ++i) {
        st = st * 1103515245u + 12345u;
        buf[i] = static_cast<uint8_t>((st >> 16) & 0xFF);
    }
}

static bool all_zero(const void* ptr, size_t len) {
    const auto* p = static_cast<const uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

/* Build n compressed tweak public keys via ufsecp_pubkey_create.
 * Caller must ensure out_tweaks33 has room for n*33 bytes.
 * Returns false if any pubkey derivation fails. */
static bool build_tweak_pubkeys(ufsecp_ctx* ctx, int n, uint8_t* out_tweaks33) {
    for (int i = 0; i < n; ++i) {
        uint8_t sk[32];
        fill_det(sk, 32, static_cast<uint8_t>(i + 1));
        sk[0] &= 0x7F; /* keep in scalar range */
        if (ufsecp_pubkey_create(ctx, sk, out_tweaks33 + i * 33) != UFSECP_OK)
            return false;
    }
    return true;
}

/* ============================================================================
 * SW-BIP352-1 — macro constant
 * ============================================================================ */
static void test_bip352_1_macro() {
    std::printf("[bip352_scan] SW-BIP352-1: UFSECP_BIP352_SCAN_PLAN_BYTES == 264\n");
    CHECK(UFSECP_BIP352_SCAN_PLAN_BYTES == 264,
          "SW-BIP352-1", "UFSECP_BIP352_SCAN_PLAN_BYTES macro == 264");
}

/* ============================================================================
 * SW-BIP352-2, SW-BIP352-3 — CPU prepare_scan_plan
 * ============================================================================ */
static void test_bip352_2_3_cpu_plan() {
    std::printf("[bip352_scan] SW-BIP352-2/3: ufsecp_bip352_prepare_scan_plan\n");

    /* SW-BIP352-2: null scan_privkey */
    uint8_t plan[264] = {};
    auto rc_null = ufsecp_bip352_prepare_scan_plan(nullptr, plan);
    CHECK(rc_null != UFSECP_OK, "SW-BIP352-2", "null scan_privkey → error");

    std::memset(plan, 0xA5, sizeof(plan));
    uint8_t zero_scan[32] = {};
    auto rc_zero = ufsecp_bip352_prepare_scan_plan(zero_scan, plan);
    CHECK(rc_zero == UFSECP_ERR_BAD_KEY,
          "SW-BIP352-2b", "zero scan_privkey → BAD_KEY");
    CHECK(all_zero(plan, sizeof(plan)),
          "SW-BIP352-2c", "zero scan_privkey leaves plan output zeroed");

    std::memset(plan, 0xA5, sizeof(plan));
    auto rc_order = ufsecp_bip352_prepare_scan_plan(ORDER_N, plan);
    CHECK(rc_order == UFSECP_ERR_BAD_KEY,
          "SW-BIP352-2d", "scan_privkey == group order → BAD_KEY");
    CHECK(all_zero(plan, sizeof(plan)),
          "SW-BIP352-2e", "order scan_privkey leaves plan output zeroed");

    /* SW-BIP352-3: valid key → non-zero plan */
    auto rc_ok = ufsecp_bip352_prepare_scan_plan(SCAN_KEY, plan);
    CHECK(rc_ok == UFSECP_OK, "SW-BIP352-3a", "prepare_scan_plan returns UFSECP_OK");

    /* wNAF bytes at offset 0 should not all be zero for a random-looking key */
    uint8_t zero_plan[264] = {};
    CHECK(std::memcmp(plan, zero_plan, 264) != 0,
          "SW-BIP352-3b", "plan output is non-zero");
}

/* ============================================================================
 * SW-BIP352-4 to SW-BIP352-13 — GPU batch scan
 * ============================================================================ */
static void test_bip352_4_13_gpu(ufsecp_ctx* cpu_ctx) {
    std::printf("[bip352_scan] SW-BIP352-4..13: GPU batch scan\n");

    /* --- open GPU context ----------------------------------------------- */
    ufsecp_gpu_ctx* gpu = nullptr;
    {
        uint32_t ids[8] = {};
        uint32_t cnt = ufsecp_gpu_backend_count(ids, 8);
        if (cnt == 0) {
            SKIP("SW-BIP352-4", "no GPU backend available");
            SKIP("SW-BIP352-5", "no GPU backend available");
            SKIP("SW-BIP352-6", "no GPU backend available");
            SKIP("SW-BIP352-7", "no GPU backend available");
            SKIP("SW-BIP352-8", "no GPU backend available");
            SKIP("SW-BIP352-9", "no GPU backend available");
            SKIP("SW-BIP352-10", "no GPU backend available");
            SKIP("SW-BIP352-11", "no GPU backend available");
            SKIP("SW-BIP352-12", "no GPU backend available");
            SKIP("SW-BIP352-13", "no GPU backend available");
            return;
        }
        auto rc = ufsecp_gpu_ctx_create(&gpu, ids[0], 0);
        if (rc != UFSECP_OK || !gpu) {
            SKIP("SW-BIP352-4", "GPU context creation failed");
            SKIP("SW-BIP352-5", "GPU context creation failed");
            SKIP("SW-BIP352-6", "GPU context creation failed");
            SKIP("SW-BIP352-7", "GPU context creation failed");
            SKIP("SW-BIP352-8", "GPU context creation failed");
            SKIP("SW-BIP352-9", "GPU context creation failed");
            SKIP("SW-BIP352-10", "GPU context creation failed");
            SKIP("SW-BIP352-11", "GPU context creation failed");
            SKIP("SW-BIP352-12", "GPU context creation failed");
            SKIP("SW-BIP352-13", "GPU context creation failed");
            return;
        }
    }

    /* Build 16 deterministic tweak pubkeys */
    constexpr int N = 16;
    uint8_t tweaks[N * 33] = {};
    bool ok = build_tweak_pubkeys(cpu_ctx, N, tweaks);
    if (!ok) {
        std::printf("  WARN: failed to build deterministic tweak pubkeys\n");
        ufsecp_gpu_ctx_destroy(gpu);
        return;
    }

    uint64_t prefixes[N] = {};
    uint64_t dummy1 = 0;

    /* SW-BIP352-4: null ctx */
    auto rc4 = ufsecp_gpu_bip352_scan_batch(nullptr, SCAN_KEY, SPEND_PUBKEY,
                                             tweaks, 1, prefixes);
    CHECK(rc4 != UFSECP_OK, "SW-BIP352-4", "null GPU ctx → error");

    /* SW-BIP352-5: null scan_privkey */
    auto rc5 = ufsecp_gpu_bip352_scan_batch(gpu, nullptr, SPEND_PUBKEY,
                                             tweaks, 1, prefixes);
    CHECK(rc5 != UFSECP_OK, "SW-BIP352-5", "null scan_privkey → error");

    /* SW-BIP352-6: null spend_pubkey */
    auto rc6 = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, nullptr,
                                             tweaks, 1, prefixes);
    CHECK(rc6 != UFSECP_OK, "SW-BIP352-6", "null spend_pubkey → error");

    /* SW-BIP352-7: null tweak_pubkeys (n_tweaks > 0) */
    auto rc7 = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, SPEND_PUBKEY,
                                             nullptr, 1, prefixes);
    CHECK(rc7 != UFSECP_OK, "SW-BIP352-7", "null tweak_pubkeys w/ n>0 → error");

    /* SW-BIP352-8: null prefix64_out */
    auto rc8 = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, SPEND_PUBKEY,
                                             tweaks, 1, nullptr);
    CHECK(rc8 != UFSECP_OK, "SW-BIP352-8", "null prefix64_out → error");

    /* SW-BIP352-9: n_tweaks == 0 → must not crash and must return OK */
    auto rc9 = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, SPEND_PUBKEY,
                                             tweaks, 0, &dummy1);
    CHECK(rc9 == UFSECP_OK, "SW-BIP352-9", "n_tweaks==0 → UFSECP_OK");

    uint8_t zero_scan[32] = {};
    dummy1 = UINT64_MAX;
    auto rc9a = ufsecp_gpu_bip352_scan_batch(gpu, zero_scan, SPEND_PUBKEY,
                                              tweaks, 1, &dummy1);
    CHECK(rc9a == UFSECP_ERR_BAD_KEY,
          "SW-BIP352-9a", "zero scan key is rejected before GPU dispatch");
    CHECK(dummy1 == 0,
          "SW-BIP352-9b", "bad scan key clears prefix64_out");

    uint8_t bad_tweak[33] = {};
    std::memcpy(bad_tweak, tweaks, sizeof(bad_tweak));
    bad_tweak[0] = 0x05;
    dummy1 = UINT64_MAX;
    auto rc9b = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, SPEND_PUBKEY,
                                              bad_tweak, 1, &dummy1);
    if (rc9b == UFSECP_ERR_GPU_UNSUPPORTED) {
        SKIP("SW-BIP352-14", "bip352_scan_batch not supported on this backend");
    } else {
        CHECK(rc9b != UFSECP_OK,
              "SW-BIP352-14", "invalid compressed tweak pubkey is rejected");
        CHECK(dummy1 == 0,
              "SW-BIP352-14b", "invalid tweak pubkey clears prefix64_out");
    }

    /* SW-BIP352-10: single tweak → prefix non-zero */
    uint64_t p1 = 0;
    auto rc10 = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, SPEND_PUBKEY,
                                              tweaks, 1, &p1);
    if (rc10 == UFSECP_ERR_GPU_UNSUPPORTED) {
        SKIP("SW-BIP352-10", "bip352_scan_batch not supported on this backend");
    } else {
        CHECK(rc10 == UFSECP_OK,  "SW-BIP352-10a", "single tweak returns UFSECP_OK");
        CHECK(p1   != 0,          "SW-BIP352-10b", "prefix is non-zero for single tweak");
    }

    /* SW-BIP352-11: batch of N tweaks → all prefixes non-zero */
    auto rc11 = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, SPEND_PUBKEY,
                                              tweaks, N, prefixes);
    if (rc11 == UFSECP_ERR_GPU_UNSUPPORTED) {
        SKIP("SW-BIP352-11", "bip352_scan_batch not supported on this backend");
    } else {
        CHECK(rc11 == UFSECP_OK, "SW-BIP352-11a", "batch of 16 returns UFSECP_OK");
        bool any_zero = false;
        for (int i = 0; i < N; ++i) if (prefixes[i] == 0) { any_zero = true; break; }
        CHECK(!any_zero, "SW-BIP352-11b", "no prefix is zero in batch of 16");
    }

    /* SW-BIP352-12: determinism — same call must return identical prefixes */
    uint64_t prefixes2[N] = {};
    auto rc12 = ufsecp_gpu_bip352_scan_batch(gpu, SCAN_KEY, SPEND_PUBKEY,
                                              tweaks, N, prefixes2);
    if (rc12 == UFSECP_ERR_GPU_UNSUPPORTED) {
        SKIP("SW-BIP352-12", "bip352_scan_batch not supported on this backend");
    } else {
        CHECK(rc12 == UFSECP_OK, "SW-BIP352-12a", "second call returns UFSECP_OK");
        CHECK(std::memcmp(prefixes, prefixes2, N * sizeof(uint64_t)) == 0,
              "SW-BIP352-12b", "identical call → identical prefixes");
    }

    /* SW-BIP352-13: distinct tweaks → not all prefixes identical */
    if (rc11 == UFSECP_OK && N >= 2) {
        bool all_same = true;
        for (int i = 1; i < N; ++i) {
            if (prefixes[i] != prefixes[0]) { all_same = false; break; }
        }
        CHECK(!all_same, "SW-BIP352-13", "distinct tweaks produce distinct prefixes");
    } else {
        SKIP("SW-BIP352-13", "batch scan unavailable or N<2");
    }

    ufsecp_gpu_ctx_destroy(gpu);
}

/* ============================================================================
 * Entry point
 * ============================================================================ */
int test_gpu_bip352_scan_run() {
    std::printf("=== BIP-352 Silent Payment GPU Scan Audit ===\n\n");

    test_bip352_1_macro();
    std::printf("\n");

    test_bip352_2_3_cpu_plan();
    std::printf("\n");

    ufsecp_ctx* cpu_ctx = nullptr;
    if (ufsecp_ctx_create(&cpu_ctx) != UFSECP_OK || !cpu_ctx) {
        std::printf("FATAL: ufsecp_ctx_create failed\n");
        return 1;
    }

    test_bip352_4_13_gpu(cpu_ctx);
    std::printf("\n");

    ufsecp_ctx_destroy(cpu_ctx);

    std::printf("=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return (g_fail > 0) ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() {
    return test_gpu_bip352_scan_run();
}
#endif /* STANDALONE_TEST */
