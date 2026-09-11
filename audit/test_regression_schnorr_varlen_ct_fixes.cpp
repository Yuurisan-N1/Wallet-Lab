// ============================================================================
// REGRESSION: secp256k1_schnorrsig_sign_custom varlen path CT fixes
//
// Fixed in 2026-05-21 review (review v8):
//   VCS-1: generator_mul -> generator_mul_blinded (DPA defence on nonce)
//   VCS-2: k_prime.is_zero() -> k_prime.is_zero_ct() (CT branch on secret nonce)
//   VCS-3: s.is_zero() -> s.is_zero_ct() (CT branch on secret scalar)
//   VCS-4: e_hash, e, nonce_input, rand_hash, challenge_input, t_hash
//           not erased in varlen path — all now erased before return
//
// The varlen path is triggered when msglen != 32.
// The 32-byte fast path delegates to secp256k1_schnorrsig_sign32 which routes
// through ct::schnorr_sign — that path was already correct.
//
// REGRESSION GUARD (SHIM-001, restored 2026-06-01): the varlen *signing* path was
// removed (AUDIT-003) when shim verify was 32-byte-only, replaced by a
// `if (msglen != 32) return 0;` rejection — a divergence from upstream
// libsecp256k1, whose secp256k1_schnorrsig_sign_custom accepts any msglen. Verify
// is now varlen, so signing was restored via secp256k1::ct::schnorr_sign(kp, msg,
// msglen, aux). These tests lock in that sign_custom MUST NOT reject msglen != 32
// and MUST round-trip through verify, so the rejection cannot silently return.
//
// CT properties themselves (blinding, is_zero_ct) are validated by the
// Valgrind/MSAN CT pipeline; this test guards functional correctness only.
//
// VCS-1: sign_custom varlen 64-byte returns 1 (NOT rejected)
// VCS-2: sign_custom varlen 33-byte (smallest varlen)
// VCS-3: sign_custom varlen 256-byte (stack buffer boundary)
// VCS-4: sign_custom varlen 300-byte (heap buffer path)
// VCS-5: sign_custom varlen determinism (same inputs -> same sig)
// VCS-6: 32-byte fast path still delegates to sign32 (byte-identical)
// VCS-7: sign_custom + schnorrsig_verify varlen round-trip (accept valid,
//        reject tampered) across multiple lengths — the sign/verify symmetry guard
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#include <cstdio>
#define STANDALONE_TEST
#endif

#include <cstring>
#include <cstdio>
#include <cstdint>

static constexpr int ADVISORY_SKIP_CODE = 77;
static int g_fail = 0;

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { std::printf("  FAIL [%s:%d] %s\n", __FILE__, __LINE__, (msg)); ++g_fail; } \
} while(0)

// Include the REAL shim public headers (strong extern-C prototypes) instead of
// local WEAK declarations. The previous SHIM_WEAK __attribute__((weak)) decls
// stayed null when the shim was compiled INTO the fastsecp256k1 / secp256k1_shim
// static archive, because weak UNDEFINED references are NOT pulled from a .a —
// so the runtime null-check self-skipped with code 77 ("SKIP VCS: shim not
// linked"). Strong prototypes force archive resolution (the targets that compile
// this file already link secp256k1_shim and add the shim include dir in
// audit/CMakeLists.txt). Context flags come from the real header
// (SECP256K1_CONTEXT_SIGN == 0x201, SECP256K1_CONTEXT_VERIFY == 0x101).
#if __has_include("secp256k1.h")
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#define VARLEN_SHIM_AVAILABLE 1
#else
#define VARLEN_SHIM_AVAILABLE 0
#endif

#if VARLEN_SHIM_AVAILABLE

static const unsigned char kPrivkey[32] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0xDE,0xAD,0xBE,0xEF,
};

// VCS-1: 64-byte message — basic varlen correctness
static void test_varlen_64byte(secp256k1_context* ctx) {
    std::printf("  [VCS-1] sign_custom varlen 64-byte round-trip\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-1: keypair_create");

    unsigned char msg[64] = {};
    msg[0] = 0xDE; msg[32] = 0xAD; msg[63] = 0xBE;
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 64, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-1: sign_custom 64-byte returns 1");

    unsigned int r_nonzero = 0;
    for (int i = 0; i < 32; ++i) r_nonzero |= sig[i];
    ASSERT_TRUE(r_nonzero != 0, "VCS-1: r component is not all-zero");

    unsigned int s_nonzero = 0;
    for (int i = 32; i < 64; ++i) s_nonzero |= sig[i];
    ASSERT_TRUE(s_nonzero != 0, "VCS-1: s component is not all-zero");
}

// VCS-2: 33-byte message — smallest varlen case
static void test_varlen_33byte(secp256k1_context* ctx) {
    std::printf("  [VCS-2] sign_custom varlen 33-byte (smallest varlen)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-2: keypair_create");

    unsigned char msg[33] = {};
    msg[0] = 0xFF; msg[32] = 0x01;
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 33, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-2: sign_custom 33-byte returns 1");

    unsigned int nonzero = 0;
    for (int i = 0; i < 64; ++i) nonzero |= sig[i];
    ASSERT_TRUE(nonzero != 0, "VCS-2: signature is non-zero");
}

// VCS-3: 256-byte message — stack buffer boundary (kStackMsgMax)
static void test_varlen_256byte(secp256k1_context* ctx) {
    std::printf("  [VCS-3] sign_custom varlen 256-byte (stack buffer boundary)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-3: keypair_create");

    unsigned char msg[256] = {};
    for (int i = 0; i < 256; ++i) msg[i] = (unsigned char)i;
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 256, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-3: sign_custom 256-byte returns 1");

    unsigned int nonzero = 0;
    for (int i = 0; i < 64; ++i) nonzero |= sig[i];
    ASSERT_TRUE(nonzero != 0, "VCS-3: signature is non-zero");
}

// VCS-4: 300-byte message — triggers heap buffer path (msglen > 256)
static void test_varlen_300byte_heap(secp256k1_context* ctx) {
    std::printf("  [VCS-4] sign_custom varlen 300-byte (heap path, msglen > 256)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-4: keypair_create");

    unsigned char msg[300] = {};
    for (int i = 0; i < 300; ++i) msg[i] = (unsigned char)(i ^ 0xA5);
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 300, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-4: sign_custom 300-byte (heap path) returns 1");

    unsigned int nonzero = 0;
    for (int i = 0; i < 64; ++i) nonzero |= sig[i];
    ASSERT_TRUE(nonzero != 0, "VCS-4: signature is non-zero");
}

// VCS-5: determinism — same inputs must yield identical signature
static void test_varlen_determinism(secp256k1_context* ctx) {
    std::printf("  [VCS-5] sign_custom varlen determinism (same inputs -> same sig)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-5: keypair_create");

    unsigned char msg[64] = {};
    msg[7] = 0xCA; msg[35] = 0xFE;
    unsigned char sig1[64] = {}, sig2[64] = {};

    ASSERT_TRUE(secp256k1_schnorrsig_sign_custom(ctx, sig1, msg, 64, &kp, nullptr) == 1,
                "VCS-5: first sign returns 1");
    ASSERT_TRUE(secp256k1_schnorrsig_sign_custom(ctx, sig2, msg, 64, &kp, nullptr) == 1,
                "VCS-5: second sign returns 1");
    ASSERT_TRUE(std::memcmp(sig1, sig2, 64) == 0,
                "VCS-5: varlen sign_custom is deterministic (CT erasure must not affect output)");
}

// VCS-6: 32-byte fast path still delegates correctly (regression guard)
static void test_32byte_fast_path(secp256k1_context* ctx) {
    std::printf("  [VCS-6] sign_custom 32-byte fast path still works after varlen fixes\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-6: keypair_create");

    unsigned char msg[32] = {}; msg[0] = 0x42; msg[31] = 0x77;
    unsigned char sig_custom[64] = {}, sig_sign32[64] = {};

    ASSERT_TRUE(secp256k1_schnorrsig_sign_custom(ctx, sig_custom, msg, 32, &kp, nullptr) == 1,
                "VCS-6: sign_custom 32-byte returns 1");
    ASSERT_TRUE(secp256k1_schnorrsig_sign32(ctx, sig_sign32, msg, &kp, nullptr) == 1,
                "VCS-6: sign32 returns 1");

    // sign_custom(msglen=32) must delegate to sign32 — same deterministic output
    ASSERT_TRUE(std::memcmp(sig_custom, sig_sign32, 64) == 0,
                "VCS-6: sign_custom(32) == sign32 (fast path delegation correct)");
}

// VCS-7: full sign+verify symmetry — sign_custom(msg,len) must produce a
// signature that schnorrsig_verify(msg,len) accepts, and a tampered message must
// be rejected, across several lengths. This is the strongest guard against the
// AUDIT-003 regression (sign_custom rejecting msglen != 32) silently returning:
// if sign rejected varlen, rc would be 0; if verify were 32-only, verify would
// be 0 for varlen. Both must be 1 here.
static void test_varlen_sign_verify_roundtrip(secp256k1_context* ctx) {
    std::printf("  [VCS-7] sign_custom + schnorrsig_verify varlen round-trip\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-7: keypair_create");

    secp256k1_xonly_pubkey xpk{};
    ASSERT_TRUE(secp256k1_keypair_xonly_pub(ctx, &xpk, nullptr, &kp) == 1, "VCS-7: keypair_xonly_pub");

    const size_t lens[] = {1, 31, 33, 64, 100, 256, 300};
    for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); ++li) {
        const size_t mlen = lens[li];
        unsigned char msg[300];
        for (size_t i = 0; i < mlen; ++i) msg[i] = (unsigned char)((i * 7u + 3u) ^ 0x5Au);
        unsigned char sig[64] = {};

        int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, mlen, &kp, nullptr);
        ASSERT_TRUE(rc == 1, "VCS-7: sign_custom varlen returns 1 (NOT rejected)");

        int v = secp256k1_schnorrsig_verify(ctx, sig, msg, mlen, &xpk);
        ASSERT_TRUE(v == 1, "VCS-7: verify accepts the varlen signature (sign/verify symmetric)");

        // Tamper one message byte -> verify MUST reject (proves verify binds msg, len).
        msg[mlen / 2] ^= 0x01;
        int vt = secp256k1_schnorrsig_verify(ctx, sig, msg, mlen, &xpk);
        ASSERT_TRUE(vt == 0, "VCS-7: verify rejects a tampered varlen message");
    }
}

int test_regression_schnorr_varlen_ct_fixes_run() {
    g_fail = 0;

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        std::printf("  SKIP VCS: context_create failed\n");
        return ADVISORY_SKIP_CODE;
    }

    test_varlen_64byte(ctx);
    test_varlen_33byte(ctx);
    test_varlen_256byte(ctx);
    test_varlen_300byte_heap(ctx);
    test_varlen_determinism(ctx);
    test_32byte_fast_path(ctx);
    test_varlen_sign_verify_roundtrip(ctx);

    secp256k1_context_destroy(ctx);

    if (g_fail == 0)
        std::printf("  PASS VCS-1..7: sign_custom varlen restored + sign/verify symmetric\n");
    else
        std::printf("  FAIL VCS: sign_custom varlen: %d failure(s)\n", g_fail);
    return g_fail;
}
#else  // !VARLEN_SHIM_AVAILABLE
// Shim headers absent at compile time (non-shim build configuration). The
// targets that exercise this regression always link secp256k1_shim and add the
// shim include dir, so this branch only guards exotic configs. Self-skip with
// the advisory sentinel rather than fail the build.
int test_regression_schnorr_varlen_ct_fixes_run() {
    std::printf("  SKIP VCS: shim headers not available at compile time\n");
    return ADVISORY_SKIP_CODE;
}
#endif // VARLEN_SHIM_AVAILABLE

#ifdef STANDALONE_TEST
int main() { return test_regression_schnorr_varlen_ct_fixes_run(); }
#endif
