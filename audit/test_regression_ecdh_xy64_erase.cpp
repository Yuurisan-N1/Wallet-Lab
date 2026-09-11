// ============================================================================
// test_regression_ecdh_xy64_erase.cpp
// ============================================================================
// Regression for SEC-002: secp256k1_ecdh() left the 64-byte X‖Y shared-secret
// buffer (xy64) on the stack after passing it to the hashfp callback. The fix
// adds secure_erase(xy64, 64) after the hashfp call.
//
// The erasure cannot be verified directly in a portable unit test (the stack
// frame is gone by the time a test could inspect it). This test instead verifies
// behavioral correctness — if xy64 was readable and correctly passed to hashfp,
// both parties derive the same shared secret. Correctness is the witness that
// the computation ran before the erase.
//
// Tests (EXY-1..4):
//   EXY-1  both parties derive the same ECDH output (default hashfp)
//   EXY-2  custom hashfp receives the X coordinate (first 32 bytes)
//   EXY-3  ECDH output is non-zero (not zeroed by erase before use)
//   EXY-4  NULL non-ctx argument on a valid ctx fires the illegal callback and
//          returns 0 (fail-closed). The literal-NULL-ctx abort path is not
//          testable in-process (SHIM_REQUIRE_CTX routes NULL ctx to the default
//          abort callback regardless of any per-context callback) — that path is
//          validated by code review of shim_ecdh.cpp / shim_internal.hpp, the
//          same convention as test_shim_security_edge_cases.cpp SHIM-004.
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#include <cstdio>
#define STANDALONE_TEST
#endif

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <array>
#include <atomic>

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

#if __has_include("secp256k1_ecdh.h")
#include "secp256k1.h"
#include "secp256k1_ecdh.h"

// privkey a = 7, privkey b = 11
static const uint8_t kSkA[32] = {
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,7
};
static const uint8_t kSkB[32] = {
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,11
};

// Custom hashfp that copies the raw X coordinate into output for inspection.
static int capture_x_hashfp(unsigned char* output,
    const unsigned char* x32, const unsigned char* /*y32*/, void* /*data*/)
{
    std::memcpy(output, x32, 32);
    return 1;
}

// Non-aborting counting illegal callback (mirror test_regression_shim_null_arg_cb.cpp).
// Installed via secp256k1_context_set_illegal_callback so an intentionally-illegal
// argument returns 0 instead of calling std::abort().
static std::atomic<int> g_exy_illegal_cb{0};
static void exy_illegal_cb(const char*, void*) { ++g_exy_illegal_cb; }

// ─── EXY-1: both parties get same ECDH output ────────────────────────────────
static void test_exy1_shared_secret_matches() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pkA, pkB;
    CHECK(secp256k1_ec_pubkey_create(ctx, &pkA, kSkA), "[EXY-1] create pkA");
    CHECK(secp256k1_ec_pubkey_create(ctx, &pkB, kSkB), "[EXY-1] create pkB");

    uint8_t outA[32] = {}, outB[32] = {};
    CHECK(secp256k1_ecdh(ctx, outA, &pkB, kSkA, nullptr, nullptr) == 1,
          "[EXY-1] ECDH A->B succeeds");
    CHECK(secp256k1_ecdh(ctx, outB, &pkA, kSkB, nullptr, nullptr) == 1,
          "[EXY-1] ECDH B->A succeeds");
    CHECK(std::memcmp(outA, outB, 32) == 0,
          "[EXY-1] shared secrets match (SEC-002: erase does not corrupt before output)");

    secp256k1_context_destroy(ctx);
}

// ─── EXY-2: custom hashfp gets correct X coordinate ─────────────────────────
static void test_exy2_x_coord_correct() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pkA, pkB;
    secp256k1_ec_pubkey_create(ctx, &pkA, kSkA);
    secp256k1_ec_pubkey_create(ctx, &pkB, kSkB);

    uint8_t xA[32] = {}, xB[32] = {};
    CHECK(secp256k1_ecdh(ctx, xA, &pkB, kSkA, capture_x_hashfp, nullptr) == 1,
          "[EXY-2] ECDH with capture_x_hashfp (A)");
    CHECK(secp256k1_ecdh(ctx, xB, &pkA, kSkB, capture_x_hashfp, nullptr) == 1,
          "[EXY-2] ECDH with capture_x_hashfp (B)");
    CHECK(std::memcmp(xA, xB, 32) == 0,
          "[EXY-2] X coordinates from both sides match — xy64 was read before erase");

    secp256k1_context_destroy(ctx);
}

// ─── EXY-3: output is non-zero ───────────────────────────────────────────────
static void test_exy3_output_nonzero() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pkB;
    secp256k1_ec_pubkey_create(ctx, &pkB, kSkB);

    uint8_t out[32] = {};
    secp256k1_ecdh(ctx, out, &pkB, kSkA, nullptr, nullptr);
    bool nonzero = false;
    for (int i = 0; i < 32; ++i) nonzero |= (out[i] != 0);
    CHECK(nonzero, "[EXY-3] ECDH output must be non-zero (SEC-002: not zeroed prematurely)");

    secp256k1_context_destroy(ctx);
}

// ─── EXY-4: NULL non-ctx arg fires illegal callback and returns 0 (fail-closed) ─
static void test_exy4_null_arg_fails_closed() {
    // A non-aborting illegal callback lets us exercise the fail-closed path
    // in-process. shim_ecdh.cpp checks output/pubkey/seckey AFTER ctx and, on a
    // valid ctx, fires ctx->illegal_cb (the installed counting callback) then
    // returns 0 — it does NOT abort.
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context_set_illegal_callback(ctx, exy_illegal_cb, nullptr);

    secp256k1_pubkey pkB;
    secp256k1_ec_pubkey_create(ctx, &pkB, kSkB);

    int before = g_exy_illegal_cb.load();
    int rc = secp256k1_ecdh(ctx, nullptr, &pkB, kSkA, nullptr, nullptr);
    int after = g_exy_illegal_cb.load();

    CHECK(rc == 0,        "[EXY-4] secp256k1_ecdh(NULL output) returns 0 (secp256k1 0=false convention)");
    CHECK(after > before, "[EXY-4] secp256k1_ecdh(NULL output) fires the illegal callback");

    // The literal-NULL-ctx path (secp256k1_ecdh(nullptr, ...)) routes through
    // SHIM_REQUIRE_CTX -> secp256k1_shim_call_illegal_cb(NULL, ...) ->
    // default_illegal_callback -> std::abort(). Because NULL ctx always reaches
    // the default callback (no per-context override is consulted), it cannot be
    // intercepted in-process. Validated by code review of shim_ecdh.cpp and
    // shim_internal.hpp — same convention as test_shim_security_edge_cases SHIM-004.
    std::printf("    INFO: [EXY-4] NULL-ctx abort path validated by code review (not testable in-process)\n");

    secp256k1_context_destroy(ctx);
}

static bool shim_available = true;

#else

static bool shim_available = false;

#endif // __has_include("secp256k1_ecdh.h")

int test_regression_ecdh_xy64_erase_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_ecdh_xy64_erase] SEC-002: xy64 erase correctness verification\n");

    if (!shim_available) {
        std::printf("  (shim not linked — skipping)\n");
        return 77;
    }

#if __has_include("secp256k1_ecdh.h")
    test_exy1_shared_secret_matches();
    test_exy2_x_coord_correct();
    test_exy3_output_nonzero();
    test_exy4_null_arg_fails_closed();
#endif

    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_ecdh_xy64_erase_run(); }
#endif
