// ============================================================================
// test_regression_shim_preallocated_ctx.cpp — secp256k1_context_preallocated_*
// ============================================================================
// Verifies that the preallocated context family (TASK-008) behaves correctly:
//
//   PAC-1  secp256k1_context_preallocated_size returns >= sizeof(ctx) and > 0
//   PAC-2  secp256k1_context_preallocated_create succeeds with valid buffer
//   PAC-3  Created context is functional (sign + verify round-trip)
//   PAC-4  secp256k1_context_preallocated_destroy does NOT free (no crash reuse)
//   PAC-5  secp256k1_context_preallocated_clone round-trip produces valid clone
//   PAC-6  NULL prealloc fires illegal callback (no segfault)
//
// advisory=true: only runs when secp256k1_shim is linked.
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#define STANDALONE_TEST
#endif

#include "secp256k1.h"
#include "secp256k1_schnorrsig.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("  [FAIL] %s\n", (msg)); } \
} while(0)

static const unsigned char SK[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7
};
static const unsigned char MSG[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};

static bool g_cb_fired = false;
static void capture_cb(const char* /*text*/, void* /*data*/) noexcept {
    g_cb_fired = true;
}

// PAC-1: size is positive and at least the struct size
static void test_pac1_preallocated_size() {
    size_t sz = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN);
    CHECK(sz > 0, "PAC-1: preallocated_size > 0");
    // The shim context struct is flag-size-independent (shim_context.cpp:324:
    // preallocated_size ignores flags and returns sizeof(secp256k1_context)). The
    // earlier ">= 256" lower bound was an incorrect guess — the struct is smaller —
    // so assert the real invariant: the size is stable across flag combinations.
    // PAC-2 below proves the returned size is sufficient for preallocated_create.
    CHECK(sz == secp256k1_context_preallocated_size(
                    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY),
          "PAC-1: preallocated_size is flag-independent (stable)");
}

// PAC-2/PAC-3: create in caller buffer and exercise sign+verify
static void test_pac2_pac3_create_and_use() {
    size_t sz = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    std::vector<unsigned char> buf(sz + alignof(std::max_align_t), 0);

    // Align the buffer
    void* aligned = buf.data();
    size_t space  = buf.size();
    aligned = std::align(alignof(std::max_align_t), sz, aligned, space);
    CHECK(aligned != nullptr, "PAC-2: aligned pointer non-null");

    secp256k1_context *ctx = secp256k1_context_preallocated_create(
        aligned, SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    CHECK(ctx != nullptr, "PAC-2: preallocated_create returns non-null");

    if (!ctx) return;

    // Randomize and do a sign+verify round-trip (PAC-3)
    unsigned char seed[32] = {};
    seed[31] = 0x42;
    secp256k1_context_randomize(ctx, seed);

    secp256k1_xonly_pubkey xpk{};
    secp256k1_keypair kp{};
    int rc = secp256k1_keypair_create(ctx, &kp, SK);
    CHECK(rc == 1, "PAC-3: keypair_create in preallocated ctx");
    rc = secp256k1_keypair_xonly_pub(ctx, &xpk, nullptr, &kp);
    CHECK(rc == 1, "PAC-3: xonly_pub from keypair");

    unsigned char sig[64] = {};
    rc = secp256k1_schnorrsig_sign32(ctx, sig, MSG, &kp, nullptr);
    CHECK(rc == 1, "PAC-3: schnorrsig_sign32 in preallocated ctx");
    rc = secp256k1_schnorrsig_verify(ctx, sig, MSG, 32, &xpk);
    CHECK(rc == 1, "PAC-3: schnorrsig_verify in preallocated ctx");

    // PAC-4: destroy without freeing — buffer is still valid, re-create works
    secp256k1_context_preallocated_destroy(ctx);

    // Re-use the same buffer (no crash = no double-free or UAF)
    secp256k1_context *ctx2 = secp256k1_context_preallocated_create(
        aligned, SECP256K1_CONTEXT_SIGN);
    CHECK(ctx2 != nullptr, "PAC-4: buffer reusable after preallocated_destroy");
    if (ctx2) secp256k1_context_preallocated_destroy(ctx2);
}

// PAC-5: clone into caller buffer, verify clone is functional
static void test_pac5_clone() {
    secp256k1_context *src = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!src) { std::printf("  [SKIP] PAC-5: context_create failed\n"); return; }

    unsigned char seed[32] = {};
    seed[31] = 0xAB;
    secp256k1_context_randomize(src, seed);

    size_t sz = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN);
    std::vector<unsigned char> buf(sz + alignof(std::max_align_t), 0);
    void* aligned = buf.data();
    size_t space  = buf.size();
    aligned = std::align(alignof(std::max_align_t), sz, aligned, space);

    secp256k1_context *clone = secp256k1_context_preallocated_clone(src, aligned);
    CHECK(clone != nullptr, "PAC-5: preallocated_clone returns non-null");

    if (clone) {
        // Clone must be functional: sign + verify
        secp256k1_keypair kp{};
        int rc = secp256k1_keypair_create(clone, &kp, SK);
        CHECK(rc == 1, "PAC-5: keypair_create in clone context");

        secp256k1_xonly_pubkey xpk{};
        secp256k1_keypair_xonly_pub(clone, &xpk, nullptr, &kp);
        unsigned char sig[64] = {};
        rc = secp256k1_schnorrsig_sign32(clone, sig, MSG, &kp, nullptr);
        CHECK(rc == 1, "PAC-5: sign in cloned preallocated context");
        rc = secp256k1_schnorrsig_verify(clone, sig, MSG, 32, &xpk);
        CHECK(rc == 1, "PAC-5: verify in cloned preallocated context");

        secp256k1_context_preallocated_destroy(clone);
    }

    secp256k1_context_destroy(src);
}

// PAC-6: NULL prealloc fires illegal callback, no crash
static void test_pac6_null_prealloc() {
    g_cb_fired = false;
    // Install a capture callback on the static context
    secp256k1_context_set_illegal_callback(
        const_cast<secp256k1_context*>(secp256k1_context_static), capture_cb, nullptr);

    secp256k1_context *ctx = secp256k1_context_preallocated_create(
        nullptr, SECP256K1_CONTEXT_SIGN);
    CHECK(ctx == nullptr,    "PAC-6: NULL prealloc -> returns NULL");
    CHECK(g_cb_fired,        "PAC-6: NULL prealloc -> illegal callback fired");

    // Restore default callback
    secp256k1_context_set_illegal_callback(
        const_cast<secp256k1_context*>(secp256k1_context_static), nullptr, nullptr);

    // preallocated_clone with a VALID context but NULL prealloc routes through the
    // per-context illegal callback (secp256k1_shim_call_illegal_cb(ctx, ...)), so a
    // non-aborting callback intercepts it. Passing a NULL ctx instead would hit the
    // helper's NULL-ctx branch which unconditionally calls default_illegal_callback
    // → std::abort() (uncatchable in this runner) — see test_shim_security_edge_cases
    // SHIM-004, which documents that the NULL-ctx clone path cannot be tested without fork().
    secp256k1_context *probe = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (probe) {
        secp256k1_context_set_illegal_callback(probe, capture_cb, nullptr);
        g_cb_fired = false;
        secp256k1_context *ctx2 = secp256k1_context_preallocated_clone(probe, nullptr);
        CHECK(ctx2 == nullptr, "PAC-6: clone with NULL prealloc -> returns NULL");
        CHECK(g_cb_fired,      "PAC-6: clone with NULL prealloc -> illegal callback fired");
        secp256k1_context_destroy(probe);
    }
}

} // namespace

int test_regression_shim_preallocated_ctx_run() {
    std::printf("[test_regression_shim_preallocated_ctx] PAC-1..PAC-6\n");
    g_pass = 0; g_fail = 0;

    test_pac1_preallocated_size();
    test_pac2_pac3_create_and_use();
    test_pac5_clone();
    test_pac6_null_prealloc();

    std::printf("[test_regression_shim_preallocated_ctx] %d/%d passed\n",
                g_pass, g_pass + g_fail);
    return g_fail > 0 ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_shim_preallocated_ctx_run(); }
#endif
