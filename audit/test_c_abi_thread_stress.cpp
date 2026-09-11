// ============================================================================
// C ABI Thread Stress Tests -- UltrafastSecp256k1
// ============================================================================
//
// Validates the thread-safety contract that the public C ABI actually
// documents: each ufsecp_ctx is single-threaded, so callers must create one
// context per thread or externally synchronize shared use.
//
// This module stresses the safe usage pattern directly:
//   1. Multiple threads start work at the same time.
//   2. Each thread repeatedly creates its own ctx and ctx clone.
//   3. Each thread performs sign/verify/pubkey/xonly/ECDH operations only on
//      its own contexts.
//   4. All contexts are destroyed before the next round.
//
// The goal is not to bless shared-ctx concurrent use. The goal is to prove
// that the supported per-thread usage model survives high concurrency under
// normal audit and sanitizer runs.
// ============================================================================

#include <atomic>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#ifndef UFSECP_BUILDING
#define UFSECP_BUILDING
#endif
#include "ufsecp/ufsecp.h"

#include "secp256k1/sanitizer_scale.hpp"

static int g_pass = 0, g_fail = 0;

#include "audit_check.hpp"

namespace {

constexpr unsigned kFallbackThreads = 4;
constexpr unsigned kMaxThreads = 8;

struct WorkerResult {
    int checks = 0;
    int failures = 0;
};

static void make_message(unsigned thread_id, unsigned round, uint8_t out[32]) {
    for (size_t i = 0; i < 32; ++i) {
        out[i] = static_cast<uint8_t>((thread_id * 37u + round * 13u + static_cast<unsigned>(i) * 7u) & 0xFFu);
    }
}

static void make_aux(unsigned thread_id, unsigned round, uint8_t out[32]) {
    for (size_t i = 0; i < 32; ++i) {
        out[i] = static_cast<uint8_t>((0xA5u + thread_id * 11u + round * 5u + static_cast<unsigned>(i) * 3u) & 0xFFu);
    }
}

static void make_scalar(unsigned thread_id, unsigned round, uint8_t out[32], uint8_t tweak) {
    std::memset(out, 0, 32);
    unsigned value = 1u + ((thread_id + 1u) * 257u + round * 17u + tweak) % 65520u;
    out[30] = static_cast<uint8_t>((value >> 8) & 0xFFu);
    out[31] = static_cast<uint8_t>(value & 0xFFu);
    if (out[30] == 0 && out[31] == 0) {
        out[31] = 1;
    }
}

static WorkerResult run_worker(unsigned thread_id,
                               unsigned rounds,
                               std::atomic<unsigned>& ready_count,
                               std::atomic<bool>& start_flag) {
    WorkerResult result{};
    ready_count.fetch_add(1, std::memory_order_release);
    while (!start_flag.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    for (unsigned round = 0; round < rounds; ++round) {
        ufsecp_ctx* ctx = nullptr;
        ufsecp_ctx* clone = nullptr;
        uint8_t msg[32];
        uint8_t aux[32];
        uint8_t priv[32];
        uint8_t peer_priv[32];
        uint8_t pub33[33] = {};
        uint8_t peer33[33] = {};
        uint8_t xonly[32] = {};
        uint8_t ecdsa_sig[64] = {};
        uint8_t schnorr_sig[64] = {};
        uint8_t shared_a[32] = {};
        uint8_t shared_b[32] = {};

        make_message(thread_id, round, msg);
        make_aux(thread_id, round, aux);
        make_scalar(thread_id, round, priv, 0x11);
        make_scalar(thread_id, round, peer_priv, 0x55);

        if (ufsecp_ctx_create(&ctx) != UFSECP_OK || ctx == nullptr) {
            ++result.failures;
            continue;
        }
        ++result.checks;

        if (ufsecp_ctx_clone(ctx, &clone) != UFSECP_OK || clone == nullptr) {
            ++result.failures;
            ufsecp_ctx_destroy(ctx);
            continue;
        }
        ++result.checks;

        if (ufsecp_seckey_verify(ctx, priv) != UFSECP_OK) {
            ++result.failures;
        } else {
            ++result.checks;
        }

        if (ufsecp_pubkey_create(ctx, priv, pub33) != UFSECP_OK) {
            ++result.failures;
        } else {
            ++result.checks;
        }

        if (ufsecp_pubkey_xonly(clone, priv, xonly) != UFSECP_OK) {
            ++result.failures;
        } else {
            ++result.checks;
        }

        if (ufsecp_ecdsa_sign(ctx, msg, priv, ecdsa_sig) != UFSECP_OK) {
            ++result.failures;
        } else {
            ++result.checks;
            if (ufsecp_ecdsa_verify(clone, msg, ecdsa_sig, pub33) != UFSECP_OK) {
                ++result.failures;
            } else {
                ++result.checks;
            }
        }

        if (ufsecp_schnorr_sign(ctx, msg, priv, aux, schnorr_sig) != UFSECP_OK) {
            ++result.failures;
        } else {
            ++result.checks;
            if (ufsecp_schnorr_verify(clone, msg, schnorr_sig, xonly) != UFSECP_OK) {
                ++result.failures;
            } else {
                ++result.checks;
            }
        }

        if (ufsecp_pubkey_create(clone, peer_priv, peer33) != UFSECP_OK) {
            ++result.failures;
        } else {
            ++result.checks;
            if (ufsecp_ecdh(ctx, priv, peer33, shared_a) != UFSECP_OK) {
                ++result.failures;
            } else {
                ++result.checks;
            }
            if (ufsecp_ecdh(clone, peer_priv, pub33, shared_b) != UFSECP_OK) {
                ++result.failures;
            } else {
                ++result.checks;
            }
            if (std::memcmp(shared_a, shared_b, sizeof(shared_a)) != 0) {
                ++result.failures;
            } else {
                ++result.checks;
            }
        }

        if (ufsecp_ctx_size() == 0) {
            ++result.failures;
        } else {
            ++result.checks;
        }

        ufsecp_ctx_destroy(clone);
        ufsecp_ctx_destroy(ctx);
    }

    return result;
}

}  // namespace

int test_c_abi_thread_stress_run() {
    g_pass = 0;
    g_fail = 0;

    AUDIT_LOG("============================================================\n");
    AUDIT_LOG("  C ABI Thread Stress Tests\n");
    AUDIT_LOG("  One ctx per thread, concurrent lifecycle + sign/verify/ECDH\n");
    AUDIT_LOG("============================================================\n");

    unsigned threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = kFallbackThreads;
    if (threads > kMaxThreads) threads = kMaxThreads;
    if (threads < kFallbackThreads) threads = kFallbackThreads;
    const unsigned rounds = static_cast<unsigned>(SCALED(64, 8));

    AUDIT_LOG("  [TS-1] Launching %u threads, %u rounds each\n", threads, rounds);

    std::atomic<unsigned> ready_count{0};
    std::atomic<bool> start_flag{false};
    std::vector<std::thread> workers;
    std::vector<WorkerResult> results(threads);
    workers.reserve(threads);

    for (unsigned i = 0; i < threads; ++i) {
        workers.emplace_back([&, i]() {
            results[i] = run_worker(i, rounds, ready_count, start_flag);
        });
    }

    while (ready_count.load(std::memory_order_acquire) != threads) {
        std::this_thread::yield();
    }
    start_flag.store(true, std::memory_order_release);

    for (auto& worker : workers) {
        worker.join();
    }

    int total_checks = 0;
    int total_failures = 0;
    for (const auto& result : results) {
        total_checks += result.checks;
        total_failures += result.failures;
    }

    CHECK(total_failures == 0, "TS-1: per-thread ctx lifecycle + crypto operations stay race-free and correct");
    CHECK(total_checks == static_cast<int>(threads * rounds * 14u), "TS-2: all expected thread-stress checks executed");

    std::printf("[test_c_abi_thread_stress] %d/%d checks passed (%d worker checks)\n",
                g_pass, g_pass + g_fail, total_checks);
    return (g_fail > 0) ? 1 : 0;
}

#ifndef UNIFIED_AUDIT_RUNNER
int main() {
    return test_c_abi_thread_stress_run();
}
#endif