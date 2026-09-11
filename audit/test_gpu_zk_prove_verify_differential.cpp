/* ============================================================================
 * UltrafastSecp256k1 — GPU Bulletproof poly-check vs CPU prover differential
 * ============================================================================
 * Closes a GPU correctness blind-spot: until now the GPU range-proof verifier
 * `ufsecp_gpu_bulletproof_verify_batch` was only ever exercised with malformed
 * stub inputs (test_gpu_host_api_negative). No VALID, CPU-generated range proof
 * was ever fed to it, so the device polynomial check was never proven to ACCEPT
 * a genuine proof — only to reject garbage.
 *
 * WHAT THE GPU VERIFIES (and what it does NOT):
 *   The GPU kernel checks ONLY the Bulletproof t-polynomial identity over the
 *   324-byte poly-part of a proof:
 *       A(65) || S(65) || T1(65) || T2(65) || tau_x(32) || t_hat(32)
 *   (4 uncompressed points + 2 scalars). It recomputes the Fiat-Shamir
 *   challenges y,z,x from A,S,V and checks
 *       g^{t_hat} h^{tau_x} == V^{z^2} g^{delta(y,z)} T1^x T2^{x^2}.
 *   It does NOT run the inner-product argument (the L,R,a,b part of the proof).
 *   So the GPU check is a NECESSARY (not sufficient) condition for validity.
 *
 * WHY THIS IS NOT A SYMMETRIC CPU<->GPU DIFFERENTIAL:
 *   There is no standalone CPU `range_proof_poly_check`; the CPU only exposes
 *   the FULL `range_verify` (poly + IPA). So the oracle here is:
 *     - CPU full `range_verify` == true   → the proof is genuinely valid, hence
 *       its poly-part MUST pass the GPU poly check → assert GPU verdict == 1.
 *     - A one-byte tamper of a poly-part scalar (tau_x / t_hat) breaks the
 *       polynomial identity → assert GPU verdict == 0.
 *   This proves the CPU prover and the GPU verifier agree on the SAME
 *   Fiat-Shamir transcript and the SAME polynomial equation — a real
 *   cross-implementation consistency check on a previously untested device path.
 *
 * ADVISORY: requires a GPU with the ZK module compiled in. Skips cleanly when no
 * GPU backend is present (GitHub-hosted runners) or when the backend was built
 * without SECP256K1_GPU_HAS_ZK (bulletproof_verify_batch → ERR_GPU_UNSUPPORTED).
 *
 * Compiles standalone (-DSTANDALONE_TEST) or as part of the unified audit runner.
 * ============================================================================ */

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "ufsecp/ufsecp_gpu.h"

#include "secp256k1/pedersen.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/zk.hpp"

using secp256k1::PedersenCommitment;
using secp256k1::pedersen_commit;
using secp256k1::pedersen_generator_H;
using secp256k1::zk::RangeProof;
using secp256k1::zk::range_prove;
using secp256k1::zk::range_verify;
using Scalar = secp256k1::fast::Scalar;

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

/* Rule 16 / Guardrail 16: a GPU advisory module MUST return ADVISORY_SKIP_CODE
 * (77) — never 0 — when the GPU runtime (or the GPU ZK module) is absent. Returning
 * 0 would be a false PASS. Enforced by gate.yml's shim security gate (CI-012) and
 * ci/check_advisory_skip_codes.py. Returns 0 only when the GPU actually ran and all
 * assertions passed; 1 on a real failure. */
static constexpr int ADVISORY_SKIP_CODE = 77;

/* "GPU runtime cannot actually dispatch this kernel" — broader than UNSUPPORTED.
 * On GitHub-hosted macos runners software Metal registers a backend and creates a
 * context, but the ZK metallib fails to load ("Failed to load metallib") and the
 * dispatch returns GPU_LAUNCH/BACKEND/QUEUE/MEMORY/DEVICE rather than UNSUPPORTED.
 * All of these mean "the kernel did not run" → advisory skip, not a failure.
 * Mirrors gpu_runtime_unusable() in test_gpu_host_api_negative.cpp. */
static inline bool gpu_runtime_unusable(ufsecp_error_t rc) {
    return rc == UFSECP_ERR_GPU_UNSUPPORTED ||
           rc == UFSECP_ERR_GPU_LAUNCH      ||
           rc == UFSECP_ERR_GPU_MEMORY      ||
           rc == UFSECP_ERR_GPU_BACKEND     ||
           rc == UFSECP_ERR_GPU_QUEUE       ||
           rc == UFSECP_ERR_GPU_DEVICE;
}

#define CHECK(cond, id, msg)                                                    \
    do {                                                                        \
        if (cond) { ++g_pass; }                                                 \
        else { ++g_fail; std::printf("  FAIL %s: %s\n", (id), (msg)); }         \
    } while (0)

#define SKIP(id, msg)                                                           \
    do { ++g_skip; std::printf("  SKIP %s: %s\n", (id), (msg)); } while (0)

/* GPU poly-part layout (must match gpu_backend_*::bulletproof_verify_batch):
 *   A @ 0, S @ 65, T1 @ 130, T2 @ 195 (each 65-byte uncompressed 04||x||y),
 *   tau_x @ 260, t_hat @ 292 (each 32-byte big-endian scalar). Total 324. */
static void serialize_poly324(const RangeProof& p, uint8_t out[324]) {
    const auto A  = p.A.to_uncompressed();
    const auto S  = p.S.to_uncompressed();
    const auto T1 = p.T1.to_uncompressed();
    const auto T2 = p.T2.to_uncompressed();
    const auto tx = p.tau_x.to_bytes();
    const auto th = p.t_hat.to_bytes();
    std::memcpy(out +   0, A.data(),  65);
    std::memcpy(out +  65, S.data(),  65);
    std::memcpy(out + 130, T1.data(), 65);
    std::memcpy(out + 195, T2.data(), 65);
    std::memcpy(out + 260, tx.data(), 32);
    std::memcpy(out + 292, th.data(), 32);
}

/* A fixed, non-zero blinding factor (deterministic test vector). */
static Scalar fixed_blinding() {
    std::array<uint8_t, 32> b = {
        0x9a,0x1f,0x42,0xe7,0x55,0xc3,0x0b,0x88,
        0x2d,0x6e,0xf1,0x04,0x77,0xbb,0x39,0xac,
        0x10,0x5d,0xe2,0x91,0x48,0x36,0xca,0x7f,
        0x63,0x02,0xd9,0x4b,0x8c,0x1a,0xfe,0x57
    };
    return Scalar::from_bytes(b);
}

int test_gpu_zk_prove_verify_differential_run() {
    std::printf("=== GPU Bulletproof poly-check vs CPU prover differential ===\n\n");
    g_pass = g_fail = g_skip = 0;

    /* --- open GPU context (skip cleanly when no GPU) ---------------------- */
    ufsecp_gpu_ctx* gpu = nullptr;
    {
        uint32_t ids[8] = {};
        uint32_t cnt = ufsecp_gpu_backend_count(ids, 8);
        if (cnt == 0) {
            SKIP("GZK-PV", "no GPU backend available");
            std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                        g_pass, g_fail, g_skip);
            return ADVISORY_SKIP_CODE;
        }
        if (ufsecp_gpu_ctx_create(&gpu, ids[0], 0) != UFSECP_OK || !gpu) {
            SKIP("GZK-PV", "GPU context creation failed");
            std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                        g_pass, g_fail, g_skip);
            return ADVISORY_SKIP_CODE;
        }
    }

    /* Fixed nothing-up-my-sleeve H generator (same one the CPU prover uses). */
    const auto H = pedersen_generator_H().to_uncompressed();
    const Scalar blinding = fixed_blinding();
    const std::array<uint8_t, 32> aux_rand = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
    };

    /* Range of committed values spanning bit 0 .. bit 63. */
    const uint64_t VALUES[] = {
        0ull, 1ull, 42ull, 1000000ull,
        (1ull << 32), (1ull << 63), ~0ull /* 2^64 - 1 */
    };
    constexpr int NV = static_cast<int>(sizeof(VALUES) / sizeof(VALUES[0]));

    /* Build all valid proofs once; reuse for single, batch, and tamper tests. */
    std::vector<std::array<uint8_t, 324>> proofs(NV);
    std::vector<std::array<uint8_t, 65>>  commits(NV);
    bool any_cpu_fail = false;

    for (int i = 0; i < NV; ++i) {
        const Scalar v = Scalar::from_uint64(VALUES[i]);
        const PedersenCommitment C = pedersen_commit(v, blinding);
        const RangeProof proof = range_prove(VALUES[i], blinding, C, aux_rand);

        /* CPU oracle: the proof must be genuinely valid (poly + inner-product). */
        char id[24]; std::snprintf(id, sizeof(id), "GZK-CPU-%d", i);
        bool cpu_ok = range_verify(C, proof);
        CHECK(cpu_ok, id, "CPU range_verify accepts freshly-generated proof");
        if (!cpu_ok) any_cpu_fail = true;

        serialize_poly324(proof, proofs[i].data());
        commits[i] = C.point.to_uncompressed();
    }

    /* --- single-proof: GPU poly-check must ACCEPT each valid proof -------- */
    bool gpu_unsupported = false;
    for (int i = 0; i < NV; ++i) {
        uint8_t res = 0xff;
        ufsecp_error_t rc = ufsecp_gpu_bulletproof_verify_batch(
            gpu, proofs[i].data(), commits[i].data(), H.data(), 1, &res);
        char id[24]; std::snprintf(id, sizeof(id), "GZK-GPU-%d", i);
        if (gpu_runtime_unusable(rc)) {
            SKIP(id, "GPU ZK kernel unavailable (module not built / metallib not loaded)");
            gpu_unsupported = true;
            continue;
        }
        CHECK(rc == UFSECP_OK, id, "GPU bulletproof_verify_batch returns OK");
        CHECK(res == 1, id, "GPU poly-check ACCEPTS valid CPU-generated proof");
    }

    if (gpu_unsupported) {
        ufsecp_gpu_ctx_destroy(gpu);
        std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                    g_pass, g_fail, g_skip);
        /* GPU present but ZK module absent → advisory skip (77), unless the CPU
         * oracle itself failed (a real prover regression must still surface). */
        return (g_fail > 0) ? 1 : ADVISORY_SKIP_CODE;
    }

    /* --- batch: all-valid proofs in one call must all verify ------------- */
    {
        std::vector<uint8_t> proof_buf(static_cast<size_t>(NV) * 324);
        std::vector<uint8_t> commit_buf(static_cast<size_t>(NV) * 65);
        for (int i = 0; i < NV; ++i) {
            std::memcpy(proof_buf.data()  + static_cast<size_t>(i) * 324, proofs[i].data(),  324);
            std::memcpy(commit_buf.data() + static_cast<size_t>(i) * 65,  commits[i].data(), 65);
        }
        std::vector<uint8_t> res(NV, 0xff);
        ufsecp_error_t rc = ufsecp_gpu_bulletproof_verify_batch(
            gpu, proof_buf.data(), commit_buf.data(), H.data(),
            static_cast<size_t>(NV), res.data());
        CHECK(rc == UFSECP_OK, "GZK-BATCH", "batch verify returns OK");
        bool all_one = true;
        for (int i = 0; i < NV; ++i) if (res[i] != 1) { all_one = false; break; }
        CHECK(all_one, "GZK-BATCH", "all valid proofs verify == 1 in batch");
    }

    /* --- tamper: one-byte flip of a poly-part SCALAR must be REJECTED ----
     * Use scalar fields (tau_x @ 260, t_hat @ 292): flipping a coordinate of a
     * point could land off-curve and be rejected by the host prefix/curve
     * pre-check (BAD_PUBKEY) rather than by the poly identity, which would not
     * exercise the device math. Scalars are always valid field elements, so a
     * flip is guaranteed to break ONLY the polynomial equation → verdict 0. */
    {
        std::array<uint8_t, 324> bad = proofs[2]; /* value = 42 */
        bad[292] ^= 0x01; /* flip lowest byte of t_hat */
        uint8_t res = 0xff;
        ufsecp_error_t rc = ufsecp_gpu_bulletproof_verify_batch(
            gpu, bad.data(), commits[2].data(), H.data(), 1, &res);
        CHECK(rc == UFSECP_OK, "GZK-TAMP-THAT", "tampered-t_hat call returns OK");
        CHECK(res == 0, "GZK-TAMP-THAT", "GPU REJECTS tampered t_hat (verdict 0)");
    }
    {
        std::array<uint8_t, 324> bad = proofs[2];
        bad[260] ^= 0x01; /* flip lowest byte of tau_x */
        uint8_t res = 0xff;
        ufsecp_error_t rc = ufsecp_gpu_bulletproof_verify_batch(
            gpu, bad.data(), commits[2].data(), H.data(), 1, &res);
        CHECK(rc == UFSECP_OK, "GZK-TAMP-TAUX", "tampered-tau_x call returns OK");
        CHECK(res == 0, "GZK-TAMP-TAUX", "GPU REJECTS tampered tau_x (verdict 0)");
    }

    /* --- wrong commitment: valid proof against a DIFFERENT commitment ---- */
    {
        uint8_t res = 0xff;
        ufsecp_error_t rc = ufsecp_gpu_bulletproof_verify_batch(
            gpu, proofs[2].data(), commits[3].data() /* mismatched V */,
            H.data(), 1, &res);
        CHECK(rc == UFSECP_OK, "GZK-WRONGV", "mismatched-commitment call returns OK");
        CHECK(res == 0, "GZK-WRONGV", "GPU REJECTS proof under wrong commitment");
    }

    /* --- mixed batch: valid + tampered, per-slot independence ------------- */
    {
        const int M = 3;
        std::vector<uint8_t> proof_buf(static_cast<size_t>(M) * 324);
        std::vector<uint8_t> commit_buf(static_cast<size_t>(M) * 65);
        /* slot0 valid(1), slot1 tampered, slot2 valid(4) */
        std::memcpy(proof_buf.data() + 0 * 324, proofs[1].data(), 324);
        std::memcpy(proof_buf.data() + 1 * 324, proofs[3].data(), 324);
        std::memcpy(proof_buf.data() + 2 * 324, proofs[4].data(), 324);
        proof_buf[1 * 324 + 292] ^= 0x01; /* tamper slot1 t_hat */
        std::memcpy(commit_buf.data() + 0 * 65, commits[1].data(), 65);
        std::memcpy(commit_buf.data() + 1 * 65, commits[3].data(), 65);
        std::memcpy(commit_buf.data() + 2 * 65, commits[4].data(), 65);
        std::vector<uint8_t> res(M, 0xff);
        ufsecp_error_t rc = ufsecp_gpu_bulletproof_verify_batch(
            gpu, proof_buf.data(), commit_buf.data(), H.data(),
            static_cast<size_t>(M), res.data());
        CHECK(rc == UFSECP_OK, "GZK-MIX", "mixed batch returns OK");
        CHECK(res[0] == 1 && res[1] == 0 && res[2] == 1,
              "GZK-MIX", "per-slot verdicts: valid=1, tampered=0, valid=1");
    }

    (void)any_cpu_fail;
    ufsecp_gpu_ctx_destroy(gpu);

    std::printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
                g_pass, g_fail, g_skip);
    return (g_fail > 0) ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main() { return test_gpu_zk_prove_verify_differential_run(); }
#endif /* STANDALONE_TEST */
