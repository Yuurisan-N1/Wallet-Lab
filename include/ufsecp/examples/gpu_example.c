/* ============================================================================
 * UltrafastSecp256k1 -- GPU API Example (C)
 * ============================================================================
 * Demonstrates:
 *   1. Backend discovery and device info
 *   2. Context creation
 *   3. Batch generator multiplication (k*G)
 *   4. Graceful UNSUPPORTED handling
 *   5. Cleanup
 *
 * Compile (assuming library is installed or build directory available):
 *   cc -o gpu_example gpu_example.c -lufsecp -lsecp256k1_gpu_host
 *
 * Or from build directory:
 *   cc -I../../include -o gpu_example gpu_example.c \
 *      -L../../build/lib -lufsecp -lsecp256k1_gpu_host
 * ============================================================================ */

#include <stdio.h>
#include <string.h>
#include "ufsecp/ufsecp_gpu.h"

int main(void) {
    /* ---- 1. Discover backends ---------------------------------------- */
    uint32_t ids[4];
    uint32_t n = ufsecp_gpu_backend_count(ids, 4);
    printf("Compiled GPU backends: %u\n", n);

    if (n == 0) {
        printf("No GPU backends compiled in. Rebuild with CUDA/OpenCL/Metal.\n");
        return 0;
    }

    /* Pick the first available backend */
    uint32_t backend = UFSECP_GPU_BACKEND_NONE;
    for (uint32_t i = 0; i < n; i++) {
        printf("  [%u] %s  available=%d  devices=%u\n",
               ids[i], ufsecp_gpu_backend_name(ids[i]),
               ufsecp_gpu_is_available(ids[i]),
               ufsecp_gpu_device_count(ids[i]));
        if (backend == UFSECP_GPU_BACKEND_NONE && ufsecp_gpu_is_available(ids[i]))
            backend = ids[i];
    }

    if (backend == UFSECP_GPU_BACKEND_NONE) {
        printf("No available GPU device found.\n");
        return 0;
    }

    /* ---- 2. Device info ---------------------------------------------- */
    ufsecp_gpu_device_info_t info;
    if (ufsecp_gpu_device_info(backend, 0, &info) == UFSECP_OK) {
        printf("\nUsing: %s (%s) -- %lu MB, %u CUs\n",
               info.name, ufsecp_gpu_backend_name(backend),
               (unsigned long)(info.global_mem_bytes / (1024*1024)),
               info.compute_units);
    }

    /* ---- 3. Create context ------------------------------------------- */
    ufsecp_gpu_ctx* ctx = NULL;
    ufsecp_error_t err = ufsecp_gpu_ctx_create(&ctx, backend, 0);
    if (err != UFSECP_OK) {
        printf("Context creation failed: %s\n", ufsecp_gpu_error_str(err));
        return 1;
    }

    /* ---- 4. Batch generator_mul: compute 4 public keys --------------- */
    /* deterministic test scalars (NOT cryptographically random!) */
    uint8_t scalars[4][32];
    memset(scalars, 0, sizeof(scalars));
    scalars[0][31] = 1;  /* scalar = 1 → generator point G */
    scalars[1][31] = 2;  /* scalar = 2 → 2G */
    scalars[2][31] = 3;
    scalars[3][31] = 4;

    uint8_t pubkeys[4][33];
    err = ufsecp_gpu_generator_mul_batch(ctx, (const uint8_t*)scalars, 4,
                                         (uint8_t*)pubkeys);
    if (err == UFSECP_OK) {
        printf("\nGenerator mul results (k*G):\n");
        for (int i = 0; i < 4; i++) {
            printf("  k=%d: %02x", i + 1, pubkeys[i][0]);
            for (int j = 1; j < 5; j++) printf("%02x", pubkeys[i][j]);
            printf("...\n");
        }
    } else if (err == UFSECP_ERR_GPU_UNSUPPORTED) {
        printf("generator_mul_batch not supported on this backend.\n");
    } else {
        printf("generator_mul_batch error: %s\n", ufsecp_gpu_error_str(err));
    }

    /* ---- 5. Try an op that might be unsupported ---------------------- */
    uint8_t dummy_hash[32] = {0};
    uint8_t result;
    err = ufsecp_gpu_ecdsa_verify_batch(ctx, dummy_hash, pubkeys[0],
                                         dummy_hash, 1, &result);
    if (err == UFSECP_ERR_GPU_UNSUPPORTED) {
        printf("\necdsa_verify_batch: UNSUPPORTED on %s (expected).\n",
               ufsecp_gpu_backend_name(backend));
    } else {
        printf("\necdsa_verify_batch returned: %s\n",
               ufsecp_gpu_error_str(err));
    }

    /* ---- 6. Cleanup -------------------------------------------------- */
    ufsecp_gpu_ctx_destroy(ctx);
    printf("\nDone.\n");
    return 0;
}
