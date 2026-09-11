// ============================================================================
// bch_grinding.cu — BCH RPA EC Grinding GPU Kernel (CUDA)
// ============================================================================
// Finds a signature nonce such that:
//   SHA256(SHA256(compact_sig))[0:prefix_bits] == paycode_prefix
//
// Algorithm per thread:
//   k = rfc6979_nonce_hedged(sk, msg, nonce_4B)  // unique k per thread
//   sig = ct_ecdsa_sign_with_k(sk, msg, k)
//   h = SHA256(SHA256(sig.compact))
//   if h[0:prefix_bits] == prefix: atomicCAS → store result
//
// CPU: ~75k attempts/s (single core), ~450k (16 cores)
// GPU: expected ~50-200M attempts/s depending on prefix filter & batch size
// ============================================================================

#include "ct/ct_sign.cuh"
#include "ecdsa.cuh"
#include "secp256k1.cuh"
#include <cstdint>
#include <cstring>
#include <cstdio>

namespace secp256k1 { namespace cuda { namespace bch {

// ── Hedged RFC6979 nonce: mixes 4-byte nonce into HMAC-DRBG extra data ──────
// RFC6979 §3.6: extra entropy feeds into the K derivation.
// This gives each GPU thread a unique, valid deterministic nonce.

__device__ void rfc6979_nonce_hedged(
    const Scalar* private_key,
    const uint8_t msg_hash[32],
    uint32_t     extra_nonce,      // 4-byte thread nonce counter
    Scalar*      k_out)
{
    uint8_t x_bytes[32];
    scalar_to_bytes(private_key, x_bytes);

    uint8_t V[32], K[32];
    for (int i = 0; i < 32; i++) { V[i] = 0x01; K[i] = 0x00; }

    // extra = 4-byte nonce (little-endian)
    uint8_t extra[4] = {
        uint8_t(extra_nonce),
        uint8_t(extra_nonce >> 8),
        uint8_t(extra_nonce >> 16),
        uint8_t(extra_nonce >> 24)
    };

    // d: K = HMAC_K(V || 0x00 || x || h1 || extra)
    {
        uint8_t buf[101]; // 32 + 1 + 32 + 32 + 4
        for (int i = 0; i < 32; i++) buf[i] = V[i];
        buf[32] = 0x00;
        for (int i = 0; i < 32; i++) buf[33 + i] = x_bytes[i];
        for (int i = 0; i < 32; i++) buf[65 + i] = msg_hash[i];
        for (int i = 0; i < 4;  i++) buf[97 + i] = extra[i];
        hmac_sha256(K, K, 32, buf, 101);
    }
    // e: V = HMAC_K(V)
    hmac_sha256(K, V, 32, V, 32);

    // f: K = HMAC_K(V || 0x01 || x || h1 || extra)
    {
        uint8_t buf[101];
        for (int i = 0; i < 32; i++) buf[i] = V[i];
        buf[32] = 0x01;
        for (int i = 0; i < 32; i++) buf[33 + i] = x_bytes[i];
        for (int i = 0; i < 32; i++) buf[65 + i] = msg_hash[i];
        for (int i = 0; i < 4;  i++) buf[97 + i] = extra[i];
        hmac_sha256(K, K, 32, buf, 101);
    }
    // g: V = HMAC_K(V)
    hmac_sha256(K, V, 32, V, 32);

    // h1: k = V (first candidate)
    scalar_from_bytes(V, k_out);
}

// ── Double-SHA256 of 64-byte compact sig → 32-byte result ───────────────────
__device__ void double_sha256_64(const uint8_t sig64[64], uint8_t out32[32]) {
    // first pass: SHA256(sig64)
    SHA256Ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, sig64, 64);
    uint8_t inner[32];
    sha256_final(&ctx, inner);

    // second pass: SHA256(inner)
    sha256_init(&ctx);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out32);
}

// ── Prefix match: check first prefix_bits bits ───────────────────────────────
__device__ bool prefix_matches(const uint8_t hash[32],
                               uint8_t prefix_bits,
                               const uint8_t prefix_data[4]) {
    if (prefix_bits == 0) return true;
    uint8_t full = prefix_bits / 8;
    uint8_t rem  = prefix_bits % 8;
    for (uint8_t i = 0; i < full; ++i)
        if (hash[i] != prefix_data[i]) return false;
    if (rem == 0) return true;
    uint8_t mask = 0xff << (8 - rem);
    return (hash[full] & mask) == (prefix_data[full] & mask);
}

// ── Main grinding kernel ──────────────────────────────────────────────────────
// Each thread: attempts one nonce (base_nonce + global_thread_idx)
// Launch: <<<blocks, threads>>> with enough threads to cover max_attempts

__global__ void rpa_grind_kernel(
    const Scalar* __restrict__ sk,          // sender private key (constant)
    const uint8_t* __restrict__ msg32,      // sighash (constant)
    uint8_t                     prefix_bits,
    const uint8_t* __restrict__ prefix_data,// first ceil(prefix_bits/8) bytes
    uint32_t                    base_nonce, // nonce offset for this launch
    int32_t* __restrict__       result_nonce,  // output: -1 or winning nonce
    uint8_t*  __restrict__       result_sig64) // output: 64-byte compact sig
{
    uint32_t nonce = base_nonce + blockIdx.x * blockDim.x + threadIdx.x;

    // Derive unique k via hedged RFC6979
    Scalar k;
    rfc6979_nonce_hedged(sk, msg32, nonce, &k);
    if (scalar_is_zero(&k)) return;

    // CT sign with derived k
    // Build sig manually: r = (k*G).x mod n, s = k^-1 * (z + r*sk)
    JacobianPoint R;
    ct_generator_mul(&k, &R);

    FieldElement rx, ry; uint8_t y_parity;
    secp256k1::cuda::ct::ct_jacobian_to_affine(&R, &rx, &ry, &y_parity);

    uint8_t rx_bytes[32];
    field_to_bytes(&rx, rx_bytes);

    Scalar r, z, k_inv, rd, s;
    scalar_from_bytes(rx_bytes, &r);
    if (scalar_is_zero(&r)) return;

    scalar_from_bytes(msg32, &z);
    scalar_inverse(&k, &k_inv);
    scalar_mul(&r, sk, &rd);

    // s = k^-1 * (z + r*sk)
    uint8_t z_bytes[32], rd_bytes[32], sum_bytes[32];
    scalar_to_bytes(&z,  z_bytes);
    scalar_to_bytes(&rd, rd_bytes);
    // add z + rd mod n
    Scalar sum;
    scalar_add_mod_n(&z, &rd, &sum);
    scalar_to_bytes(&sum, sum_bytes);
    scalar_mul(&k_inv, &sum, &s);

    // Low-S normalization
    secp256k1::cuda::ct::scalar_normalize_low_s(&s, &s);
    if (scalar_is_zero(&s)) return;

    // Compact sig: r[32] || s[32]
    uint8_t sig64[64];
    scalar_to_bytes(&r, sig64);
    scalar_to_bytes(&s, sig64 + 32);

    // Double-SHA256 + prefix check
    uint8_t hash[32];
    double_sha256_64(sig64, hash);

    if (!prefix_matches(hash, prefix_bits, prefix_data)) return;

    // Found a match — atomically claim the result slot
    int32_t expected = -1;
    int32_t prev = atomicCAS(result_nonce, expected, (int32_t)nonce);
    if (prev == -1) {
        // We won the race — store sig
        for (int i = 0; i < 64; ++i) result_sig64[i] = sig64[i];
    }

    // Erase secret material
    secp256k1::cuda::ct::secure_erase(&k, sizeof(k));
    secp256k1::cuda::ct::secure_erase(&k_inv, sizeof(k_inv));
    secp256k1::cuda::ct::secure_erase(&s, sizeof(s));
}

// ── Host-side launcher ────────────────────────────────────────────────────────

struct GrindResult {
    bool     found;
    uint32_t nonce;
    uint8_t  sig64[64];
};

GrindResult rpa_grind_gpu(
    const uint8_t sk32[32],
    const uint8_t msg32[32],
    uint8_t prefix_bits,
    const uint8_t prefix_data[4],
    uint32_t max_attempts = 0,   // 0 = unlimited
    int threads_per_block = 256)
{
    // Allocate device memory
    Scalar* d_sk;
    uint8_t *d_msg, *d_prefix, *d_sig;
    int32_t* d_result_nonce;

    cudaMalloc(&d_sk, sizeof(Scalar));
    cudaMalloc(&d_msg, 32);
    cudaMalloc(&d_prefix, 4);
    cudaMalloc(&d_sig, 64);
    cudaMalloc(&d_result_nonce, sizeof(int32_t));

    // Convert privkey to Scalar
    Scalar h_sk; scalar_from_bytes_host(sk32, &h_sk);
    cudaMemcpy(d_sk, &h_sk, sizeof(Scalar), cudaMemcpyHostToDevice);
    cudaMemcpy(d_msg, msg32, 32, cudaMemcpyHostToDevice);
    cudaMemcpy(d_prefix, prefix_data, 4, cudaMemcpyHostToDevice);

    int32_t neg1 = -1;
    cudaMemcpy(d_result_nonce, &neg1, sizeof(int32_t), cudaMemcpyHostToDevice);

    GrindResult result{};

    // Launch in batches — check for result after each batch
    uint32_t batch_size = 1 << 20; // 1M attempts per launch
    uint32_t base = 0;

    while (max_attempts == 0 || base < max_attempts) {
        uint32_t n = (max_attempts > 0)
            ? std::min(batch_size, max_attempts - base) : batch_size;
        int blocks = (n + threads_per_block - 1) / threads_per_block;

        rpa_grind_kernel<<<blocks, threads_per_block>>>(
            d_sk, d_msg, prefix_bits, d_prefix,
            base, d_result_nonce, d_sig);
        cudaDeviceSynchronize();

        int32_t found_nonce;
        cudaMemcpy(&found_nonce, d_result_nonce, sizeof(int32_t), cudaMemcpyDeviceToHost);
        if (found_nonce >= 0) {
            result.found = true;
            result.nonce = (uint32_t)found_nonce;
            cudaMemcpy(result.sig64, d_sig, 64, cudaMemcpyDeviceToHost);
            break;
        }
        base += n;
    }

    // Secure erase device key
    cudaMemset(d_sk, 0, sizeof(Scalar));
    cudaFree(d_sk); cudaFree(d_msg);
    cudaFree(d_prefix); cudaFree(d_sig);
    cudaFree(d_result_nonce);

    return result;
}

} } } // namespace secp256k1::cuda::bch
