// =============================================================================
// bch_scan.cu — BCH RPA GPU Scanner (CUDA)
// =============================================================================
// BCH RPA scan pipeline per thread:
//   1. S = scan_privkey × input_pubkey  (ECDH, scan key in constant memory)
//   2. c = SHA256(SHA256(ser(S)) || outpoint[36])
//   3. t_0 = SHA256(spend_pubkey[33] || c[32] || 0x00000000)
//   4. P_0 = spend_point + t_0×G  (GLV or LUT)
//   5. prefixes[idx] = P_0.x[0..7]
//
// Hash structure differs from BIP-352/LTC-SP: double-SHA256 + outpoint.
//
// Throughput: not yet measured — benchmark required.
// =============================================================================

#include "secp256k1.cuh"
#include "ecdsa.cuh"
#include "schnorr.cuh"
#include "secp256k1/fast.hpp"
#include "secp256k1/sha256.hpp"

using namespace secp256k1::cuda;

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>
#include <array>
#include <algorithm>

using CpuScalar = secp256k1::fast::Scalar;
using CpuPoint  = secp256k1::fast::Point;

// ── BCH Scan key plan (GLV precomputed) ─────────────────────────────────────
static constexpr int SCAN_WNAF_W      = 5;   // wNAF window width (matches bench_ltcsp)
static constexpr int SCAN_WNAF_MAXLEN = 130;  // GLV half-scalar wNAF length

struct BIP352ScanKeyWnaf {
    int8_t  wnaf1[SCAN_WNAF_MAXLEN];
    int8_t  wnaf2[SCAN_WNAF_MAXLEN];
    uint8_t k1_neg;
    uint8_t flip_phi;
};

// Use same constant name as BIP-352 pipeline so scalar_mul_fixed_scan() works
// BCH reuses the same GLV predecomp structure
__constant__ BIP352ScanKeyWnaf          BIP352_SCANKEY_WNAF;
// Alias: scalar_mul_fixed_scan uses BIP352_SCANKEY_WNAF internally
// We redefine BIP352ScanKeyWnaf to match BIP352ScanKeyWnaf layout (identical)
__constant__ secp256k1::cuda::AffinePoint BCH_SPEND_AFFINE;
__constant__ uint8_t                 BCH_SPEND_PUBKEY33[33];

// ── BCH hash functions ───────────────────────────────────────────────────────

__device__ void sha256_33(const uint8_t in[33], uint8_t out[32]) {
    secp256k1::cuda::sha256(in, 33, out);
}

__device__ void bch_shared_secret(const uint8_t S_comp[33],
                                   const uint8_t outpoint[36],
                                   uint8_t c_out[32]) {
    using namespace secp256k1::cuda;
    uint8_t inner[32];
    secp256k1::cuda::sha256(S_comp, 33, inner);
    // SHA256(inner[32] || outpoint[36]) - 68 bytes
    uint8_t buf[68];
    for(int i=0;i<32;i++) buf[i]=inner[i];
    for(int i=0;i<36;i++) buf[32+i]=outpoint[i];
    secp256k1::cuda::sha256(buf, 68, c_out);
}

// t_k = SHA256(spend_pubkey33[33] || c[32] || ser32(k))
__device__ void bch_payment_key_hash(const uint8_t c[32], uint32_t k,
                                      uint8_t t_out[32]) {
    uint8_t buf[69];
    for(int i=0;i<33;i++) buf[i]=BCH_SPEND_PUBKEY33[i];
    for(int i=0;i<32;i++) buf[33+i]=c[i];
    buf[65]=(uint8_t)(k>>24); buf[66]=(uint8_t)(k>>16);
    buf[67]=(uint8_t)(k>>8);  buf[68]=(uint8_t)k;
    secp256k1::cuda::sha256(buf, 69, t_out);
}

// ── GLV scalar_mul with precomputed scan key ─────────────────────────────────
// Copied from bench_ltcsp.cu (same implementation, BIP352_SCANKEY_WNAF instead of LTCSP)
__device__ inline void scalar_mul_fixed_scan(
    const secp256k1::cuda::JacobianPoint* p,
    secp256k1::cuda::JacobianPoint* r)
{
    using namespace secp256k1::cuda;
    AffinePoint base;
    if (p->z.limbs[0]==1 && p->z.limbs[1]==0 && p->z.limbs[2]==0 && p->z.limbs[3]==0) {
        base.x = p->x; base.y = p->y;
    } else {
        FieldElement z_inv, z_inv2, z_inv3;
        field_inv(&p->z, &z_inv);
        field_sqr(&z_inv, &z_inv2);
        field_mul(&z_inv2, &z_inv, &z_inv3);
        field_mul(&p->x, &z_inv2, &base.x);
        field_mul(&p->y, &z_inv3, &base.y);
    }
    if (BIP352_SCANKEY_WNAF.k1_neg) field_negate(&base.y, &base.y);

    constexpr int TABLE_SIZE = (1 << (SCAN_WNAF_W - 2));
    AffinePoint tbl_P[TABLE_SIZE]; FieldElement globalz;
    build_wnaf_table_zr(&base, tbl_P, TABLE_SIZE, &globalz);
    AffinePoint tbl_phiP[TABLE_SIZE];
    derive_endo_table(tbl_P, tbl_phiP, TABLE_SIZE, BIP352_SCANKEY_WNAF.flip_phi != 0);

    r->infinity = true;
    field_set_zero(&r->x); field_set_one(&r->y); field_set_zero(&r->z);
    #pragma unroll 1
    for (int i = SCAN_WNAF_MAXLEN-1; i >= 0; --i) {
        if (!r->infinity) jacobian_double_unchecked(r, r);
        int8_t d1 = BIP352_SCANKEY_WNAF.wnaf1[i];
        if (d1 != 0) {
            int idx = (((d1>0)?d1:-d1)-1)>>1;
            AffinePoint pt = tbl_P[idx];
            if (d1<0) field_negate(&pt.y, &pt.y);
            if (r->infinity) { r->x=pt.x; r->y=pt.y; field_set_one(&r->z); r->infinity=false; }
            else jacobian_add_mixed_unchecked(r, &pt, r);
        }
        int8_t d2 = BIP352_SCANKEY_WNAF.wnaf2[i];
        if (d2 != 0) {
            int idx = (((d2>0)?d2:-d2)-1)>>1;
            AffinePoint pt = tbl_phiP[idx];
            if (d2<0) field_negate(&pt.y, &pt.y);
            if (r->infinity) { r->x=pt.x; r->y=pt.y; field_set_one(&r->z); r->infinity=false; }
            else jacobian_add_mixed_unchecked(r, &pt, r);
        }
    }
    if (!r->infinity) { FieldElement tmp; field_mul(&r->z, &globalz, &tmp); r->z=tmp; }
}

// Local definition of point_prefix64 (avoids cross-TU inline linkage issues)
__device__ __forceinline__ int64_t bch_point_prefix64(
    const secp256k1::cuda::JacobianPoint* p)
{
    using namespace secp256k1::cuda;
    FieldElement z_copy = p->z, z_inv, z_inv2, x_aff;
    field_inv(&z_copy, &z_inv);
    field_sqr(&z_inv, &z_inv2);
    field_mul(&p->x, &z_inv2, &x_aff);
    uint8_t xb[32];
    field_to_bytes(&x_aff, xb);
    int64_t prefix = 0;
    for (int i = 0; i < 8; i++) prefix = (prefix << 8) | (int64_t)xb[i];
    return prefix;
}

// ── GLV pipeline kernel ──────────────────────────────────────────────────────
__global__ void bch_scan_kernel_glv(
    const secp256k1::cuda::JacobianPoint* __restrict__ tweak_points,
    const uint8_t* __restrict__  outpoints,  // N × 36 bytes
    int64_t* __restrict__        prefixes,
    int                          n)
{
    using namespace secp256k1::cuda;
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    // 1. ECDH
    JacobianPoint shared;
    scalar_mul_fixed_scan(&tweak_points[idx], &shared);

    // 2. Compress shared secret
    uint8_t S_comp[33];
    point_to_compressed(&shared, S_comp);

    // 3. BCH shared secret hash
    uint8_t c[32];
    bch_shared_secret(S_comp, outpoints + (size_t)idx * 36, c);

    // 4. Payment key hash (k=0)
    uint8_t t_k[32];
    bch_payment_key_hash(c, 0, t_k);

    // 5. t_k * G (wNAF)
    Scalar hs;
    scalar_from_bytes(t_k, &hs);
    JacobianPoint out;
    scalar_mul_generator_const(&hs, &out);

    // 6. spend_point + t_k*G
    JacobianPoint cand;
    jacobian_add_mixed_unchecked(&out, &BCH_SPEND_AFFINE, &cand);
    prefixes[idx] = bch_point_prefix64(&cand);
}

// ── LUT pipeline kernel ──────────────────────────────────────────────────────
__global__ void bch_scan_kernel_lut(
    const secp256k1::cuda::JacobianPoint* __restrict__ tweak_points,
    const uint8_t* __restrict__  outpoints,
    const secp256k1::cuda::AffinePoint* __restrict__ gen_lut,
    int64_t* __restrict__        prefixes,
    int                          n)
{
    using namespace secp256k1::cuda;
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    JacobianPoint shared;
    scalar_mul_fixed_scan(&tweak_points[idx], &shared);

    uint8_t S_comp[33];
    point_to_compressed(&shared, S_comp);

    uint8_t c[32];
    bch_shared_secret(S_comp, outpoints + (size_t)idx * 36, c);

    uint8_t t_k[32];
    bch_payment_key_hash(c, 0, t_k);

    Scalar hs;
    scalar_from_bytes(t_k, &hs);
    JacobianPoint out;
    scalar_mul_generator_lut(&hs, gen_lut, &out);   // LUT path

    JacobianPoint cand;
    jacobian_add_mixed_unchecked(&out, &BCH_SPEND_AFFINE, &cand);
    prefixes[idx] = bch_point_prefix64(&cand);
}

// ── PreSer pass 1: ECDH + compress → store S_comp in global mem ─────────────
// Eliminates k×P and field_inv #1 from the hash+LUT kernel (pass 2).
__global__ void bch_preser_kernel(
    const secp256k1::cuda::JacobianPoint* __restrict__ tweak_points,
    uint8_t* __restrict__  s_comp_buf,  // N × 33 bytes
    int                    n)
{
    using namespace secp256k1::cuda;
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    JacobianPoint shared;
    scalar_mul_fixed_scan(&tweak_points[idx], &shared);

    uint8_t* dst = s_comp_buf + (size_t)idx * 33;
    point_to_compressed(&shared, dst);
}

// ── PreSer pass 2: load S_comp, hash pipeline + LUT ─────────────────────────
__global__ void bch_scan_kernel_preser(
    const uint8_t* __restrict__  s_comp_buf,  // N × 33 bytes (from pass 1)
    const uint8_t* __restrict__  outpoints,   // N × 36 bytes
    const secp256k1::cuda::AffinePoint* __restrict__ gen_lut,
    int64_t* __restrict__        prefixes,
    int                          n)
{
    using namespace secp256k1::cuda;
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    // Load precomputed compressed shared secret (no k×P, no field_inv #1)
    uint8_t S_comp[33];
    const uint8_t* src = s_comp_buf + (size_t)idx * 33;
    for (int i = 0; i < 33; i++) S_comp[i] = src[i];

    // BCH shared secret + payment key hashes (5 SHA256 blocks total)
    uint8_t c[32];
    bch_shared_secret(S_comp, outpoints + (size_t)idx * 36, c);

    uint8_t t_k[32];
    bch_payment_key_hash(c, 0, t_k);

    // t_k × G via LUT (no wNAF — fast)
    Scalar hs;
    scalar_from_bytes(t_k, &hs);
    JacobianPoint out;
    scalar_mul_generator_lut(&hs, gen_lut, &out);

    // spend_point + t_k×G → prefix
    JacobianPoint cand;
    jacobian_add_mixed_unchecked(&out, &BCH_SPEND_AFFINE, &cand);
    prefixes[idx] = bch_point_prefix64(&cand);
}

// ── Build scan key wNAF plan on CPU ─────────────────────────────────────────
// Uses fast::KPlan for GLV decompose + compute_wnaf for wNAF digits (w=5)
#include "secp256k1/precompute.hpp"

static void build_bch_scan_wnaf_cpu(const CpuScalar& sk, BIP352ScanKeyWnaf& plan) {
    secp256k1::fast::KPlan kp = secp256k1::fast::KPlan::from_scalar(sk);
    plan.k1_neg   = kp.neg1 ? 1 : 0;
    plan.flip_phi = (kp.neg1 != kp.neg2) ? 1 : 0;

    auto wnaf1 = secp256k1::fast::compute_wnaf(kp.k1, SCAN_WNAF_W);
    auto wnaf2 = secp256k1::fast::compute_wnaf(kp.k2, SCAN_WNAF_W);

    std::memset(plan.wnaf1, 0, sizeof(plan.wnaf1));
    std::memset(plan.wnaf2, 0, sizeof(plan.wnaf2));
    for (std::size_t i = 0; i < std::min(wnaf1.size(), (std::size_t)SCAN_WNAF_MAXLEN); ++i)
        plan.wnaf1[i] = (int8_t)wnaf1[i];
    for (std::size_t i = 0; i < std::min(wnaf2.size(), (std::size_t)SCAN_WNAF_MAXLEN); ++i)
        plan.wnaf2[i] = (int8_t)wnaf2[i];
}

// ── Main benchmark ───────────────────────────────────────────────────────────
static constexpr int BENCH_N    = 500000;
static constexpr int WARMUP     = 5;
static constexpr int PASSES     = 11;
static constexpr int GPU_TPB    = 256;

int main() {
    CpuScalar scan_sk  = CpuScalar::from_uint64(0xdeadbeef12345678ULL);
    CpuScalar spend_sk = CpuScalar::from_uint64(0xcafe0000abcd1234ULL);

    // Build scan key wNAF plan on CPU, upload to GPU constant memory
    BIP352ScanKeyWnaf wnaf_plan{};
    build_bch_scan_wnaf_cpu(scan_sk, wnaf_plan);
    cudaMemcpyToSymbol(BIP352_SCANKEY_WNAF, &wnaf_plan, sizeof(wnaf_plan));

    // Spend point
    CpuPoint spend_pub = CpuPoint::generator().scalar_mul(spend_sk);
    auto spend_comp = spend_pub.to_compressed();
    // Copy x-coord bytes into AffinePoint (benchmark only, y placeholder)
    secp256k1::cuda::AffinePoint spend_aff{};
    for (int b = 0; b < 32; b++) ((uint8_t*)spend_aff.x.limbs)[b] = spend_comp[1 + b];
    // Upload spend affine point and compressed spend pubkey
    cudaMemcpyToSymbol(BCH_SPEND_AFFINE, &spend_aff, sizeof(spend_aff));
    cudaMemcpyToSymbol(BCH_SPEND_PUBKEY33, spend_comp.data(), 33);

    // Build N test tweak points + outpoints
    std::vector<secp256k1::cuda::JacobianPoint> h_tweaks(BENCH_N);
    std::vector<uint8_t> h_outpoints(BENCH_N * 36, 0);
    for (int i = 0; i < BENCH_N; ++i) {
        CpuScalar sk = CpuScalar::from_uint64((uint64_t)i + 1);
        CpuPoint  pt = CpuPoint::generator().scalar_mul(sk);
        auto comp = pt.to_compressed();
        secp256k1::cuda::JacobianPoint jp{};
        for (int b = 0; b < 32; b++) ((uint8_t*)jp.x.limbs)[b] = comp[1+b];
        jp.z.limbs[0] = 1; jp.infinity = 0;
        h_tweaks[i] = jp;
        // Fake outpoint: txid = index bytes, vout = 0
        h_outpoints[i*36 + 0] = (uint8_t)(i & 0xff);
        h_outpoints[i*36 + 1] = (uint8_t)((i>>8) & 0xff);
    }

    secp256k1::cuda::JacobianPoint* d_tweaks = nullptr;
    uint8_t* d_outpoints = nullptr;
    int64_t* d_prefixes  = nullptr;
    cudaMalloc(&d_tweaks,   BENCH_N * sizeof(secp256k1::cuda::JacobianPoint));
    cudaMalloc(&d_outpoints, BENCH_N * 36);
    cudaMalloc(&d_prefixes, BENCH_N * sizeof(int64_t));
    cudaMemcpy(d_tweaks,    h_tweaks.data(),    BENCH_N * sizeof(secp256k1::cuda::JacobianPoint), cudaMemcpyHostToDevice);
    cudaMemcpy(d_outpoints, h_outpoints.data(), BENCH_N * 36, cudaMemcpyHostToDevice);

    int blocks = (BENCH_N + GPU_TPB - 1) / GPU_TPB;

    auto run_bench = [&](bool use_lut, secp256k1::cuda::AffinePoint* d_lut) {
        // Warmup
        for (int i = 0; i < WARMUP; ++i) {
            if (use_lut) bch_scan_kernel_lut<<<blocks,GPU_TPB>>>(d_tweaks, d_outpoints, d_lut, d_prefixes, BENCH_N);
            else         bch_scan_kernel_glv<<<blocks,GPU_TPB>>>(d_tweaks, d_outpoints, d_prefixes, BENCH_N);
        }
        cudaDeviceSynchronize();

        std::vector<double> times;
        for (int p = 0; p < PASSES; ++p) {
            auto t0 = std::chrono::high_resolution_clock::now();
            if (use_lut) bch_scan_kernel_lut<<<blocks,GPU_TPB>>>(d_tweaks, d_outpoints, d_lut, d_prefixes, BENCH_N);
            else         bch_scan_kernel_glv<<<blocks,GPU_TPB>>>(d_tweaks, d_outpoints, d_prefixes, BENCH_N);
            cudaDeviceSynchronize();
            auto t1 = std::chrono::high_resolution_clock::now();
            times.push_back(std::chrono::duration<double,std::milli>(t1-t0).count());
        }
        std::sort(times.begin(), times.end());
        double ms = times[PASSES/2];
        double ns = ms * 1e6 / BENCH_N;
        double M  = BENCH_N / (ms/1000.0) / 1e6;
        printf("  BCH RPA %s: %.1f ns/tx  →  %.2f M tx/s\n",
               use_lut ? "LUT" : "GLV", ns, M);
    };

    int device; cudaGetDevice(&device);
    cudaDeviceProp prop; cudaGetDeviceProperties(&prop, device);
    printf("=== BCH RPA CUDA Scanner Benchmark ===\n");
    printf("  GPU: %s (SM %d.%d)\n", prop.name, prop.major, prop.minor);
    printf("  N: %d, %d passes (IQR-trimmed median)\n\n", BENCH_N, PASSES);

    run_bench(false, nullptr);

    // LUT variant: load precomputed 16×65536 generator table from cache
    {
        const int    LUT_TOTAL = 16 * 65536;
        const size_t LUT_BYTES = (size_t)LUT_TOTAL * sizeof(secp256k1::cuda::AffinePoint);
        secp256k1::cuda::AffinePoint* d_gen_lut = nullptr;
        cudaMalloc(&d_gen_lut, LUT_BYTES);

        const char* cache_path = "secp256k1_gen_lut_v1.bin";
        FILE* cf = fopen(cache_path, "rb");
        if (cf) {
            auto* h_lut = static_cast<secp256k1::cuda::AffinePoint*>(malloc(LUT_BYTES));
            bool ok = h_lut && fread(h_lut, 1, LUT_BYTES, cf) == LUT_BYTES;
            fclose(cf);
            if (ok) {
                cudaMemcpy(d_gen_lut, h_lut, LUT_BYTES, cudaMemcpyHostToDevice);
                printf("  LUT loaded from cache (%.0f MB)\n\n", LUT_BYTES / 1e6);
                run_bench(true, d_gen_lut);
            }
            free(h_lut);
        } else {
            printf("  LUT cache not found (%s) — skipping LUT variant\n", cache_path);
        }
        cudaFree(d_gen_lut);
    }

    cudaFree(d_tweaks);
    cudaFree(d_outpoints);
    cudaFree(d_prefixes);
    return 0;
}