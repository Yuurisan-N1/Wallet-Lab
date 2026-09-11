# CUDA Zero-Knowledge Benchmark -- NVIDIA RTX 5060 Ti

**Date:** 2026-03-13  
**OS:** Linux x86_64 (Ubuntu)  
**Driver:** NVIDIA 580.126.09  
**CUDA:** 12.0, sm_89  
**Build:** GCC 14.2.0, Release, -O3 --use_fast_math  
**Commit:** `02ac59d` (dev branch)

## GPU Info

| Property | Value |
|----------|-------|
| Device | NVIDIA GeForce RTX 5060 Ti |
| Compute Capability | 12.0 (Blackwell) |
| SM Count | 36 |
| Clock | 2602 MHz |
| Memory | 16 GB GDDR7 |
| Memory Clock | 14001 MHz |
| Memory Bus | 128-bit |

## Bulletproof Range Proof Results

### Verify (batch=256 proofs, BP_BITS=64)

| Implementation | ns/op | Throughput | vs Single | vs CPU |
|----------------|------:|----------:|----------:|-------:|
| Single-thread baseline | 765,690 | 1.3 k/s | 1.0x | 3.5x |
| Warp-cooperative | 145,821 | 6.9 k/s | 5.3x | 18.3x |
| Warp + precomp w=4 | 135,624 | 7.4 k/s | 5.6x | 19.7x |
| Warp + precomp w=8 | 134,392 | 7.4 k/s | 5.7x | 19.9x |
| Positional LUT4 | 121,498 | 8.2 k/s | 6.3x | 22.0x |
| **P1par + LUT4 (final)** | **14,836** | **67.4 k/s** | **51.6x** | **180.0x** |

### Prove (batch=256 proofs, BP_BITS=64)

| Implementation | ns/op | Throughput | vs Single | vs CPU |
|----------------|------:|----------:|----------:|-------:|
| Single-thread baseline | 3,715,219 | 0.3 k/s | 1.0x | 3.7x |
| Warp-cooperative | 3,242,142 | 0.3 k/s | 1.1x | 4.2x |
| Warp + LUT4 | 2,750,526 | 0.4 k/s | 1.4x | 5.0x |

### Other ZK Operations

| Operation | GPU (ns) | CPU (ns) | Speedup |
|-----------|----------|----------|---------|
| Pedersen Commit | 66.5 | 29,718 | **446.6x** |
| Knowledge Prove (G) | 254.2 | 384.3 | 1.5x |
| Knowledge Verify | 746.7 | 894.3 | 1.2x |
| DLEQ Prove | 674.8 | 833.1 | 1.2x |
| DLEQ Verify | 1,919.5 | 2,148.2 | 1.1x |

### Phase Profile (P1par + LUT4 verify, single proof)

| Phase | Description | Cycles | % | ~ns |
|-------|-------------|-------:|--:|----:|
| P1a | Fiat-Shamir + IPA hashes | 194,582 | 2.6% | 74,782 |
| P1b | s_coeff + batch inverse + powers | 935,874 | 12.6% | 359,675 |
| P1c | 19-lane GLV scalar mul | 3,231,631 | 43.5% | 1,241,980 |
| P2 | LUT4 MSM (128 generators) | 2,979,065 | 40.1% | 1,144,914 |
| P3 | Warp reduction + identity check | 81,674 | 1.1% | 31,389 |
| **Total** | | **7,422,828** | **100%** | **2,852,739** |

## Resource Costs

| Resource | Value |
|----------|-------|
| Device memory (LUT4 tables) | 8.25 MB |
| -- BP generator LUT4 (128 gens x 16 entries) | 8 MB |
| -- H-generator LUT4 (1 gen x 16 entries) | 64 KB |
| -- G-generator LUT4 (1 gen x 16 entries) | 64 KB |
| Shared memory per warp | ~11 KB (BPWarpShared) |
| Registers per thread | ~128 (near SM limit) |
| Threads per proof | 32 (1 warp) |
| Active threads in P1c | 19 of 32 |
| Active threads in P2 | 32 of 32 |
| Batch size | 256 proofs per kernel |

## Optimization History

The journey from a naive single-thread GPU implementation to 180x CPU speedup,
documented step by step.

### Step 1: Single-Thread Baseline

**Result:** 765,690 ns/op (3.5x vs CPU)

Direct port of the CPU Bulletproof verifier to a CUDA kernel. One thread does
all the work: Fiat-Shamir hashing, coefficient computation, scalar multiplications,
and the final multi-scalar multiplication (MSM). Barely faster than CPU due to
GPU's lower single-thread clock and memory latency.

### Step 2: Warp-Cooperative Verify

**Result:** 145,821 ns/op (18.3x vs CPU) -- 5.3x improvement

Distributed the 128-generator MSM across all 32 threads of a warp. Each thread
handles 4 generators. Warp shuffle (`__shfl_sync`) used for the final Jacobian
point reduction. First time the GPU's parallelism actually helps -- the MSM was
the dominant cost.

### Step 3: Precomputed Window Tables (w=4, w=8)

**Result:** 134,392 ns/op (19.9x vs CPU) -- 1.09x improvement

Added windowed precomputation tables for the 128 Bulletproof generators. Window
width 4 (16 entries per generator) and 8 (256 entries) tested. Marginal gain
because the precomputation table init cost partially offsets the faster per-proof
table lookups.

### Step 4: Positional LUT4 Tables

**Result:** 121,498 ns/op (22.0x vs CPU) -- 1.20x improvement

Replaced windowed scalar multiplication with a positional LUT4 approach.
For each generator, precompute 16 multiples (0-15) in affine coordinates.
The scalar multiplication becomes a series of doublings and mixed additions
(Jacobian + Affine), with 4-bit windows. No table recomputation per proof --
tables are permanent in device memory. This was the first LUT4 implementation.

### Step 5: Phase1-Parallel + H-Generator LUT4

**Result:** 59,351 ns/op (45.0x vs CPU) -- 2.05x improvement

Major restructure of Phase 1. Previously all Fiat-Shamir and coefficient
computation was done serially by lane 0. Now:
- **P1a**: Lane 0 does Fiat-Shamir transcript; lanes 1-6 compute IPA round hashes in parallel
- **P1b**: After lane 0 finishes the batch inverse, all 32 lanes compute `s_coeff`, `s_inv`, `y_inv_powers`, and `two_powers` in parallel using bit-decomposition tricks
- Added dedicated H-generator LUT4 table (64 KB) for the merged `H * (t_hat + t_ab - delta)` computation

### Step 6: GLV Endomorphism

**Result:** 45,102 ns/op (59.2x vs CPU) -- 1.32x improvement

Applied the GLV (Gallant-Lambert-Vanstone) endomorphism to all scalar
multiplications in P1c. GLV splits a 256-bit scalar multiplication into
two 128-bit half-width multiplications using the secp256k1 endomorphism
`lambda * P = (beta * x, y)`. Combined with wNAF (window width 5) and
Shamir's trick for simultaneous double scalar multiplication: `k*P = k1*P + k2*lambda*P`.
This halves the number of point doublings from ~256 to ~130.

### Step 7: G-Generator LUT4 Precomputation

**Result:** 38,033 ns/op (70.2x vs CPU) -- 1.19x improvement

Added a dedicated LUT4 table for the secp256k1 generator point G (64 KB).
The P1c phase computes `(tau_x - mu) * G` using the precomputed G-table
instead of computing from scratch each time. Small but consistent win.

### Step 8: Full P1b Parallelism

**Result:** 34,983 ns/op (76.3x vs CPU) -- 1.09x improvement

Eliminated the serial batch inverse computation from P1b. Instead of lane 0
computing the batch modular inverse of all 64 `s_coeff` values, restructured
the coefficient computation so each lane independently computes its own subset
using bit-flip patterns and binary decomposition. The `s_inv` values are derived
directly from `s_coeff` using the pre-computed `y_inv_powers`.

### Step 9: Warp-Divergence-Free P1c (MAJOR BREAKTHROUGH)

**Result:** 14,823 ns/op (180.1x vs CPU) -- 2.36x improvement

The single biggest optimization. Before this, P1c had severe warp divergence:
22 different scalar multiplications were distributed across lanes using
if/else chains. Since each lane executed a different code path (different point,
different scalar), the warp serialized all 22 paths.

**Solution:** Restructured P1c so ALL 19 active lanes execute the same
`scalar_mul_glv_wnaf` function in lockstep. Each lane loads its own
(scalar, point) pair via a `switch(lane_id)` statement (uniform across the
warp since each lane takes its own case), then all lanes call the same GLV
function simultaneously. The GPU executes one unified code path with full
SIMT utilization instead of serializing 22 divergent paths.

Key implementation details:
- Lanes 0-12: individual point scalar multiplications (IPA rounds, blinding, etc.)
- Lane 13: merged H computation `(t_hat + t_ab - delta) * H` using H-LUT4
- Lane 14: merged G computation `(tau_x - mu) * G` using G-LUT4
- Lanes 15-18: multi-element merged computations (e.g., `A + x*S`, `T1 + x^2*T2`)
- Lanes 19-31: idle (masked off, zero cost due to uniform control flow)
- Fixed loop bound `LOOP_LEN = WNAF_MAXLEN = 130` -- no early exit, no divergence

This eliminated ~60% of P1c's execution time by removing warp serialization.

### Failed Optimization Attempts

Two additional P2 optimizations were attempted and reverted:

1. **P2 Coefficient Precompute** (0% gain): Pre-computed all 128 generator
   coefficients in P1b's parallel section, eliminating 4 `scalar_mul_mod_n`
   calls per generator in P2. No improvement because P2 is **memory-bound** --
   the scalar multiplications were hiding in LUT4 table load latency.

2. **Interleaved Dual-Generator P2** (catastrophic regression): Attempted to
   process g_i and h_i tables window-by-window in an interleaved fashion to
   overlap memory loads with computation. Required 2 JacobianPoint accumulators
   (+24 registers), causing register spilling to local memory and making the
   kernel orders of magnitude slower.

### Why 14.8 us is the Limit

The remaining time is split between two fundamentally bounded phases:

- **P1c (43.5%)**: 19 independent GLV scalar multiplications, each requiring
  ~130 point doublings. Cannot be reduced without changing the Bulletproof
  protocol itself.

- **P2 (40.1%)**: 128 LUT4 multi-scalar multiplications, memory-bound at
  GPU L2 cache bandwidth. Arithmetic operations hide within memory stall
  cycles -- adding more compute or removing compute has no effect.

- **P1b (12.6%)**: Modular inverse is inherently sequential (~384 field
  multiplications in the addition chain).

## Benchmark Methodology

- 256 proofs per batch, 32 runs per benchmark, 4 warmup passes discarded
- Phase profiling uses `clock64()` per-warp timestamps
- GPU clock: 2602 MHz (used for cycle-to-nanosecond conversion)
- CPU baseline: single-threaded, same host machine (x86-64)
- All correctness checks pass before timing begins
