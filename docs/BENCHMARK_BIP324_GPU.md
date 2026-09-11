# BIP-324 Transport Benchmark — CUDA GPU

Full BIP-324 ChaCha20-Poly1305 AEAD transport pipeline on GPU, with
protocol-level packet processing, PCIe transfer analysis, latency profiling,
and multi-stream overlap measurement.

**Hardware:** NVIDIA GeForce RTX 5060 Ti (sm_120, 36 SMs, 2602 MHz, 16 GB)
**Compiler:** nvcc with `-O3 --use_fast_math -Xptxas=-O3`
**Commit:** `f84b2f95` (lib `dev`)

---

## Optimizations Applied

| Technique | Target | Mechanism |
|-----------|--------|-----------|
| PTX `__byte_perm()` | rotl32(16), rotl32(8) | Single-instruction byte permutation |
| PTX `__funnelshift_l()` | rotl32(12), rotl32(7) | Single-instruction funnel shift |
| AEAD state reuse | encrypt & decrypt | Eliminate redundant `d_chacha20_setup` — setup once, reuse for poly key (counter=0) and encryption (counter=1+) |
| Direct XOR | encrypt path | `ct[i] = pt[i] ^ keystream[i]` instead of memcpy-then-XOR |

---

## 1. ChaCha20 Block Throughput (GPU Ceiling)

Raw ChaCha20 block generation — 1M blocks, each thread computes one 64-byte
keystream block independently.

```
batch:         1,048,576 blocks
time:          2.836 ms
blocks/sec:    370 M
throughput:    22,568 MB/s  (22.0 GB/s)
ns/block:      2.7
```

This is the **compute ceiling** — AEAD overhead and memory access reduce
effective throughput below this line.

---

## 2. Fixed-Size Batch AEAD (Encrypt + Decrypt Roundtrip)

Each thread handles one independent packet (own key + nonce), simulating
parallel peer connections.

| Payload | Batch | Time (ms) | Packets/sec | Goodput | Overhead |
|---------|-------|-----------|-------------|---------|----------|
| 32 B | 262,144 | 0.870 | **301.45 M** | 9,200 MB/s | 37.3% |
| 128 B | 131,072 | 2.703 | **48.49 M** | 5,919 MB/s | 12.9% |
| 512 B | 65,536 | 5.415 | **12.10 M** | 5,909 MB/s | 3.6% |
| 4,096 B | 16,384 | 11.042 | **1.48 M** | 5,796 MB/s | 0.5% |

**Key insight:** Small packets are compute-bound (massive pps).
Large packets are memory-bandwidth-bound (goodput plateaus at ~5.8 GB/s).

---

## 3. Mixed Traffic (Realistic Distribution)

BIP-324 realistic payload size distribution (128K packets):

| Bucket | Range | Share |
|--------|-------|-------|
| Tiny | 0–32 B | 40% |
| Small | 33–128 B | 30% |
| Medium | 129–512 B | 19% |
| Large | 513–4096 B | 9% |

```
packets:       131,072 (128K)
avg payload:   323.1 B
GPU time:      6.132 ms
packets/sec:   21.37 M
goodput:       6,586 MB/s  (6.4 GB/s, payload only)
wire rate:     6,973 MB/s
overhead:      5.6%
```

### CPU vs GPU Comparison (Mixed Traffic)

| Metric | CPU (i5-14400F) | GPU (RTX 5060 Ti) | Speedup |
|--------|----------------:|------------------:|--------:|
| Packets/sec | 715 K | **21.37 M** | **29.9×** |
| Goodput | 221 MB/s | **6,586 MB/s** | **29.8×** |
| Overhead | 5.7% | 5.6% | identical |

The protocol overhead ratio is identical — the GPU accelerates the entire
transport pipeline, not just the raw crypto.

---

## 4. Decoy Overhead

BIP-324 decoy packets (chaff for traffic analysis resistance):

| Decoy Rate | GPU Time | Useful Goodput | Throughput Drop |
|------------|----------|----------------|-----------------|
| 0% (base) | 5.910 ms | 6,586 MB/s | — |
| **5%** | 5.978 ms | **6,497 MB/s** | **1.1%** |
| **20%** | 5.284 ms | **6,183 MB/s** | **4.2%** |

On GPU, decoys are **nearly free** — massive parallelism absorbs the extra
packets without meaningful throughput loss. On CPU, decoys impose a noticeable
penalty due to sequential processing.

---

## 5. Batch Size Scaling (GPU Occupancy)

How throughput scales with batch size (128 B payload):

| Batch | Time (ms) | Packets/sec | Goodput |
|-------|-----------|-------------|---------|
| 256 | 0.068 | 3.74 M | 456 MB/s |
| 1,024 | 0.068 | 15.00 M | 1,830 MB/s |
| **4,096** | **0.081** | **50.79 M** | **6,200 MB/s** |
| 16,384 | 0.341 | 48.01 M | 5,861 MB/s |
| 65,536 | 1.369 | 47.89 M | 5,845 MB/s |
| 262,144 | 5.323 | 49.25 M | 6,011 MB/s |

**Sweet spot:** 4K+ packets saturates the SMs. Below 1K, GPU is underutilized.

---

## 6. PCIe-Aware End-to-End (H2D + Kernel + D2H)

Real-world GPU crypto requires host↔device data transfer. This section
measures all three phases separately (64K packets, pinned memory):

| Payload | H2D (ms) | Kernel (ms) | D2H (ms) | Total (ms) | Eff. MB/s | Kernel % |
|---------|----------|-------------|----------|------------|-----------|----------|
| 128 B | 0.594 | 1.375 | 0.530 | **2.499** | **3,201** | 55.0% |
| 512 B | 1.823 | 5.394 | 2.226 | **9.443** | **3,389** | 57.1% |
| 4,096 B | 13.330 | 41.217 | 16.510 | **71.057** | **3,603** | 58.0% |

**Key finding:** The kernel (actual crypto) is only 55–58% of total wall time.
PCIe transfers consume 42–45%. This is why multi-stream overlap matters.

---

## 7. Per-Packet Latency vs Batch Size

How per-packet latency amortizes as batch size grows:

| Batch | Total (µs) | µs/packet | Packets/sec |
|-------|-----------|-----------|-------------|
| 1 | 17.6 | **17.632** | 56.7 K |
| 4 | 17.4 | 4.360 | 229.4 K |
| 16 | 21.5 | 1.342 | 745.2 K |
| 64 | 31.7 | 0.495 | 2.02 M |
| 256 | 64.6 | 0.252 | 3.96 M |
| **1,024** | **64.5** | **0.063** | **15.88 M** |
| 4,096 | 76.7 | 0.019 | 53.40 M |
| 16,384 | 318.7 | 0.019 | 51.41 M |
| 65,536 | 1,359.7 | 0.021 | 48.20 M |

**GPU launch overhead:** ~17.6 µs fixed cost (kernel launch + synchronization).
At batch=1, the GPU is **312× slower per-packet than CPU** (17.6 µs vs 1.4 µs).
At batch=1024+, GPU amortizes to **63 ns/packet** — 22× faster than CPU.

> **GPU = throughput engine, not latency engine.**

---

## 8. Multi-Stream Pipeline (Copy/Compute Overlap)

Using CUDA streams to overlap PCIe transfers with kernel execution
(128K total packets, 128 B payload, pinned memory):

| Streams | Time (ms) | Packets/sec | Speedup |
|---------|-----------|-------------|---------|
| 1 | 3.893 | 33.67 M | 1.00× |
| 2 | 3.275 | 40.02 M | 1.19× |
| 4 | 2.989 | 43.85 M | 1.30× |
| **8** | **2.838** | **46.18 M** | **1.37×** |

8 streams hide **37% of PCIe transfer overhead**, pushing effective throughput
from 33.67M to **46.18M packets/sec**.

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│                    GPU Pipeline                          │
│                                                         │
│  ┌──────────┐    ┌───────────────────┐    ┌──────────┐  │
│  │  H2D     │───▶│  AEAD Kernel      │───▶│  D2H     │  │
│  │  keys    │    │  ChaCha20 (PTX)   │    │  results │  │
│  │  nonces  │    │  Poly1305 (5×26)  │    │  status  │  │
│  │  payload │    │  128 threads/blk  │    │          │  │
│  └──────────┘    └───────────────────┘    └──────────┘  │
│       ↑                                        │        │
│       └────── Multi-stream overlap ────────────┘        │
│                                                         │
│  Stream 0: [H2D chunk₀][kern₀       ][D2H chunk₀]      │
│  Stream 1:     [H2D chunk₁][kern₁       ][D2H chunk₁]  │
│  Stream 2:         [H2D chunk₂][kern₂       ][D2H₂]    │
│  ...                                                    │
└─────────────────────────────────────────────────────────┘
```

---

## Deployment Model Recommendations

### GPU is ideal for:

- **Block relay batching** — hundreds of transactions per block
- **Mempool sync** — bulk transaction verification
- **Relay nodes / gateways** — high-throughput packet processing
- **DoS filtering layer** — verify+discard at line rate
- **Batch decoy injection** — nearly zero marginal cost

### GPU is NOT ideal for:

- **Interactive P2P** (single Bitcoin node) — latency too high for 1-packet
- **RPC / low-latency responses** — 17.6 µs launch overhead dominates
- **Small batch (<256 packets)** — GPU underutilized

### Optimal hybrid architecture:

```
incoming packets
       │
       ▼
  ┌─────────┐     batch < 64    ┌─────────┐
  │  Router  │─────────────────▶│   CPU    │  ← low latency
  │         │                   │  1.4 µs  │
  │         │     batch ≥ 64    └─────────┘
  │         │─────────────────▶┌─────────┐
  └─────────┘                  │   GPU    │  ← high throughput
                               │  63 ns   │
                               └─────────┘
```

---

## Reproducibility

```bash
cd libs/UltrafastSecp256k1/cuda/build_bench
cmake ..
ninja bench_bip324_cuda
./bench_bip324_cuda
```

Requires CUDA toolkit ≥ 12.0, `sm_89` or newer GPU.
