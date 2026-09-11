# Shim & Backend Footprint Comparison

**Generated:** 2026-05-22
**Host:** Intel i5-14400F, GCC 14.2.0, x86-64 Linux
**Build mode:** Release, **no-LTO** (worst-case for the size delta — LTO co-optimises and
shrinks the inlined hot-path further on both sides)
**Methodology:** `size -t libfoo.a` (sum of `.text` / `.data` / `.bss` across all archive
members). Static archive byte-size is misleading because Ultra archives are built without
debug info while the Bitcoin Core libsecp256k1 build embeds `-g`; `size -t` is the
apples-to-apples machine-code measurement.

## 1. Headline numbers (no-LTO)

| Build | `.text` (KB) | `.data` (B) | `.bss` (KB) | Multiplier vs libsecp256k1 |
|-------|-------------:|------------:|------------:|---------------------------:|
| **libsecp256k1** (Bitcoin Core bundled) | **1,261** | 280 | 0 | 1.00× (baseline) |
| **Ultra `bitcoin-core` profile** (shim inlined) | **2,310** | 2,720 | 683 | **1.83×** |
| **Ultra full-feature profile** (FROST+ZK+BIP-352+Adaptor+Wallet+Pippenger ON) | **2,669** | 19,216 | 703 | 2.12× |

**`.bss`** difference: dominated by precomputed generator tables. Ultra uses a w=18 fixed-base
table (~672 KB) while libsecp256k1 uses w=15 (~80 KB). This is a deliberate signing-throughput
tradeoff documented in `docs/PRECOMP_GENERATOR_TABLE.md`. `.bss` does not contribute to
i-cache pressure — it is data, not code.

**`.text` difference:** the figure the i-cache discussion in
`docs/BITCOIN_CORE_BACKEND_EVIDENCE.md §2.1` refers to. Bitcoin-core deployment profile is
**+1,049 KB** of code over libsecp256k1. Stripping the Bitcoin-Core-irrelevant modules
(FROST, ZK, ECIES, BIP-352, Adaptor, Wallet, Pippenger batch) saves **359 KB** of `.text`
relative to the full feature build (2,669 − 2,310). Profile selection is real footprint
control — not just a configuration flag.

## 2. Shim wrapper layer (standalone, Mode A)

The shim is the libsecp256k1 ABI translation layer (`compat/libsecp256k1_shim/`). It is
**~188 KB** of object code total across the 12 translation units, measured by compiling
each `.cpp` with `g++ -O3 -DNDEBUG -std=c++20` and summing the resulting `.o` sizes.

| Translation unit | `.o` size (B) |
|------------------|--------------:|
| `shim_pubkey.cpp` | 39,560 |
| `shim_musig.cpp` | 37,704 |
| `shim_ecdsa.cpp` | 17,288 |
| `shim_schnorr.cpp` | 16,736 |
| `shim_ellswift.cpp` | 14,616 |
| `shim_context.cpp` | 14,376 |
| `shim_batch_verify.cpp` | 13,800 |
| `shim_extrakeys.cpp` | 13,664 |
| `shim_recovery.cpp` | 8,472 |
| `shim_tagged_hash.cpp` | 6,232 |
| `shim_ecdh.cpp` | 5,912 |
| `shim_seckey.cpp` | 4,312 |
| **Total** | **192,672 (≈ 188 KB)** |

In the `bitcoin-core` deployment profile (`SECP256K1_BUILD_SHIM=ON`), the shim
sources are compiled directly into `libfastsecp256k1.a` so that the LTO cross-TU
inliner sees them as part of the engine — there is no separate shim archive in
this mode. The 188 KB shim translation overhead is included in the 2,310 KB
bitcoin-core `.text` figure above; it is not additional.

## 3. What this changes about the no-LTO discussion

The README and `docs/BITCOIN_CORE_BACKEND_EVIDENCE.md §2.1` previously referenced
`~1.3 MB Ultra vs ~400 KB libsecp256k1`. That figure was an approximation that pre-dated
the bitcoin-core deployment profile (which strips Pippenger / BIP-352 / FROST / ZK /
ECIES / Adaptor / Wallet — modules Bitcoin Core does not call) and used a stripped-binary
comparison that excluded the shim layer on both sides.

The measured numbers above replace the earlier approximation:

* Bitcoin Core-relevant Ultra footprint = **2,310 KB** `.text` (not 1,300 KB).
* libsecp256k1 baseline = **1,261 KB** `.text` (not 400 KB).
* Multiplier = **1.83×**, not 3.25×.

The residual no-LTO ConnectBlock deficit of **~0.5–1.0%** is consistent with a 1.83×
hot-path size delta when the cross-TU inliner is disabled — the inlining boundary forces
the engine and shim TUs to spill registers across function calls that LTO would otherwise
fuse. With `-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON` (Bitcoin Core's default release
build) the deficit flips to **+0.9–1.5%** because the inliner co-optimises both sides.

## 4. Reproducing this measurement

```bash
# Build libsecp256k1 baseline (no-LTO)
cmake -S bitcoin-core-dev/src/secp256k1 -B /tmp/libsecp -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/libsecp -j$(nproc)

# Build Ultra bitcoin-core deployment profile (no-LTO, shim inlined)
cmake --preset bitcoin-core -B /tmp/ultra
cmake --build /tmp/ultra --target fastsecp256k1 -j$(nproc)

# Build Ultra full-feature profile for comparison
cmake -S libs/UltrafastSecp256k1 -B /tmp/ultra-full \
    -DCMAKE_BUILD_TYPE=Release -DSECP256K1_BUILD_SHIM=ON
cmake --build /tmp/ultra-full --target fastsecp256k1 -j$(nproc)

# Measure
size -t /tmp/libsecp/src/libsecp256k1.a \
       /tmp/ultra/src/cpu/libfastsecp256k1.a \
       /tmp/ultra-full/src/cpu/libfastsecp256k1.a
```

The `bitcoin-core` deployment profile is the only Ultra configuration relevant to a
Bitcoin Core integration PR. The full-feature row exists to quantify how much footprint
the optional modules contribute — useful for downstream wallets / forks that need
different module sets (see `ci/profiles.json` for the wallet / Litecoin / Dogecoin
/ BCH preset module matrices).
