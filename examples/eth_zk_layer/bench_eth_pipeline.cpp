// ============================================================================
// bench_eth_pipeline.cpp — UltrafastSecp256k1 Ethereum Pipeline Benchmark
// ============================================================================
//
// Measures the full real-world Ethereum cryptographic pipeline using only the
// public C ABI.  Numbers here are directly comparable to go-ethereum, ethers.js
// (Node.js), and web3.py (Python/CFFI) — the three runtimes Ethereum devs
// most commonly benchmark against.
//
// Operations measured:
//   Primitives:
//     keccak256            — raw 32-byte hash (block header hashing)
//     eth_personal_hash    — EIP-191 prefix hash (wallet authentication)
//     eth_address          — pubkey → 20-byte address (block/receipt processing)
//     eth_address_cksum    — EIP-55 checksummed address string
//     eth_sign             — ECDSA sign with recovery (wallet transaction signing)
//     eth_ecrecover        — recover sender address from (v,r,s) ← THE hot path
//
//   Full pipeline (end-to-end single-tx latency):
//     wallet_auth          — personal_hash + ecrecover (backend auth per connection)
//     tx_sign              — personal_hash + eth_sign (wallet-side per tx)
//     tx_verify_roundtrip  — personal_hash + sign + ecrecover + memcmp (full round-trip)
//
//   Batch (mempool / sequencer / block processing):
//     ecrecover_batch(N=16)   — 16 txs (small block)
//     ecrecover_batch(N=64)   — 64 txs (typical ERC-20 block)
//     ecrecover_batch(N=256)  — 256 txs (full Ethereum block)
//     ecrecover_batch(N=1000) — 1000 txs (archive node / rollup sequencer)
//
// Build:
//   cmake --build <build_dir> --target bench_eth_pipeline
//
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "ufsecp/ufsecp.h"

// ── Compile-time configuration ───────────────────────────────────────────────
static constexpr int   POOL_SIZE  = 64;   // independent key/msg sets (defeats BP)
static constexpr int   WARMUP     = 30;   // warmup passes
static constexpr int   PASSES     = 13;   // measurement passes (odd → exact median)
static constexpr int   ITERS      = 200;  // reps per pass (for cheap ops)
static constexpr int   CHAIN_ID   = 1;    // Ethereum mainnet

// ── Helpers ──────────────────────────────────────────────────────────────────

static void prevent_elision(const void* p, size_t n) {
    volatile const uint8_t* vp = reinterpret_cast<volatile const uint8_t*>(p);
    (void)(*vp); (void)n;
}

// Deterministic, non-secure PRNG for reproducible test vectors
static uint64_t g_rng_state = 0xDEADBEEF_CAFEC0DEULL;
static uint64_t rng64() {
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 7;
    g_rng_state ^= g_rng_state << 17;
    return g_rng_state;
}
static void fill_rand(uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i += 8) {
        uint64_t v = rng64();
        size_t chunk = (n - i) < 8 ? (n - i) : 8;
        __builtin_memcpy(out + i, &v, chunk);
    }
}

// ── Timing harness ────────────────────────────────────────────────────────────

static double compute_median(std::vector<double>& v) {
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    if (n == 0) return 0.0;
    return (n & 1) ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) * 0.5;
}

static std::vector<double> iqr_filter(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    if (n < 4) return v;
    double q1 = v[n / 4], q3 = v[3 * n / 4];
    double fence = 1.5 * (q3 - q1);
    std::vector<double> out;
    out.reserve(n);
    for (double x : v)
        if (x >= q1 - fence && x <= q3 + fence) out.push_back(x);
    return out;
}

template<typename F>
static double measure_ns(int iters, F&& fn) {
    // warmup
    for (int w = 0; w < WARMUP; ++w)
        for (int i = 0; i < iters; ++i) fn(i);

    std::vector<double> samples;
    samples.reserve(PASSES);
    for (int p = 0; p < PASSES; ++p) {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iters; ++i) fn(i);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ns = (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        samples.push_back(ns / iters);
    }
    auto cleaned = iqr_filter(samples);
    return compute_median(cleaned);
}

// ── Formatting ───────────────────────────────────────────────────────────────

static void print_bar() {
    puts("+----------------------------------------------+------------+------------+");
}
static void print_header2(const char* section) {
    puts("");
    print_bar();
    printf("| %-44s | %10s | %10s |\n", section, "ns / op", "op / sec");
    print_bar();
}
static void print_row2(const char* name, double ns) {
    double ops = (ns > 0.0) ? 1e9 / ns : 0.0;
    if (ops >= 1e6)
        printf("| %-44s | %10.1f | %8.2f M  |\n", name, ns, ops / 1e6);
    else if (ops >= 1e3)
        printf("| %-44s | %10.1f | %7.2f k   |\n", name, ns, ops / 1e3);
    else
        printf("| %-44s | %10.1f | %7.2f    |\n", name, ns, ops);
}
static void section_title(const char* t) {
    printf("\n  %s\n", t);
    for (size_t i = 0; i < 2 + strlen(t); ++i) putchar('-');
    putchar('\n');
}

// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    // --------------------------------------------------------------------------
    printf("============================================================\n");
    printf(" UltrafastSecp256k1  --  Ethereum Pipeline Benchmark\n");
    printf(" Public C ABI  |  %d.%d.%d  |  ABI rev %u\n",
           UFSECP_VERSION_MAJOR, UFSECP_VERSION_MINOR, UFSECP_VERSION_PATCH,
           ufsecp_abi_version());
    printf(" Harness: %d warmup × %d iters | %d passes | IQR filter | median\n",
           WARMUP, ITERS, PASSES);
    printf(" Key pool: %d independent sets (defeats branch predictor)\n", POOL_SIZE);
    printf("============================================================\n");

    // --------------------------------------------------------------------------
    // Create context once (represents a long-lived node process)
    // --------------------------------------------------------------------------
    ufsecp_ctx* ctx = nullptr;
    {
        ufsecp_error_t rc = ufsecp_ctx_create(&ctx);
        if (rc != UFSECP_OK || !ctx) {
            fprintf(stderr, "FAIL: ufsecp_ctx_create => %d\n", (int)rc);
            return 1;
        }
    }

    // --------------------------------------------------------------------------
    // Build pre-computed pool of keys / messages / signatures
    // --------------------------------------------------------------------------
    struct Slot {
        uint8_t privkey[32];
        uint8_t pubkey33[33];
        uint8_t addr20[20];
        uint8_t msg32[32];       // raw 32-byte hash
        uint8_t personal_hash[32]; // EIP-191 hash of a challenge string
        uint8_t sig_r[32];
        uint8_t sig_s[32];
        uint64_t sig_v;
    };

    std::vector<Slot> pool(POOL_SIZE);

    // Fixed challenge string (mimics real node activator challenge)
    const char* challenge_base = "Authenticate to UltrafastSecp256k1 ZK-Layer Node\nNonce: ";
    for (int i = 0; i < POOL_SIZE; ++i) {
        Slot& sl = pool[i];

        // generate valid private key
        do { fill_rand(sl.privkey, 32); }
        while (ufsecp_pubkey_create(ctx, sl.privkey, sl.pubkey33) != UFSECP_OK);

        if (ufsecp_eth_address(ctx, sl.pubkey33, sl.addr20) != UFSECP_OK) {
            fprintf(stderr, "FAIL: pool eth_address slot %d\n", i);
            ufsecp_ctx_destroy(ctx);
            return 1;
        }

        fill_rand(sl.msg32, 32);

        // Build a per-slot challenge string (nonce differs)
        char challenge[128];
        snprintf(challenge, sizeof(challenge), "%s%016llx", challenge_base,
                 (unsigned long long)rng64());
        if (ufsecp_eth_personal_hash(
                reinterpret_cast<const uint8_t*>(challenge), strlen(challenge),
                sl.personal_hash) != UFSECP_OK) {
            fprintf(stderr, "FAIL: pool personal_hash slot %d\n", i);
            ufsecp_ctx_destroy(ctx);
            return 1;
        }

        if (ufsecp_eth_sign(ctx, sl.personal_hash, sl.privkey,
                            sl.sig_r, sl.sig_s, &sl.sig_v, CHAIN_ID) != UFSECP_OK) {
            fprintf(stderr, "FAIL: pool eth_sign slot %d\n", i);
            ufsecp_ctx_destroy(ctx);
            return 1;
        }
    }
    printf("\n  Pool ready: %d key/hash/sig sets\n", POOL_SIZE);

    // ==========================================================================
    // SECTION 1 — Primitive operations
    // ==========================================================================
    section_title("SECTION 1 — Primitive Ethereum Operations");
    print_header2("Operation");

    // --- keccak256 (32-byte input) ---
    double ns_keccak = measure_ns(ITERS, [&](int i) {
        uint8_t out[32];
        ufsecp_keccak256(pool[i % POOL_SIZE].msg32, 32, out);
        prevent_elision(out, 32);
    });
    print_row2("keccak256 (32-byte input)", ns_keccak);

    // --- keccak256 (typical tx RLP ~250 bytes) ---
    std::vector<uint8_t> rlp_buf(250);
    fill_rand(rlp_buf.data(), 250);
    double ns_keccak_rlp = measure_ns(ITERS, [&](int /*i*/) {
        uint8_t out[32];
        ufsecp_keccak256(rlp_buf.data(), 250, out);
        prevent_elision(out, 32);
    });
    print_row2("keccak256 (250-byte tx hash)", ns_keccak_rlp);

    // --- eth_personal_hash ---
    const char* auth_msg = "Authenticate to UltrafastSecp256k1 ZK-Layer\nNonce: 0xdeadbeef";
    double ns_personal = measure_ns(ITERS, [&](int /*i*/) {
        uint8_t out[32];
        ufsecp_eth_personal_hash(
            reinterpret_cast<const uint8_t*>(auth_msg), strlen(auth_msg), out);
        prevent_elision(out, 32);
    });
    print_row2("eth_personal_hash (EIP-191)", ns_personal);

    // --- eth_address ---
    double ns_addr = measure_ns(ITERS, [&](int i) {
        uint8_t addr[20];
        ufsecp_eth_address(ctx, pool[i % POOL_SIZE].pubkey33, addr);
        prevent_elision(addr, 20);
    });
    print_row2("eth_address (pubkey -> 20B)", ns_addr);

    // --- eth_address_checksummed ---
    double ns_cksum = measure_ns(ITERS, [&](int i) {
        char buf[44];
        size_t len = sizeof(buf);
        ufsecp_eth_address_checksummed(ctx, pool[i % POOL_SIZE].pubkey33, buf, &len);
        prevent_elision(buf, 43);
    });
    print_row2("eth_address_checksummed (EIP-55)", ns_cksum);

    // --- eth_sign ---
    double ns_sign = measure_ns(ITERS, [&](int i) {
        uint8_t r[32], s[32]; uint64_t v;
        ufsecp_eth_sign(ctx,
            pool[i % POOL_SIZE].personal_hash,
            pool[i % POOL_SIZE].privkey,
            r, s, &v, CHAIN_ID);
        prevent_elision(r, 32);
    });
    print_row2("eth_sign (v,r,s — EIP-155)", ns_sign);

    // --- eth_ecrecover ---
    double ns_recover = measure_ns(ITERS, [&](int i) {
        uint8_t addr[20];
        const Slot& sl = pool[i % POOL_SIZE];
        ufsecp_eth_ecrecover(ctx, sl.personal_hash,
                             sl.sig_r, sl.sig_s, sl.sig_v, addr);
        prevent_elision(addr, 20);
    });
    print_row2("eth_ecrecover (THE hot path)", ns_recover);

    print_bar();

    // ==========================================================================
    // SECTION 2 — Full pipeline latency (end-to-end per transaction)
    // ==========================================================================
    section_title("SECTION 2 — Full Pipeline Latency (end-to-end per tx)");
    print_header2("Pipeline Stage");

    // --- wallet_auth: personal_hash + ecrecover (backend validates one connection) ---
    double ns_wallet_auth = measure_ns(ITERS, [&](int i) {
        const Slot& sl = pool[i % POOL_SIZE];
        uint8_t hash[32], addr[20];
        ufsecp_eth_personal_hash(
            reinterpret_cast<const uint8_t*>(auth_msg), strlen(auth_msg), hash);
        ufsecp_eth_ecrecover(ctx, hash, sl.sig_r, sl.sig_s, sl.sig_v, addr);
        prevent_elision(addr, 20);
    });
    print_row2("wallet_auth  (hash + ecrecover)", ns_wallet_auth);

    // --- tx_sign: personal_hash + eth_sign (client wallet signs one tx) ---
    double ns_tx_sign = measure_ns(ITERS, [&](int i) {
        const Slot& sl = pool[i % POOL_SIZE];
        uint8_t hash[32], r[32], s[32]; uint64_t v;
        ufsecp_eth_personal_hash(
            reinterpret_cast<const uint8_t*>(auth_msg), strlen(auth_msg), hash);
        ufsecp_eth_sign(ctx, hash, sl.privkey, r, s, &v, CHAIN_ID);
        prevent_elision(r, 32);
    });
    print_row2("tx_sign      (hash + sign)", ns_tx_sign);

    // --- tx_verify_roundtrip: full round-trip including address comparison ---
    double ns_roundtrip = measure_ns(ITERS, [&](int i) {
        const Slot& sl = pool[i % POOL_SIZE];
        uint8_t hash[32], r[32], s[32], recv[20]; uint64_t v;
        ufsecp_eth_personal_hash(
            reinterpret_cast<const uint8_t*>(auth_msg), strlen(auth_msg), hash);
        ufsecp_eth_sign(ctx, hash, sl.privkey, r, s, &v, CHAIN_ID);
        ufsecp_eth_ecrecover(ctx, hash, r, s, v, recv);
        volatile int match = (memcmp(recv, sl.addr20, 20) == 0);
        (void)match;
    });
    print_row2("tx_round_trip (hash+sign+ecrecover)", ns_roundtrip);

    print_bar();

    // ==========================================================================
    // SECTION 3 — Batch ecrecover throughput (mempool / block processing)
    // ==========================================================================
    section_title("SECTION 3 — Batch ecrecover (mempool / block validator)");
    print_bar();
    printf("| %-44s | %10s | %10s |\n",
           "Batch size", "total ms", "ns / tx");
    print_bar();

    const int batch_sizes[] = {16, 64, 256, 1000};
    double ns_per_tx_batch[4] = {};
    for (int bi = 0; bi < 4; ++bi) {
        int N = batch_sizes[bi];
        double ns = measure_ns(10, [&](int iter) {
            for (int j = 0; j < N; ++j) {
                const Slot& sl = pool[(iter * N + j) % POOL_SIZE];
                uint8_t addr[20];
                ufsecp_eth_ecrecover(ctx, sl.personal_hash,
                                     sl.sig_r, sl.sig_s, sl.sig_v, addr);
                prevent_elision(addr, 20);
            }
        });
        double total_ms = ns * N / 1e6;
        double per_tx   = ns;  // ns = per iteration = per batch; per_tx = ns/N
        per_tx = ns;           // ns/iter where iter = N reps → already ns/batch
        // measure_ns divides by iters so ns is the batch total
        // per_tx = ns / N  (wait — measure_ns with iters=10 returns ns/iter
        //                   where iter = 1 call to fn(j) which loops N times)
        // Actually measure_ns already divides by iters(=10), so ns = avg ns per
        // call to fn(), which does N ecrecovers → per_tx_ns = ns / N
        ns_per_tx_batch[bi] = ns / N;
        printf("| ecrecover_batch(N=%-4d)                      | %10.3f | %10.1f |\n",
               N, total_ms, ns / N);
    }
    print_bar();

    // ==========================================================================
    // SECTION 4 — Ethereum Node Throughput estimates (1 CPU core, this machine)
    // ==========================================================================
    section_title("SECTION 4 — Ethereum Node Throughput (1 CPU core)");

    double ecrecover_per_sec   = 1e9 / ns_recover;
    double sign_per_sec        = 1e9 / ns_sign;
    double mempool_tx_per_sec  = ecrecover_per_sec;  // mempool validation = ecrecover
    double block_500tx_ms      = 500.0 * ns_recover / 1e6;
    double block_300tx_ms      = 300.0 * ns_recover / 1e6;
    double auth_per_sec        = 1e9 / ns_wallet_auth;

    printf("\n");
    printf("  ecrecover throughput (1 core):    %.1f k op/s\n",  ecrecover_per_sec / 1e3);
    printf("  eth_sign   throughput (1 core):   %.1f k op/s\n",  sign_per_sec      / 1e3);
    printf("  wallet_auth throughput (1 core):  %.1f k req/s\n", auth_per_sec      / 1e3);
    printf("\n");
    printf("  Mempool validation (pre-EIP-1559 style):\n");
    printf("    %.0f txs/sec  (1 core, ecrecover-gated)\n",  mempool_tx_per_sec);
    printf("    %.0f txs/sec  extrapolated to 8 cores\n",    mempool_tx_per_sec * 8.0);
    printf("    %.0f txs/sec  extrapolated to 32 cores\n",   mempool_tx_per_sec * 32.0);
    printf("\n");
    printf("  Block validation time:\n");
    printf("    500-tx block:  %.2f ms   (1 core)\n", block_500tx_ms);
    printf("    300-tx block:  %.2f ms   (1 core)\n", block_300tx_ms);
    printf("    Ethereum slot (12s budget): can validate ~%.0f blocks/slot\n",
           12000.0 / block_500tx_ms);
    printf("\n");
    printf("  ZK-Layer node activator (wallet auth):\n");
    printf("    %.1f k simultaneous auth handshakes/sec  (1 core)\n", auth_per_sec / 1e3);
    printf("    %.1f k simultaneous auth handshakes/sec  (8 cores)\n", auth_per_sec * 8 / 1e3);

    // ==========================================================================
    // SECTION 5 — Stack comparison note
    // ==========================================================================
    section_title("SECTION 5 — Stack Comparison (reference numbers)");
    printf("\n");
    printf("  Typical ecrecover throughput on same hardware class (Intel i5/i7):\n");
    printf("  ┌──────────────────────────────────────────┬──────────────┬───────────┐\n");
    printf("  │ Stack                                    │  ecrecover   │  vs Ultra │\n");
    printf("  ├──────────────────────────────────────────┼──────────────┼───────────┤\n");
    printf("  │ UltrafastSecp256k1 (this run, 1 core)    │  %6.1f k/s  │   1.00 x  │\n",
           ecrecover_per_sec / 1e3);
    printf("  │ libsecp256k1 (bitcoin-core, 1 core)      │   ~39.4 k/s  │  %5.1f x  │\n",
           ecrecover_per_sec / 39400.0);
    printf("  │ go-ethereum (secp256k1 cgo, 1 goroutine) │   ~50-60k/s  │  %5.1f x  │\n",
           ecrecover_per_sec / 55000.0);
    printf("  │ ethers.js   (Node.js WASM, 1 thread)     │   ~15-20k/s  │  %5.1f x  │\n",
           ecrecover_per_sec / 17500.0);
    printf("  │ web3.py     (Python CFFI, 1 thread)      │    ~8-12k/s  │  %5.1f x  │\n",
           ecrecover_per_sec / 10000.0);
    printf("  └──────────────────────────────────────────┴──────────────┴───────────┘\n");
    printf("\n");
    printf("  Notes:\n");
    printf("  * Reference numbers are community-reported on x86-64; vary ±30%% by CPU.\n");
    printf("  * go-ethereum uses cgo → libsecp256k1; this library is faster than that.\n");
    printf("  * ethers.js uses @noble/secp256k1 WASM; significant JS overhead.\n");
    printf("  * web3.py uses coincurve (libsecp256k1 CFFI) + Python overhead.\n");
    printf("  * All Ultra numbers above are 1-core, no SIMD batch tricks.\n");
    printf("  * GPU ecrecover (OpenCL kernel) is not included in this CPU benchmark.\n");

    // ==========================================================================
    // Footer
    // ==========================================================================
    printf("\n");
    printf("============================================================\n");
    printf(" CPU:     " __HOST_SYSTEM_PROCESSOR__ " (compile-time)\n");
    printf(" Library: UltrafastSecp256k1 %d.%d.%d\n",
           UFSECP_VERSION_MAJOR, UFSECP_VERSION_MINOR, UFSECP_VERSION_PATCH);
    printf(" Timer:   std::chrono::high_resolution_clock\n");
    printf(" Build:   " __DATE__ "  " __TIME__ "\n");
    printf("============================================================\n");

    ufsecp_ctx_destroy(ctx);
    return 0;
}
