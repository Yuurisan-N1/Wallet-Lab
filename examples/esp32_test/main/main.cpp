/**
 * UltrafastSecp256k1 -- ESP32-S3 Comprehensive Benchmark
 *
 * Full benchmark matching x86/ARM64 format (bench_comprehensive_riscv.cpp):
 *   1. Field Arithmetic    (mul, square, add, negate, inverse)
 *   2. Point Operations    (add, double, scalar_mul, generator_mul)
 *   3. ECDSA & Schnorr     (sign, verify -- BIP-340)
 *   4. Batch Operations    (batch inversion)
 *   5. Constant-Time Layer (CT scalar_mul, CT generator_mul, CT add/dbl)
 *   6. libsecp256k1        (bitcoin-core comparison)
 *
 * Measurement: median of 3 runs, per-function warmup, esp_timer (1 us).
 * Output: aligned section + Markdown summary table suitable for README.
 */

#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <array>
#include "esp_chip_info.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// -- Core library -------------------------------------------------------------
#include "secp256k1/field.hpp"
#include "secp256k1/field_26.hpp"
#include "secp256k1/field_optimal.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/selftest.hpp"

// -- Signatures ---------------------------------------------------------------
#include "secp256k1/ecdsa.hpp"
#include "secp256k1/schnorr.hpp"

// -- Constant-Time layer ------------------------------------------------------
#include "secp256k1/ct/point.hpp"
#include "secp256k1/ct/field.hpp"
#include "secp256k1/ct/scalar.hpp"

// -- libsecp256k1 (bitcoin-core) benchmark ------------------------------------
extern "C" void libsecp_benchmark(void);

using namespace secp256k1::fast;

// ============================================================================
//  Platform Detection
// ============================================================================

static const char* chip_model_name(esp_chip_model_t m) {
    switch (m) {
        case CHIP_ESP32:   return "ESP32 (Xtensa LX6, dual-core)";
        case CHIP_ESP32S2: return "ESP32-S2 (Xtensa LX7, single-core)";
        case CHIP_ESP32S3: return "ESP32-S3 (Xtensa LX7, dual-core)";
        case CHIP_ESP32C3: return "ESP32-C3 (RISC-V, single-core)";
        case CHIP_ESP32C2: return "ESP32-C2 (RISC-V, single-core)";
        case CHIP_ESP32C6: return "ESP32-C6 (RISC-V, single-core)";
        case CHIP_ESP32H2: return "ESP32-H2 (RISC-V, single-core)";
        default:           return "Unknown ESP32";
    }
}

// ============================================================================
//  Formatting helpers (identical logic to x86 bench)
// ============================================================================

// format_time: < 1000 ns -> "NNN ns", < 1 ms -> "NNN us", else -> "NNN ms"
static int format_time(char* buf, size_t sz, double ns) {
    if      (ns < 1000.0)     return snprintf(buf, sz, "%d ns",  (int)(ns + 0.5));
    else if (ns < 1000000.0)  return snprintf(buf, sz, "%d us",  (int)(ns / 1000.0 + 0.5));
    else                      return snprintf(buf, sz, "%d ms",  (int)(ns / 1000000.0 + 0.5));
}

static void print_result(const char* label, double ns) {
    char buf[32];
    format_time(buf, sizeof(buf), ns);
    printf("  %-28s %10s\n", label, buf);
}

static void print_result_suffix(const char* label, double ns, const char* suffix) {
    char buf[32];
    format_time(buf, sizeof(buf), ns);
    printf("  %-28s %10s  %s\n", label, buf, suffix);
}

// ============================================================================
//  PRNG -- xoshiro128** (deterministic, no stdlib rand dependency)
// ============================================================================

static uint32_t s_prng[4] = {0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0};

static inline uint32_t rotl32(uint32_t x, int k) {
    return (x << k) | (x >> (32 - k));
}

static uint32_t prng_next() {
    const uint32_t result = rotl32(s_prng[1] * 5, 7) * 9;
    const uint32_t t = s_prng[1] << 9;
    s_prng[2] ^= s_prng[0];
    s_prng[3] ^= s_prng[1];
    s_prng[1] ^= s_prng[2];
    s_prng[0] ^= s_prng[3];
    s_prng[2] ^= t;
    s_prng[3] = rotl32(s_prng[3], 11);
    return result;
}

static FieldElement random_fe() {
    uint64_t limbs[4];
    for (int i = 0; i < 4; i++)
        limbs[i] = ((uint64_t)prng_next() << 32) | prng_next();
    return FieldElement::from_limbs({limbs[0], limbs[1], limbs[2], limbs[3]});
}

static Scalar random_scalar() {
    uint8_t bytes[32];
    for (int i = 0; i < 32; i += 4) {
        uint32_t v = prng_next();
        memcpy(&bytes[i], &v, 4);
    }
    return Scalar::from_bytes(*reinterpret_cast<std::array<uint8_t,32>*>(bytes));
}

static std::array<uint8_t,32> random_msg() {
    std::array<uint8_t,32> msg;
    for (int i = 0; i < 32; i += 4) {
        uint32_t v = prng_next();
        memcpy(&msg[i], &v, 4);
    }
    return msg;
}

// ============================================================================
//  Measurement: median of 3
// ============================================================================

static double median3(double a, double b, double c) {
    if (a > b) { double t = a; a = b; b = t; }
    if (b > c) { double t = b; b = c; c = t; }
    if (a > b) { double t = a; a = b; b = t; }
    return b;
}

// Feed watchdog between measurement phases
#define WDT_YIELD()  vTaskDelay(pdMS_TO_TICKS(10))

// ============================================================================
//  1. FIELD ARITHMETIC BENCHMARKS
// ============================================================================

static double bench_field_mul(int N) {
    FieldElement a = random_fe(), b = random_fe();
    for (int i = 0; i < 100; i++) a = a * b;  // warmup

    int64_t t0 = esp_timer_get_time();
    FieldElement r = a;
    for (int i = 0; i < N; i++) r = r * b;
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;            // ns/op
}

static double bench_field_sqr(int N) {
    FieldElement a = random_fe();
    for (int i = 0; i < 100; i++) a = a.square();

    int64_t t0 = esp_timer_get_time();
    FieldElement r = a;
    for (int i = 0; i < N; i++) r = r.square();
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_field_add(int N) {
    FieldElement a = random_fe(), b = random_fe();
    for (int i = 0; i < 100; i++) a = a + b;

    int64_t t0 = esp_timer_get_time();
    FieldElement r = a;
    for (int i = 0; i < N; i++) r = r + b;
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_field_neg(int N) {
    FieldElement a = random_fe();
    for (int i = 0; i < 100; i++) a = a.negate();

    int64_t t0 = esp_timer_get_time();
    FieldElement r = a;
    for (int i = 0; i < N; i++) r = r.negate();
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_field_inv(int N) {
    FieldElement a = random_fe();
    for (int i = 0; i < 3; i++) a = a.inverse();

    int64_t t0 = esp_timer_get_time();
    FieldElement r = a;
    for (int i = 0; i < N; i++) r = r.inverse();
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

// ============================================================================
//  2. POINT OPERATION BENCHMARKS
// ============================================================================

static double bench_point_add(int N) {
    Point G = Point::generator();
    Point P = G.scalar_mul(Scalar::from_uint64(7));
    Point Q = G.scalar_mul(Scalar::from_uint64(11));
    Q = Point::from_affine(Q.x(), Q.y());
    for (int i = 0; i < 50; i++) P.add_inplace(Q);

    int64_t t0 = esp_timer_get_time();
    Point r = P;
    for (int i = 0; i < N; i++) r.add_inplace(Q);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x_raw().limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_point_dbl(int N) {
    Point G = Point::generator();
    Point P = G.scalar_mul(Scalar::from_uint64(7));
    for (int i = 0; i < 50; i++) P.dbl_inplace();

    int64_t t0 = esp_timer_get_time();
    Point r = P;
    for (int i = 0; i < N; i++) r.dbl_inplace();
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x_raw().limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_scalar_mul(int N) {
    Point G = Point::generator();
    Point Q = G.scalar_mul(Scalar::from_uint64(12345));
    Scalar k = Scalar::from_hex(
        "4727daf2986a9804b1117f8261aba645c34537e4474e19be58700792d501a591");
    volatile auto warm = Q.scalar_mul(k); (void)warm;

    int64_t t0 = esp_timer_get_time();
    Point r = Q;
    for (int i = 0; i < N; i++) r = Q.scalar_mul(k);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x_raw().limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_generator_mul(int N) {
    Point G = Point::generator();
    Scalar k = Scalar::from_hex(
        "4727daf2986a9804b1117f8261aba645c34537e4474e19be58700792d501a591");
    volatile auto warm = G.scalar_mul(k); (void)warm;

    int64_t t0 = esp_timer_get_time();
    Point r = G;
    for (int i = 0; i < N; i++) r = G.scalar_mul(k);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x_raw().limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

// ============================================================================
//  3. ECDSA & SCHNORR BENCHMARKS
// ============================================================================

static double bench_ecdsa_sign(int N) {
    Scalar key = random_scalar();
    auto msg = random_msg();
    volatile auto w = secp256k1::ecdsa_sign(msg, key); (void)w;

    int64_t t0 = esp_timer_get_time();
    for (int i = 0; i < N; i++) {
        volatile auto sig = secp256k1::ecdsa_sign(msg, key); (void)sig;
    }
    int64_t dt = esp_timer_get_time() - t0;
    return (double)dt * 1000.0 / N;
}

static double bench_ecdsa_verify(int N) {
    Scalar key = random_scalar();
    auto msg = random_msg();
    Point G = Point::generator();
    Point pubkey = G.scalar_mul(key);
    auto sig = secp256k1::ecdsa_sign(msg, key);
    volatile bool w = secp256k1::ecdsa_verify(msg, pubkey, sig); (void)w;

    int64_t t0 = esp_timer_get_time();
    for (int i = 0; i < N; i++) {
        volatile bool ok = secp256k1::ecdsa_verify(msg, pubkey, sig); (void)ok;
    }
    int64_t dt = esp_timer_get_time() - t0;
    return (double)dt * 1000.0 / N;
}

static double bench_schnorr_sign(int N) {
    Scalar key = random_scalar();
    auto kp = secp256k1::schnorr_keypair_create(key);
    auto msg = random_msg();
    std::array<uint8_t,32> aux{};
    volatile auto w = secp256k1::schnorr_sign(kp, msg, aux); (void)w;

    int64_t t0 = esp_timer_get_time();
    for (int i = 0; i < N; i++) {
        volatile auto sig = secp256k1::schnorr_sign(kp, msg, aux); (void)sig;
    }
    int64_t dt = esp_timer_get_time() - t0;
    return (double)dt * 1000.0 / N;
}

static double bench_schnorr_verify(int N) {
    Scalar key = random_scalar();
    auto msg = random_msg();
    std::array<uint8_t,32> aux{};
    auto sig = secp256k1::schnorr_sign(key, msg, aux);
    auto xpk = secp256k1::schnorr_pubkey(key);
    volatile bool w = secp256k1::schnorr_verify(xpk, msg, sig); (void)w;

    int64_t t0 = esp_timer_get_time();
    for (int i = 0; i < N; i++) {
        volatile bool ok = secp256k1::schnorr_verify(xpk, msg, sig); (void)ok;
    }
    int64_t dt = esp_timer_get_time() - t0;
    return (double)dt * 1000.0 / N;
}

// ============================================================================
//  3b. ECDSA BOTTLENECK PROFILING
// ============================================================================

static double bench_scalar_inverse(int N) {
    Scalar k = random_scalar();
    volatile auto w = k.inverse(); (void)w;

    int64_t t0 = esp_timer_get_time();
    Scalar r = k;
    for (int i = 0; i < N; i++) r = k.inverse();
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_scalar_modmul(int N) {
    Scalar a = random_scalar();
    Scalar b = random_scalar();
    volatile auto w = a * b; (void)w;

    int64_t t0 = esp_timer_get_time();
    Scalar r = a;
    for (int i = 0; i < N; i++) r = a * b;
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

#include "secp256k1/sha256.hpp"
static double bench_sha256_hash32(int N) {
    std::array<uint8_t,32> msg{};
    msg[0] = 0x42;
    secp256k1::SHA256 sha;
    sha.update(msg.data(), 32);
    auto d = sha.finalize();

    int64_t t0 = esp_timer_get_time();
    for (int i = 0; i < N; i++) {
        sha.reset();
        sha.update(msg.data(), 32);
        d = sha.finalize();
    }
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = d[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

// ============================================================================
//  4. BATCH OPERATIONS
// ============================================================================

static double bench_batch_inverse(int batch_sz) {
    constexpr int MAX_BATCH = 100;
    if (batch_sz > MAX_BATCH) batch_sz = MAX_BATCH;
    FieldElement src[MAX_BATCH], tmp[MAX_BATCH];
    for (int i = 0; i < batch_sz; i++) src[i] = random_fe();

    // warmup
    memcpy(tmp, src, sizeof(FieldElement) * batch_sz);
    fe_batch_inverse(tmp, batch_sz);

    // measure
    memcpy(tmp, src, sizeof(FieldElement) * batch_sz);
    int64_t t0 = esp_timer_get_time();
    fe_batch_inverse(tmp, batch_sz);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = tmp[0].limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / batch_sz;   // ns per element
}

// ============================================================================
//  5. CONSTANT-TIME (CT) LAYER BENCHMARKS
// ============================================================================

static const Scalar CT_TEST_K = Scalar::from_hex(
    "4727daf2986a9804b1117f8261aba645c34537e4474e19be58700792d501a591");

static double bench_ct_scalar_mul(int N) {
    Point G = Point::generator();
    volatile auto w = secp256k1::ct::scalar_mul(G, CT_TEST_K); (void)w;

    int64_t t0 = esp_timer_get_time();
    Point r = G;
    for (int i = 0; i < N; i++) r = secp256k1::ct::scalar_mul(G, CT_TEST_K);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x().limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_ct_generator_mul(int N) {
    // warmup (triggers Comb table init on first call)
    volatile auto w = secp256k1::ct::generator_mul(CT_TEST_K); (void)w;

    int64_t t0 = esp_timer_get_time();
    Point r = Point::generator();
    for (int i = 0; i < N; i++) r = secp256k1::ct::generator_mul(CT_TEST_K);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x().limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_ct_point_add(int N) {
    Point G = Point::generator();
    auto jG = secp256k1::ct::CTJacobianPoint::from_point(G);
    auto r = jG;
    for (int i = 0; i < 50; i++) r = secp256k1::ct::point_add_complete(r, jG);

    int64_t t0 = esp_timer_get_time();
    r = jG;
    for (int i = 0; i < N; i++) r = secp256k1::ct::point_add_complete(r, jG);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

static double bench_ct_point_dbl(int N) {
    Point G = Point::generator();
    auto jG = secp256k1::ct::CTJacobianPoint::from_point(G);
    auto r = jG;
    for (int i = 0; i < 50; i++) r = secp256k1::ct::point_dbl(r);

    int64_t t0 = esp_timer_get_time();
    r = jG;
    for (int i = 0; i < N; i++) r = secp256k1::ct::point_dbl(r);
    int64_t dt = esp_timer_get_time() - t0;
    volatile auto sink = r.x.limbs()[0]; (void)sink;
    return (double)dt * 1000.0 / N;
}

// ============================================================================
//  Result accumulator for summary table
// ============================================================================

struct BenchResult {
    const char* name;
    double ns;
};

static BenchResult g_results[40];
static int         g_nresults = 0;

static void record(const char* name, double ns) {
    if (g_nresults < 40) g_results[g_nresults++] = {name, ns};
}

// ============================================================================
//  CT CORRECTNESS TESTS
// ============================================================================

static int run_ct_tests() {
    int pass = 0, fail = 0;
    auto check = [&](const char* name, bool ok) {
        ok ? pass++ : fail++;
        printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    };

    // 1) CT scalar_mul matches fast path
    {
        Point G = Point::generator();
        Point fast_r = G.scalar_mul(CT_TEST_K);
        Point ct_r   = secp256k1::ct::scalar_mul(G, CT_TEST_K);
        check("CT scalar_mul == fast scalar_mul",
              fast_r.x() == ct_r.x() && fast_r.y() == ct_r.y());
    }
    // 2) CT generator_mul matches fast path
    {
        Scalar k2 = Scalar::from_hex(
            "a1b2c3d4e5f6071819283746556473829aabbccddeeff00112233445566778899");
        Point G = Point::generator();
        Point fast_r = G.scalar_mul(k2);
        Point ct_r   = secp256k1::ct::generator_mul(k2);
        check("CT generator_mul == fast generator_mul",
              fast_r.x() == ct_r.x() && fast_r.y() == ct_r.y());
    }
    // 3) field_cmov
    {
        FieldElement a = FieldElement::from_limbs({1, 2, 3, 4});
        FieldElement b = FieldElement::from_limbs({5, 6, 7, 8});
        FieldElement r = a;
        secp256k1::ct::field_cmov(&r, b, UINT64_MAX);
        bool ok1 = (r == b);
        r = a;
        secp256k1::ct::field_cmov(&r, b, 0);
        bool ok2 = (r == a);
        check("CT field_cmov (select / no-select)", ok1 && ok2);
    }
    // 4) Complete addition (P+P = 2P)
    {
        Point G = Point::generator();
        auto jG  = secp256k1::ct::CTJacobianPoint::from_point(G);
        auto jGG = secp256k1::ct::point_add_complete(jG, jG);
        Point ct_2G   = jGG.to_point();
        Point fast_2G = G.add(G);
        check("CT complete_add(G,G) == fast G+G",
              ct_2G.x() == fast_2G.x() && ct_2G.y() == fast_2G.y());
    }

    printf("  CT Tests: %d/%d PASS\n", pass, pass + fail);
    return fail;
}

// ================================================================================
//  MAIN
// ================================================================================

extern "C" void app_main() {
    // Let serial settle
    vTaskDelay(pdMS_TO_TICKS(1000));

    // -- Header ---------------------------------------------------------------
    esp_chip_info_t ci;
    esp_chip_info(&ci);

    printf("\n");
    printf("================================================================\n");
    printf("   UltrafastSecp256k1 -- Comprehensive Benchmark\n");
    printf("================================================================\n\n");

    printf("Platform Information:\n");
    printf("  Chip:           %s\n", chip_model_name(ci.model));
    printf("  CPU Freq:       240 MHz\n");
    printf("  Cores:          %d\n", ci.cores);
    printf("  Revision:       %d.%d\n", ci.revision / 100, ci.revision % 100);
    printf("  Free Heap:      %lu bytes\n", (unsigned long)esp_get_free_heap_size());
    printf("  Compiler:       GCC %s\n", __VERSION__);
    printf("  Build Target:   Release (-O3)\n\n");

    printf("Optimization Configuration:\n");
    printf("  Assembly:       Portable C++ (no platform ASM)\n");
    printf("  Int128:         Disabled (32-bit Xtensa)\n");
    printf("  Field Tier:     %s\n", secp256k1::fast::kOptimalTierName);
    printf("  Reduction:      ESP32 Comba 8x32 + branchless reduce\n\n");

    printf("Benchmark method: median of 3 runs, per-op warmup\n\n");

    // -- Self-Test ------------------------------------------------------------
    printf("Self-Test...\n");
    bool ok = Selftest(true);
    printf("\n");
    if (!ok) {
        printf("!!! SELF-TEST FAILED -- aborting benchmark !!!\n");
        while (1) vTaskDelay(pdMS_TO_TICKS(10000));
        return;
    }
    printf("Self-Test: ALL PASSED\n\n");

    // ==========================================================================
    //  1. FIELD ARITHMETIC
    // ==========================================================================
    printf("================================================================\n");
    printf("  1. FIELD ARITHMETIC  (%s)\n", secp256k1::fast::kOptimalTierName);
    printf("================================================================\n");
    {
        const int N = 2000;
        double t;

        t = median3(bench_field_mul(N), bench_field_mul(N), bench_field_mul(N));
        record("Field Mul", t);
        print_result("Field Mul", t);

        t = median3(bench_field_sqr(N), bench_field_sqr(N), bench_field_sqr(N));
        record("Field Square", t);
        print_result("Field Square", t);

        t = median3(bench_field_add(N), bench_field_add(N), bench_field_add(N));
        record("Field Add", t);
        print_result("Field Add", t);

        t = median3(bench_field_neg(N), bench_field_neg(N), bench_field_neg(N));
        record("Field Negate", t);
        print_result("Field Negate", t);

        t = median3(bench_field_inv(50), bench_field_inv(50), bench_field_inv(50));
        record("Field Inverse", t);
        print_result("Field Inverse", t);
    }
    WDT_YIELD();
    printf("\n");

    // ==========================================================================
    //  2. POINT OPERATIONS
    // ==========================================================================
    printf("================================================================\n");
    printf("  2. POINT OPERATIONS\n");
    printf("================================================================\n");
    {
        double t;

        t = median3(bench_point_add(500), bench_point_add(500), bench_point_add(500));
        record("Point Add (Jacobian)", t);
        print_result("Point Add (Jacobian)", t);
        WDT_YIELD();

        t = median3(bench_point_dbl(500), bench_point_dbl(500), bench_point_dbl(500));
        record("Point Double", t);
        print_result("Point Double", t);
        WDT_YIELD();

        t = median3(bench_scalar_mul(3), bench_scalar_mul(3), bench_scalar_mul(3));
        record("Scalar Mul (k*P)", t);
        print_result("Scalar Mul (k*P)", t);
        WDT_YIELD();

        t = median3(bench_generator_mul(3), bench_generator_mul(3), bench_generator_mul(3));
        record("Generator Mul (k*G)", t);
        print_result("Generator Mul (k*G)", t);
    }
    WDT_YIELD();
    printf("\n");

    // ==========================================================================
    //  3. ECDSA & SCHNORR SIGNATURES
    // ==========================================================================
    printf("================================================================\n");
    printf("  3. ECDSA & SCHNORR SIGNATURES\n");
    printf("================================================================\n");
    {
        double t;

        WDT_YIELD();
        t = median3(bench_ecdsa_sign(3), bench_ecdsa_sign(3), bench_ecdsa_sign(3));
        record("ECDSA Sign", t);
        print_result("ECDSA Sign", t);
        WDT_YIELD();

        t = median3(bench_ecdsa_verify(3), bench_ecdsa_verify(3), bench_ecdsa_verify(3));
        record("ECDSA Verify", t);
        print_result("ECDSA Verify", t);
        WDT_YIELD();

        t = median3(bench_schnorr_sign(3), bench_schnorr_sign(3), bench_schnorr_sign(3));
        record("Schnorr Sign (BIP-340)", t);
        print_result("Schnorr Sign (BIP-340)", t);
        WDT_YIELD();

        t = median3(bench_schnorr_verify(3), bench_schnorr_verify(3), bench_schnorr_verify(3));
        record("Schnorr Verify (BIP-340)", t);
        print_result("Schnorr Verify (BIP-340)", t);
    }
    WDT_YIELD();
    printf("\n");

    // ==========================================================================
    //  3b. ECDSA BOTTLENECK PROFILING
    // ==========================================================================
    printf("================================================================\n");
    printf("  3b. ECDSA BOTTLENECK PROFILING\n");
    printf("================================================================\n");
    {
        double t;

        WDT_YIELD();
        t = median3(bench_scalar_inverse(3), bench_scalar_inverse(3), bench_scalar_inverse(3));
        record("Scalar Inverse", t);
        print_result("Scalar Inverse", t);
        WDT_YIELD();

        t = median3(bench_scalar_modmul(10), bench_scalar_modmul(10), bench_scalar_modmul(10));
        record("Scalar Mul (a*b mod n)", t);
        print_result("Scalar Mul (a*b mod n)", t);
        WDT_YIELD();

        t = median3(bench_sha256_hash32(20), bench_sha256_hash32(20), bench_sha256_hash32(20));
        record("SHA-256 (32-byte)", t);
        print_result("SHA-256 (32-byte)", t);
    }
    WDT_YIELD();
    printf("\n");

    // ==========================================================================
    //  4. BATCH OPERATIONS
    // ==========================================================================
    printf("================================================================\n");
    printf("  4. BATCH OPERATIONS\n");
    printf("================================================================\n");
    {
        double t;

        t = median3(bench_batch_inverse(32), bench_batch_inverse(32), bench_batch_inverse(32));
        record("Batch Inv (n=32)", t);
        print_result_suffix("Batch Inv (n=32)", t, "per elem");

        t = median3(bench_batch_inverse(100), bench_batch_inverse(100), bench_batch_inverse(100));
        record("Batch Inv (n=100)", t);
        print_result_suffix("Batch Inv (n=100)", t, "per elem");
    }
    WDT_YIELD();
    printf("\n");

    // ==========================================================================
    //  5. CONSTANT-TIME (CT) LAYER
    // ==========================================================================
    printf("================================================================\n");
    printf("  5. CONSTANT-TIME (CT) LAYER\n");
    printf("================================================================\n\n");

    // -- CT correctness --
    printf("--- CT Correctness Tests ---\n");
    run_ct_tests();
    WDT_YIELD();
    printf("\n");

    // -- CT performance --
    printf("--- CT Performance ---\n");
    {
        double t;

        t = median3(bench_ct_scalar_mul(3), bench_ct_scalar_mul(3), bench_ct_scalar_mul(3));
        record("CT Scalar Mul (k*P)", t);
        print_result("CT Scalar Mul (k*P)", t);
        WDT_YIELD();

        t = median3(bench_ct_generator_mul(3), bench_ct_generator_mul(3), bench_ct_generator_mul(3));
        record("CT Generator Mul (k*G)", t);
        print_result_suffix("CT Generator Mul (k*G)", t, "(Comb)");
        WDT_YIELD();

        t = median3(bench_ct_point_add(500), bench_ct_point_add(500), bench_ct_point_add(500));
        record("CT Point Add (complete)", t);
        print_result("CT Point Add (complete)", t);
        WDT_YIELD();

        t = median3(bench_ct_point_dbl(500), bench_ct_point_dbl(500), bench_ct_point_dbl(500));
        record("CT Point Double", t);
        print_result("CT Point Double", t);
    }
    WDT_YIELD();

    // -- Fast vs CT comparison --
    printf("\n--- Fast vs CT Comparison ---\n");
    {
        Point G = Point::generator();

        int64_t t1 = esp_timer_get_time();
        volatile auto fr = G.scalar_mul(CT_TEST_K); (void)fr;
        int64_t t_fast = esp_timer_get_time() - t1;

        int64_t t2 = esp_timer_get_time();
        volatile auto cr = secp256k1::ct::scalar_mul(G, CT_TEST_K); (void)cr;
        int64_t t_ct = esp_timer_get_time() - t2;

        printf("  Fast Scalar*G:   %" PRId64 " us\n", t_fast);
        printf("  CT Scalar*G:     %" PRId64 " us\n", t_ct);
        if (t_fast > 0)
            printf("  CT/Fast ratio:   %.2fx\n", (double)t_ct / (double)t_fast);
    }
    WDT_YIELD();
    printf("\n");

    // ==========================================================================
    //  6. libsecp256k1 (bitcoin-core) COMPARISON
    // ==========================================================================
    printf("================================================================\n");
    printf("  6. libsecp256k1 (bitcoin-core v0.7.2) COMPARISON\n");
    printf("================================================================\n");
    libsecp_benchmark();
    WDT_YIELD();
    printf("\n");

    // ==========================================================================
    //  SUMMARY TABLE (for README)
    // ==========================================================================
    printf("================================================================\n");
    printf("  PERFORMANCE SUMMARY\n");
    printf("================================================================\n\n");
    printf("Platform: %s @ 240 MHz\n", chip_model_name(ci.model));
    printf("Compiler: GCC %s | Field: %s\n\n", __VERSION__, secp256k1::fast::kOptimalTierName);

    printf("| %-28s | %12s |\n", "Operation", "Time");
    printf("|%-30s|%14s|\n",
           "------------------------------", "--------------");
    for (int i = 0; i < g_nresults; i++) {
        char buf[32];
        format_time(buf, sizeof(buf), g_results[i].ns);
        printf("| %-28s | %12s |\n", g_results[i].name, buf);
    }

    printf("\n");
    printf("================================================================\n");
    printf("   Benchmark Complete -- %s @ 240 MHz\n", chip_model_name(ci.model));
    printf("   Field Tier: %s\n", secp256k1::fast::kOptimalTierName);
    printf("================================================================\n");

    // idle loop
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
