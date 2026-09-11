/**
 * UltrafastSecp256k1 - STM32F103ZET6 Integration Test
 *
 * Tests secp256k1 library on bare-metal Cortex-M3 @ 72MHz
 * Output via USART1 (PA9/TX -> CH340 -> COM4)
 *
 * Memory budget: 512KB Flash, 64KB SRAM
 * - NO gen_fixed_mul (30KB table too large for 64KB SRAM)
 * - Uses GLV + Shamir's trick for scalar multiplication
 * - Expected Scalar*G: ~35ms at 72MHz
 */

#include <cstdio>
#include <cstdint>

// secp256k1 library
#include "secp256k1/field.hpp"
#include "secp256k1/field_26.hpp"
#include "secp256k1/field_optimal.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/selftest.hpp"

using namespace secp256k1::fast;

// DWT cycle counter for microsecond-precision timing
#define DWT_CYCCNT (*(volatile uint32_t*)0xE0001004UL)
#define SYSCLK_MHZ 72U

static inline uint32_t micros() {
    return DWT_CYCCNT / SYSCLK_MHZ;
}

// UART init (defined in syscalls.cpp)
extern void uart_init();

// Simple delay using DWT
static void delay_ms(uint32_t ms) {
    uint32_t start = DWT_CYCCNT;
    uint32_t ticks = ms * SYSCLK_MHZ * 1000U;
    while ((DWT_CYCCNT - start) < ticks) {}
}

int main() {
    uart_init();
    delay_ms(500);  // Let CH340 settle

    printf("\n");
    printf("============================================================\n");
    printf("   UltrafastSecp256k1 - STM32F103ZET6 Library Test\n");
    printf("============================================================\n");
    printf("\n");

    // Platform information
    printf("Platform Information:\n");
    printf("  MCU:          STM32F103ZET6 (Cortex-M3)\n");
    printf("  Clock:        %u MHz\n", SYSCLK_MHZ);
    printf("  Flash:        512 KB\n");
    printf("  SRAM:         64 KB\n");
    printf("  Build:        32-bit Portable (no __int128)\n");
    printf("  Features:     GLV+Shamir (no fixed-base table)\n");
    printf("\n");

    // Quick field diagnostics
    printf("=== Field Arithmetic Diagnostics ===\n");
    {
        // (p-1)^2 should equal 1
        FieldElement pm1 = FieldElement::from_limbs({
            0xFFFFFFFEFFFFFC2EULL, 0xFFFFFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
        });
        FieldElement pm1_mul = pm1 * pm1;
        printf("  (p-1)*(p-1)==1?  %s\n", (pm1_mul == FieldElement::one()) ? "PASS" : "FAIL");
        if (pm1_mul != FieldElement::one()) {
            printf("    Got: %s\n", pm1_mul.to_hex().c_str());
        }
        FieldElement pm1_sq = pm1; pm1_sq.square_inplace();
        printf("  (p-1).sq()==1?   %s\n", (pm1_sq == FieldElement::one()) ? "PASS" : "FAIL");
        if (pm1_sq != FieldElement::one()) {
            printf("    Got: %s\n", pm1_sq.to_hex().c_str());
        }
        printf("  sq==mul?         %s\n", (pm1_sq == pm1_mul) ? "PASS" : "FAIL");

        // Commutativity, associativity, distributivity
        FieldElement x = FieldElement::from_limbs({
            0xA1B2C3D4E5F60718ULL, 0x1928374655647382ULL,
            0xBBAACCDDEEFF0011ULL, 0x2233445566778899ULL
        });
        FieldElement y = FieldElement::from_limbs({
            0xFEDCBA9876543210ULL, 0x0123456789ABCDEFULL,
            0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL
        });
        FieldElement z = FieldElement::from_limbs({
            0x1111111122222222ULL, 0x3333333344444444ULL,
            0x5555555566666666ULL, 0x7777777788888888ULL
        });
        printf("  x*y==y*x?        %s\n", (x*y == y*x) ? "PASS" : "FAIL");
        printf("  (x*y)*z==x*(y*z)? %s\n", ((x*y)*z == x*(y*z)) ? "PASS" : "FAIL");
        FieldElement xsq = x; xsq.square_inplace();
        FieldElement xmul = x * x;
        printf("  x.sq==x*x?       %s\n", (xsq == xmul) ? "PASS" : "FAIL");
        if (xsq != xmul) {
            printf("    sq:  %s\n", xsq.to_hex().c_str());
            printf("    mul: %s\n", xmul.to_hex().c_str());
        }
        printf("  x*(y+z)==x*y+x*z? %s\n", (x*(y+z) == x*y + x*z) ? "PASS" : "FAIL");
    }
    printf("=== End Diagnostics ===\n\n");

    // Run library self-test
    printf("Running SECP256K1 Library Self-Test...\n");
    printf("(This may take 30-60 seconds on STM32 @ 72MHz)\n\n");

    bool test_passed = Selftest(true);

    printf("\n");
    if (test_passed) {
        printf("============================================================\n");
        printf("   SUCCESS: All library tests passed on STM32!\n");
        printf("============================================================\n");
    } else {
        printf("============================================================\n");
        printf("   FAILURE: Some tests failed. Check output above.\n");
        printf("============================================================\n");
    }

    // Performance benchmarks
    printf("\n");
    printf("==============================================\n");
    printf("  Basic Performance Benchmark (STM32 @ %u MHz)\n", SYSCLK_MHZ);
    printf("==============================================\n");

    const int iterations = 1000;
    FieldElement a = FieldElement::from_limbs({0x12345678, 0xABCDEF01, 0x11223344, 0x55667788});
    FieldElement b = FieldElement::from_limbs({0x87654321, 0xFEDCBA98, 0x99AABBCC, 0xDDEEFF00});

    // Field Multiplication
    {
        uint32_t start = micros();
        FieldElement result = a;
        for (int i = 0; i < iterations; i++) {
            result = result * b;
        }
        uint32_t elapsed = micros() - start;
        printf("  Field Mul:    %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
        if (result == FieldElement::zero()) printf("!");
    }

    // Field Squaring
    {
        uint32_t start = micros();
        FieldElement result = a;
        for (int i = 0; i < iterations; i++) {
            result = result.square();
        }
        uint32_t elapsed = micros() - start;
        printf("  Field Square: %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
        if (result == FieldElement::zero()) printf("!");
    }

    // Field Addition
    {
        uint32_t start = micros();
        FieldElement result = a;
        for (int i = 0; i < iterations; i++) {
            result = result + b;
        }
        uint32_t elapsed = micros() - start;
        printf("  Field Add:    %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
        if (result == FieldElement::zero()) printf("!");
    }

    // Field Inversion
    {
        uint32_t start = micros();
        FieldElement result = a;
        for (int i = 0; i < 100; i++) {
            result = result.inverse();
        }
        uint32_t elapsed = micros() - start;
        printf("  Field Inv:    %5lu us/op\n", (unsigned long)elapsed / 100);
        if (result == FieldElement::zero()) printf("!");
    }

    // Scalar Multiplication (full 256-bit scalar)
    if (test_passed) {
        printf("\n  Scalar Mul benchmark (full 256-bit scalar):\n");
        Scalar k = Scalar::from_hex("4727daf2986a9804b1117f8261aba645c34537e4474e19be58700792d501a591");
        Point G = Point::generator();

        // Warmup
        volatile uint32_t sink = 0;
        Point warmup = G.scalar_mul(k);
        sink = static_cast<uint32_t>(warmup.x().limbs()[0]);

        uint32_t start = micros();
        Point result = G;
        for (int i = 0; i < 5; i++) {
            result = G.scalar_mul(k);
        }
        uint32_t elapsed = micros() - start;
        sink = static_cast<uint32_t>(result.x().limbs()[0]);
        printf("  Scalar*G:     %5lu us/op\n", (unsigned long)elapsed / 5);
        (void)sink;
    }

    // ===================================================================
    // 10x26 Field Element Benchmark
    // ===================================================================
    printf("\n");
    printf("==============================================\n");
    printf("  10x26 Field Element Benchmark\n");
    printf("  (Lazy-Reduction for 32-bit Platforms)\n");
    printf("==============================================\n");

    {
        FieldElement fe_x = FieldElement::from_limbs({0xDEADBEEF12345678ULL, 0xCAFEBABE87654321ULL, 0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL});
        FieldElement fe_y = FieldElement::from_limbs({0xFEDCBA9876543210ULL, 0x0123456789ABCDEFULL, 0xAABBCCDDEEFF0011ULL, 0x2233445566778899ULL});

        FieldElement26 f26_x = FieldElement26::from_fe(fe_x);
        FieldElement26 f26_y = FieldElement26::from_fe(fe_y);

        // Correctness
        FieldElement mul64 = fe_x * fe_y;
        FieldElement26 mul26 = f26_x * f26_y;
        printf("  10x26 mul OK: %s\n", (mul26.to_fe() == mul64) ? "PASS" : "FAIL");

        FieldElement sqr64 = fe_x.square();
        FieldElement26 sqr26 = f26_x.square();
        printf("  10x26 sqr OK: %s\n", (sqr26.to_fe() == sqr64) ? "PASS" : "FAIL");

        FieldElement add64 = fe_x + fe_y;
        FieldElement26 add26 = f26_x + f26_y;
        add26.normalize();
        printf("  10x26 add OK: %s\n", (add26.to_fe() == add64) ? "PASS" : "FAIL");

        printf("  10x26 roundtrip: %s\n", (f26_x.to_fe() == fe_x) ? "PASS" : "FAIL");
    }

    {
        FieldElement26 fa26 = FieldElement26::from_fe(a);
        FieldElement26 fb26 = FieldElement26::from_fe(b);

        // 10x26 Mul
        {
            uint32_t start = micros();
            FieldElement26 result = fa26;
            for (int i = 0; i < iterations; i++) {
                result = result * fb26;
            }
            uint32_t elapsed = micros() - start;
            printf("  10x26 Mul:    %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
            if (result.n[0] == 0xDEAD) printf("!");
        }

        // 10x26 Sqr
        {
            uint32_t start = micros();
            FieldElement26 result = fa26;
            for (int i = 0; i < iterations; i++) {
                result.square_inplace();
            }
            uint32_t elapsed = micros() - start;
            printf("  10x26 Sqr:    %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
            if (result.n[0] == 0xDEAD) printf("!");
        }

        // 10x26 Add (lazy)
        {
            uint32_t start = micros();
            FieldElement26 result = fa26;
            for (int i = 0; i < iterations; i++) {
                result.add_assign(fb26);
            }
            result.normalize_weak();
            uint32_t elapsed = micros() - start;
            printf("  10x26 Add:    %5lu ns/op  (LAZY)\n", (unsigned long)(elapsed * 1000UL) / iterations);
            if (result.n[0] == 0xDEAD) printf("!");
        }

        // 10x26 Neg
        {
            uint32_t start = micros();
            FieldElement26 result = fa26;
            for (int i = 0; i < iterations; i++) {
                result = result.negate(1);
            }
            uint32_t elapsed = micros() - start;
            printf("  10x26 Neg:    %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
            if (result.n[0] == 0xDEAD) printf("!");
        }
    }

    // ===================================================================
    // Optimal Field Element (compile-time dispatch)
    // ===================================================================
    printf("\n");
    printf("==============================================\n");
    printf("  Optimal Field Element (Auto-Dispatch)\n");
    printf("  Selected: %s\n", secp256k1::fast::kOptimalTierName);
    printf("==============================================\n");

    {
        using OFE = secp256k1::fast::OptimalFieldElement;
        OFE oa = secp256k1::fast::to_optimal(a);
        OFE ob = secp256k1::fast::to_optimal(b);

        // Correctness
        OFE ofe_mul = oa * ob;
        FieldElement rt_mul = secp256k1::fast::from_optimal(ofe_mul);
        FieldElement ref_mul = a * b;
        printf("  Optimal Mul OK: %s\n", (rt_mul == ref_mul) ? "PASS" : "FAIL");

        OFE ofe_sqr = oa.square();
        FieldElement rt_sqr = secp256k1::fast::from_optimal(ofe_sqr);
        FieldElement ref_sqr = a.square();
        printf("  Optimal Sqr OK: %s\n", (rt_sqr == ref_sqr) ? "PASS" : "FAIL");

        // Benchmark Optimal Mul
        {
            uint32_t start = micros();
            OFE result = oa;
            for (int i = 0; i < iterations; i++) {
                result = result * ob;
            }
            uint32_t elapsed = micros() - start;
            printf("  Optimal Mul:  %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
            volatile auto sink = result;
            (void)sink;
        }

        // Benchmark Optimal Sqr
        {
            uint32_t start = micros();
            OFE result = oa;
            for (int i = 0; i < iterations; i++) {
                result = result.square();
            }
            uint32_t elapsed = micros() - start;
            printf("  Optimal Sqr:  %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
            volatile auto sink = result;
            (void)sink;
        }

        // Benchmark Optimal Add
        {
            uint32_t start = micros();
            OFE result = oa;
            for (int i = 0; i < iterations; i++) {
                result = result + ob;
            }
            uint32_t elapsed = micros() - start;
            printf("  Optimal Add:  %5lu ns/op\n", (unsigned long)(elapsed * 1000UL) / iterations);
            volatile auto sink = result;
            (void)sink;
        }
    }

    printf("\n");
    printf("============================================================\n");
    printf("   UltrafastSecp256k1 on STM32F103ZET6 - Test Complete\n");
    printf("   Optimal Tier: %s\n", secp256k1::fast::kOptimalTierName);
    printf("============================================================\n");

    // Halt (no RTOS)
    while (1) {
        // Optionally toggle LED or wait
    }

    return 0;
}
