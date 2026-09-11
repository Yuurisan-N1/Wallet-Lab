/**
 * UltrafastSecp256k1 - ESP32 Comprehensive Benchmark (Arduino)
 *
 * Full secp256k1 implementation test for ESP32/ESP32-S3
 * Includes: Field arithmetic, Scalar operations, Point operations, Self-tests
 *
 * Board: ESP32-S3 Dev Module
 * Upload Speed: 921600
 * CPU Frequency: 240MHz
 */

#include <Arduino.h>

// ============================================================================
// Portable 256-bit Field Element (32-bit optimized for ESP32)
// ============================================================================

struct FieldElement {
    uint32_t limbs[8];  // 8 x 32-bit for ESP32 (32-bit CPU)

    static FieldElement zero() {
        FieldElement r;
        memset(r.limbs, 0, sizeof(r.limbs));
        return r;
    }

    static FieldElement one() {
        FieldElement r = zero();
        r.limbs[0] = 1;
        return r;
    }

    static FieldElement from_u32(uint32_t v) {
        FieldElement r = zero();
        r.limbs[0] = v;
        return r;
    }

    bool is_zero() const {
        for (int i = 0; i < 8; i++) {
            if (limbs[i] != 0) return false;
        }
        return true;
    }

    bool equals(const FieldElement& other) const {
        for (int i = 0; i < 8; i++) {
            if (limbs[i] != other.limbs[i]) return false;
        }
        return true;
    }
};

// secp256k1 prime: p = 2^256 - 2^32 - 977
static const uint32_t SECP256K1_P[8] = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

// Generator point G
static const uint32_t SECP256K1_GX[8] = {
    0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
    0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
};

static const uint32_t SECP256K1_GY[8] = {
    0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
    0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
};

// ============================================================================
// Scalar (256-bit integer mod n)
// ============================================================================

struct Scalar {
    uint32_t limbs[8];

    static Scalar zero() {
        Scalar r;
        memset(r.limbs, 0, sizeof(r.limbs));
        return r;
    }

    static Scalar one() {
        Scalar r = zero();
        r.limbs[0] = 1;
        return r;
    }

    static Scalar from_u32(uint32_t v) {
        Scalar r = zero();
        r.limbs[0] = v;
        return r;
    }

    bool is_zero() const {
        for (int i = 0; i < 8; i++) {
            if (limbs[i] != 0) return false;
        }
        return true;
    }
};

// ============================================================================
// Point structures
// ============================================================================

struct AffinePoint {
    FieldElement x;
    FieldElement y;
    bool infinity;

    static AffinePoint point_at_infinity() {
        AffinePoint p;
        p.x = FieldElement::zero();
        p.y = FieldElement::zero();
        p.infinity = true;
        return p;
    }

    bool is_infinity() const { return infinity; }

    bool equals(const AffinePoint& other) const {
        if (infinity && other.infinity) return true;
        if (infinity != other.infinity) return false;
        return x.equals(other.x) && y.equals(other.y);
    }
};

struct JacobianPoint {
    FieldElement X;
    FieldElement Y;
    FieldElement Z;

    static JacobianPoint identity() {
        JacobianPoint p;
        p.X = FieldElement::zero();
        p.Y = FieldElement::one();
        p.Z = FieldElement::zero();
        return p;
    }

    bool is_identity() const { return Z.is_zero(); }
};

// ============================================================================
// Field Arithmetic
// ============================================================================

static FieldElement field_add(const FieldElement& a, const FieldElement& b) {
    FieldElement r;
    uint64_t carry = 0;

    for (int i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t)a.limbs[i] + b.limbs[i] + carry;
        r.limbs[i] = (uint32_t)sum;
        carry = sum >> 32;
    }

    // Reduce if >= p
    uint64_t borrow = 0;
    uint32_t tmp[8];
    for (int i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)r.limbs[i] - SECP256K1_P[i] - borrow;
        tmp[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }

    if (borrow == 0 || carry) {
        memcpy(r.limbs, tmp, sizeof(tmp));
    }

    return r;
}

static FieldElement field_sub(const FieldElement& a, const FieldElement& b) {
    FieldElement r;
    int64_t borrow = 0;

    for (int i = 0; i < 8; i++) {
        int64_t diff = (int64_t)a.limbs[i] - b.limbs[i] - borrow;
        if (diff < 0) {
            r.limbs[i] = (uint32_t)(diff + 0x100000000LL);
            borrow = 1;
        } else {
            r.limbs[i] = (uint32_t)diff;
            borrow = 0;
        }
    }

    if (borrow) {
        uint64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t sum = (uint64_t)r.limbs[i] + SECP256K1_P[i] + carry;
            r.limbs[i] = (uint32_t)sum;
            carry = sum >> 32;
        }
    }

    return r;
}

static FieldElement field_mul(const FieldElement& a, const FieldElement& b) {
    uint64_t t[16] = {0};

    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t prod = (uint64_t)a.limbs[i] * b.limbs[j];
            uint64_t sum = t[i + j] + prod + carry;
            t[i + j] = sum & 0xFFFFFFFF;
            carry = sum >> 32;
        }
        t[i + 8] += carry;
    }

    // Reduction mod p = 2^256 - 2^32 - 977
    for (int i = 15; i >= 8; i--) {
        uint64_t hi = t[i];
        if (hi == 0) continue;

        t[i] = 0;

        uint64_t carry = 0;
        uint64_t sum = t[i - 7] + (hi << 32) + carry;
        carry = sum >> 32;
        t[i - 7] = sum & 0xFFFFFFFF;

        for (int j = i - 6; j < 16 && carry; j++) {
            sum = t[j] + carry;
            t[j] = sum & 0xFFFFFFFF;
            carry = sum >> 32;
        }

        carry = 0;
        sum = t[i - 8] + hi * 977 + carry;
        t[i - 8] = sum & 0xFFFFFFFF;
        carry = sum >> 32;

        for (int j = i - 7; j < 16 && carry; j++) {
            sum = t[j] + carry;
            t[j] = sum & 0xFFFFFFFF;
            carry = sum >> 32;
        }
    }

    FieldElement r;
    for (int i = 0; i < 8; i++) {
        r.limbs[i] = (uint32_t)t[i];
    }

    return r;
}

static FieldElement field_sqr(const FieldElement& a) {
    return field_mul(a, a);
}

// Field inverse using Fermat's little theorem: a^(p-2) mod p
static FieldElement field_inv(const FieldElement& a) {
    FieldElement result = FieldElement::one();
    FieldElement base = a;

    uint32_t p_minus_2[8] = {
        0xFFFFFC2D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    for (int i = 0; i < 256; i++) {
        int limb_idx = i / 32;
        int bit_idx = i % 32;

        if ((p_minus_2[limb_idx] >> bit_idx) & 1) {
            result = field_mul(result, base);
        }
        base = field_sqr(base);
    }

    return result;
}

// ============================================================================
// Point Operations
// ============================================================================

static AffinePoint get_generator() {
    AffinePoint G;
    for (int i = 0; i < 8; i++) {
        G.x.limbs[i] = SECP256K1_GX[i];
        G.y.limbs[i] = SECP256K1_GY[i];
    }
    G.infinity = false;
    return G;
}

static JacobianPoint affine_to_jacobian(const AffinePoint& p) {
    if (p.infinity) return JacobianPoint::identity();
    JacobianPoint j;
    j.X = p.x;
    j.Y = p.y;
    j.Z = FieldElement::one();
    return j;
}

static AffinePoint jacobian_to_affine(const JacobianPoint& j) {
    if (j.is_identity()) return AffinePoint::point_at_infinity();

    FieldElement z_inv = field_inv(j.Z);
    FieldElement z_inv2 = field_sqr(z_inv);
    FieldElement z_inv3 = field_mul(z_inv2, z_inv);

    AffinePoint a;
    a.x = field_mul(j.X, z_inv2);
    a.y = field_mul(j.Y, z_inv3);
    a.infinity = false;
    return a;
}

static JacobianPoint point_double(const JacobianPoint& p) {
    if (p.is_identity()) return p;

    FieldElement S = field_mul(FieldElement::from_u32(4), field_mul(p.X, field_sqr(p.Y)));
    FieldElement M = field_mul(FieldElement::from_u32(3), field_sqr(p.X));

    FieldElement X3 = field_sub(field_sqr(M), field_mul(FieldElement::from_u32(2), S));
    FieldElement Y3 = field_sub(field_mul(M, field_sub(S, X3)),
                                 field_mul(FieldElement::from_u32(8), field_sqr(field_sqr(p.Y))));
    FieldElement Z3 = field_mul(FieldElement::from_u32(2), field_mul(p.Y, p.Z));

    JacobianPoint r;
    r.X = X3;
    r.Y = Y3;
    r.Z = Z3;
    return r;
}

static JacobianPoint point_add(const JacobianPoint& p, const JacobianPoint& q) {
    if (p.is_identity()) return q;
    if (q.is_identity()) return p;

    FieldElement Z1Z1 = field_sqr(p.Z);
    FieldElement Z2Z2 = field_sqr(q.Z);
    FieldElement U1 = field_mul(p.X, Z2Z2);
    FieldElement U2 = field_mul(q.X, Z1Z1);
    FieldElement S1 = field_mul(p.Y, field_mul(q.Z, Z2Z2));
    FieldElement S2 = field_mul(q.Y, field_mul(p.Z, Z1Z1));

    FieldElement H = field_sub(U2, U1);
    FieldElement r_field = field_sub(S2, S1);

    if (H.is_zero()) {
        if (r_field.is_zero()) {
            return point_double(p);
        }
        return JacobianPoint::identity();
    }

    FieldElement HH = field_sqr(H);
    FieldElement HHH = field_mul(H, HH);
    FieldElement V = field_mul(U1, HH);

    FieldElement X3 = field_sub(field_sub(field_sqr(r_field), HHH),
                                 field_mul(FieldElement::from_u32(2), V));
    FieldElement Y3 = field_sub(field_mul(r_field, field_sub(V, X3)),
                                 field_mul(S1, HHH));
    FieldElement Z3 = field_mul(H, field_mul(p.Z, q.Z));

    JacobianPoint result;
    result.X = X3;
    result.Y = Y3;
    result.Z = Z3;
    return result;
}

static JacobianPoint scalar_mul(const Scalar& k, const AffinePoint& p) {
    JacobianPoint result = JacobianPoint::identity();
    JacobianPoint base = affine_to_jacobian(p);

    for (int i = 0; i < 8; i++) {
        for (int bit = 0; bit < 32; bit++) {
            if ((k.limbs[i] >> bit) & 1) {
                result = point_add(result, base);
            }
            base = point_double(base);
        }
    }

    return result;
}

// ============================================================================
// Self-Test
// ============================================================================

static int tests_passed = 0;
static int tests_total = 0;

static void test_result(const char* name, bool passed) {
    tests_total++;
    if (passed) {
        tests_passed++;
        Serial.printf("  %s: PASS\n", name);
    } else {
        Serial.printf("  %s: FAIL\n", name);
    }
}

static bool run_self_test() {
    tests_passed = 0;
    tests_total = 0;

    Serial.println();
    Serial.println("==============================================");
    Serial.println("  SECP256K1 Self-Test");
    Serial.println("==============================================");

    // Test 1: Field addition
    {
        FieldElement a = FieldElement::from_u32(100);
        FieldElement b = FieldElement::from_u32(200);
        FieldElement c = field_add(a, b);
        test_result("Field Add: 100 + 200 = 300", c.limbs[0] == 300);
    }

    // Test 2: Field subtraction
    {
        FieldElement a = FieldElement::from_u32(500);
        FieldElement b = FieldElement::from_u32(200);
        FieldElement c = field_sub(a, b);
        test_result("Field Sub: 500 - 200 = 300", c.limbs[0] == 300);
    }

    // Test 3: Field multiplication
    {
        FieldElement a = FieldElement::from_u32(7);
        FieldElement b = FieldElement::from_u32(11);
        FieldElement c = field_mul(a, b);
        test_result("Field Mul: 7 * 11 = 77", c.limbs[0] == 77);
    }

    // Test 4: Field squaring
    {
        FieldElement a = FieldElement::from_u32(9);
        FieldElement b = field_sqr(a);
        test_result("Field Sqr: 9^2 = 81", b.limbs[0] == 81);
    }

    // Test 5: Generator point validity
    {
        AffinePoint G = get_generator();
        FieldElement y2 = field_sqr(G.y);
        FieldElement x3 = field_mul(field_sqr(G.x), G.x);
        FieldElement x3_plus_7 = field_add(x3, FieldElement::from_u32(7));
        test_result("Generator on curve", y2.equals(x3_plus_7));
    }

    // Test 6: Point at infinity
    {
        JacobianPoint inf = JacobianPoint::identity();
        test_result("Identity point", inf.is_identity());
    }

    // Test 7: 1*G = G
    {
        AffinePoint G = get_generator();
        Scalar one = Scalar::one();
        JacobianPoint result_j = scalar_mul(one, G);
        AffinePoint result = jacobian_to_affine(result_j);
        test_result("1*G = G", result.x.equals(G.x) && result.y.equals(G.y));
    }

    // Test 8: 2*G via doubling
    {
        AffinePoint G = get_generator();
        JacobianPoint G_j = affine_to_jacobian(G);
        JacobianPoint G2_j = point_double(G_j);
        AffinePoint G2 = jacobian_to_affine(G2_j);

        Scalar two = Scalar::from_u32(2);
        JacobianPoint G2_scalar_j = scalar_mul(two, G);
        AffinePoint G2_scalar = jacobian_to_affine(G2_scalar_j);

        test_result("2*G (double vs scalar)", G2.equals(G2_scalar));
    }

    // Test 9: G + G = 2*G
    {
        AffinePoint G = get_generator();
        JacobianPoint G_j = affine_to_jacobian(G);
        JacobianPoint sum_j = point_add(G_j, G_j);
        AffinePoint sum = jacobian_to_affine(sum_j);

        JacobianPoint G2_j = point_double(G_j);
        AffinePoint G2 = jacobian_to_affine(G2_j);

        test_result("G + G = 2*G", sum.equals(G2));
    }

    // Test 10: 3*G = 2*G + G
    {
        AffinePoint G = get_generator();
        Scalar three = Scalar::from_u32(3);
        JacobianPoint G3_j = scalar_mul(three, G);
        AffinePoint G3 = jacobian_to_affine(G3_j);

        JacobianPoint G_j = affine_to_jacobian(G);
        JacobianPoint G2_j = point_double(G_j);
        JacobianPoint G3_add_j = point_add(G2_j, G_j);
        AffinePoint G3_add = jacobian_to_affine(G3_add_j);

        test_result("3*G = 2*G + G", G3.equals(G3_add));
    }

    Serial.println("==============================================");
    Serial.printf("  Results: %d/%d tests passed\n", tests_passed, tests_total);
    if (tests_passed == tests_total) {
        Serial.println("  [OK] ALL TESTS PASSED");
    } else {
        Serial.println("  [FAIL] SOME TESTS FAILED");
    }
    Serial.println("==============================================");

    return tests_passed == tests_total;
}

// ============================================================================
// Benchmark Functions
// ============================================================================

static void benchmark_field_mul(int iterations) {
    FieldElement a = FieldElement::from_u32(0x12345678);
    FieldElement b = FieldElement::from_u32(0x87654321);

    unsigned long start = micros();

    FieldElement result = a;
    for (int i = 0; i < iterations; i++) {
        result = field_mul(result, b);
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long ns_per_op = (elapsed_us * 1000) / iterations;

    Serial.printf("Field Mul:        %5lu ns\n", ns_per_op);
    (void)result;
}

static void benchmark_field_sqr(int iterations) {
    FieldElement a = FieldElement::from_u32(0x12345678);

    unsigned long start = micros();

    FieldElement result = a;
    for (int i = 0; i < iterations; i++) {
        result = field_sqr(result);
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long ns_per_op = (elapsed_us * 1000) / iterations;

    Serial.printf("Field Square:     %5lu ns\n", ns_per_op);
    (void)result;
}

static void benchmark_field_add(int iterations) {
    FieldElement a = FieldElement::from_u32(0x12345678);
    FieldElement b = FieldElement::from_u32(0x87654321);

    unsigned long start = micros();

    FieldElement result = a;
    for (int i = 0; i < iterations; i++) {
        result = field_add(result, b);
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long ns_per_op = (elapsed_us * 1000) / iterations;

    Serial.printf("Field Add:        %5lu ns\n", ns_per_op);
    (void)result;
}

static void benchmark_field_sub(int iterations) {
    FieldElement a = FieldElement::from_u32(0x87654321);
    FieldElement b = FieldElement::from_u32(0x12345678);

    unsigned long start = micros();

    FieldElement result = a;
    for (int i = 0; i < iterations; i++) {
        result = field_sub(result, b);
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long ns_per_op = (elapsed_us * 1000) / iterations;

    Serial.printf("Field Sub:        %5lu ns\n", ns_per_op);
    (void)result;
}

static void benchmark_field_inv(int iterations) {
    FieldElement a = FieldElement::from_u32(0x12345678);

    unsigned long start = micros();

    FieldElement result = a;
    for (int i = 0; i < iterations; i++) {
        result = field_inv(result);
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long us_per_op = elapsed_us / iterations;

    Serial.printf("Field Inverse:    %5lu us\n", us_per_op);
    (void)result;
}

static void benchmark_point_double(int iterations) {
    AffinePoint G = get_generator();
    JacobianPoint p = affine_to_jacobian(G);

    unsigned long start = micros();

    for (int i = 0; i < iterations; i++) {
        p = point_double(p);
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long us_per_op = elapsed_us / iterations;

    Serial.printf("Point Double:     %5lu us\n", us_per_op);
}

static void benchmark_point_add(int iterations) {
    AffinePoint G = get_generator();
    JacobianPoint p1 = affine_to_jacobian(G);
    JacobianPoint p2 = point_double(p1);

    unsigned long start = micros();

    for (int i = 0; i < iterations; i++) {
        p1 = point_add(p1, p2);
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long us_per_op = elapsed_us / iterations;

    Serial.printf("Point Add:        %5lu us\n", us_per_op);
}

static void benchmark_scalar_mul(int iterations) {
    AffinePoint G = get_generator();
    Scalar k = Scalar::from_u32(0xDEADBEEF);

    unsigned long start = micros();

    for (int i = 0; i < iterations; i++) {
        JacobianPoint result = scalar_mul(k, G);
        (void)result;
    }

    unsigned long elapsed_us = micros() - start;
    unsigned long ms_per_op = elapsed_us / (iterations * 1000);

    Serial.printf("Scalar Mul:       %5lu ms\n", ms_per_op);
}

// ============================================================================
// Arduino Setup & Loop
// ============================================================================

void setup() {
    Serial.begin(115200);
    while (!Serial) { delay(10); }

    delay(1000);  // Wait for serial to stabilize

    Serial.println();
    Serial.println("╔══════════════════════════════════════════════════════════╗");
    Serial.println("║   UltrafastSecp256k1 - ESP32 Comprehensive Benchmark     ║");
    Serial.println("╚══════════════════════════════════════════════════════════╝");
    Serial.println();

    // Print chip info
    Serial.println("Platform Information:");
    Serial.printf("  Chip Model:   ESP32-S3\n");
    Serial.printf("  CPU Freq:     %d MHz\n", ESP.getCpuFreqMHz());
    Serial.printf("  Free Heap:    %d bytes\n", ESP.getFreeHeap());
    Serial.printf("  SDK Version:  %s\n", ESP.getSdkVersion());
    Serial.println("  Build:        Portable C++ (32-bit)");

    // Run self-test first
    if (!run_self_test()) {
        Serial.println();
        Serial.println("Self-test FAILED! Aborting benchmark.");
        while (1) { delay(10000); }
    }

    Serial.println();
    Serial.println("==============================================");
    Serial.println("  BENCHMARK RESULTS");
    Serial.println("==============================================");

    // Warm up
    benchmark_field_mul(100);

    // Field arithmetic benchmarks
    Serial.println();
    Serial.println("--- Field Arithmetic ---");
    benchmark_field_mul(10000);
    benchmark_field_sqr(10000);
    benchmark_field_add(10000);
    benchmark_field_sub(10000);
    benchmark_field_inv(10);

    // Point operation benchmarks
    Serial.println();
    Serial.println("--- Point Operations ---");
    benchmark_point_double(1000);
    benchmark_point_add(1000);
    benchmark_scalar_mul(3);

    // Platform comparison
    Serial.println();
    Serial.println("==============================================");
    Serial.println("  Platform Comparison");
    Serial.println("==============================================");
    Serial.println("  x86-64 (i5):   Field Mul ~33 ns,  Scalar Mul ~110 us");
    Serial.println("  RISC-V 64:     Field Mul ~198 ns, Scalar Mul ~672 us");
    Serial.println("  ARM64:         Field Mul ~50 ns,  Scalar Mul ~150 us");
    Serial.println("  ESP32-S3:      See results above");

    Serial.println();
    Serial.println("╔══════════════════════════════════════════════════════════╗");
    Serial.println("║   Benchmark Complete!                                    ║");
    Serial.println("╚══════════════════════════════════════════════════════════╝");
}

void loop() {
    delay(10000);
}

