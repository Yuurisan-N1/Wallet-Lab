// ============================================================================
// Regression test: ct::scalar_inverse zero-input branch removal (SEC-001)
// ============================================================================
// Verifies that ct::scalar_inverse produces correct results for:
// 1. Zero input -> returns zero (CT-select, no early branch)
// 2. Non-zero input -> returns correct modular inverse
// 3. a * a^{-1} == 1 for random scalars
//
// SEC-001-PARTIAL: The data-dependent `if (a.is_zero()) return Scalar::zero()`
// branch has been replaced with a CT scalar_select at the end of the Fermat
// fallback. The multiplication chain still uses fast::operator* on non-int128
// platforms (CT mul requires __int128 or a dedicated 32-bit CT scalar mul).
// ============================================================================

#include <cstdio>
#include <cstring>
#include <array>
#include <random>

#include "secp256k1/scalar.hpp"
#include "secp256k1/ct/scalar.hpp"
#include "secp256k1/ct/ops.hpp"

static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"

using namespace secp256k1;
using namespace secp256k1::fast;

static std::mt19937_64 rng(0xABCD'1234'5678'9ABCULL);  // NOLINT(cert-msc32-c)

static Scalar random_nonzero_scalar() {
    for (;;) {
        std::array<uint8_t, 32> buf{};
        for (int i = 0; i < 4; ++i) {
            uint64_t v = rng();
            std::memcpy(buf.data() + static_cast<std::size_t>(i) * 8, &v, 8);
        }
        Scalar s{};
        if (Scalar::parse_bytes_strict_nonzero(buf.data(), s)) return s;
    }
}

// ─── zero_input_returns_zero ───
static void test_zero_input_returns_zero() {
    AUDIT_LOG("  [SEC-001] ct::scalar_inverse(0) must return 0 (no early branch)\n");
    Scalar zero{};
    Scalar inv = ct::scalar_inverse(zero);
    CHECK(inv.is_zero(), "[SEC-001] ct::scalar_inverse(zero) must return zero");
}

// ─── inverse_correctness ───
static void test_inverse_correctness() {
    AUDIT_LOG("  [SEC-001] ct::scalar_inverse: a * a^{-1} == 1\n");
    Scalar one = Scalar::one();
    for (int i = 0; i < 200; ++i) {
        Scalar a = random_nonzero_scalar();
        Scalar inv = ct::scalar_inverse(a);
        CHECK(!inv.is_zero(), "[SEC-001] inverse of nonzero must be nonzero");
        CHECK((a * inv) == one, "[SEC-001] a * a^{-1} == 1");
    }
}

// ─── double_inverse ───
static void test_double_inverse() {
    AUDIT_LOG("  [SEC-001] ct::scalar_inverse: (a^{-1})^{-1} == a\n");
    for (int i = 0; i < 50; ++i) {
        Scalar a = random_nonzero_scalar();
        Scalar inv_inv = ct::scalar_inverse(ct::scalar_inverse(a));
        CHECK(inv_inv == a, "[SEC-001] (a^{-1})^{-1} == a");
    }
}

int test_regression_ct_scalar_inverse_zero_run();

#ifdef STANDALONE_TEST
int main() { return test_regression_ct_scalar_inverse_zero_run(); }
#endif

int test_regression_ct_scalar_inverse_zero_run() {
    g_pass = 0; g_fail = 0;
    AUDIT_LOG("=== test_regression_ct_scalar_inverse_zero ===\n");
    AUDIT_LOG("  SEC-001: CT scalar_inverse zero-branch removal\n");
    test_zero_input_returns_zero();
    test_inverse_correctness();
    test_double_inverse();
    AUDIT_LOG("  %d checks passed, %d failed\n", g_pass, g_fail);
    AUDIT_LOG("=== %s ===\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
