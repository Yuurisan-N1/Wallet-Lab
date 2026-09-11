// ============================================================================
// Test: Schnorr hot-path correctness regression (PERF-001, PERF-009)
// ============================================================================
// Verifies that the PERF-009 optimization (CT-conditional Y-negation instead
// of a second ct::generator_mul in schnorr_xonly_from_keypair) produces
// results identical to the BIP-340 specification, and that schnorr_verify
// still validates correctly across a range of known test vectors.
//
// PERF-001 (normalize → normalize_weak) is documented-only (normalize_weak
// is not safe for parity extraction); this file contains a correctness
// regression so any future attempt to use normalize_weak is caught early.
// ============================================================================

#include "secp256k1/schnorr.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/ct/sign.hpp"

#include <cstdio>
#include <cstring>
#include <array>

using namespace secp256k1;
using fast::Scalar;

// Intentionally exercises schnorr_xonly_from_keypair and related public entry
// points. Suppress deprecation warnings for legacy non-CT APIs used as ground
// truth in this regression context.
#if defined(__GNUC__) || defined(__clang__)
#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static int tests_run    = 0;
static int tests_passed = 0;

#define CHECK(cond, msg) do { \
    ++tests_run; \
    if (cond) { ++tests_passed; printf("  [PASS] %s\n", msg); } \
    else       {                printf("  [FAIL] %s\n", msg); } \
} while(0)

// -- Hex helper ---------------------------------------------------------------

static std::array<uint8_t, 32> h32(const char* hex) {
    std::array<uint8_t, 32> r{};
    for (size_t i = 0; i < 32; ++i) {
        unsigned hi = 0, lo = 0;
        char c0 = hex[i * 2], c1 = hex[i * 2 + 1];
        if (c0 >= '0' && c0 <= '9') hi = static_cast<unsigned>(c0 - '0');
        else if (c0 >= 'a' && c0 <= 'f') hi = static_cast<unsigned>(c0 - 'a' + 10);
        else if (c0 >= 'A' && c0 <= 'F') hi = static_cast<unsigned>(c0 - 'A' + 10);
        if (c1 >= '0' && c1 <= '9') lo = static_cast<unsigned>(c1 - '0');
        else if (c1 >= 'a' && c1 <= 'f') lo = static_cast<unsigned>(c1 - 'a' + 10);
        else if (c1 >= 'A' && c1 <= 'F') lo = static_cast<unsigned>(c1 - 'A' + 10);
        r[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return r;
}

static std::array<uint8_t, 64> h64(const char* hex) {
    std::array<uint8_t, 64> r{};
    for (size_t i = 0; i < 64; ++i) {
        unsigned hi = 0, lo = 0;
        char c0 = hex[i * 2], c1 = hex[i * 2 + 1];
        if (c0 >= '0' && c0 <= '9') hi = static_cast<unsigned>(c0 - '0');
        else if (c0 >= 'a' && c0 <= 'f') hi = static_cast<unsigned>(c0 - 'a' + 10);
        else if (c0 >= 'A' && c0 <= 'F') hi = static_cast<unsigned>(c0 - 'A' + 10);
        if (c1 >= '0' && c1 <= '9') lo = static_cast<unsigned>(c1 - '0');
        else if (c1 >= 'a' && c1 <= 'f') lo = static_cast<unsigned>(c1 - 'a' + 10);
        else if (c1 >= 'A' && c1 <= 'F') lo = static_cast<unsigned>(c1 - 'A' + 10);
        r[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return r;
}

// ============================================================================
// PERF-009: schnorr_xonly_from_keypair correctness
// Verifies that the CT-conditional Y-negation path gives the same x-only
// pubkey as the reference BIP-340 derivation (schnorr_pubkey).
// Uses all four BIP-340 sign vectors from bitcoin/bips.
// ============================================================================

static void test_xonly_from_keypair_vector0() {
    printf("\n  -- PERF-009 vector 0 (sk=3, even-Y case) --\n");

    // BIP-340 vector 0: sk=3, expected pk = F9308A...
    auto sk = Scalar::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000003");
    const auto expected_pk = h32(
        "F9308A019258C31049344F85F89D5229"
        "B531C845836F99B08601F113BCE036F9");

    // Ground truth: schnorr_pubkey (uses ct_sign path)
    auto ref_pk = schnorr_pubkey(sk);
    CHECK(ref_pk == expected_pk, "V0: schnorr_pubkey matches BIP-340");

    // PERF-009 path: keypair create → xonly_from_keypair
    auto kp = ct::schnorr_keypair_create(sk);
    auto xonly = schnorr_xonly_from_keypair(kp);
    CHECK(xonly.x_bytes == expected_pk,
          "V0: schnorr_xonly_from_keypair x_bytes matches BIP-340");

    // Verify the stored point encodes the same x-coordinate
    SchnorrXonlyPubkey parsed{};
    bool ok = schnorr_xonly_pubkey_parse(parsed, expected_pk.data());
    CHECK(ok, "V0: schnorr_xonly_pubkey_parse succeeds");

    // The points from both paths must represent the same curve point:
    // verify a signature created from the keypair against the parsed pubkey.
    const auto msg = h32(
        "0000000000000000000000000000000000000000000000000000000000000000");
    const auto aux = h32(
        "0000000000000000000000000000000000000000000000000000000000000000");
    auto sig = schnorr_sign(sk, msg, aux);
    const auto expected_sig = h64(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
    CHECK(sig.to_bytes() == expected_sig, "V0: signature matches expected");
    CHECK(schnorr_verify(expected_pk, msg, sig), "V0: verify passes");
    CHECK(schnorr_verify(xonly, msg, sig),
          "V0: verify(xonly_from_keypair pubkey) passes");
}

static void test_xonly_from_keypair_vector1() {
    printf("\n  -- PERF-009 vector 1 --\n");

    auto sk = Scalar::from_hex(
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    const auto expected_pk = h32(
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");

    auto ref_pk = schnorr_pubkey(sk);
    CHECK(ref_pk == expected_pk, "V1: schnorr_pubkey matches BIP-340");

    auto kp = ct::schnorr_keypair_create(sk);
    auto xonly = schnorr_xonly_from_keypair(kp);
    CHECK(xonly.x_bytes == expected_pk,
          "V1: schnorr_xonly_from_keypair x_bytes matches BIP-340");

    const auto msg = h32(
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    const auto aux = h32(
        "0000000000000000000000000000000000000000000000000000000000000001");
    const auto expected_sig = h64(
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A");
    auto sig = schnorr_sign(sk, msg, aux);
    CHECK(sig.to_bytes() == expected_sig, "V1: signature matches expected");
    CHECK(schnorr_verify(expected_pk, msg, sig), "V1: verify passes");
    CHECK(schnorr_verify(xonly, msg, sig),
          "V1: verify(xonly_from_keypair pubkey) passes");
}

static void test_xonly_from_keypair_vector2() {
    printf("\n  -- PERF-009 vector 2 --\n");

    auto sk = Scalar::from_hex(
        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
    const auto expected_pk = h32(
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8");

    auto ref_pk = schnorr_pubkey(sk);
    CHECK(ref_pk == expected_pk, "V2: schnorr_pubkey matches BIP-340");

    auto kp = ct::schnorr_keypair_create(sk);
    auto xonly = schnorr_xonly_from_keypair(kp);
    CHECK(xonly.x_bytes == expected_pk,
          "V2: schnorr_xonly_from_keypair x_bytes matches BIP-340");

    const auto msg = h32(
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C");
    const auto aux = h32(
        "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906");
    const auto expected_sig = h64(
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
        "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7");
    auto sig = schnorr_sign(sk, msg, aux);
    CHECK(sig.to_bytes() == expected_sig, "V2: signature matches expected");
    CHECK(schnorr_verify(expected_pk, msg, sig), "V2: verify passes");
    CHECK(schnorr_verify(xonly, msg, sig),
          "V2: verify(xonly_from_keypair pubkey) passes");
}

static void test_xonly_from_keypair_vector3() {
    printf("\n  -- PERF-009 vector 3 (nonce=all-ff, odd-Y case for some internals) --\n");

    auto sk = Scalar::from_hex(
        "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710");
    const auto expected_pk = h32(
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517");

    auto ref_pk = schnorr_pubkey(sk);
    CHECK(ref_pk == expected_pk, "V3: schnorr_pubkey matches BIP-340");

    auto kp = ct::schnorr_keypair_create(sk);
    auto xonly = schnorr_xonly_from_keypair(kp);
    CHECK(xonly.x_bytes == expected_pk,
          "V3: schnorr_xonly_from_keypair x_bytes matches BIP-340");

    const auto msg = h32(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    const auto aux = h32(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    const auto expected_sig = h64(
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
        "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3");
    auto sig = schnorr_sign(sk, msg, aux);
    CHECK(sig.to_bytes() == expected_sig, "V3: signature matches expected");
    CHECK(schnorr_verify(expected_pk, msg, sig), "V3: verify passes");
    CHECK(schnorr_verify(xonly, msg, sig),
          "V3: verify(xonly_from_keypair pubkey) passes");
}

// ============================================================================
// PERF-001: normalize() correctness regression
// Confirms that schnorr_verify correctly identifies even/odd Y for a range
// of signatures — if normalize_weak were incorrectly substituted, this would
// fail on vectors where the Y parity bit matters.
// ============================================================================

static void test_verify_y_parity_correctness() {
    printf("\n  -- PERF-001: verify Y-parity correctness (normalize not normalize_weak) --\n");

    // Use the four BIP-340 sign vectors as ground truth.
    // Each produces a specific R.y parity internally — a wrong normalize_weak
    // call in schnorr_verify would occasionally produce false negatives.
    struct Vec {
        const char* sk_hex;
        const char* pk_hex;
        const char* msg_hex;
        const char* aux_hex;
        const char* sig_hex;
    };
    static const Vec vectors[] = {
        {
            "0000000000000000000000000000000000000000000000000000000000000003",
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
        },
        {
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
        },
        {
            "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"
        },
        {
            "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
            "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"
        },
    };

    for (int i = 0; i < 4; ++i) {
        const auto& v = vectors[i];
        auto pk   = h32(v.pk_hex);
        auto msg  = h32(v.msg_hex);
        auto sig_bytes = h64(v.sig_hex);
        auto sig  = SchnorrSignature::from_bytes(sig_bytes);
        char lbl[64];
        std::snprintf(lbl, sizeof(lbl),
                      "PERF-001: vector %d verify passes (Y-parity correct)", i);
        CHECK(schnorr_verify(pk, msg, sig), lbl);
    }
}

// ============================================================================
// Entry
// ============================================================================

int test_perf_schnorr_correctness_run() {
    printf("================================================================\n");
    printf("  Schnorr hot-path correctness regression (PERF-001 / PERF-009)\n");
    printf("================================================================\n");

    test_xonly_from_keypair_vector0();
    test_xonly_from_keypair_vector1();
    test_xonly_from_keypair_vector2();
    test_xonly_from_keypair_vector3();
    test_verify_y_parity_correctness();

    printf("\n================================================================\n");
    printf("  Results: %d / %d passed\n", tests_passed, tests_run);
    printf("================================================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() {
    return test_perf_schnorr_correctness_run();
}
#endif
