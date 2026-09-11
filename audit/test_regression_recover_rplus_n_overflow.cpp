// ============================================================================
// REGRESSION: ECDSA recover must reject r >= (p - n) in the recid&2 branch
// (bbhunt-001)
// ============================================================================
// Bug: ecdsa_recover(), when recid bit 1 is set, reconstructs R.x = r + n as a
// field element. FieldElement::operator+ reduces mod p, so for any r >= (p - n)
// the sum r + n silently wraps to (r + n - p) -- a DIFFERENT x-coordinate --
// instead of being rejected. A wrapped x that happens to be liftable then
// yields a BOGUS public key returned as success, whereas upstream libsecp256k1
// (secp256k1_ecdsa_sig_recover) returns 0 for r >= p-n. This is a cross-backend
// consensus divergence and is attacker-craftable (recid&2 + r in [p-n, n) covers
// almost the entire scalar range -- it is NOT the ~2^-128 honest case).
//
// Fix: recovery.cpp adds a branchless r < (p - n) guard before r + n and returns
// failure when r >= p-n. The same guard is mirrored in the CUDA and OpenCL
// recovery kernels. The shim (secp256k1_ecdsa_recover) and native ABI
// (ufsecp_ecdsa_recover) both route through secp256k1::ecdsa_recover, so this
// one CPU guard covers CPU + shim + ABI.
//
// Tests:
//   REC-1: positive control -- a real sign->recover round-trip still succeeds
//          and returns the correct pubkey (the guard did not break recovery).
//   REC-2: r = Gx + (p-n) with recid 2 and 3 -> recover FAILS.
//          The wrapped x = r + n - p = Gx is liftable (to +/-G), so WITHOUT the
//          guard this returned a bogus pubkey as success. With the guard it
//          returns {infinity,false}, matching upstream.
//   REC-3: r = p - n exactly (the boundary, equality) with recid 2/3 -> FAILS.
//   REC-4: r = n - 1 (well above p-n) with recid 2/3 -> FAILS.
// ============================================================================

#include <array>
#include <cstdint>
#include <cstdio>

#include "secp256k1/recovery.hpp"
#include "secp256k1/ecdsa.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"

using secp256k1::fast::Scalar;
using secp256k1::fast::Point;
using secp256k1::ECDSASignature;
using secp256k1::ecdsa_recover;
using secp256k1::ecdsa_sign_recoverable;

static int g_pass = 0, g_fail = 0;
static void check(bool cond, const char* msg) {
    if (cond) { ++g_pass; std::printf("    [OK] %s\n", msg); }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", msg); }
    std::fflush(stdout);
}

// Generator x-coordinate (big-endian).
static const std::array<uint8_t, 32> GX_BE = {
    0x79,0xBE,0x66,0x7E, 0xF9,0xDC,0xBB,0xAC, 0x55,0xA0,0x62,0x95, 0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB, 0x2D,0xCE,0x28,0xD9, 0x59,0xF2,0x81,0x5B, 0x16,0xF8,0x17,0x98
};
// p - n (== upstream secp256k1_ecdsa_const_p_minus_order), big-endian.
static const std::array<uint8_t, 32> PMN_BE = {
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01,
    0x45,0x51,0x23,0x19, 0x50,0xB7,0x5F,0xC4, 0x40,0x2D,0xA1,0x72, 0x2F,0xC9,0xBA,0xEE
};
// n - 1, big-endian (order ends ...D0364141 -> ...D0364140).
static const std::array<uint8_t, 32> N_MINUS_1_BE = {
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6, 0xAF,0x48,0xA0,0x3B, 0xBF,0xD2,0x5E,0x8C, 0xD0,0x36,0x41,0x40
};

// Big-endian 256-bit addition (no modular reduction).
static std::array<uint8_t, 32> add_be(const std::array<uint8_t, 32>& a,
                                      const std::array<uint8_t, 32>& b) {
    std::array<uint8_t, 32> r{};
    unsigned carry = 0;
    for (int i = 31; i >= 0; --i) {
        unsigned const s = static_cast<unsigned>(a[static_cast<unsigned>(i)]) +
                           static_cast<unsigned>(b[static_cast<unsigned>(i)]) + carry;
        r[static_cast<unsigned>(i)] = static_cast<uint8_t>(s & 0xFFu);
        carry = s >> 8;
    }
    return r;
}

static bool recover_fails(const std::array<uint8_t, 32>& r_be, int recid) {
    std::array<uint8_t, 32> msg{};
    msg[31] = 0x2A; // arbitrary public message hash
    std::array<uint8_t, 32> one{}; one[31] = 0x01;
    ECDSASignature sig{Scalar::from_bytes(r_be), Scalar::from_bytes(one)};
    auto [Q, ok] = ecdsa_recover(msg, sig, recid);
    return !ok; // must be rejected
}

#ifndef UNIFIED_AUDIT_RUNNER
int main() {
#else
int test_regression_recover_rplus_n_overflow_run() {
#endif
    std::printf("====================================================================\n");
    std::printf("REGRESSION: ECDSA recover rejects r >= (p-n) in recid&2 (bbhunt-001)\n");
    std::printf("====================================================================\n\n");

    // REC-1: positive control -- real round-trip still recovers the right key.
    {
        std::array<uint8_t, 32> sk_bytes{};
        sk_bytes[31] = 0x2B; sk_bytes[0] = 0x11; // arbitrary non-zero key
        Scalar sk = Scalar::from_bytes(sk_bytes);
        Point pk = Point::generator().scalar_mul(sk);

        std::array<uint8_t, 32> msg{};
        for (int i = 0; i < 32; ++i) msg[static_cast<unsigned>(i)] = static_cast<uint8_t>(0x40 + i);

        auto rsig = ecdsa_sign_recoverable(msg, sk);
        auto [Q, ok] = ecdsa_recover(msg, rsig.sig, rsig.recid);
        check(ok, "REC-1a: round-trip recover succeeds");
        check(ok && !Q.is_infinity() && Q.to_compressed() == pk.to_compressed(),
              "REC-1b: recovered pubkey matches d*G");
    }

    // REC-2: r = Gx + (p-n). Wrapped x = Gx is liftable -> pre-fix returned a
    // bogus pubkey as success; post-fix must reject for both recid 2 and 3.
    {
        std::array<uint8_t, 32> r = add_be(GX_BE, PMN_BE); // < n, and >= p-n
        check(recover_fails(r, 2), "REC-2a: r=Gx+(p-n), recid=2 -> rejected");
        check(recover_fails(r, 3), "REC-2b: r=Gx+(p-n), recid=3 -> rejected");
    }

    // REC-3: r = p-n exactly (equality boundary) -> rejected (>= includes ==).
    {
        check(recover_fails(PMN_BE, 2), "REC-3a: r=p-n, recid=2 -> rejected");
        check(recover_fails(PMN_BE, 3), "REC-3b: r=p-n, recid=3 -> rejected");
    }

    // REC-4: r = n-1 (well above p-n) -> rejected.
    {
        check(recover_fails(N_MINUS_1_BE, 2), "REC-4a: r=n-1, recid=2 -> rejected");
        check(recover_fails(N_MINUS_1_BE, 3), "REC-4b: r=n-1, recid=3 -> rejected");
    }

    std::printf("\n--- Result: %d passed, %d failed ---\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
