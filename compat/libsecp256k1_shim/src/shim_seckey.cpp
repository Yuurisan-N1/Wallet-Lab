// ============================================================================
// shim_seckey.cpp -- Secret key verification and tweaking
// ============================================================================
#include "secp256k1.h"
#include "shim_internal.hpp"

#include <cstring>
#include <array>

#include "secp256k1/scalar.hpp"
#include "secp256k1/ct/scalar.hpp"
#include "secp256k1/detail/secure_erase.hpp"   // RT-05

using namespace secp256k1::fast;

extern "C" {

int secp256k1_ec_seckey_verify(
    const secp256k1_context *ctx, const unsigned char *seckey)
{
    SHIM_REQUIRE_CTX(ctx);
    if (!seckey) {
        secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ec_seckey_verify: seckey is NULL");
        return 0;
    }
    // RT-05: erase the parsed private-key scalar before returning.
    Scalar k;
    bool ok = Scalar::parse_bytes_strict_nonzero(seckey, k);
    secp256k1::detail::secure_erase(&k, sizeof(k));
    return ok ? 1 : 0;
}

int secp256k1_ec_seckey_negate(
    const secp256k1_context *ctx, unsigned char *seckey)
{
    SHIM_REQUIRE_CTX(ctx);
    if (!seckey) {
        secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ec_seckey_negate: seckey is NULL");
        return 0;
    }
    Scalar k;
    if (!Scalar::parse_bytes_strict_nonzero(seckey, k)) {
        secp256k1::detail::secure_erase(&k, sizeof(k));   // RT-05
        // PASS-COMPAT-001: upstream zeroes the caller's seckey on failure
        // (secp256k1_scalar_cmov(&sec, &zero, !ret) + get_b32). Match it so a
        // failed seckey op never leaves a usable key in the caller's buffer.
        std::memset(seckey, 0, 32);
        return 0;
    }
    // CT-SECKEY-NEGATE: use scalar_cneg with always-negate mask (all-ones) so
    // that the negate is unconditional and branchless on the secret key value.
    // k.negate() is variable-time (data-dependent branch on is_zero) — banned
    // on secret key material per CT signing guardrail.
    auto neg = secp256k1::ct::scalar_cneg(k, ~std::uint64_t(0));
    auto out = neg.to_bytes();
    std::memcpy(seckey, out.data(), 32);
    // RT-05: erase parsed key, negated scalar, and the serialized new key.
    secp256k1::detail::secure_erase(&k, sizeof(k));
    secp256k1::detail::secure_erase(&neg, sizeof(neg));
    secp256k1::detail::secure_erase(out.data(), out.size());
    return 1;
}

int secp256k1_ec_seckey_tweak_add(
    const secp256k1_context *ctx, unsigned char *seckey,
    const unsigned char *tweak32)
{
    SHIM_REQUIRE_CTX(ctx);
    if (!seckey) {
        secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ec_seckey_tweak_add: seckey is NULL");
        return 0;
    }
    if (!tweak32) {
        secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ec_seckey_tweak_add: tweak32 is NULL");
        return 0;
    }
    // RT-05: k is the caller's private key; t (a BIP-32 IL tweak) is also
    // secret-derived; result/out is the NEW private key. Erase all on every path.
    Scalar k, t;
    if (!Scalar::parse_bytes_strict_nonzero(seckey, k)) {
        secp256k1::detail::secure_erase(&k, sizeof(k));   // RT-05
        secp256k1::detail::secure_erase(&t, sizeof(t));
        std::memset(seckey, 0, 32);  // PASS-COMPAT-001: upstream zeroes seckey on failure
        return 0;
    }
    // tweak in [0, n-1]; 0 is valid (result == seckey)
    if (!Scalar::parse_bytes_strict(tweak32, t)) {
        secp256k1::detail::secure_erase(&k, sizeof(k));   // RT-05
        secp256k1::detail::secure_erase(&t, sizeof(t));
        std::memset(seckey, 0, 32);  // PASS-COMPAT-001: upstream zeroes seckey on failure
        return 0;
    }
    auto result = secp256k1::ct::scalar_add(k, t);  // CT-001: k is secret
    if (result.is_zero_ct()) {
        secp256k1::detail::secure_erase(&k, sizeof(k));        // RT-05
        secp256k1::detail::secure_erase(&t, sizeof(t));
        secp256k1::detail::secure_erase(&result, sizeof(result));
        std::memset(seckey, 0, 32);  // PASS-COMPAT-001: upstream zeroes seckey on failure
        return 0;
    }
    auto out = result.to_bytes();
    std::memcpy(seckey, out.data(), 32);
    secp256k1::detail::secure_erase(&k, sizeof(k));           // RT-05
    secp256k1::detail::secure_erase(&t, sizeof(t));
    secp256k1::detail::secure_erase(&result, sizeof(result));
    secp256k1::detail::secure_erase(out.data(), out.size());
    return 1;
}

int secp256k1_ec_seckey_tweak_mul(
    const secp256k1_context *ctx, unsigned char *seckey,
    const unsigned char *tweak32)
{
    SHIM_REQUIRE_CTX(ctx);
    if (!seckey) {
        secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ec_seckey_tweak_mul: seckey is NULL");
        return 0;
    }
    if (!tweak32) {
        secp256k1_shim_call_illegal_cb(ctx, "secp256k1_ec_seckey_tweak_mul: tweak32 is NULL");
        return 0;
    }
    // RT-05: k is the caller's private key; result/out is the NEW private key.
    Scalar k, t;
    if (!Scalar::parse_bytes_strict_nonzero(seckey, k)) {
        secp256k1::detail::secure_erase(&k, sizeof(k));   // RT-05
        secp256k1::detail::secure_erase(&t, sizeof(t));
        std::memset(seckey, 0, 32);  // PASS-COMPAT-001: upstream zeroes seckey on failure
        return 0;
    }
    if (!Scalar::parse_bytes_strict_nonzero(tweak32, t)) {
        secp256k1::detail::secure_erase(&k, sizeof(k));   // RT-05
        secp256k1::detail::secure_erase(&t, sizeof(t));
        std::memset(seckey, 0, 32);  // PASS-COMPAT-001: upstream zeroes seckey on failure
        return 0;
    }
    auto result = secp256k1::ct::scalar_mul(k, t);  // CT-001: k is secret
    if (result.is_zero_ct()) {
        secp256k1::detail::secure_erase(&k, sizeof(k));        // RT-05
        secp256k1::detail::secure_erase(&t, sizeof(t));
        secp256k1::detail::secure_erase(&result, sizeof(result));
        std::memset(seckey, 0, 32);  // PASS-COMPAT-001: upstream zeroes seckey on failure
        return 0;
    }
    auto out = result.to_bytes();
    std::memcpy(seckey, out.data(), 32);
    secp256k1::detail::secure_erase(&k, sizeof(k));           // RT-05
    secp256k1::detail::secure_erase(&t, sizeof(t));
    secp256k1::detail::secure_erase(&result, sizeof(result));
    secp256k1::detail::secure_erase(out.data(), out.size());
    return 1;
}

} // extern "C"
