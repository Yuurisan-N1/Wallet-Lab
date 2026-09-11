/*
 * libsecp_ufsecp_shim.c — Reverse bridge: ufsecp_* ABI → secp256k1_* (libsecp256k1)
 * Enables CAAS Python audit scripts to run against bitcoin-core/libsecp256k1.
 *
 * ABI matches UltrafastSecp256k1 ufsecp_* C API (from ci/_ufsecp.py _bind).
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o /tmp/libsecp_ufsecp_shim.so /tmp/libsecp_ufsecp_shim.c \
 *       -I/tmp/libsecp-src/include \
 *       -L/tmp/libsecp-build/lib -lsecp256k1 \
 *       -Wl,-rpath,/tmp/libsecp-build/lib
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_recovery.h"
#include "secp256k1_ecdh.h"

typedef int ufsecp_error_t;
#define UFSECP_OK            0
#define UFSECP_ERR_BAD_INPUT 1
#define UFSECP_ERR_INTERNAL  2

#define _FLAGS (SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
#define _COMP  SECP256K1_EC_COMPRESSED

/* ── context: int ufsecp_ctx_create(void** out_ctx) ──────────────────── */
ufsecp_error_t ufsecp_ctx_create(void** out_ctx) {
    secp256k1_context* ctx = secp256k1_context_create(_FLAGS);
    if (!ctx) return UFSECP_ERR_INTERNAL;
    *out_ctx = ctx;
    return UFSECP_OK;
}

void ufsecp_ctx_destroy(void* ctx) {
    secp256k1_context_destroy((secp256k1_context*)ctx);
}

ufsecp_error_t ufsecp_ctx_randomize(void* ctx, const uint8_t* seed32) {
    return secp256k1_context_randomize((secp256k1_context*)ctx, seed32)
           ? UFSECP_OK : UFSECP_ERR_BAD_INPUT;
}

/* ── pubkey: int ufsecp_pubkey_create(ctx, sk32_in, out33_out) ───────── */
ufsecp_error_t ufsecp_pubkey_create(void* ctx,
                                     const uint8_t* sk32,
                                     uint8_t* out33) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create((secp256k1_context*)ctx, &pk, sk32))
        return UFSECP_ERR_BAD_INPUT;
    size_t outlen = 33;
    secp256k1_ec_pubkey_serialize((secp256k1_context*)ctx, out33, &outlen, &pk, _COMP);
    return UFSECP_OK;
}

ufsecp_error_t ufsecp_pubkey_parse(void* ctx,
                                    const uint8_t* in, size_t inlen,
                                    uint8_t* out33) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse((secp256k1_context*)ctx, &pk, in, inlen))
        return UFSECP_ERR_BAD_INPUT;
    size_t outlen = 33;
    secp256k1_ec_pubkey_serialize((secp256k1_context*)ctx, out33, &outlen, &pk, _COMP);
    return UFSECP_OK;
}

/* ── seckey: int ufsecp_seckey_verify(ctx, sk32) ─────────────────────── */
ufsecp_error_t ufsecp_seckey_verify(void* ctx, const uint8_t* sk32) {
    return secp256k1_ec_seckey_verify((secp256k1_context*)ctx, sk32)
           ? UFSECP_OK : UFSECP_ERR_BAD_INPUT;
}

/* ── ECDSA: int ufsecp_ecdsa_sign(ctx, msg32, sk32, sig64_out) ───────── */
ufsecp_error_t ufsecp_ecdsa_sign(void* ctx,
                                  const uint8_t* msg32,
                                  const uint8_t* sk32,
                                  uint8_t* sig64) {
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign((secp256k1_context*)ctx, &sig, msg32, sk32, NULL, NULL))
        return UFSECP_ERR_INTERNAL;
    secp256k1_ecdsa_signature_serialize_compact((secp256k1_context*)ctx, sig64, &sig);
    return UFSECP_OK;
}

/* ── ECDSA verify: int ufsecp_ecdsa_verify(ctx, msg32, sig64, pk33) ──── */
ufsecp_error_t ufsecp_ecdsa_verify(void* ctx,
                                    const uint8_t* msg32,
                                    const uint8_t* sig64,
                                    const uint8_t* pk33) {
    secp256k1_context* c = (secp256k1_context*)ctx;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(c, &pk, pk33, 33)) return UFSECP_ERR_BAD_INPUT;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(c, &sig, sig64)) return UFSECP_ERR_BAD_INPUT;
    secp256k1_ecdsa_signature_normalize(c, &sig, &sig);
    return secp256k1_ecdsa_verify(c, &sig, msg32, &pk) ? UFSECP_OK : UFSECP_ERR_BAD_INPUT;
}

/* ── ECDSA recoverable sign: int ufsecp_ecdsa_sign_recoverable(ctx, msg32, sk32, sig64, recid*) */
ufsecp_error_t ufsecp_ecdsa_sign_recoverable(void* ctx,
                                              const uint8_t* msg32,
                                              const uint8_t* sk32,
                                              uint8_t* sig64,
                                              int* recid) {
    secp256k1_context* c = (secp256k1_context*)ctx;
    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_sign_recoverable(c, &rsig, msg32, sk32, NULL, NULL))
        return UFSECP_ERR_INTERNAL;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(c, sig64, recid, &rsig);
    return UFSECP_OK;
}

/* ── ECDH: int ufsecp_ecdh(ctx, sk32, pk33, out32) ──────────────────── */
static int _ecdh_hashfn_raw(unsigned char* out, const unsigned char* x32,
                             const unsigned char* y32, void* data) {
    (void)y32; (void)data;
    memcpy(out, x32, 32);
    return 1;
}

ufsecp_error_t ufsecp_ecdh(void* ctx,
                            const uint8_t* sk32,
                            const uint8_t* pk33,
                            uint8_t* out32) {
    secp256k1_context* c = (secp256k1_context*)ctx;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(c, &pk, pk33, 33)) return UFSECP_ERR_BAD_INPUT;
    return secp256k1_ecdh(c, out32, &pk, sk32, _ecdh_hashfn_raw, NULL)
           ? UFSECP_OK : UFSECP_ERR_BAD_INPUT;
}

/* ── Schnorr (BIP-340) ────────────────────────────────────────────────── */
ufsecp_error_t ufsecp_schnorr_sign(void* ctx,
                                    const uint8_t* msg32,
                                    const uint8_t* sk32,
                                    const uint8_t* aux32,
                                    uint8_t* sig64) {
    secp256k1_context* c = (secp256k1_context*)ctx;
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(c, &kp, sk32)) return UFSECP_ERR_BAD_INPUT;
    return secp256k1_schnorrsig_sign32(c, sig64, msg32, &kp, aux32)
           ? UFSECP_OK : UFSECP_ERR_INTERNAL;
}

ufsecp_error_t ufsecp_schnorr_verify(void* ctx,
                                      const uint8_t* msg32,
                                      const uint8_t* sig64,
                                      const uint8_t* xonly32) {
    secp256k1_context* c = (secp256k1_context*)ctx;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(c, &xpk, xonly32)) return UFSECP_ERR_BAD_INPUT;
    return secp256k1_schnorrsig_verify(c, sig64, msg32, 32, &xpk)
           ? UFSECP_OK : UFSECP_ERR_BAD_INPUT;
}

/* ── Stubs for unimplemented functions (return advisory skip 77) ──────── */
#define _STUB(name, ...) ufsecp_error_t name(__VA_ARGS__) { return 77; }
_STUB(ufsecp_bip32_master, void* c, const uint8_t* s, size_t l, void* o)
_STUB(ufsecp_bip32_derive, void* c, void* k, uint32_t i, void* o)
_STUB(ufsecp_bip32_derive_path, void* c, void* k, const uint8_t* p, void* o)
_STUB(ufsecp_bip32_privkey, void* c, void* k, uint8_t* o)
_STUB(ufsecp_bip32_pubkey, void* c, void* k, uint8_t* o)

/* ── Selftest ─────────────────────────────────────────────────────────── */
int ufsecp_selftest(void) {
    void* ctx = NULL;
    if (ufsecp_ctx_create(&ctx) != UFSECP_OK) return 0;
    uint8_t sk[32] = {1};
    int ok = (ufsecp_seckey_verify(ctx, sk) == UFSECP_OK);
    ufsecp_ctx_destroy(ctx);
    return ok;
}

const char* ufsecp_version(void) { return "libsecp256k1-reverse-bridge/4.0"; }
