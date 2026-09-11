/* ============================================================================
 * UltrafastSecp256k1 -- C API (ABI-stable)
 * ============================================================================
 * Shared C interface for all language bindings.
 * All types are opaque byte arrays -- no internal types exposed.
 *
 * Conventions:
 *   - Private keys:   uint8_t[32]  (big-endian scalar)
 *   - Public keys:    uint8_t[33]  (compressed) or uint8_t[65] (uncompressed)
 *   - Signatures:     uint8_t[64]  (compact R||S for ECDSA, r||s for Schnorr)
 *   - Message hashes: uint8_t[32]
 *   - Return 0 on success, non-zero on failure (unless stated otherwise)
 * ============================================================================ */

#ifndef ULTRAFAST_SECP256K1_H
#define ULTRAFAST_SECP256K1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -- Export macros ------------------------------------------------------------ */
#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef ULTRAFAST_SECP256K1_BUILDING
    #define SECP256K1_API __declspec(dllexport)
  #else
    #define SECP256K1_API __declspec(dllimport)
  #endif
#elif __GNUC__ >= 4
  #define SECP256K1_API __attribute__((visibility("default")))
#else
  #define SECP256K1_API
#endif

/* -- Version ----------------------------------------------------------------- */
#define ULTRAFAST_SECP256K1_VERSION_MAJOR 1
#define ULTRAFAST_SECP256K1_VERSION_MINOR 0
#define ULTRAFAST_SECP256K1_VERSION_PATCH 0

/** Return version string, e.g. "1.0.0" */
SECP256K1_API const char* secp256k1_version(void);

/* -- Library Lifecycle ------------------------------------------------------- */

/** Initialize library (runs selftest). Call once before any other function.
 *  Returns 0 on success, 1 on selftest failure. */
SECP256K1_API int secp256k1_init(void);

/* -- Key Operations ---------------------------------------------------------- */

/** Compute public key (compressed, 33 bytes) from private key (32 bytes).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ec_pubkey_create(
    const uint8_t privkey[32],
    uint8_t pubkey_out[33]);

/** Compute uncompressed public key (65 bytes) from private key (32 bytes).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ec_pubkey_create_uncompressed(
    const uint8_t privkey[32],
    uint8_t pubkey_out[65]);

/** Parse a public key from compressed (33 bytes) or uncompressed (65 bytes).
 *  Output is always compressed 33 bytes.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ec_pubkey_parse(
    const uint8_t* input,
    size_t input_len,
    uint8_t pubkey_out[33]);

/** Negate a private key in-place (mod n).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ec_privkey_negate(uint8_t privkey[32]);

/** Add tweak to private key in-place: key = (key + tweak) mod n.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ec_privkey_tweak_add(
    uint8_t privkey[32],
    const uint8_t tweak[32]);

/** Multiply private key by tweak in-place: key = (key * tweak) mod n.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ec_privkey_tweak_mul(
    uint8_t privkey[32],
    const uint8_t tweak[32]);

/** Verify that a private key is valid (non-zero, < curve order).
 *  Returns 1 if valid, 0 if invalid. */
SECP256K1_API int secp256k1_ec_seckey_verify(const uint8_t privkey[32]);

/* -- ECDSA ------------------------------------------------------------------- */

/** Sign a 32-byte message hash using ECDSA (RFC 6979 deterministic nonce).
 *  sig_out: 64-byte compact signature (R || S, low-S normalized).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ecdsa_sign(
    const uint8_t msg_hash[32],
    const uint8_t privkey[32],
    uint8_t sig_out[64]);

/** Verify an ECDSA signature.
 *  sig: 64-byte compact signature.
 *  pubkey: 33-byte compressed public key.
 *  Returns 1 if valid, 0 if invalid. */
SECP256K1_API int secp256k1_ecdsa_verify(
    const uint8_t msg_hash[32],
    const uint8_t sig[64],
    const uint8_t pubkey[33]);

/** Encode ECDSA signature to DER format.
 *  der_out: buffer for DER-encoded signature (max 72 bytes).
 *  der_len: on input, buffer size; on output, actual DER length.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ecdsa_signature_serialize_der(
    const uint8_t sig[64],
    uint8_t* der_out,
    size_t* der_len);

/* -- ECDSA Recovery ---------------------------------------------------------- */

/** Sign with recovery id.
 *  sig_out: 64-byte compact signature.
 *  recid_out: recovery id (0-3).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ecdsa_sign_recoverable(
    const uint8_t msg_hash[32],
    const uint8_t privkey[32],
    uint8_t sig_out[64],
    int* recid_out);

/** Recover public key from recoverable signature.
 *  pubkey_out: 33-byte compressed public key.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ecdsa_recover(
    const uint8_t msg_hash[32],
    const uint8_t sig[64],
    int recid,
    uint8_t pubkey_out[33]);

/* -- Schnorr (BIP-340) ------------------------------------------------------ */

/** Create a Schnorr signature (BIP-340).
 *  msg: 32-byte message.
 *  aux_rand: 32-byte auxiliary randomness (can be zeros).
 *  sig_out: 64-byte signature.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_schnorr_sign(
    const uint8_t msg[32],
    const uint8_t privkey[32],
    const uint8_t aux_rand[32],
    uint8_t sig_out[64]);

/** Verify a Schnorr signature (BIP-340).
 *  pubkey_x: 32-byte x-only public key.
 *  Returns 1 if valid, 0 if invalid. */
SECP256K1_API int secp256k1_schnorr_verify(
    const uint8_t msg[32],
    const uint8_t sig[64],
    const uint8_t pubkey_x[32]);

/** Get x-only public key for Schnorr (32 bytes, even Y).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_schnorr_pubkey(
    const uint8_t privkey[32],
    uint8_t pubkey_x_out[32]);

/* -- ECDH -------------------------------------------------------------------- */

/** Compute ECDH shared secret: SHA256(compressed_shared_point).
 *  pubkey: 33-byte compressed public key.
 *  secret_out: 32-byte shared secret.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ecdh(
    const uint8_t privkey[32],
    const uint8_t pubkey[33],
    uint8_t secret_out[32]);

/** ECDH x-only: SHA256(x-coordinate of shared point).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ecdh_xonly(
    const uint8_t privkey[32],
    const uint8_t pubkey[33],
    uint8_t secret_out[32]);

/** ECDH raw: raw x-coordinate of shared point (32 bytes).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_ecdh_raw(
    const uint8_t privkey[32],
    const uint8_t pubkey[33],
    uint8_t secret_out[32]);

/* -- Hashing ----------------------------------------------------------------- */

/** SHA-256 hash.
 *  digest_out: 32-byte output. */
SECP256K1_API void secp256k1_sha256(
    const uint8_t* data,
    size_t data_len,
    uint8_t digest_out[32]);

/** HASH160: RIPEMD160(SHA256(data)).
 *  digest_out: 20-byte output. */
SECP256K1_API void secp256k1_hash160(
    const uint8_t* data,
    size_t data_len,
    uint8_t digest_out[20]);

/** BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
 *  digest_out: 32-byte output. */
SECP256K1_API void secp256k1_tagged_hash(
    const char* tag,
    const uint8_t* data,
    size_t data_len,
    uint8_t digest_out[32]);

/* -- Bitcoin Addresses ------------------------------------------------------- */

/** Network constants for address generation. */
#define SECP256K1_NETWORK_MAINNET 0
#define SECP256K1_NETWORK_TESTNET 1

/** Generate P2PKH address from compressed public key.
 *  addr_out: buffer (min 35 bytes + null terminator).
 *  addr_len: on input, buffer size; on output, string length (excl. null).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_address_p2pkh(
    const uint8_t pubkey[33],
    int network,
    char* addr_out,
    size_t* addr_len);

/** Generate P2WPKH (SegWit v0) address from compressed public key.
 *  addr_out: buffer (min 62 + 1 bytes).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_address_p2wpkh(
    const uint8_t pubkey[33],
    int network,
    char* addr_out,
    size_t* addr_len);

/** Generate P2TR (Taproot) address from x-only public key (32 bytes).
 *  addr_out: buffer (min 62 + 1 bytes).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_address_p2tr(
    const uint8_t internal_key_x[32],
    int network,
    char* addr_out,
    size_t* addr_len);

/* -- WIF (Wallet Import Format) ---------------------------------------------- */

/** Encode private key to WIF string.
 *  wif_out: buffer (min 52 + 1 bytes).
 *  wif_len: on input, buffer size; on output, string length.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_wif_encode(
    const uint8_t privkey[32],
    int compressed,
    int network,
    char* wif_out,
    size_t* wif_len);

/** Decode WIF string to private key.
 *  compressed_out: 1 if compressed, 0 if uncompressed.
 *  network_out: SECP256K1_NETWORK_MAINNET or SECP256K1_NETWORK_TESTNET.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_wif_decode(
    const char* wif,
    uint8_t privkey_out[32],
    int* compressed_out,
    int* network_out);

/* -- BIP-32 (HD Key Derivation) ---------------------------------------------- */

/** Opaque BIP-32 extended key structure (78 bytes serialized). */
typedef struct {
    uint8_t data[78];     /* BIP-32 serialized form */
    uint8_t is_private;   /* 1 = xprv, 0 = xpub */
} secp256k1_bip32_key;

/** Create master key from seed.
 *  seed: 16-64 bytes.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_bip32_master_key(
    const uint8_t* seed,
    size_t seed_len,
    secp256k1_bip32_key* key_out);

/** Derive child key.
 *  index: child index (>= 0x80000000 for hardened).
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_bip32_derive_child(
    const secp256k1_bip32_key* parent,
    uint32_t index,
    secp256k1_bip32_key* child_out);

/** Derive key from path string, e.g. "m/44'/0'/0'/0/0".
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_bip32_derive_path(
    const secp256k1_bip32_key* master,
    const char* path,
    secp256k1_bip32_key* key_out);

/** Get private key bytes from extended key.
 *  Returns 0 on success, 1 if key is public. */
SECP256K1_API int secp256k1_bip32_get_privkey(
    const secp256k1_bip32_key* key,
    uint8_t privkey_out[32]);

/** Get compressed public key from extended key.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_bip32_get_pubkey(
    const secp256k1_bip32_key* key,
    uint8_t pubkey_out[33]);

/* -- Taproot (BIP-341) ------------------------------------------------------- */

/** Derive Taproot output key from internal key.
 *  merkle_root: 32-byte merkle root (NULL for key-path only).
 *  output_key_x_out: 32-byte x-only output key.
 *  parity_out: 0 = even, 1 = odd.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_taproot_output_key(
    const uint8_t internal_key_x[32],
    const uint8_t* merkle_root,
    uint8_t output_key_x_out[32],
    int* parity_out);

/** Tweak a private key for Taproot key-path spending.
 *  merkle_root: 32-byte merkle root (NULL for key-path only).
 *  tweaked_privkey_out: 32-byte tweaked private key.
 *  Returns 0 on success. */
SECP256K1_API int secp256k1_taproot_tweak_privkey(
    const uint8_t privkey[32],
    const uint8_t* merkle_root,
    uint8_t tweaked_privkey_out[32]);

/** Verify Taproot commitment (control block validation).
 *  Returns 1 if valid, 0 if invalid. */
SECP256K1_API int secp256k1_taproot_verify_commitment(
    const uint8_t output_key_x[32],
    int output_key_parity,
    const uint8_t internal_key_x[32],
    const uint8_t* merkle_root,
    size_t merkle_root_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ULTRAFAST_SECP256K1_H */
