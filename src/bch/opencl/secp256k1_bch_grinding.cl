// =============================================================================
// secp256k1_bch_grinding.cl — BCH RPA EC Grinding (OpenCL)
// =============================================================================
// Finds a signature nonce k such that:
//   SHA256(SHA256(compact_sig(k)))[0:prefix_bits] == paycode_prefix
//
// Algorithm per work-item:
//   k = rfc6979_hedged(sk, msg, thread_nonce)   // unique k per work-item
//   sig = ct_ecdsa_sign_with_k(sk, msg, k)       // CT signing
//   h = SHA256(SHA256(sig.r || sig.s))            // double-hash compact sig
//   if h[0:prefix_bits] == prefix: atomic store result
//
// CPU (bench_bch):  ~78k/s single core, ~590k/s (16 cores)
// OpenCL:           expected ~30-100M/s depending on GPU and prefix length
//
// Requires (included by build system):
//   secp256k1_extended.cl  — SHA256Ctx, hmac_sha256_impl, scalar ops
//   secp256k1_ct_ops.cl    — CT helper macros
//   secp256k1_ct_scalar.cl — ct_scalar_*, ct_scalar_normalize_low_s
//   secp256k1_ct_point.cl  — ct_generator_mul_impl, ct_jacobian_to_affine
//   secp256k1_hash160.cl   — sha256_oneshot_impl (one-shot SHA-256)
// =============================================================================

#ifndef SECP256K1_BCH_GRINDING_CL
#define SECP256K1_BCH_GRINDING_CL

// =============================================================================
// Hedged RFC 6979 nonce (RFC 6979 §3.6 + 4-byte extra entropy)
// =============================================================================
// Standard RFC 6979 with extra_nonce appended to the HMAC-DRBG seed.
// Gives each OpenCL work-item a unique, valid deterministic nonce without
// random number generators.
//
// Extra bytes format: extra_nonce in little-endian (4 bytes).
// HMAC inputs use the 101-byte hedged variant:
//   V || 0x00 || priv_bytes || msg_hash || extra[4]   (101 bytes)
//   V || 0x01 || priv_bytes || msg_hash || extra[4]   (101 bytes)
// =============================================================================
inline void rfc6979_hedged_nonce_impl(
    const Scalar* priv,
    const uchar   msg_hash[32],
    uint          extra_nonce,
    Scalar*       k_out)
{
    uchar priv_bytes[32];
    scalar_to_bytes_impl(priv, priv_bytes);

    uchar extra[4];
    extra[0] = (uchar)(extra_nonce);
    extra[1] = (uchar)(extra_nonce >>  8);
    extra[2] = (uchar)(extra_nonce >> 16);
    extra[3] = (uchar)(extra_nonce >> 24);

    uchar V[32], K_[32];
    for (int i = 0; i < 32; i++) { V[i] = 0x01; K_[i] = 0x00; }

    uchar hmac_in[101];
    for (int i = 0; i < 32; i++) hmac_in[i] = V[i];
    hmac_in[32] = 0x00;
    for (int i = 0; i < 32; i++) hmac_in[33 + i] = priv_bytes[i];
    for (int i = 0; i < 32; i++) hmac_in[65 + i] = msg_hash[i];
    for (int i = 0; i < 4;  i++) hmac_in[97 + i] = extra[i];

    // K = HMAC_K(V || 0x00 || priv || msg || extra)
    hmac_sha256_impl(K_, 32, hmac_in, 101, K_);
    // V = HMAC_K(V)
    hmac_sha256_impl(K_, 32, V, 32, V);

    // K = HMAC_K(V || 0x01 || priv || msg || extra)
    for (int i = 0; i < 32; i++) hmac_in[i] = V[i];
    hmac_in[32] = 0x01;
    hmac_sha256_impl(K_, 32, hmac_in, 101, K_);
    // V = HMAC_K(V)
    hmac_sha256_impl(K_, 32, V, 32, V);

    // k candidate: V = HMAC_K(V), interpret as scalar
    hmac_sha256_impl(K_, 32, V, 32, V);
    scalar_from_bytes_impl(V, k_out);
    // k >= n with probability ~2^-128 — negligible for grinding; skip retry.
}

// =============================================================================
// Double-SHA256 of a 64-byte input → 32-byte output
// Used to hash the compact (r || s) signature before prefix check.
// =============================================================================
inline void double_sha256_64(const uchar in64[64], uchar out32[32]) {
    uchar inner[32];
    sha256_oneshot_impl(in64, 64, inner);
    sha256_oneshot_impl(inner, 32, out32);
}

// =============================================================================
// Prefix match: check that hash[0:prefix_bits] == prefix_data[0:prefix_bits]
// prefix_bits == 0  → always match (every sig accepted, used for throughput bench)
// prefix_bits == 8  → first byte must match
// prefix_bits == 16 → first two bytes must match
// prefix_bits == 24 → first three bytes must match
// =============================================================================
inline bool bch_prefix_matches(
    const uchar hash[32],
    uchar       prefix_bits,
    const uchar prefix_data[4])
{
    if (prefix_bits == 0) return true;
    uchar full_bytes = prefix_bits >> 3;          // floor(prefix_bits / 8)
    uchar rem_bits   = prefix_bits & 7;           // prefix_bits % 8
    for (uchar i = 0; i < full_bytes; i++)
        if (hash[i] != prefix_data[i]) return false;
    if (rem_bits == 0) return true;
    uchar mask = (uchar)(0xffu << (8u - rem_bits));
    return (hash[full_bytes] & mask) == (prefix_data[full_bytes] & mask);
}

// =============================================================================
// Main grinding kernel
// =============================================================================
// Each work-item attempts one nonce: base_nonce + get_global_id(0).
// On match: atomically writes the winning nonce and signature to output.
//
// Launch: global_size = number of attempts per batch
//         local_size  = workgroup size (e.g. 64 or 256)
//
// Outputs:
//   result_nonce — initialise to -1 before launch; set to winning nonce on match
//   result_sig64 — 64-byte compact sig (r || s) of the winning nonce
// =============================================================================
__kernel void rpa_grind_kernel(
    __global const uchar* sk32,          // sender private key (32 bytes, constant)
    __global const uchar* msg32,         // sighash message   (32 bytes, constant)
    uchar                 prefix_bits,   // 0, 8, 16, or 24 — bits to match
    __global const uchar* prefix_data,   // first ceil(prefix_bits/8) bytes to match
    uint                  base_nonce,    // nonce offset for this launch batch
    __global int*         result_nonce,  // in/out: -1 until a match is found
    __global uchar*       result_sig64)  // out: 64-byte compact sig on match
{
    uint gid   = get_global_id(0);
    uint nonce = base_nonce + gid;

    // Copy key and message to private memory (avoids repeated global reads)
    uchar sk[32], msg[32];
    for (int i = 0; i < 32; i++) { sk[i] = sk32[i]; msg[i] = msg32[i]; }

    // Parse private key
    Scalar priv;
    scalar_from_bytes_impl(sk, &priv);
    if (ct_scalar_is_zero(&priv)) return;

    // ── Step 1: derive unique nonce k via hedged RFC 6979 ─────────────────────
    Scalar k;
    rfc6979_hedged_nonce_impl(&priv, msg, nonce, &k);
    if (ct_scalar_is_zero(&k)) return;

    // ── Step 2: CT ECDSA sign with nonce k ────────────────────────────────────
    // R = k * G  (constant-time generator multiplication)
    CTJacobianPoint R_jac;
    ct_generator_mul_impl(&k, &R_jac);

    // R → affine (branchless)
    FieldElement rx, ry;
    ct_jacobian_to_affine(&R_jac, &rx, &ry);

    // r = rx mod n
    Scalar r;
    for (int i = 0; i < 4; i++) r.limbs[i] = rx.limbs[i];
    ct_reduce_order(&r);
    if (ct_scalar_is_zero(&r)) return;

    // k_inv = k^(-1) mod n  (CT)
    Scalar k_inv;
    ct_scalar_inverse_impl(&k, &k_inv);

    // s = k^(-1) * (msg + r * priv) mod n  (CT)
    Scalar msg_s;
    scalar_from_bytes_impl(msg, &msg_s);
    Scalar r_priv, sum, s;
    ct_scalar_mul_impl(&r, &priv, &r_priv);
    ct_scalar_add_impl(&msg_s, &r_priv, &sum);
    ct_scalar_mul_impl(&k_inv, &sum, &s);

    // Low-S normalisation (BIP-62)
    ct_scalar_normalize_low_s(&s);
    if (ct_scalar_is_zero(&s)) return;

    // Serialise compact signature: r[32] || s[32]
    uchar sig64[64];
    scalar_to_bytes_impl(&r, sig64);
    scalar_to_bytes_impl(&s, sig64 + 32);

    // ── Step 3: double-SHA256 of compact sig ──────────────────────────────────
    uchar hash[32];
    double_sha256_64(sig64, hash);

    // ── Step 4: prefix match ──────────────────────────────────────────────────
    uchar pdata[4] = { 0u, 0u, 0u, 0u };
    int nb = ((int)prefix_bits + 7) >> 3;
    for (int i = 0; i < nb && i < 4; i++) pdata[i] = prefix_data[i];

    if (!bch_prefix_matches(hash, prefix_bits, pdata)) return;

    // ── Step 5: atomically claim the result slot ───────────────────────────────
    int prev = atomic_cmpxchg(result_nonce, -1, (int)nonce);
    if (prev == -1) {
        // This work-item won the race — write the signature
        for (int i = 0; i < 64; i++) result_sig64[i] = sig64[i];
    }
}

#endif // SECP256K1_BCH_GRINDING_CL
