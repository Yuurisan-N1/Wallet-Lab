// =============================================================================
// secp256k1_ecdh.h -- ECDH Key Agreement for Metal
// =============================================================================
// Three variants:
//   - ecdh_compute_raw:   raw 32-byte x-coordinate
//   - ecdh_compute_xonly: SHA-256(x)
//   - ecdh_compute:       SHA-256(0x02|x) standard compressed hash
//
// SECURITY (RED-001 / P1-SEC-001 / TASK-006): every variant takes a SECRET
// private key scalar. The shared-secret scalar multiplication MUST be
// constant-time — a timing oracle on the Metal GPU (shared shader-cache /
// EM side-channel on Apple Silicon multi-tenant hosts) would otherwise
// leak bit windows of the private key. Until this file was updated, the
// implementations called `scalar_mul(peer_pubkey, private_key)` which (a)
// did not have a JacobianPoint overload in the first place (link-error
// surface) and (b) wherever it did link, used the fixed-window var-time
// scalar_mul at src/metal/shaders/secp256k1_point.h:340 — a real VT path
// that breaks GPU Guardrail #8.
//
// The fix below mirrors the OpenCL `ct_ecdh_scalar_mul_affine` helper
// (src/opencl/kernels/secp256k1_extended.cl:1566) but is adapted for
// Metal's 8×32-bit Scalar256 limb layout: bit `i` of the scalar lives at
// `(sk.limbs[i >> 5] >> (i & 31)) & 1`. No branches on scalar bits, no
// table lookups, no early exits — a bit-by-bit double-and-add loop with
// mask-select XOR over x/y/z/infinity is the only way to keep this path
// CT on a GPU.
// =============================================================================

#ifndef SECP256K1_ECDH_H
#define SECP256K1_ECDH_H

// ---------------------------------------------------------------------------
// CT helper: bit-by-bit double-and-add scalar multiplication of a Jacobian
// peer-pubkey by a SECRET scalar. No data-dependent branches; no GLV; no
// wNAF; no table lookups indexed by secret bits. Mask-XOR conditional move
// over every limb of x/y/z plus the infinity flag.
// ---------------------------------------------------------------------------
inline JacobianPoint ct_ecdh_scalar_mul_metal(thread const JacobianPoint& peer,
                                              thread const Scalar256& sk) {
    JacobianPoint R = point_at_infinity();
    JacobianPoint T;
    for (int i = 255; i >= 0; --i) {
        R = jacobian_double(R);
        T = jacobian_add(R, peer);
        // CT select: if bit `i` of sk is 1, R = T; else R = R.
        // word = i / 32, bit = i % 32. Mask is 0xFFFFFFFF when bit=1, else 0.
        uint word = (uint)(i >> 5);
        uint bit  = (sk.limbs[word] >> (uint)(i & 31)) & 1u;
        uint mask = -(uint)bit;
        for (int j = 0; j < 8; ++j) {
            R.x.limbs[j] ^= mask & (R.x.limbs[j] ^ T.x.limbs[j]);
            R.y.limbs[j] ^= mask & (R.y.limbs[j] ^ T.y.limbs[j]);
            R.z.limbs[j] ^= mask & (R.z.limbs[j] ^ T.z.limbs[j]);
        }
        // infinity flag CT-select on the same mask.
        R.infinity = (R.infinity & ~mask) | (T.infinity & mask);
    }
    return R;
}

// ECDH: raw x-coordinate (8x32 limbs -> big-endian bytes)
inline bool ecdh_compute_raw_metal(thread const Scalar256& private_key,
                                   thread const JacobianPoint& peer_pubkey,
                                   thread uchar* out) {
    JacobianPoint shared = ct_ecdh_scalar_mul_metal(peer_pubkey, private_key);
    if (shared.infinity) return false;

    FieldElement z_inv = field_inv(shared.z);
    FieldElement z_inv2 = field_sqr(z_inv);
    FieldElement x_aff = field_mul(shared.x, z_inv2);

    for (int i = 0; i < 8; ++i) {
        uint v = x_aff.limbs[7 - i];
        out[i * 4 + 0] = (uchar)(v >> 24);
        out[i * 4 + 1] = (uchar)(v >> 16);
        out[i * 4 + 2] = (uchar)(v >> 8);
        out[i * 4 + 3] = (uchar)(v);
    }
    return true;
}

// ECDH: x-only hash SHA-256(x)
inline bool ecdh_compute_xonly_metal(thread const Scalar256& private_key,
                                     thread const JacobianPoint& peer_pubkey,
                                     thread uchar* out) {
    uchar x_bytes[32];
    if (!ecdh_compute_raw_metal(private_key, peer_pubkey, x_bytes))
        return false;

    SHA256Ctx ctx = sha256_init();
    ctx = sha256_update(ctx, x_bytes, 32);
    sha256_final(ctx, out);
    return true;
}

// ECDH: standard compressed hash SHA-256(prefix || x)
// prefix = 0x02 if Y is even, 0x03 if Y is odd — must match CPU/CUDA behaviour.
inline bool ecdh_compute_metal(thread const Scalar256& private_key,
                                thread const JacobianPoint& peer_pubkey,
                                thread uchar* out) {
    JacobianPoint shared = ct_ecdh_scalar_mul_metal(peer_pubkey, private_key);
    if (shared.infinity) return false;

    // BUG-3 FIX: compute y_aff to derive the correct compressed-point prefix.
    // Previously hardcoded 0x02, producing wrong output for ~50% of key pairs
    // (those where the shared point has odd Y). limbs[0] is the least-significant
    // 32-bit word (8×32 LE layout); bit 0 is the Y parity.
    FieldElement z_inv = field_inv(shared.z);
    FieldElement z_inv2 = field_sqr(z_inv);
    FieldElement z_inv3 = field_mul(z_inv, z_inv2);
    FieldElement x_aff = field_mul(shared.x, z_inv2);
    FieldElement y_aff = field_mul(shared.y, z_inv3);

    uchar x_bytes[32];
    for (int i = 0; i < 8; ++i) {
        uint v = x_aff.limbs[7 - i];
        x_bytes[i * 4 + 0] = (uchar)(v >> 24);
        x_bytes[i * 4 + 1] = (uchar)(v >> 16);
        x_bytes[i * 4 + 2] = (uchar)(v >> 8);
        x_bytes[i * 4 + 3] = (uchar)(v);
    }

    uchar prefix = (y_aff.limbs[0] & 1u) ? 0x03u : 0x02u;
    SHA256Ctx ctx = sha256_init();
    ctx = sha256_update(ctx, &prefix, 1);
    ctx = sha256_update(ctx, x_bytes, 32);
    sha256_final(ctx, out);
    return true;
}

#endif // SECP256K1_ECDH_H
