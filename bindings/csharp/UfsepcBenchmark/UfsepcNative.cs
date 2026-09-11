// ============================================================================
// UfsepcNative.cs — P/Invoke declarations for the ufsecp C ABI
// ============================================================================
// Maps every ufsecp_* function to .NET via DllImport.
// DLL name: "ufsecp"  (ufsecp.dll on Windows, libufsecp.so on Linux)
//
// Architecture:
//   ┌─────────────────────────────────────────────────────────────┐
//   │  Layer 1 — FAST:  public operations (verify, point arith)  │
//   │  Layer 2 — CT  :  secret operations (sign, nonce, tweak)   │
//   │  Both layers are ALWAYS ACTIVE.  No flag.  No user choice. │
//   └─────────────────────────────────────────────────────────────┘
// ============================================================================

using System;
using System.Runtime.InteropServices;

namespace Ufsecp
{
    /// <summary>
    /// Raw P/Invoke declarations for the ufsecp C ABI.
    /// All functions return int (ufsecp_error_t): 0 = OK.
    /// </summary>
    internal static class Native
    {
        private const string Lib = "ufsecp";

        // ── Version / ABI ────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ufsecp_version();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ufsecp_abi_version();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ufsecp_version_string();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ufsecp_error_str(int err);

        // ── Context ──────────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ctx_create(out IntPtr ctx_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ctx_clone(IntPtr src, out IntPtr ctx_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ufsecp_ctx_destroy(IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_last_error(IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ufsecp_last_error_msg(IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern nuint ufsecp_ctx_size();

        // ── Private key utilities ────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_seckey_verify(IntPtr ctx, byte[] privkey);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_seckey_negate(IntPtr ctx, byte[] privkey);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_seckey_tweak_add(IntPtr ctx, byte[] privkey, byte[] tweak);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_seckey_tweak_mul(IntPtr ctx, byte[] privkey, byte[] tweak);

        // ── Public key ───────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_pubkey_create(IntPtr ctx, byte[] privkey, byte[] pubkey33_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_pubkey_create_uncompressed(IntPtr ctx, byte[] privkey, byte[] pubkey65_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_pubkey_parse(IntPtr ctx, byte[] input, nuint input_len, byte[] pubkey33_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_pubkey_xonly(IntPtr ctx, byte[] privkey, byte[] xonly32_out);

        // ── ECDSA ────────────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdsa_sign(IntPtr ctx, byte[] msg32, byte[] privkey, byte[] sig64_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdsa_verify(IntPtr ctx, byte[] msg32, byte[] sig64, byte[] pubkey33);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdsa_sig_to_der(IntPtr ctx, byte[] sig64, byte[] der_out, ref nuint der_len);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdsa_sig_from_der(IntPtr ctx, byte[] der, nuint der_len, byte[] sig64_out);

        // ── ECDSA recovery ───────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdsa_sign_recoverable(IntPtr ctx, byte[] msg32, byte[] privkey,
                                                                byte[] sig64_out, ref int recid_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdsa_recover(IntPtr ctx, byte[] msg32, byte[] sig64,
                                                       int recid, byte[] pubkey33_out);

        // ── Schnorr / BIP-340 ────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_schnorr_sign(IntPtr ctx, byte[] msg32, byte[] privkey,
                                                      byte[] aux_rand, byte[] sig64_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_schnorr_verify(IntPtr ctx, byte[] msg32, byte[] sig64, byte[] pubkey_x);

        // ── ECDH ─────────────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdh(IntPtr ctx, byte[] privkey, byte[] pubkey33, byte[] secret32_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdh_xonly(IntPtr ctx, byte[] privkey, byte[] pubkey33, byte[] secret32_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_ecdh_raw(IntPtr ctx, byte[] privkey, byte[] pubkey33, byte[] secret32_out);

        // ── Hashing (stateless — no ctx needed) ──────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_sha256(byte[] data, nuint len, byte[] digest32_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_hash160(byte[] data, nuint len, byte[] digest20_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_tagged_hash([MarshalAs(UnmanagedType.LPUTF8Str)] string tag,
                                                     byte[] data, nuint len, byte[] digest32_out);

        // ── Addresses ────────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_addr_p2pkh(IntPtr ctx, byte[] pubkey33, int network,
                                                    byte[] addr_out, ref nuint addr_len);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_addr_p2wpkh(IntPtr ctx, byte[] pubkey33, int network,
                                                     byte[] addr_out, ref nuint addr_len);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_addr_p2tr(IntPtr ctx, byte[] internal_key_x, int network,
                                                   byte[] addr_out, ref nuint addr_len);

        // ── WIF ──────────────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_wif_encode(IntPtr ctx, byte[] privkey, int compressed,
                                                    int network, byte[] wif_out, ref nuint wif_len);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_wif_decode(IntPtr ctx,
                                                    [MarshalAs(UnmanagedType.LPUTF8Str)] string wif,
                                                    byte[] privkey32_out, ref int compressed_out,
                                                    ref int network_out);

        // ── BIP-32 ──────────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_bip32_master(IntPtr ctx, byte[] seed, nuint seed_len,
                                                      byte[] key_out);   // 82 bytes

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_bip32_derive(IntPtr ctx, byte[] parent, uint index,
                                                      byte[] child_out); // 82 bytes

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_bip32_derive_path(IntPtr ctx, byte[] master,
                                                           [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
                                                           byte[] key_out); // 82 bytes

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_bip32_privkey(IntPtr ctx, byte[] key, byte[] privkey32_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_bip32_pubkey(IntPtr ctx, byte[] key, byte[] pubkey33_out);

        // ── Taproot ──────────────────────────────────────────────────────
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_taproot_output_key(IntPtr ctx, byte[] internal_x,
                                                            byte[]? merkle_root,
                                                            byte[] output_x_out, ref int parity_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_taproot_tweak_seckey(IntPtr ctx, byte[] privkey,
                                                              byte[]? merkle_root, byte[] tweaked32_out);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int ufsecp_taproot_verify(IntPtr ctx, byte[] output_x, int output_parity,
                                                        byte[] internal_x, byte[]? merkle_root,
                                                        nuint merkle_root_len);
    }
}
