// UltrafastSecp256k1 — C# P/Invoke binding (ufsecp stable C ABI v1).
//
// High-performance secp256k1 elliptic curve cryptography with dual-layer
// constant-time architecture. Context-based API.
//
// Usage:
//   using var ctx = new Ufsecp();
//   byte[] pub = ctx.PubkeyCreate(privkey);

#nullable enable
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace Ultrafast.Ufsecp
{
    /// <summary>Error codes returned by ufsecp functions.</summary>
    public enum UfsecpErrorCode
    {
        Ok              = 0,
        NullArg         = 1,
        BadKey          = 2,
        BadPubkey       = 3,
        BadSig          = 4,
        BadInput        = 5,
        VerifyFail      = 6,
        Arith           = 7,
        Selftest        = 8,
        Internal        = 9,
        BufTooSmall     = 10,
    }

    /// <summary>Network type for address generation.</summary>
    public enum Network { Mainnet = 0, Testnet = 1 }

    /// <summary>Exception thrown when a ufsecp C function returns an error.</summary>
    public class UfsecpException : Exception
    {
        public string Operation { get; }
        public UfsecpErrorCode ErrorCode { get; }

        public UfsecpException(string op, UfsecpErrorCode code)
            : base($"ufsecp {op} failed: {code}") { Operation = op; ErrorCode = code; }
    }

    /// <summary>Recoverable signature result.</summary>
    public readonly record struct RecoverableSignature(byte[] Signature, int RecoveryId);

    /// <summary>WIF decode result.</summary>
    public readonly record struct WifDecoded(byte[] Privkey, bool Compressed, Network Network);

    /// <summary>Taproot output key result.</summary>
    public readonly record struct TaprootOutputKeyResult(byte[] OutputKeyX, int Parity);

    // ── Native interop ─────────────────────────────────────────────────

    internal static class Native
    {
        private const string Lib = "ufsecp";

        // Context
        [DllImport(Lib)] internal static extern int ufsecp_ctx_create(out IntPtr ctx);
        [DllImport(Lib)] internal static extern void ufsecp_ctx_destroy(IntPtr ctx);
        [DllImport(Lib)] internal static extern int ufsecp_ctx_clone(IntPtr src, out IntPtr dst);

        // Version
        [DllImport(Lib)] internal static extern uint ufsecp_version();
        [DllImport(Lib)] internal static extern uint ufsecp_abi_version();
        [DllImport(Lib)] internal static extern IntPtr ufsecp_version_string();
        [DllImport(Lib)] internal static extern IntPtr ufsecp_error_str(int err);
        [DllImport(Lib)] internal static extern int ufsecp_last_error(IntPtr ctx);
        [DllImport(Lib)] internal static extern IntPtr ufsecp_last_error_msg(IntPtr ctx);

        // Key ops
        [DllImport(Lib)] internal static extern int ufsecp_pubkey_create(IntPtr ctx, byte[] privkey, byte[] pubkey33);
        [DllImport(Lib)] internal static extern int ufsecp_pubkey_create_uncompressed(IntPtr ctx, byte[] privkey, byte[] pubkey65);
        [DllImport(Lib)] internal static extern int ufsecp_pubkey_parse(IntPtr ctx, byte[] input, nuint len, byte[] pubkey33);
        [DllImport(Lib)] internal static extern int ufsecp_pubkey_xonly(IntPtr ctx, byte[] privkey, byte[] xonly32);
        [DllImport(Lib)] internal static extern int ufsecp_seckey_verify(IntPtr ctx, byte[] privkey);
        [DllImport(Lib)] internal static extern int ufsecp_seckey_negate(IntPtr ctx, byte[] privkey);
        [DllImport(Lib)] internal static extern int ufsecp_seckey_tweak_add(IntPtr ctx, byte[] privkey, byte[] tweak);
        [DllImport(Lib)] internal static extern int ufsecp_seckey_tweak_mul(IntPtr ctx, byte[] privkey, byte[] tweak);

        // ECDSA
        [DllImport(Lib)] internal static extern int ufsecp_ecdsa_sign(IntPtr ctx, byte[] msg32, byte[] privkey, byte[] sig64);
        [DllImport(Lib)] internal static extern int ufsecp_ecdsa_verify(IntPtr ctx, byte[] msg32, byte[] sig64, byte[] pubkey33);
        [DllImport(Lib)] internal static extern int ufsecp_ecdsa_sig_to_der(IntPtr ctx, byte[] sig64, byte[] der, ref nuint len);
        [DllImport(Lib)] internal static extern int ufsecp_ecdsa_sig_from_der(IntPtr ctx, byte[] der, nuint len, byte[] sig64);

        // Recovery
        [DllImport(Lib)] internal static extern int ufsecp_ecdsa_sign_recoverable(IntPtr ctx, byte[] msg32, byte[] privkey, byte[] sig64, out int recid);
        [DllImport(Lib)] internal static extern int ufsecp_ecdsa_recover(IntPtr ctx, byte[] msg32, byte[] sig64, int recid, byte[] pubkey33);

        // Schnorr
        [DllImport(Lib)] internal static extern int ufsecp_schnorr_sign(IntPtr ctx, byte[] msg32, byte[] privkey, byte[] auxRand, byte[] sig64);
        [DllImport(Lib)] internal static extern int ufsecp_schnorr_verify(IntPtr ctx, byte[] msg32, byte[] sig64, byte[] pubkeyX);

        // ECDH
        [DllImport(Lib)] internal static extern int ufsecp_ecdh(IntPtr ctx, byte[] privkey, byte[] pubkey33, byte[] secret32);
        [DllImport(Lib)] internal static extern int ufsecp_ecdh_xonly(IntPtr ctx, byte[] privkey, byte[] pubkey33, byte[] secret32);
        [DllImport(Lib)] internal static extern int ufsecp_ecdh_raw(IntPtr ctx, byte[] privkey, byte[] pubkey33, byte[] secret32);

        // Hashing
        [DllImport(Lib)] internal static extern int ufsecp_sha256(byte[] data, nuint len, byte[] digest32);
        [DllImport(Lib)] internal static extern int ufsecp_hash160(byte[] data, nuint len, byte[] digest20);
        [DllImport(Lib)] internal static extern int ufsecp_tagged_hash([MarshalAs(UnmanagedType.LPUTF8Str)] string tag, byte[] data, nuint len, byte[] digest32);

        // Addresses
        [DllImport(Lib)] internal static extern int ufsecp_addr_p2pkh(IntPtr ctx, byte[] pubkey33, int network, byte[] addr, ref nuint len);
        [DllImport(Lib)] internal static extern int ufsecp_addr_p2wpkh(IntPtr ctx, byte[] pubkey33, int network, byte[] addr, ref nuint len);
        [DllImport(Lib)] internal static extern int ufsecp_addr_p2tr(IntPtr ctx, byte[] xonly32, int network, byte[] addr, ref nuint len);

        // WIF
        [DllImport(Lib)] internal static extern int ufsecp_wif_encode(IntPtr ctx, byte[] privkey, int compressed, int network, byte[] wif, ref nuint len);
        [DllImport(Lib)] internal static extern int ufsecp_wif_decode(IntPtr ctx, [MarshalAs(UnmanagedType.LPUTF8Str)] string wif, byte[] privkey32, out int compressed, out int network);

        // BIP-32
        [DllImport(Lib)] internal static extern int ufsecp_bip32_master(IntPtr ctx, byte[] seed, nuint len, byte[] key82);
        [DllImport(Lib)] internal static extern int ufsecp_bip32_derive(IntPtr ctx, byte[] parent82, uint index, byte[] child82);
        [DllImport(Lib)] internal static extern int ufsecp_bip32_derive_path(IntPtr ctx, byte[] master82, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] key82);
        [DllImport(Lib)] internal static extern int ufsecp_bip32_privkey(IntPtr ctx, byte[] key82, byte[] privkey32);
        [DllImport(Lib)] internal static extern int ufsecp_bip32_pubkey(IntPtr ctx, byte[] key82, byte[] pubkey33);

        // Taproot
        [DllImport(Lib)] internal static extern int ufsecp_taproot_output_key(IntPtr ctx, byte[] internalX, byte[]? merkleRoot, byte[] outputX, out int parity);
        [DllImport(Lib)] internal static extern int ufsecp_taproot_tweak_seckey(IntPtr ctx, byte[] privkey, byte[]? merkleRoot, byte[] tweaked32);
        [DllImport(Lib)] internal static extern int ufsecp_taproot_verify(IntPtr ctx, byte[] outputX, int parity, byte[] internalX, byte[]? merkleRoot, nuint mrLen);
    }

    // ── Main class ─────────────────────────────────────────────────────

    /// <summary>
    /// Context-based wrapper around the ufsecp C ABI. Implements IDisposable.
    /// </summary>
    public sealed class Ufsecp : IDisposable
    {
        private const uint ExpectedAbi = 1;
        private IntPtr _ctx;
        private bool _disposed;

        public Ufsecp()
        {
	        var abi = Native.ufsecp_abi_version();
	        if (abi != ExpectedAbi)
	            throw new InvalidOperationException($"ABI mismatch: wrapper expects ABI {ExpectedAbi}, lib reports ABI {abi}.");
            Throw(Native.ufsecp_ctx_create(out _ctx), "ctx_create");
        }

	    ~Ufsecp()
	    {
	        Dispose(false);
	    }

        public void Dispose()
        {
	        Dispose(true);
	        GC.SuppressFinalize(this);
        }

	    private void Dispose(bool disposing)
	    {
	        if (!_disposed && _ctx != IntPtr.Zero)
	        {
	            Native.ufsecp_ctx_destroy(_ctx);
	            _ctx = IntPtr.Zero;
	        }
	        _disposed = true;
	    }

        // ── Version ────────────────────────────────────────────────────

        public static uint Version => Native.ufsecp_version();
        public static uint AbiVersion => Native.ufsecp_abi_version();
        public static string VersionString => Marshal.PtrToStringUTF8(Native.ufsecp_version_string()) ?? "";

        public int LastError { get { Alive(); return Native.ufsecp_last_error(_ctx); } }
        public string LastErrorMsg { get { Alive(); return Marshal.PtrToStringUTF8(Native.ufsecp_last_error_msg(_ctx)) ?? ""; } }

        // ── Key operations ─────────────────────────────────────────────

        public byte[] PubkeyCreate(byte[] privkey)
        {
            Chk(privkey, 32, nameof(privkey)); Alive();
            var pub = new byte[33];
            Throw(Native.ufsecp_pubkey_create(_ctx, privkey, pub), nameof(PubkeyCreate));
            return pub;
        }

        public byte[] PubkeyCreateUncompressed(byte[] privkey)
        {
            Chk(privkey, 32, nameof(privkey)); Alive();
            var pub = new byte[65];
            Throw(Native.ufsecp_pubkey_create_uncompressed(_ctx, privkey, pub), nameof(PubkeyCreateUncompressed));
            return pub;
        }

        public byte[] PubkeyParse(byte[] pubkey)
        {
            Alive();
            var pub = new byte[33];
            Throw(Native.ufsecp_pubkey_parse(_ctx, pubkey, (nuint)pubkey.Length, pub), nameof(PubkeyParse));
            return pub;
        }

        public byte[] PubkeyXonly(byte[] privkey)
        {
            Chk(privkey, 32, nameof(privkey)); Alive();
            var x = new byte[32];
            Throw(Native.ufsecp_pubkey_xonly(_ctx, privkey, x), nameof(PubkeyXonly));
            return x;
        }

        public bool SeckeyVerify(byte[] privkey) { Chk(privkey, 32, nameof(privkey)); Alive(); return Native.ufsecp_seckey_verify(_ctx, privkey) == 0; }

        public byte[] SeckeyNegate(byte[] privkey)
        {
            Chk(privkey, 32, nameof(privkey)); Alive();
            var buf = CloneSensitive(privkey);
            try {
                Throw(Native.ufsecp_seckey_negate(_ctx, buf), nameof(SeckeyNegate));
                return buf;
            } catch {
                ZeroSensitive(buf);
                throw;
            }
        }

        public byte[] SeckeyTweakAdd(byte[] privkey, byte[] tweak)
        {
            Chk(privkey, 32, nameof(privkey)); Chk(tweak, 32, nameof(tweak)); Alive();
            var buf = CloneSensitive(privkey);
            var tweakCopy = CloneSensitive(tweak);
            try {
                Throw(Native.ufsecp_seckey_tweak_add(_ctx, buf, tweakCopy), nameof(SeckeyTweakAdd));
                return buf;
            } catch {
                ZeroSensitive(buf);
                throw;
            } finally {
                ZeroSensitive(tweakCopy);
            }
        }

        public byte[] SeckeyTweakMul(byte[] privkey, byte[] tweak)
        {
            Chk(privkey, 32, nameof(privkey)); Chk(tweak, 32, nameof(tweak)); Alive();
            var buf = CloneSensitive(privkey);
            var tweakCopy = CloneSensitive(tweak);
            try {
                Throw(Native.ufsecp_seckey_tweak_mul(_ctx, buf, tweakCopy), nameof(SeckeyTweakMul));
                return buf;
            } catch {
                ZeroSensitive(buf);
                throw;
            } finally {
                ZeroSensitive(tweakCopy);
            }
        }

        // ── ECDSA ──────────────────────────────────────────────────────

        public byte[] EcdsaSign(byte[] msgHash, byte[] privkey)
        {
            Chk(msgHash, 32, nameof(msgHash)); Chk(privkey, 32, nameof(privkey)); Alive();
            var keyCopy = CloneSensitive(privkey);
            var sig = new byte[64];
            try {
                Throw(Native.ufsecp_ecdsa_sign(_ctx, msgHash, keyCopy, sig), nameof(EcdsaSign));
                return sig;
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        public bool EcdsaVerify(byte[] msgHash, byte[] sig, byte[] pubkey)
        {
            Chk(msgHash, 32, nameof(msgHash)); Chk(sig, 64, nameof(sig)); Chk(pubkey, 33, nameof(pubkey)); Alive();
            return Native.ufsecp_ecdsa_verify(_ctx, msgHash, sig, pubkey) == 0;
        }

        public byte[] EcdsaSigToDer(byte[] sig)
        {
            Chk(sig, 64, nameof(sig)); Alive();
            var der = new byte[72]; nuint len = 72;
            Throw(Native.ufsecp_ecdsa_sig_to_der(_ctx, sig, der, ref len), nameof(EcdsaSigToDer));
            return der.AsSpan(0, (int)len).ToArray();
        }

        public byte[] EcdsaSigFromDer(byte[] der)
        {
            Alive();
            var sig = new byte[64];
            Throw(Native.ufsecp_ecdsa_sig_from_der(_ctx, der, (nuint)der.Length, sig), nameof(EcdsaSigFromDer));
            return sig;
        }

        // ── Recovery ───────────────────────────────────────────────────

        public RecoverableSignature EcdsaSignRecoverable(byte[] msgHash, byte[] privkey)
        {
            Chk(msgHash, 32, nameof(msgHash)); Chk(privkey, 32, nameof(privkey)); Alive();
            var keyCopy = CloneSensitive(privkey);
            var sig = new byte[64];
            try {
                Throw(Native.ufsecp_ecdsa_sign_recoverable(_ctx, msgHash, keyCopy, sig, out int recid), nameof(EcdsaSignRecoverable));
                return new RecoverableSignature(sig, recid);
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        public byte[] EcdsaRecover(byte[] msgHash, byte[] sig, int recid)
        {
            Chk(msgHash, 32, nameof(msgHash)); Chk(sig, 64, nameof(sig)); Alive();
            var pub = new byte[33];
            Throw(Native.ufsecp_ecdsa_recover(_ctx, msgHash, sig, recid, pub), nameof(EcdsaRecover));
            return pub;
        }

        // ── Schnorr ────────────────────────────────────────────────────

        public byte[] SchnorrSign(byte[] msg, byte[] privkey, byte[] auxRand)
        {
            Chk(msg, 32, nameof(msg)); Chk(privkey, 32, nameof(privkey)); Chk(auxRand, 32, nameof(auxRand)); Alive();
            var keyCopy = CloneSensitive(privkey);
            var auxCopy = CloneSensitive(auxRand);
            var sig = new byte[64];
            try {
                Throw(Native.ufsecp_schnorr_sign(_ctx, msg, keyCopy, auxCopy, sig), nameof(SchnorrSign));
                return sig;
            } finally {
                ZeroSensitive(keyCopy);
                ZeroSensitive(auxCopy);
            }
        }

        public bool SchnorrVerify(byte[] msg, byte[] sig, byte[] pubkeyX)
        {
            Chk(msg, 32, nameof(msg)); Chk(sig, 64, nameof(sig)); Chk(pubkeyX, 32, nameof(pubkeyX)); Alive();
            return Native.ufsecp_schnorr_verify(_ctx, msg, sig, pubkeyX) == 0;
        }

        // ── ECDH ───────────────────────────────────────────────────────

        public byte[] Ecdh(byte[] privkey, byte[] pubkey)
        {
            Chk(privkey, 32, nameof(privkey)); Chk(pubkey, 33, nameof(pubkey)); Alive();
            var keyCopy = CloneSensitive(privkey);
            try {
                var o = new byte[32]; Throw(Native.ufsecp_ecdh(_ctx, keyCopy, pubkey, o), nameof(Ecdh)); return o;
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        public byte[] EcdhXonly(byte[] privkey, byte[] pubkey)
        {
            Chk(privkey, 32, nameof(privkey)); Chk(pubkey, 33, nameof(pubkey)); Alive();
            var keyCopy = CloneSensitive(privkey);
            try {
                var o = new byte[32]; Throw(Native.ufsecp_ecdh_xonly(_ctx, keyCopy, pubkey, o), nameof(EcdhXonly)); return o;
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        public byte[] EcdhRaw(byte[] privkey, byte[] pubkey)
        {
            Chk(privkey, 32, nameof(privkey)); Chk(pubkey, 33, nameof(pubkey)); Alive();
            var keyCopy = CloneSensitive(privkey);
            try {
                var o = new byte[32]; Throw(Native.ufsecp_ecdh_raw(_ctx, keyCopy, pubkey, o), nameof(EcdhRaw)); return o;
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        // ── Hashing ────────────────────────────────────────────────────

        public static byte[] Sha256(byte[] data)
        {
            var o = new byte[32];
            Throw(Native.ufsecp_sha256(data, (nuint)data.Length, o), nameof(Sha256)); return o;
        }

        public static byte[] Hash160(byte[] data)
        {
            var o = new byte[20];
            Throw(Native.ufsecp_hash160(data, (nuint)data.Length, o), nameof(Hash160)); return o;
        }

        public static byte[] TaggedHash(string tag, byte[] data)
        {
            var o = new byte[32];
            Throw(Native.ufsecp_tagged_hash(tag, data, (nuint)data.Length, o), nameof(TaggedHash)); return o;
        }

        // ── Addresses ──────────────────────────────────────────────────

        public string AddrP2PKH(byte[] pubkey, Network net = Network.Mainnet)
        { Chk(pubkey, 33, nameof(pubkey)); return GetAddr(Native.ufsecp_addr_p2pkh, pubkey, net); }

        public string AddrP2WPKH(byte[] pubkey, Network net = Network.Mainnet)
        { Chk(pubkey, 33, nameof(pubkey)); return GetAddr(Native.ufsecp_addr_p2wpkh, pubkey, net); }

        public string AddrP2TR(byte[] xonlyKey, Network net = Network.Mainnet)
        { Chk(xonlyKey, 32, nameof(xonlyKey)); return GetAddr(Native.ufsecp_addr_p2tr, xonlyKey, net); }

        // ── WIF ────────────────────────────────────────────────────────

        public string WifEncode(byte[] privkey, bool compressed = true, Network net = Network.Mainnet)
        {
            Chk(privkey, 32, nameof(privkey)); Alive();
            var keyCopy = CloneSensitive(privkey);
            var buf = new byte[128]; nuint len = 128;
            try {
                Throw(Native.ufsecp_wif_encode(_ctx, keyCopy, compressed ? 1 : 0, (int)net, buf, ref len), nameof(WifEncode));
                return Encoding.UTF8.GetString(buf, 0, (int)len);
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        public WifDecoded WifDecode(string wif)
        {
            Alive();
            var key = new byte[32];
            Throw(Native.ufsecp_wif_decode(_ctx, wif, key, out int comp, out int net), nameof(WifDecode));
            return new WifDecoded(key, comp == 1, (Network)net);
        }

        // ── BIP-32 ─────────────────────────────────────────────────────

        public byte[] Bip32Master(byte[] seed)
        {
            if (seed.Length < 16 || seed.Length > 64) throw new ArgumentException("Seed must be 16-64 bytes");
            Alive(); var k = new byte[82];
            var seedCopy = CloneSensitive(seed);
            try {
                Throw(Native.ufsecp_bip32_master(_ctx, seedCopy, (nuint)seedCopy.Length, k), nameof(Bip32Master));
                return k;
            } finally {
                ZeroSensitive(seedCopy);
            }
        }

        public byte[] Bip32Derive(byte[] parent, uint index)
        {
            Chk(parent, 82, nameof(parent)); Alive(); var c = new byte[82];
            var parentCopy = CloneSensitive(parent);
            try {
                Throw(Native.ufsecp_bip32_derive(_ctx, parentCopy, index, c), nameof(Bip32Derive));
                return c;
            } finally {
                ZeroSensitive(parentCopy);
            }
        }

        public byte[] Bip32DerivePath(byte[] master, string path)
        {
            Chk(master, 82, nameof(master)); Alive(); var k = new byte[82];
            var masterCopy = CloneSensitive(master);
            try {
                Throw(Native.ufsecp_bip32_derive_path(_ctx, masterCopy, path, k), nameof(Bip32DerivePath));
                return k;
            } finally {
                ZeroSensitive(masterCopy);
            }
        }

        public byte[] Bip32Privkey(byte[] key)
        {
            Chk(key, 82, nameof(key)); Alive(); var p = new byte[32];
            var keyCopy = CloneSensitive(key);
            try {
                Throw(Native.ufsecp_bip32_privkey(_ctx, keyCopy, p), nameof(Bip32Privkey));
                return p;
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        public byte[] Bip32Pubkey(byte[] key)
        { Chk(key, 82, nameof(key)); Alive(); var p = new byte[33]; Throw(Native.ufsecp_bip32_pubkey(_ctx, key, p), nameof(Bip32Pubkey)); return p; }

        // ── Taproot ────────────────────────────────────────────────────

        public TaprootOutputKeyResult TaprootOutputKey(byte[] internalKeyX, byte[]? merkleRoot = null)
        {
            Chk(internalKeyX, 32, nameof(internalKeyX)); Alive();
            var o = new byte[32];
            Throw(Native.ufsecp_taproot_output_key(_ctx, internalKeyX, merkleRoot, o, out int parity), nameof(TaprootOutputKey));
            return new TaprootOutputKeyResult(o, parity);
        }

        public byte[] TaprootTweakSeckey(byte[] privkey, byte[]? merkleRoot = null)
        {
            Chk(privkey, 32, nameof(privkey)); Alive();
            var keyCopy = CloneSensitive(privkey);
            var o = new byte[32];
            try {
                Throw(Native.ufsecp_taproot_tweak_seckey(_ctx, keyCopy, merkleRoot, o), nameof(TaprootTweakSeckey));
                return o;
            } finally {
                ZeroSensitive(keyCopy);
            }
        }

        public bool TaprootVerify(byte[] outputKeyX, int parity, byte[] internalKeyX, byte[]? merkleRoot = null)
        {
            Chk(outputKeyX, 32, nameof(outputKeyX)); Chk(internalKeyX, 32, nameof(internalKeyX)); Alive();
            return Native.ufsecp_taproot_verify(_ctx, outputKeyX, parity, internalKeyX, merkleRoot, (nuint)(merkleRoot?.Length ?? 0)) == 0;
        }

        // ── Internal ───────────────────────────────────────────────────

        private void Alive() { if (_disposed) throw new ObjectDisposedException(nameof(Ufsecp)); }

        private static void Throw(int rc, string op)
        {
            if (rc != 0) throw new UfsecpException(op, (UfsecpErrorCode)rc);
        }

        private static void Chk(byte[] data, int expected, string name)
        {
            if (data.Length != expected)
                throw new ArgumentException($"{name} must be {expected} bytes, got {data.Length}");
        }

        private delegate int AddrFn(IntPtr ctx, byte[] key, int network, byte[] addr, ref nuint len);

        private static byte[] CloneSensitive(byte[] input)
        {
            return (byte[])input.Clone();
        }

        private static void ZeroSensitive(byte[]? buffer)
        {
            if (buffer is { Length: > 0 })
                CryptographicOperations.ZeroMemory(buffer);
        }

        private string GetAddr(AddrFn fn, byte[] key, Network net)
        {
            Alive();
            var buf = new byte[128]; nuint len = 128;
            Throw(fn(_ctx, key, (int)net, buf, ref len), "address");
            return Encoding.UTF8.GetString(buf, 0, (int)len);
        }
    }
}
