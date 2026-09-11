package com.ultrafast.secp256k1;

/**
 * High-performance secp256k1 elliptic curve cryptography.
 * <p>
 * JNI wrapper around the UltrafastSecp256k1 C library.
 * Load the native library before use:
 * <pre>
 *   Secp256k1.loadLibrary();           // auto-detect
 *   Secp256k1.loadLibrary("path/to");  // explicit directory
 * </pre>
 */
public final class Secp256k1 {

    public static final int NETWORK_MAINNET = 0;
    public static final int NETWORK_TESTNET = 1;

    private static boolean loaded = false;

    /** Load the native library from default paths. */
    public static synchronized void loadLibrary() {
        if (loaded) return;
        System.loadLibrary("ultrafast_secp256k1_jni");
        int rc = nativeInit();
        if (rc != 0) throw new RuntimeException("secp256k1_init() selftest failed");
        loaded = true;
    }

    /** Load the native library from a specific directory. */
    public static synchronized void loadLibrary(String dir) {
        if (loaded) return;
        String os = System.getProperty("os.name", "").toLowerCase();
        String name;
        if (os.contains("win")) {
            name = "ultrafast_secp256k1_jni.dll";
        } else if (os.contains("mac")) {
            name = "libultrafast_secp256k1_jni.dylib";
        } else {
            name = "libultrafast_secp256k1_jni.so";
        }
        System.load(dir + java.io.File.separator + name);
        int rc = nativeInit();
        if (rc != 0) throw new RuntimeException("secp256k1_init() selftest failed");
        loaded = true;
    }

    private Secp256k1() {}

    // ── Key Operations ───────────────────────────────────────────────────

    /**
     * Compute compressed public key (33 bytes) from private key (32 bytes).
     * @throws IllegalArgumentException on invalid key
     */
    public static native byte[] ecPubkeyCreate(byte[] privkey);

    /** Compute uncompressed public key (65 bytes). */
    public static native byte[] ecPubkeyCreateUncompressed(byte[] privkey);

    /** Parse compressed/uncompressed pubkey. Returns compressed form. */
    public static native byte[] ecPubkeyParse(byte[] input);

    /** Check whether a private key is valid. */
    public static native boolean ecSeckeyVerify(byte[] privkey);

    /** Negate a private key (mod n). */
    public static native byte[] ecPrivkeyNegate(byte[] privkey);

    /** Add tweak to private key: (key + tweak) mod n. */
    public static native byte[] ecPrivkeyTweakAdd(byte[] privkey, byte[] tweak);

    /** Multiply private key by tweak: (key * tweak) mod n. */
    public static native byte[] ecPrivkeyTweakMul(byte[] privkey, byte[] tweak);

    // ── ECDSA ────────────────────────────────────────────────────────────

    /** Sign a 32-byte hash (RFC 6979). Returns 64-byte compact signature. */
    public static native byte[] ecdsaSign(byte[] msgHash, byte[] privkey);

    /** Verify ECDSA signature. */
    public static native boolean ecdsaVerify(byte[] msgHash, byte[] sig, byte[] pubkey);

    /** Serialize compact sig to DER format. */
    public static native byte[] ecdsaSerializeDer(byte[] sig);

    // ── Recovery ─────────────────────────────────────────────────────────

    /**
     * Sign with recovery id.
     * @return RecoverableSignature containing sig bytes and recovery id.
     */
    public static native RecoverableSignature ecdsaSignRecoverable(byte[] msgHash, byte[] privkey);

    /** Recover compressed public key from recoverable signature. */
    public static native byte[] ecdsaRecover(byte[] msgHash, byte[] sig, int recid);

    // ── Schnorr ──────────────────────────────────────────────────────────

    /** BIP-340 Schnorr sign. Returns 64-byte signature. */
    public static native byte[] schnorrSign(byte[] msg, byte[] privkey, byte[] auxRand);

    /** Verify Schnorr signature. */
    public static native boolean schnorrVerify(byte[] msg, byte[] sig, byte[] pubkeyX);

    /** Get x-only public key (32 bytes). */
    public static native byte[] schnorrPubkey(byte[] privkey);

    // ── ECDH ─────────────────────────────────────────────────────────────

    /** ECDH shared secret: SHA256(compressed shared point). */
    public static native byte[] ecdh(byte[] privkey, byte[] pubkey);

    /** ECDH x-only. */
    public static native byte[] ecdhXonly(byte[] privkey, byte[] pubkey);

    /** ECDH raw x-coordinate. */
    public static native byte[] ecdhRaw(byte[] privkey, byte[] pubkey);

    // ── Hashing ──────────────────────────────────────────────────────────

    /** SHA-256. */
    public static native byte[] sha256(byte[] data);

    /** HASH160 (RIPEMD160(SHA256)). */
    public static native byte[] hash160(byte[] data);

    /** BIP-340 tagged hash. */
    public static native byte[] taggedHash(String tag, byte[] data);

    // ── Addresses ────────────────────────────────────────────────────────

    /** P2PKH address from compressed pubkey. */
    public static native String addressP2pkh(byte[] pubkey, int network);

    /** P2WPKH address from compressed pubkey. */
    public static native String addressP2wpkh(byte[] pubkey, int network);

    /** P2TR address from x-only key. */
    public static native String addressP2tr(byte[] internalKeyX, int network);

    // ── WIF ──────────────────────────────────────────────────────────────

    /** Encode private key as WIF. */
    public static native String wifEncode(byte[] privkey, boolean compressed, int network);

    /** Decode WIF string. */
    public static native WifDecodeResult wifDecode(String wif);

    // ── BIP-32 ───────────────────────────────────────────────────────────

    /** Create master key from seed. Returns 79-byte opaque key. */
    public static native byte[] bip32MasterKey(byte[] seed);

    /** Derive child key by index. */
    public static native byte[] bip32DeriveChild(byte[] parentKey, int index);

    /** Derive key from path string. */
    public static native byte[] bip32DerivePath(byte[] masterKey, String path);

    /** Extract 32-byte private key from extended key. */
    public static native byte[] bip32GetPrivkey(byte[] key);

    /** Extract 33-byte compressed pubkey from extended key. */
    public static native byte[] bip32GetPubkey(byte[] key);

    // ── Taproot ──────────────────────────────────────────────────────────

    /** Taproot output key. Returns TaprootOutputKeyResult. */
    public static native TaprootOutputKeyResult taprootOutputKey(byte[] internalKeyX, byte[] merkleRoot);

    /** Tweak private key for Taproot. */
    public static native byte[] taprootTweakPrivkey(byte[] privkey, byte[] merkleRoot);

    /** Verify Taproot commitment. */
    public static native boolean taprootVerifyCommitment(byte[] outputKeyX, int parity,
                                                         byte[] internalKeyX, byte[] merkleRoot);

    // ── Native bridge ────────────────────────────────────────────────────

    private static native int nativeInit();
    public static native String nativeVersion();

    // ── Result Types ─────────────────────────────────────────────────────

    /** Recoverable signature result. */
    public static final class RecoverableSignature {
        public final byte[] signature;
        public final int recid;

        public RecoverableSignature(byte[] signature, int recid) {
            this.signature = signature;
            this.recid = recid;
        }
    }

    /** WIF decode result. */
    public static final class WifDecodeResult {
        public final byte[] privkey;
        public final boolean compressed;
        public final int network;

        public WifDecodeResult(byte[] privkey, boolean compressed, int network) {
            this.privkey = privkey;
            this.compressed = compressed;
            this.network = network;
        }
    }

    /** Taproot output key result. */
    public static final class TaprootOutputKeyResult {
        public final byte[] outputKeyX;
        public final int parity;

        public TaprootOutputKeyResult(byte[] outputKeyX, int parity) {
            this.outputKeyX = outputKeyX;
            this.parity = parity;
        }
    }
}
