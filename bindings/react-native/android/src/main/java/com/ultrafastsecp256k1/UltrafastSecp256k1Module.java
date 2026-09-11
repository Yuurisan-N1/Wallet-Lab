package com.ultrafastsecp256k1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

/**
 * React Native Android bridge for UltrafastSecp256k1.
 *
 * All byte data is passed as hex strings across the bridge.
 */
public class UltrafastSecp256k1Module extends ReactContextBaseJavaModule {

    static {
        System.loadLibrary("ultrafast_secp256k1_jni");
    }

    public UltrafastSecp256k1Module(ReactApplicationContext reactContext) {
        super(reactContext);
        nativeInit();
    }

    @NonNull
    @Override
    public String getName() {
        return "UltrafastSecp256k1";
    }

    // ── Hex helpers ──────────────────────────────────────────────────────

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hex[i * 2] = HEX_CHARS[v >>> 4];
            hex[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hex);
    }

    // ── Bridge methods ───────────────────────────────────────────────────

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String version() {
        return nativeVersion();
    }

    @ReactMethod
    public void ecPubkeyCreate(String privkeyHex, Promise promise) {
        try {
            byte[] pubkey = nativeEcPubkeyCreate(hexToBytes(privkeyHex));
            promise.resolve(bytesToHex(pubkey));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecPubkeyCreateUncompressed(String privkeyHex, Promise promise) {
        try {
            byte[] pubkey = nativeEcPubkeyCreateUncompressed(hexToBytes(privkeyHex));
            promise.resolve(bytesToHex(pubkey));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecPubkeyParse(String pubkeyHex, Promise promise) {
        try {
            byte[] pubkey = nativeEcPubkeyParse(hexToBytes(pubkeyHex));
            promise.resolve(bytesToHex(pubkey));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecSeckeyVerify(String privkeyHex, Promise promise) {
        try {
            promise.resolve(nativeEcSeckeyVerify(hexToBytes(privkeyHex)));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecPrivkeyNegate(String privkeyHex, Promise promise) {
        try {
            byte[] result = nativeEcPrivkeyNegate(hexToBytes(privkeyHex));
            promise.resolve(bytesToHex(result));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecPrivkeyTweakAdd(String privkeyHex, String tweakHex, Promise promise) {
        try {
            byte[] result = nativeEcPrivkeyTweakAdd(hexToBytes(privkeyHex), hexToBytes(tweakHex));
            promise.resolve(bytesToHex(result));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecPrivkeyTweakMul(String privkeyHex, String tweakHex, Promise promise) {
        try {
            byte[] result = nativeEcPrivkeyTweakMul(hexToBytes(privkeyHex), hexToBytes(tweakHex));
            promise.resolve(bytesToHex(result));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdsaSign(String msgHashHex, String privkeyHex, Promise promise) {
        try {
            byte[] sig = nativeEcdsaSign(hexToBytes(msgHashHex), hexToBytes(privkeyHex));
            promise.resolve(bytesToHex(sig));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdsaVerify(String msgHashHex, String sigHex, String pubkeyHex, Promise promise) {
        try {
            promise.resolve(nativeEcdsaVerify(hexToBytes(msgHashHex), hexToBytes(sigHex), hexToBytes(pubkeyHex)));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdsaSerializeDer(String sigHex, Promise promise) {
        try {
            byte[] der = nativeEcdsaSerializeDer(hexToBytes(sigHex));
            promise.resolve(bytesToHex(der));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdsaSignRecoverable(String msgHashHex, String privkeyHex, Promise promise) {
        try {
            Object[] result = nativeEcdsaSignRecoverable(hexToBytes(msgHashHex), hexToBytes(privkeyHex));
            WritableMap map = Arguments.createMap();
            map.putString("signature", bytesToHex((byte[]) result[0]));
            map.putInt("recid", (int) result[1]);
            promise.resolve(map);
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdsaRecover(String msgHashHex, String sigHex, int recid, Promise promise) {
        try {
            byte[] pubkey = nativeEcdsaRecover(hexToBytes(msgHashHex), hexToBytes(sigHex), recid);
            promise.resolve(bytesToHex(pubkey));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void schnorrSign(String msgHex, String privkeyHex, String auxRandHex, Promise promise) {
        try {
            byte[] sig = nativeSchnorrSign(hexToBytes(msgHex), hexToBytes(privkeyHex), hexToBytes(auxRandHex));
            promise.resolve(bytesToHex(sig));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void schnorrVerify(String msgHex, String sigHex, String pubkeyXHex, Promise promise) {
        try {
            promise.resolve(nativeSchnorrVerify(hexToBytes(msgHex), hexToBytes(sigHex), hexToBytes(pubkeyXHex)));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void schnorrPubkey(String privkeyHex, Promise promise) {
        try {
            byte[] pubkey = nativeSchnorrPubkey(hexToBytes(privkeyHex));
            promise.resolve(bytesToHex(pubkey));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdh(String privkeyHex, String pubkeyHex, Promise promise) {
        try {
            byte[] secret = nativeEcdh(hexToBytes(privkeyHex), hexToBytes(pubkeyHex));
            promise.resolve(bytesToHex(secret));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdhXonly(String privkeyHex, String pubkeyHex, Promise promise) {
        try {
            byte[] secret = nativeEcdhXonly(hexToBytes(privkeyHex), hexToBytes(pubkeyHex));
            promise.resolve(bytesToHex(secret));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void ecdhRaw(String privkeyHex, String pubkeyHex, Promise promise) {
        try {
            byte[] secret = nativeEcdhRaw(hexToBytes(privkeyHex), hexToBytes(pubkeyHex));
            promise.resolve(bytesToHex(secret));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void sha256(String dataHex, Promise promise) {
        try {
            byte[] digest = nativeSha256(hexToBytes(dataHex));
            promise.resolve(bytesToHex(digest));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void hash160(String dataHex, Promise promise) {
        try {
            byte[] digest = nativeHash160(hexToBytes(dataHex));
            promise.resolve(bytesToHex(digest));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void taggedHash(String tag, String dataHex, Promise promise) {
        try {
            byte[] digest = nativeTaggedHash(tag, hexToBytes(dataHex));
            promise.resolve(bytesToHex(digest));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void addressP2PKH(String pubkeyHex, int network, Promise promise) {
        try {
            promise.resolve(nativeAddressP2PKH(hexToBytes(pubkeyHex), network));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void addressP2WPKH(String pubkeyHex, int network, Promise promise) {
        try {
            promise.resolve(nativeAddressP2WPKH(hexToBytes(pubkeyHex), network));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void addressP2TR(String internalKeyXHex, int network, Promise promise) {
        try {
            promise.resolve(nativeAddressP2TR(hexToBytes(internalKeyXHex), network));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void wifEncode(String privkeyHex, boolean compressed, int network, Promise promise) {
        try {
            promise.resolve(nativeWifEncode(hexToBytes(privkeyHex), compressed, network));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void wifDecode(String wif, Promise promise) {
        try {
            Object[] result = nativeWifDecode(wif);
            WritableMap map = Arguments.createMap();
            map.putString("privkey", bytesToHex((byte[]) result[0]));
            map.putBoolean("compressed", (boolean) result[1]);
            map.putInt("network", (int) result[2]);
            promise.resolve(map);
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void bip32MasterKey(String seedHex, Promise promise) {
        try {
            byte[] key = nativeBip32MasterKey(hexToBytes(seedHex));
            promise.resolve(bytesToHex(key));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void bip32DeriveChild(String parentKeyHex, int index, Promise promise) {
        try {
            byte[] key = nativeBip32DeriveChild(hexToBytes(parentKeyHex), index);
            promise.resolve(bytesToHex(key));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void bip32DerivePath(String masterKeyHex, String path, Promise promise) {
        try {
            byte[] key = nativeBip32DerivePath(hexToBytes(masterKeyHex), path);
            promise.resolve(bytesToHex(key));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void bip32GetPrivkey(String keyHex, Promise promise) {
        try {
            byte[] pk = nativeBip32GetPrivkey(hexToBytes(keyHex));
            promise.resolve(bytesToHex(pk));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void bip32GetPubkey(String keyHex, Promise promise) {
        try {
            byte[] pk = nativeBip32GetPubkey(hexToBytes(keyHex));
            promise.resolve(bytesToHex(pk));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void taprootOutputKey(String internalKeyXHex, @Nullable String merkleRootHex, Promise promise) {
        try {
            byte[] mr = merkleRootHex != null ? hexToBytes(merkleRootHex) : null;
            Object[] result = nativeTaprootOutputKey(hexToBytes(internalKeyXHex), mr);
            WritableMap map = Arguments.createMap();
            map.putString("outputKeyX", bytesToHex((byte[]) result[0]));
            map.putInt("parity", (int) result[1]);
            promise.resolve(map);
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void taprootTweakPrivkey(String privkeyHex, @Nullable String merkleRootHex, Promise promise) {
        try {
            byte[] mr = merkleRootHex != null ? hexToBytes(merkleRootHex) : null;
            byte[] result = nativeTaprootTweakPrivkey(hexToBytes(privkeyHex), mr);
            promise.resolve(bytesToHex(result));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    @ReactMethod
    public void taprootVerifyCommitment(String outputKeyXHex, int parity,
                                        String internalKeyXHex, @Nullable String merkleRootHex, Promise promise) {
        try {
            byte[] mr = merkleRootHex != null ? hexToBytes(merkleRootHex) : null;
            promise.resolve(nativeTaprootVerifyCommitment(hexToBytes(outputKeyXHex), parity,
                                                          hexToBytes(internalKeyXHex), mr));
        } catch (Exception e) { promise.reject("ERR", e.getMessage()); }
    }

    // ── Native declarations ──────────────────────────────────────────────
    // These delegate to the JNI bridge (same as com.ultrafast.secp256k1.Secp256k1)

    private static native int nativeInit();
    private static native String nativeVersion();
    private static native byte[] nativeEcPubkeyCreate(byte[] privkey);
    private static native byte[] nativeEcPubkeyCreateUncompressed(byte[] privkey);
    private static native byte[] nativeEcPubkeyParse(byte[] input);
    private static native boolean nativeEcSeckeyVerify(byte[] privkey);
    private static native byte[] nativeEcPrivkeyNegate(byte[] privkey);
    private static native byte[] nativeEcPrivkeyTweakAdd(byte[] privkey, byte[] tweak);
    private static native byte[] nativeEcPrivkeyTweakMul(byte[] privkey, byte[] tweak);
    private static native byte[] nativeEcdsaSign(byte[] msgHash, byte[] privkey);
    private static native boolean nativeEcdsaVerify(byte[] msgHash, byte[] sig, byte[] pubkey);
    private static native byte[] nativeEcdsaSerializeDer(byte[] sig);
    private static native Object[] nativeEcdsaSignRecoverable(byte[] msgHash, byte[] privkey);
    private static native byte[] nativeEcdsaRecover(byte[] msgHash, byte[] sig, int recid);
    private static native byte[] nativeSchnorrSign(byte[] msg, byte[] privkey, byte[] auxRand);
    private static native boolean nativeSchnorrVerify(byte[] msg, byte[] sig, byte[] pubkeyX);
    private static native byte[] nativeSchnorrPubkey(byte[] privkey);
    private static native byte[] nativeEcdh(byte[] privkey, byte[] pubkey);
    private static native byte[] nativeEcdhXonly(byte[] privkey, byte[] pubkey);
    private static native byte[] nativeEcdhRaw(byte[] privkey, byte[] pubkey);
    private static native byte[] nativeSha256(byte[] data);
    private static native byte[] nativeHash160(byte[] data);
    private static native byte[] nativeTaggedHash(String tag, byte[] data);
    private static native String nativeAddressP2PKH(byte[] pubkey, int network);
    private static native String nativeAddressP2WPKH(byte[] pubkey, int network);
    private static native String nativeAddressP2TR(byte[] internalKeyX, int network);
    private static native String nativeWifEncode(byte[] privkey, boolean compressed, int network);
    private static native Object[] nativeWifDecode(String wif);
    private static native byte[] nativeBip32MasterKey(byte[] seed);
    private static native byte[] nativeBip32DeriveChild(byte[] parentKey, int index);
    private static native byte[] nativeBip32DerivePath(byte[] masterKey, String path);
    private static native byte[] nativeBip32GetPrivkey(byte[] key);
    private static native byte[] nativeBip32GetPubkey(byte[] key);
    private static native Object[] nativeTaprootOutputKey(byte[] internalKeyX, byte[] merkleRoot);
    private static native byte[] nativeTaprootTweakPrivkey(byte[] privkey, byte[] merkleRoot);
    private static native boolean nativeTaprootVerifyCommitment(byte[] outputKeyX, int parity,
                                                                 byte[] internalKeyX, byte[] merkleRoot);
}
