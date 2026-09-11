/**
 * UltrafastSecp256k1 — React Native Android Module (ufsecp stable C ABI v1).
 *
 * Bridges NativeModule calls to ufsecp JNI (loads libufsecp_jni.so which links libufsecp.so).
 * All byte-array I/O is hex-encoded.
 */
package com.ultrafast.ufsecp;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.util.Arrays;

public class UfsecpModule extends ReactContextBaseJavaModule {

    static {
        System.loadLibrary("ufsecp_jni");
    }

    private final ReactApplicationContext ctx;

    public UfsecpModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.ctx = reactContext;
    }

    @NonNull
    @Override
    public String getName() {
        return "Ufsecp";
    }

    /* ── Hex helpers ────────────────────────────────────────────────── */

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        return out;
    }

    private static void zero(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }

    /* ── Native JNI declarations (same as Ufsecp.java) ─────────────── */

    private static native long nativeCreate();
    private static native void nativeDestroy(long ptr);
    private static native int nativeVersion();
    private static native int nativeAbiVersion();
    private static native String nativeVersionString();
    private static native byte[] nativePubkeyCreate(long ctx, byte[] privkey);
    private static native byte[] nativePubkeyCreateUncompressed(long ctx, byte[] privkey);
    private static native boolean nativeSeckeyVerify(long ctx, byte[] privkey);
    private static native byte[] nativeEcdsaSign(long ctx, byte[] msgHash, byte[] privkey);
    private static native boolean nativeEcdsaVerify(long ctx, byte[] msgHash, byte[] sig, byte[] pubkey);
    private static native byte[] nativeSchnorrSign(long ctx, byte[] msg, byte[] privkey, byte[] auxRand);
    private static native boolean nativeSchnorrVerify(long ctx, byte[] msg, byte[] sig, byte[] pubkeyX);
    private static native byte[] nativeEcdh(long ctx, byte[] privkey, byte[] pubkey);
    private static native byte[] nativeSha256(byte[] data);
    private static native byte[] nativeHash160(byte[] data);
    private static native String nativeAddrP2pkh(long ctx, byte[] pubkey, int network);
    private static native String nativeAddrP2wpkh(long ctx, byte[] pubkey, int network);
    private static native String nativeAddrP2tr(long ctx, byte[] xonly, int network);
    private static native String nativeWifEncode(long ctx, byte[] privkey, boolean compressed, int network);
    private static native byte[] nativeBip32Master(long ctx, byte[] seed);
    private static native byte[] nativeBip32Derive(long ctx, byte[] parent, int index);
    private static native byte[] nativeBip32DerivePath(long ctx, byte[] master, String path);

    /* ── React Native methods ──────────────────────────────────────── */

    @ReactMethod
    public void create(Promise promise) {
        try { promise.resolve((double) nativeCreate()); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
    }

    @ReactMethod
    public void destroy(double handle, Promise promise) {
        try { nativeDestroy((long) handle); promise.resolve(null); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
    }

    @ReactMethod
    public void version(Promise promise) { promise.resolve(nativeVersion()); }

    @ReactMethod
    public void abiVersion(Promise promise) { promise.resolve(nativeAbiVersion()); }

    @ReactMethod
    public void versionString(Promise promise) { promise.resolve(nativeVersionString()); }

    @ReactMethod
    public void pubkeyCreate(double handle, String privkeyHex, Promise promise) {
        byte[] privkey = hexToBytes(privkeyHex);
        try { promise.resolve(bytesToHex(nativePubkeyCreate((long) handle, privkey))); }
        finally { zero(privkey); }
    }

    @ReactMethod
    public void pubkeyCreateUncompressed(double handle, String privkeyHex, Promise promise) {
        byte[] privkey = hexToBytes(privkeyHex);
        try { promise.resolve(bytesToHex(nativePubkeyCreateUncompressed((long) handle, privkey))); }
        finally { zero(privkey); }
    }

    @ReactMethod
    public void seckeyVerify(double handle, String privkeyHex, Promise promise) {
        byte[] privkey = hexToBytes(privkeyHex);
        try { promise.resolve(nativeSeckeyVerify((long) handle, privkey)); }
        finally { zero(privkey); }
    }

    @ReactMethod
    public void ecdsaSign(double handle, String msgHashHex, String privkeyHex, Promise promise) {
        byte[] msgHash = hexToBytes(msgHashHex);
        byte[] privkey = hexToBytes(privkeyHex);
        try {
            byte[] sig = nativeEcdsaSign((long) handle, msgHash, privkey);
            promise.resolve(bytesToHex(sig));
        } catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally {
            zero(msgHash);
            zero(privkey);
        }
    }

    @ReactMethod
    public void ecdsaVerify(double handle, String msgHashHex, String sigHex, String pubkeyHex, Promise promise) {
        byte[] msgHash = hexToBytes(msgHashHex);
        byte[] sig = hexToBytes(sigHex);
        byte[] pubkey = hexToBytes(pubkeyHex);
        try {
            boolean ok = nativeEcdsaVerify((long) handle, msgHash, sig, pubkey);
            promise.resolve(ok);
        } catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally {
            zero(msgHash);
            zero(sig);
            zero(pubkey);
        }
    }

    @ReactMethod
    public void schnorrSign(double handle, String msgHex, String privkeyHex, String auxRandHex, Promise promise) {
        byte[] msg = hexToBytes(msgHex);
        byte[] privkey = hexToBytes(privkeyHex);
        byte[] auxRand = hexToBytes(auxRandHex);
        try {
            byte[] sig = nativeSchnorrSign((long) handle, msg, privkey, auxRand);
            promise.resolve(bytesToHex(sig));
        } catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally {
            zero(msg);
            zero(privkey);
            zero(auxRand);
        }
    }

    @ReactMethod
    public void schnorrVerify(double handle, String msgHex, String sigHex, String pubkeyXHex, Promise promise) {
        byte[] msg = hexToBytes(msgHex);
        byte[] sig = hexToBytes(sigHex);
        byte[] pubkeyX = hexToBytes(pubkeyXHex);
        try {
            boolean ok = nativeSchnorrVerify((long) handle, msg, sig, pubkeyX);
            promise.resolve(ok);
        } catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally {
            zero(msg);
            zero(sig);
            zero(pubkeyX);
        }
    }

    @ReactMethod
    public void ecdh(double handle, String privkeyHex, String pubkeyHex, Promise promise) {
        byte[] privkey = hexToBytes(privkeyHex);
        byte[] pubkey = hexToBytes(pubkeyHex);
        try {
            byte[] sec = nativeEcdh((long) handle, privkey, pubkey);
            promise.resolve(bytesToHex(sec));
        } catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally {
            zero(privkey);
            zero(pubkey);
        }
    }

    @ReactMethod
    public void wifEncode(double handle, String privkeyHex, boolean compressed, int network, Promise promise) {
        byte[] privkey = hexToBytes(privkeyHex);
        try { promise.resolve(nativeWifEncode((long) handle, privkey, compressed, network)); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(privkey); }
    }

    @ReactMethod
    public void bip32Master(double handle, String seedHex, Promise promise) {
        byte[] seed = hexToBytes(seedHex);
        try { promise.resolve(bytesToHex(nativeBip32Master((long) handle, seed))); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(seed); }
    }

    @ReactMethod
    public void bip32Derive(double handle, String parentHex, int index, Promise promise) {
        byte[] parent = hexToBytes(parentHex);
        try { promise.resolve(bytesToHex(nativeBip32Derive((long) handle, parent, index))); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(parent); }
    }

    @ReactMethod
    public void bip32DerivePath(double handle, String masterHex, String path, Promise promise) {
        byte[] master = hexToBytes(masterHex);
        try { promise.resolve(bytesToHex(nativeBip32DerivePath((long) handle, master, path))); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(master); }
    }

    @ReactMethod
    public void sha256(String dataHex, Promise promise) {
        byte[] data = hexToBytes(dataHex);
        try { promise.resolve(bytesToHex(nativeSha256(data))); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(data); }
    }

    @ReactMethod
    public void hash160(String dataHex, Promise promise) {
        byte[] data = hexToBytes(dataHex);
        try { promise.resolve(bytesToHex(nativeHash160(data))); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(data); }
    }

    @ReactMethod
    public void addrP2pkh(double handle, String pubkeyHex, int network, Promise promise) {
        byte[] pubkey = hexToBytes(pubkeyHex);
        try { promise.resolve(nativeAddrP2pkh((long) handle, pubkey, network)); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(pubkey); }
    }

    @ReactMethod
    public void addrP2wpkh(double handle, String pubkeyHex, int network, Promise promise) {
        byte[] pubkey = hexToBytes(pubkeyHex);
        try { promise.resolve(nativeAddrP2wpkh((long) handle, pubkey, network)); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(pubkey); }
    }

    @ReactMethod
    public void addrP2tr(double handle, String xonlyHex, int network, Promise promise) {
        byte[] xonly = hexToBytes(xonlyHex);
        try { promise.resolve(nativeAddrP2tr((long) handle, xonly, network)); }
        catch (Exception e) { promise.reject("UFSECP", e.getMessage()); }
        finally { zero(xonly); }
    }
}
