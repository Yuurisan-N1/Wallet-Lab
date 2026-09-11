/**
 * UltrafastSecp256k1 — Node.js FFI Bindings
 *
 * Pure JavaScript wrapper using ffi-napi to load the C shared library.
 * No compilation required — just needs the shared library (.so/.dll/.dylib).
 *
 * @example
 * const { Secp256k1 } = require('ultrafast-secp256k1');
 *
 * const lib = new Secp256k1();
 * const privkey = Buffer.alloc(32);
 * privkey[31] = 1;
 *
 * const pubkey = lib.ecPubkeyCreate(privkey);
 * const sig = lib.ecdsaSign(Buffer.alloc(32), privkey);
 * console.log('valid:', lib.ecdsaVerify(Buffer.alloc(32), sig, pubkey));
 */

'use strict';

const { createRequire } = require('module');
const path = require('path');
const fs = require('fs');
const ffi = require('ffi-napi');
const ref = require('ref-napi');

// ── Type aliases ──────────────────────────────────────────────────────────────
const int = ref.types.int;
const uint8Ptr = ref.refType(ref.types.uint8);
const charPtr = ref.types.CString;
const sizePtr = ref.refType(ref.types.size_t);
const intPtr = ref.refType(ref.types.int);

// ── Library search ────────────────────────────────────────────────────────────
function findLibrary() {
    const platform = process.platform;
    let libNames;
    if (platform === 'win32') {
        libNames = ['ultrafast_secp256k1.dll', 'libultrafast_secp256k1.dll'];
    } else if (platform === 'darwin') {
        libNames = ['libultrafast_secp256k1.dylib', 'libultrafast_secp256k1.1.dylib'];
    } else {
        libNames = ['libultrafast_secp256k1.so', 'libultrafast_secp256k1.so.1'];
    }

    // 1. Environment variable
    const envPath = process.env.ULTRAFAST_SECP256K1_LIB;
    if (envPath && fs.existsSync(envPath)) return envPath;

    // 2. Next to this module
    const base = __dirname;
    for (const name of libNames) {
        const p = path.join(base, name);
        if (fs.existsSync(p)) return p;
    }

    // 3. Common build dirs
    const root = path.resolve(base, '..', '..');
    const buildDirs = [
        path.join(root, 'bindings', 'c_api', 'build'),
        path.join(root, 'bindings', 'c_api', 'build', 'Release'),
        path.join(root, 'build_rel'),
        path.join(root, 'build-linux'),
    ];
    for (const bd of buildDirs) {
        for (const name of libNames) {
            const p = path.join(bd, name);
            if (fs.existsSync(p)) return p;
        }
    }

    // 4. System default
    return 'ultrafast_secp256k1';
}

// ── FFI definitions ───────────────────────────────────────────────────────────
function loadLib(libPath) {
    return ffi.Library(libPath, {
        // Lifecycle
        'secp256k1_version': [charPtr, []],
        'secp256k1_init': [int, []],

        // Key ops
        'secp256k1_ec_pubkey_create': [int, [uint8Ptr, uint8Ptr]],
        'secp256k1_ec_pubkey_create_uncompressed': [int, [uint8Ptr, uint8Ptr]],
        'secp256k1_ec_pubkey_parse': [int, [uint8Ptr, 'size_t', uint8Ptr]],
        'secp256k1_ec_seckey_verify': [int, [uint8Ptr]],
        'secp256k1_ec_privkey_negate': [int, [uint8Ptr]],
        'secp256k1_ec_privkey_tweak_add': [int, [uint8Ptr, uint8Ptr]],
        'secp256k1_ec_privkey_tweak_mul': [int, [uint8Ptr, uint8Ptr]],

        // ECDSA
        'secp256k1_ecdsa_sign': [int, [uint8Ptr, uint8Ptr, uint8Ptr]],
        'secp256k1_ecdsa_verify': [int, [uint8Ptr, uint8Ptr, uint8Ptr]],
        'secp256k1_ecdsa_signature_serialize_der': [int, [uint8Ptr, uint8Ptr, sizePtr]],

        // Recovery
        'secp256k1_ecdsa_sign_recoverable': [int, [uint8Ptr, uint8Ptr, uint8Ptr, intPtr]],
        'secp256k1_ecdsa_recover': [int, [uint8Ptr, uint8Ptr, int, uint8Ptr]],

        // Schnorr
        'secp256k1_schnorr_sign': [int, [uint8Ptr, uint8Ptr, uint8Ptr, uint8Ptr]],
        'secp256k1_schnorr_verify': [int, [uint8Ptr, uint8Ptr, uint8Ptr]],
        'secp256k1_schnorr_pubkey': [int, [uint8Ptr, uint8Ptr]],

        // ECDH
        'secp256k1_ecdh': [int, [uint8Ptr, uint8Ptr, uint8Ptr]],
        'secp256k1_ecdh_xonly': [int, [uint8Ptr, uint8Ptr, uint8Ptr]],
        'secp256k1_ecdh_raw': [int, [uint8Ptr, uint8Ptr, uint8Ptr]],

        // Hashing
        'secp256k1_sha256': ['void', [uint8Ptr, 'size_t', uint8Ptr]],
        'secp256k1_hash160': ['void', [uint8Ptr, 'size_t', uint8Ptr]],
        'secp256k1_tagged_hash': ['void', [charPtr, uint8Ptr, 'size_t', uint8Ptr]],

        // Addresses
        'secp256k1_address_p2pkh': [int, [uint8Ptr, int, charPtr, sizePtr]],
        'secp256k1_address_p2wpkh': [int, [uint8Ptr, int, charPtr, sizePtr]],
        'secp256k1_address_p2tr': [int, [uint8Ptr, int, charPtr, sizePtr]],

        // WIF
        'secp256k1_wif_encode': [int, [uint8Ptr, int, int, charPtr, sizePtr]],
        'secp256k1_wif_decode': [int, [charPtr, uint8Ptr, intPtr, intPtr]],

        // BIP-32
        'secp256k1_bip32_master_key': [int, [uint8Ptr, 'size_t', uint8Ptr]],
        'secp256k1_bip32_derive_path': [int, [uint8Ptr, charPtr, uint8Ptr]],
        'secp256k1_bip32_get_privkey': [int, [uint8Ptr, uint8Ptr]],
        'secp256k1_bip32_get_pubkey': [int, [uint8Ptr, uint8Ptr]],

        // Taproot
        'secp256k1_taproot_output_key': [int, [uint8Ptr, uint8Ptr, uint8Ptr, intPtr]],
        'secp256k1_taproot_tweak_privkey': [int, [uint8Ptr, uint8Ptr, uint8Ptr]],
        'secp256k1_taproot_verify_commitment': [int, [uint8Ptr, int, uint8Ptr, uint8Ptr, 'size_t']],
    });
}

// ── Constants ─────────────────────────────────────────────────────────────────
const NETWORK_MAINNET = 0;
const NETWORK_TESTNET = 1;

function bestEffortZero(buf) {
    if (!Buffer.isBuffer(buf) && !(buf instanceof Uint8Array)) {
        throw new TypeError('buf must be a Buffer or Uint8Array');
    }
    buf.fill(0);
    return buf;
}

class SensitiveBytes {
    constructor(buf, { copy = false } = {}) {
        if (!Buffer.isBuffer(buf) && !(buf instanceof Uint8Array)) {
            throw new TypeError('buf must be a Buffer or Uint8Array');
        }
        this._buf = copy
            ? Buffer.from(buf)
            : Buffer.isBuffer(buf)
                ? buf
                : Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
        this._destroyed = false;
    }

    static take(buf) {
        return new SensitiveBytes(buf, { copy: false });
    }

    static copy(buf) {
        return new SensitiveBytes(buf, { copy: true });
    }

    get bytes() {
        if (this._destroyed) throw new Error('SensitiveBytes already destroyed');
        return this._buf;
    }

    destroy() {
        if (!this._destroyed) {
            bestEffortZero(this._buf);
            this._destroyed = true;
        }
    }
}

if (typeof Symbol.dispose === 'symbol') {
    SensitiveBytes.prototype[Symbol.dispose] = SensitiveBytes.prototype.destroy;
}

function _unwrapBytes(buf) {
    return buf instanceof SensitiveBytes ? buf.bytes : buf;
}

function _wipeSecretInput(value) {
    if (value instanceof SensitiveBytes) {
        value.destroy();
        return;
    }
    bestEffortZero(value);
}

function _parseCtorArgs(libPathOrOptions, maybeOptions) {
    if (typeof libPathOrOptions === 'string' || libPathOrOptions == null) {
        return {
            libPath: libPathOrOptions || undefined,
            autoZeroInputs: Boolean(maybeOptions && maybeOptions.autoZeroInputs),
        };
    }
    if (typeof libPathOrOptions === 'object') {
        return {
            libPath: libPathOrOptions.libPath,
            autoZeroInputs: Boolean(libPathOrOptions.autoZeroInputs),
        };
    }
    throw new TypeError('constructor expects a library path string or options object');
}

// ── Secp256k1 class ───────────────────────────────────────────────────────────
class Secp256k1 {
    /**
     * @param {string|object} [libPathOrOptions] - Path to the shared library or
     *   options: { libPath?: string, autoZeroInputs?: boolean }.
     * @param {object} [maybeOptions] - Optional options when the first arg is a path.
     */
    constructor(libPathOrOptions, maybeOptions) {
        const opts = _parseCtorArgs(libPathOrOptions, maybeOptions);
        const resolvedPath = opts.libPath || findLibrary();
        this._lib = loadLib(resolvedPath);
        this._autoZeroInputs = opts.autoZeroInputs;

        const rc = this._lib.secp256k1_init();
        if (rc !== 0) {
            throw new Error('secp256k1_init() failed: library selftest failure');
        }
    }

    /** @returns {string} Library version string. */
    version() {
        return this._lib.secp256k1_version();
    }

    // ── Key Operations ───────────────────────────────────────────────────

    /**
     * Compute compressed public key (33 bytes) from private key (32 bytes).
     * @param {Buffer} privkey - 32-byte private key.
     * @returns {Buffer} 33-byte compressed public key.
     */
    ecPubkeyCreate(privkey) {
        const raw = _unwrapBytes(privkey);
        _check(raw, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.alloc(33);
            const rc = this._lib.secp256k1_ec_pubkey_create(raw, out);
            if (rc !== 0) throw new Error('Invalid private key');
            return out;
        });
    }

    /**
     * Compute uncompressed public key (65 bytes).
     * @param {Buffer} privkey
     * @returns {Buffer}
     */
    ecPubkeyCreateUncompressed(privkey) {
        const raw = _unwrapBytes(privkey);
        _check(raw, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.alloc(65);
            const rc = this._lib.secp256k1_ec_pubkey_create_uncompressed(raw, out);
            if (rc !== 0) throw new Error('Invalid private key');
            return out;
        });
    }

    /**
     * Parse public key. Returns compressed (33 bytes).
     * @param {Buffer} pubkey - 33 or 65 byte public key.
     * @returns {Buffer}
     */
    ecPubkeyParse(pubkey) {
        const out = Buffer.alloc(33);
        const rc = this._lib.secp256k1_ec_pubkey_parse(pubkey, pubkey.length, out);
        if (rc !== 0) throw new Error('Invalid public key');
        return out;
    }

    /** @returns {boolean} True if privkey is valid. */
    ecSeckeyVerify(privkey) {
        const raw = _unwrapBytes(privkey);
        _check(raw, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => this._lib.secp256k1_ec_seckey_verify(raw) === 1);
    }

    /** Negate private key (mod n). Returns new Buffer. */
    ecPrivkeyNegate(privkey) {
        const raw = _unwrapBytes(privkey);
        _check(raw, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.from(raw);
            this._lib.secp256k1_ec_privkey_negate(out);
            return out;
        });
    }

    /** Add tweak to private key. Returns new Buffer. */
    ecPrivkeyTweakAdd(privkey, tweak) {
        const rawPrivkey = _unwrapBytes(privkey);
        const rawTweak = _unwrapBytes(tweak);
        _check(rawPrivkey, 32, 'privkey');
        _check(rawTweak, 32, 'tweak');
        return this._withSecretCleanup([privkey, tweak], () => {
            const out = Buffer.from(rawPrivkey);
            const rc = this._lib.secp256k1_ec_privkey_tweak_add(out, rawTweak);
            if (rc !== 0) throw new Error('Tweak add produced invalid key');
            return out;
        });
    }

    /** Multiply private key by tweak. Returns new Buffer. */
    ecPrivkeyTweakMul(privkey, tweak) {
        const rawPrivkey = _unwrapBytes(privkey);
        const rawTweak = _unwrapBytes(tweak);
        _check(rawPrivkey, 32, 'privkey');
        _check(rawTweak, 32, 'tweak');
        return this._withSecretCleanup([privkey, tweak], () => {
            const out = Buffer.from(rawPrivkey);
            const rc = this._lib.secp256k1_ec_privkey_tweak_mul(out, rawTweak);
            if (rc !== 0) throw new Error('Tweak mul produced invalid key');
            return out;
        });
    }

    // ── ECDSA ────────────────────────────────────────────────────────────

    /**
     * Sign with ECDSA (RFC 6979). Returns 64-byte compact signature.
     * @param {Buffer} msgHash - 32-byte message hash.
     * @param {Buffer} privkey - 32-byte private key.
     * @returns {Buffer} 64-byte signature.
     */
    ecdsaSign(msgHash, privkey) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(msgHash, 32, 'msgHash');
        _check(rawPrivkey, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => {
            const sig = Buffer.alloc(64);
            const rc = this._lib.secp256k1_ecdsa_sign(msgHash, rawPrivkey, sig);
            if (rc !== 0) throw new Error('ECDSA signing failed');
            return sig;
        });
    }

    /**
     * Verify ECDSA signature.
     * @returns {boolean}
     */
    ecdsaVerify(msgHash, sig, pubkey) {
        _check(msgHash, 32, 'msgHash');
        _check(sig, 64, 'sig');
        _check(pubkey, 33, 'pubkey');
        return this._lib.secp256k1_ecdsa_verify(msgHash, sig, pubkey) === 1;
    }

    /** Serialize compact sig to DER. @returns {Buffer} */
    ecdsaSerializeDer(sig) {
        _check(sig, 64, 'sig');
        const der = Buffer.alloc(72);
        const lenBuf = ref.alloc('size_t', 72);
        const rc = this._lib.secp256k1_ecdsa_signature_serialize_der(sig, der, lenBuf);
        if (rc !== 0) throw new Error('DER serialization failed');
        return der.slice(0, ref.deref(lenBuf));
    }

    // ── Recovery ─────────────────────────────────────────────────────────

    /** Sign with recovery id. Returns { signature, recoveryId }. */
    ecdsaSignRecoverable(msgHash, privkey) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(msgHash, 32, 'msgHash');
        _check(rawPrivkey, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => {
            const sig = Buffer.alloc(64);
            const recidBuf = ref.alloc('int', 0);
            const rc = this._lib.secp256k1_ecdsa_sign_recoverable(msgHash, rawPrivkey, sig, recidBuf);
            if (rc !== 0) throw new Error('Recoverable signing failed');
            return { signature: sig, recoveryId: ref.deref(recidBuf) };
        });
    }

    /** Recover public key. @returns {Buffer} 33-byte compressed pubkey. */
    ecdsaRecover(msgHash, sig, recid) {
        _check(msgHash, 32, 'msgHash');
        _check(sig, 64, 'sig');
        const pubkey = Buffer.alloc(33);
        const rc = this._lib.secp256k1_ecdsa_recover(msgHash, sig, recid, pubkey);
        if (rc !== 0) throw new Error('Recovery failed');
        return pubkey;
    }

    // ── Schnorr ──────────────────────────────────────────────────────────

    /** Create BIP-340 Schnorr signature. @returns {Buffer} 64 bytes. */
    schnorrSign(msg, privkey, auxRand) {
        const rawPrivkey = _unwrapBytes(privkey);
        const rawAuxRand = _unwrapBytes(auxRand);
        _check(msg, 32, 'msg');
        _check(rawPrivkey, 32, 'privkey');
        _check(rawAuxRand, 32, 'auxRand');
        return this._withSecretCleanup([privkey, auxRand], () => {
            const sig = Buffer.alloc(64);
            const rc = this._lib.secp256k1_schnorr_sign(msg, rawPrivkey, rawAuxRand, sig);
            if (rc !== 0) throw new Error('Schnorr signing failed');
            return sig;
        });
    }

    /** Verify Schnorr signature. @returns {boolean} */
    schnorrVerify(msg, sig, pubkeyX) {
        _check(msg, 32, 'msg');
        _check(sig, 64, 'sig');
        _check(pubkeyX, 32, 'pubkeyX');
        return this._lib.secp256k1_schnorr_verify(msg, sig, pubkeyX) === 1;
    }

    /** Get x-only public key (32 bytes). @returns {Buffer} */
    schnorrPubkey(privkey) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(rawPrivkey, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.alloc(32);
            const rc = this._lib.secp256k1_schnorr_pubkey(rawPrivkey, out);
            if (rc !== 0) throw new Error('Invalid private key');
            return out;
        });
    }

    // ── ECDH ─────────────────────────────────────────────────────────────

    /** ECDH: SHA256(compressed shared point). @returns {Buffer} 32 bytes. */
    ecdh(privkey, pubkey) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(rawPrivkey, 32, 'privkey');
        _check(pubkey, 33, 'pubkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.alloc(32);
            const rc = this._lib.secp256k1_ecdh(rawPrivkey, pubkey, out);
            if (rc !== 0) throw new Error('ECDH failed');
            return out;
        });
    }

    /** ECDH x-only. @returns {Buffer} */
    ecdhXonly(privkey, pubkey) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(rawPrivkey, 32, 'privkey');
        _check(pubkey, 33, 'pubkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.alloc(32);
            const rc = this._lib.secp256k1_ecdh_xonly(rawPrivkey, pubkey, out);
            if (rc !== 0) throw new Error('ECDH xonly failed');
            return out;
        });
    }

    /** ECDH raw x-coordinate. @returns {Buffer} */
    ecdhRaw(privkey, pubkey) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(rawPrivkey, 32, 'privkey');
        _check(pubkey, 33, 'pubkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.alloc(32);
            const rc = this._lib.secp256k1_ecdh_raw(rawPrivkey, pubkey, out);
            if (rc !== 0) throw new Error('ECDH raw failed');
            return out;
        });
    }

    // ── Hashing ──────────────────────────────────────────────────────────

    /** SHA-256. @returns {Buffer} 32 bytes. */
    sha256(data) {
        const out = Buffer.alloc(32);
        this._lib.secp256k1_sha256(data, data.length, out);
        return out;
    }

    /** HASH160. @returns {Buffer} 20 bytes. */
    hash160(data) {
        const out = Buffer.alloc(20);
        this._lib.secp256k1_hash160(data, data.length, out);
        return out;
    }

    /** Tagged hash (BIP-340). @returns {Buffer} 32 bytes. */
    taggedHash(tag, data) {
        const out = Buffer.alloc(32);
        this._lib.secp256k1_tagged_hash(tag, data, data.length, out);
        return out;
    }

    // ── Addresses ────────────────────────────────────────────────────────

    /** P2PKH address. @returns {string} */
    addressP2PKH(pubkey, network = NETWORK_MAINNET) {
        _check(pubkey, 33, 'pubkey');
        return this._getAddress((buf, lenPtr) =>
            this._lib.secp256k1_address_p2pkh(pubkey, network, buf, lenPtr));
    }

    /** P2WPKH address. @returns {string} */
    addressP2WPKH(pubkey, network = NETWORK_MAINNET) {
        _check(pubkey, 33, 'pubkey');
        return this._getAddress((buf, lenPtr) =>
            this._lib.secp256k1_address_p2wpkh(pubkey, network, buf, lenPtr));
    }

    /** P2TR address from x-only key. @returns {string} */
    addressP2TR(internalKeyX, network = NETWORK_MAINNET) {
        _check(internalKeyX, 32, 'internalKeyX');
        return this._getAddress((buf, lenPtr) =>
            this._lib.secp256k1_address_p2tr(internalKeyX, network, buf, lenPtr));
    }

    // ── WIF ──────────────────────────────────────────────────────────────

    /** Encode private key as WIF. @returns {string} */
    wifEncode(privkey, compressed = true, network = NETWORK_MAINNET) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(rawPrivkey, 32, 'privkey');
        return this._withSecretCleanup([privkey], () =>
            this._getAddress((buf, lenPtr) =>
                this._lib.secp256k1_wif_encode(rawPrivkey, compressed ? 1 : 0, network, buf, lenPtr)));
    }

    /** Decode WIF. @returns {{ privkey: Buffer, compressed: boolean, network: number }} */
    wifDecode(wif) {
        const privkey = Buffer.alloc(32);
        const compBuf = ref.alloc('int', 0);
        const netBuf = ref.alloc('int', 0);
        const rc = this._lib.secp256k1_wif_decode(wif, privkey, compBuf, netBuf);
        if (rc !== 0) throw new Error('Invalid WIF string');
        return {
            privkey,
            compressed: ref.deref(compBuf) === 1,
            network: ref.deref(netBuf),
        };
    }

    // ── BIP-32 ───────────────────────────────────────────────────────────

    /** Create master key from seed. @returns {Buffer} 79-byte opaque key. */
    bip32MasterKey(seed) {
        const rawSeed = _unwrapBytes(seed);
        if (rawSeed.length < 16 || rawSeed.length > 64) throw new Error('Seed must be 16-64 bytes');
        return this._withSecretCleanup([seed], () => {
            const key = Buffer.alloc(79);
            const rc = this._lib.secp256k1_bip32_master_key(rawSeed, rawSeed.length, key);
            if (rc !== 0) throw new Error('Master key generation failed');
            return key;
        });
    }

    /** Derive key from path. @returns {Buffer} */
    bip32DerivePath(masterKey, path) {
        _check(masterKey, 79, 'masterKey');
        const key = Buffer.alloc(79);
        const rc = this._lib.secp256k1_bip32_derive_path(masterKey, path, key);
        if (rc !== 0) throw new Error(`Path derivation failed: ${path}`);
        return key;
    }

    /** Get privkey from extended key. @returns {Buffer} */
    bip32GetPrivkey(key) {
        _check(key, 79, 'key');
        const privkey = Buffer.alloc(32);
        const rc = this._lib.secp256k1_bip32_get_privkey(key, privkey);
        if (rc !== 0) throw new Error('Key is not a private key');
        return privkey;
    }

    /** Get compressed pubkey from extended key. @returns {Buffer} */
    bip32GetPubkey(key) {
        _check(key, 79, 'key');
        const pubkey = Buffer.alloc(33);
        const rc = this._lib.secp256k1_bip32_get_pubkey(key, pubkey);
        if (rc !== 0) throw new Error('Public key extraction failed');
        return pubkey;
    }

    // ── Taproot ──────────────────────────────────────────────────────────

    /** Derive Taproot output key. @returns {{ outputKeyX: Buffer, parity: number }} */
    taprootOutputKey(internalKeyX, merkleRoot = null) {
        _check(internalKeyX, 32, 'internalKeyX');
        const out = Buffer.alloc(32);
        const parityBuf = ref.alloc('int', 0);
        const rc = this._lib.secp256k1_taproot_output_key(internalKeyX, merkleRoot, out, parityBuf);
        if (rc !== 0) throw new Error('Taproot output key failed');
        return { outputKeyX: out, parity: ref.deref(parityBuf) };
    }

    /** Tweak privkey for Taproot. @returns {Buffer} */
    taprootTweakPrivkey(privkey, merkleRoot = null) {
        const rawPrivkey = _unwrapBytes(privkey);
        _check(rawPrivkey, 32, 'privkey');
        return this._withSecretCleanup([privkey], () => {
            const out = Buffer.alloc(32);
            const rc = this._lib.secp256k1_taproot_tweak_privkey(rawPrivkey, merkleRoot, out);
            if (rc !== 0) throw new Error('Taproot tweak failed');
            return out;
        });
    }

    // ── Internal helper ──────────────────────────────────────────────────

    _getAddress(fn) {
        const buf = Buffer.alloc(128);
        const lenPtr = ref.alloc('size_t', 128);
        const rc = fn(buf, lenPtr);
        if (rc !== 0) throw new Error('Address generation failed');
        const len = ref.deref(lenPtr);
        return buf.toString('ascii', 0, Number(len));
    }

    _withSecretCleanup(values, fn) {
        try {
            return fn();
        } finally {
            for (const value of values) {
                if (value instanceof SensitiveBytes || (this._autoZeroInputs && value && (Buffer.isBuffer(value) || value instanceof Uint8Array))) {
                    _wipeSecretInput(value);
                }
            }
        }
    }
}

function _check(buf, expected, name) {
    if (!Buffer.isBuffer(buf) && !(buf instanceof Uint8Array)) throw new TypeError(`${name} must be a Buffer or Uint8Array`);
    if (buf.length !== expected) throw new RangeError(`${name} must be ${expected} bytes, got ${buf.length}`);
}

// ── TypeScript definitions ────────────────────────────────────────────────────
// (see lib/index.d.ts)

module.exports = { Secp256k1, NETWORK_MAINNET, NETWORK_TESTNET, SensitiveBytes, bestEffortZero };
