/**
 * UltrafastSecp256k1 — Node.js FFI binding (ufsecp stable C ABI v1).
 *
 * High-performance secp256k1 elliptic curve cryptography with dual-layer
 * constant-time architecture. Context-based API.
 *
 * Security notes:
 *   - Each context is single-thread; create one per worker/thread or
 *     synchronize externally.
 *   - Call destroy() when finished. A FinalizationRegistry fallback exists,
 *     but explicit destroy remains the safe lifecycle contract.
 *   - Native code erases its transient secret buffers, but JavaScript callers
 *     must still wipe their own Buffer/Uint8Array copies.
 *
 * Usage:
 *   const { Ufsecp } = require('ufsecp');
 *   const ctx = new Ufsecp();
 *   const pub = ctx.pubkeyCreate(Buffer.alloc(32, 0).fill(1, 31));
 *   ctx.destroy();
 */

'use strict';

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const path = require('path');
const os = require('os');

const voidPtr = ref.refType(ref.types.void);
const voidPtrPtr = ref.refType(voidPtr);
const uint8Ptr = ref.refType(ref.types.uint8);
const int32Ptr = ref.refType(ref.types.int32);
const sizeTPtr = ref.refType(ref.types.size_t);

const CTX_FINALIZER = typeof FinalizationRegistry === 'function'
  ? new FinalizationRegistry(({ lib, ctx }) => {
      try {
        lib.ufsecp_ctx_destroy(ctx);
      } catch {
        // Best-effort finalizer only.
      }
    })
  : null;

// ── Error codes ────────────────────────────────────────────────────────

const UFSECP_OK              = 0;
const UFSECP_ERR_NULL_ARG    = 1;
const UFSECP_ERR_BAD_KEY     = 2;
const UFSECP_ERR_BAD_PUBKEY  = 3;
const UFSECP_ERR_BAD_SIG     = 4;
const UFSECP_ERR_BAD_INPUT   = 5;
const UFSECP_ERR_VERIFY_FAIL = 6;
const UFSECP_ERR_ARITH       = 7;
const UFSECP_ERR_SELFTEST    = 8;
const UFSECP_ERR_INTERNAL    = 9;
const UFSECP_ERR_BUF_SMALL   = 10;

const ERROR_NAMES = {
  [UFSECP_ERR_NULL_ARG]:    'null argument',
  [UFSECP_ERR_BAD_KEY]:     'invalid private key',
  [UFSECP_ERR_BAD_PUBKEY]:  'invalid public key',
  [UFSECP_ERR_BAD_SIG]:     'invalid signature',
  [UFSECP_ERR_BAD_INPUT]:   'bad input',
  [UFSECP_ERR_VERIFY_FAIL]: 'verification failed',
  [UFSECP_ERR_ARITH]:       'arithmetic error',
  [UFSECP_ERR_SELFTEST]:    'selftest failed',
  [UFSECP_ERR_INTERNAL]:    'internal error',
  [UFSECP_ERR_BUF_SMALL]:   'buffer too small',
};

class UfsecpError extends Error {
  constructor(op, code) {
    super(`ufsecp ${op} failed: ${ERROR_NAMES[code] || `unknown (${code})`}`);
    this.name = 'UfsecpError';
    this.code = code;
    this.operation = op;
  }
}

// ── Library resolution ─────────────────────────────────────────────────

function findLibrary() {
  const plat = os.platform();
  const name = plat === 'win32' ? 'ufsecp.dll'
    : plat === 'darwin' ? 'libufsecp.dylib'
    : 'libufsecp.so';

  // 1. UFSECP_LIB env var
  const env = process.env.UFSECP_LIB;
  if (env) return env;

  // 2. Next to this file
  const here = path.join(__dirname, name);
  try { require('fs').accessSync(here); return here; } catch {}

  // 3. prebuilds/<platform>-<arch>/
  const prebuilt = path.join(__dirname, '..', 'prebuilds',
    `${plat}-${os.arch()}`, name);
  try { require('fs').accessSync(prebuilt); return prebuilt; } catch {}

  // 4. System default
  return name;
}

// ── FFI binding ────────────────────────────────────────────────────────

const LIB_SPEC = {
  // Context
  ufsecp_ctx_create:    ['int', [voidPtrPtr]],
  ufsecp_ctx_destroy:   ['void', [voidPtr]],
  ufsecp_ctx_clone:     ['int', [voidPtr, voidPtrPtr]],
  // Version
  ufsecp_version:       ['uint32', []],
  ufsecp_abi_version:   ['uint32', []],
  ufsecp_version_string:['string', []],
  ufsecp_error_str:     ['string', ['int']],
  ufsecp_last_error:    ['int', [voidPtr]],
  ufsecp_last_error_msg:['string', [voidPtr]],
  // Key ops
  ufsecp_pubkey_create:             ['int', [voidPtr, uint8Ptr, uint8Ptr]],
  ufsecp_pubkey_create_uncompressed:['int', [voidPtr, uint8Ptr, uint8Ptr]],
  ufsecp_pubkey_parse:              ['int', [voidPtr, uint8Ptr, 'size_t', uint8Ptr]],
  ufsecp_pubkey_xonly:              ['int', [voidPtr, uint8Ptr, uint8Ptr]],
  ufsecp_seckey_verify:             ['int', [voidPtr, uint8Ptr]],
  ufsecp_seckey_negate:             ['int', [voidPtr, uint8Ptr]],
  ufsecp_seckey_tweak_add:          ['int', [voidPtr, uint8Ptr, uint8Ptr]],
  ufsecp_seckey_tweak_mul:          ['int', [voidPtr, uint8Ptr, uint8Ptr]],
  // ECDSA
  ufsecp_ecdsa_sign:                ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr]],
  ufsecp_ecdsa_verify:              ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr]],
  ufsecp_ecdsa_sig_to_der:          ['int', [voidPtr, uint8Ptr, uint8Ptr, sizeTPtr]],
  ufsecp_ecdsa_sig_from_der:        ['int', [voidPtr, uint8Ptr, 'size_t', uint8Ptr]],
  // Recovery
  ufsecp_ecdsa_sign_recoverable:    ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr, int32Ptr]],
  ufsecp_ecdsa_recover:             ['int', [voidPtr, uint8Ptr, uint8Ptr, 'int', uint8Ptr]],
  // Schnorr
  ufsecp_schnorr_sign:              ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr, uint8Ptr]],
  ufsecp_schnorr_verify:            ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr]],
  // ECDH
  ufsecp_ecdh:                      ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr]],
  ufsecp_ecdh_xonly:                ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr]],
  ufsecp_ecdh_raw:                  ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr]],
  // Hashing
  ufsecp_sha256:                    ['int', [uint8Ptr, 'size_t', uint8Ptr]],
  ufsecp_hash160:                   ['int', [uint8Ptr, 'size_t', uint8Ptr]],
  ufsecp_tagged_hash:               ['int', ['string', uint8Ptr, 'size_t', uint8Ptr]],
  // Addresses
  ufsecp_addr_p2pkh:                ['int', [voidPtr, uint8Ptr, 'int', uint8Ptr, sizeTPtr]],
  ufsecp_addr_p2wpkh:               ['int', [voidPtr, uint8Ptr, 'int', uint8Ptr, sizeTPtr]],
  ufsecp_addr_p2tr:                 ['int', [voidPtr, uint8Ptr, 'int', uint8Ptr, sizeTPtr]],
  // WIF
  ufsecp_wif_encode:                ['int', [voidPtr, uint8Ptr, 'int', 'int', uint8Ptr, sizeTPtr]],
  ufsecp_wif_decode:                ['int', [voidPtr, 'string', uint8Ptr, int32Ptr, int32Ptr]],
  // BIP-32
  ufsecp_bip32_master:              ['int', [voidPtr, uint8Ptr, 'size_t', uint8Ptr]],
  ufsecp_bip32_derive:              ['int', [voidPtr, uint8Ptr, 'uint32', uint8Ptr]],
  ufsecp_bip32_derive_path:         ['int', [voidPtr, uint8Ptr, 'string', uint8Ptr]],
  ufsecp_bip32_privkey:             ['int', [voidPtr, uint8Ptr, uint8Ptr]],
  ufsecp_bip32_pubkey:              ['int', [voidPtr, uint8Ptr, uint8Ptr]],
  // Taproot
  ufsecp_taproot_output_key:        ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr, int32Ptr]],
  ufsecp_taproot_tweak_seckey:      ['int', [voidPtr, uint8Ptr, uint8Ptr, uint8Ptr]],
  ufsecp_taproot_verify:            ['int', [voidPtr, uint8Ptr, 'int', uint8Ptr, uint8Ptr, 'size_t']],
};

// ── Constants ──────────────────────────────────────────────────────────

const NET_MAINNET = 0;
const NET_TESTNET = 1;

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
    if (this._destroyed) {
      throw new Error('SensitiveBytes already destroyed');
    }
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

function _normalizeSecretInput(value) {
  return value instanceof SensitiveBytes ? value.bytes : value;
}

function _wipeSecretInput(value) {
  if (value instanceof SensitiveBytes) {
    value.destroy();
    return;
  }
  bestEffortZero(value);
}

function _ffiBytes(value) {
  return value.length === 0 ? Buffer.alloc(1) : value;
}

function _parseConstructorArgs(libPathOrOptions, maybeOptions) {
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

// ── Ufsecp class ───────────────────────────────────────────────────────

class Ufsecp {
  /**
   * @param {string|object} [libPathOrOptions] Path to the ufsecp shared library,
   *   or options: { libPath?: string, autoZeroInputs?: boolean }.
   * @param {object} [maybeOptions] Optional options when the first arg is a path.
   */
  constructor(libPathOrOptions, maybeOptions) {
    const opts = _parseConstructorArgs(libPathOrOptions, maybeOptions);
    this._lib = ffi.Library(opts.libPath || findLibrary(), LIB_SPEC);
    const pp = ref.alloc(voidPtr);
    const rc = this._lib.ufsecp_ctx_create(pp);
    if (rc !== UFSECP_OK) throw new UfsecpError('ctx_create', rc);
    this._ctx = pp.deref();
    this._destroyed = false;
    this._autoZeroInputs = opts.autoZeroInputs;
    this._finalizerToken = {};
    if (CTX_FINALIZER) {
      CTX_FINALIZER.register(this, { lib: this._lib, ctx: this._ctx }, this._finalizerToken);
    }
  }

  /** Explicitly destroy the context. Safe to call multiple times. */
  destroy() {
    if (!this._destroyed && this._ctx) {
      if (CTX_FINALIZER) {
        CTX_FINALIZER.unregister(this._finalizerToken);
      }
      this._lib.ufsecp_ctx_destroy(this._ctx);
      this._ctx = null;
      this._destroyed = true;
    }
  }

  // ── Version ──────────────────────────────────────────────────────────

  version()       { return this._lib.ufsecp_version(); }
  abiVersion()    { return this._lib.ufsecp_abi_version(); }
  versionString() { return this._lib.ufsecp_version_string(); }
  lastError()     { this._alive(); return this._lib.ufsecp_last_error(this._ctx); }
  lastErrorMsg()  { this._alive(); return String(this._lib.ufsecp_last_error_msg(this._ctx)); }

  // ── Key operations ────────────────────────────────────────────────────

  /** Compressed public key (33 bytes). */
  pubkeyCreate(privkey) {
    const raw = _normalizeSecretInput(privkey);
    _chk(raw, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const out = Buffer.alloc(33);
      this._throw(this._lib.ufsecp_pubkey_create(this._ctx, raw, out), 'pubkey_create');
      return out;
    });
  }

  /** Uncompressed public key (65 bytes). */
  pubkeyCreateUncompressed(privkey) {
    const raw = _normalizeSecretInput(privkey);
    _chk(raw, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const out = Buffer.alloc(65);
      this._throw(this._lib.ufsecp_pubkey_create_uncompressed(this._ctx, raw, out), 'pubkey_create_uncompressed');
      return out;
    });
  }

  /** Parse compressed/uncompressed → compressed 33 bytes. */
  pubkeyParse(pubkey) {
    this._alive();
    const out = Buffer.alloc(33);
    this._throw(this._lib.ufsecp_pubkey_parse(this._ctx, pubkey, pubkey.length, out), 'pubkey_parse');
    return out;
  }

  /** X-only (32 bytes, BIP-340) from private key. */
  pubkeyXonly(privkey) {
    const raw = _normalizeSecretInput(privkey);
    _chk(raw, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const out = Buffer.alloc(32);
      this._throw(this._lib.ufsecp_pubkey_xonly(this._ctx, raw, out), 'pubkey_xonly');
      return out;
    });
  }

  seckeyVerify(privkey)  {
    const raw = _normalizeSecretInput(privkey);
    _chk(raw, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => this._lib.ufsecp_seckey_verify(this._ctx, raw) === UFSECP_OK);
  }

  seckeyNegate(privkey) {
    const raw = _normalizeSecretInput(privkey);
    _chk(raw, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const buf = Buffer.from(raw);
      this._throw(this._lib.ufsecp_seckey_negate(this._ctx, buf), 'seckey_negate');
      return buf;
    });
  }

  seckeyTweakAdd(privkey, tweak) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    const rawTweak = _normalizeSecretInput(tweak);
    _chk(rawPrivkey, 32, 'privkey'); _chk(rawTweak, 32, 'tweak'); this._alive();
    return this._withSecretCleanup([privkey, tweak], () => {
      const buf = Buffer.from(rawPrivkey);
      this._throw(this._lib.ufsecp_seckey_tweak_add(this._ctx, buf, rawTweak), 'seckey_tweak_add');
      return buf;
    });
  }

  seckeyTweakMul(privkey, tweak) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    const rawTweak = _normalizeSecretInput(tweak);
    _chk(rawPrivkey, 32, 'privkey'); _chk(rawTweak, 32, 'tweak'); this._alive();
    return this._withSecretCleanup([privkey, tweak], () => {
      const buf = Buffer.from(rawPrivkey);
      this._throw(this._lib.ufsecp_seckey_tweak_mul(this._ctx, buf, rawTweak), 'seckey_tweak_mul');
      return buf;
    });
  }

  // ── ECDSA ─────────────────────────────────────────────────────────────

  ecdsaSign(msgHash, privkey) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    _chk(msgHash, 32, 'msgHash'); _chk(rawPrivkey, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const sig = Buffer.alloc(64);
      this._throw(this._lib.ufsecp_ecdsa_sign(this._ctx, msgHash, rawPrivkey, sig), 'ecdsa_sign');
      return sig;
    });
  }

  ecdsaVerify(msgHash, sig, pubkey) {
    _chk(msgHash, 32, 'msgHash'); _chk(sig, 64, 'sig'); _chk(pubkey, 33, 'pubkey'); this._alive();
    return this._lib.ufsecp_ecdsa_verify(this._ctx, msgHash, sig, pubkey) === UFSECP_OK;
  }

  ecdsaSigToDer(sig) {
    _chk(sig, 64, 'sig'); this._alive();
    const der = Buffer.alloc(72);
    const len = ref.alloc('size_t', 72);
    this._throw(this._lib.ufsecp_ecdsa_sig_to_der(this._ctx, sig, der, len), 'ecdsa_sig_to_der');
    return der.subarray(0, len.deref());
  }

  ecdsaSigFromDer(der) {
    this._alive();
    const sig = Buffer.alloc(64);
    this._throw(this._lib.ufsecp_ecdsa_sig_from_der(this._ctx, der, der.length, sig), 'ecdsa_sig_from_der');
    return sig;
  }

  // ── Recovery ──────────────────────────────────────────────────────────

  ecdsaSignRecoverable(msgHash, privkey) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    _chk(msgHash, 32, 'msgHash'); _chk(rawPrivkey, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const sig = Buffer.alloc(64);
      const recid = ref.alloc('int');
      this._throw(this._lib.ufsecp_ecdsa_sign_recoverable(this._ctx, msgHash, rawPrivkey, sig, recid), 'ecdsa_sign_recoverable');
      return { signature: sig, recoveryId: recid.deref() };
    });
  }

  ecdsaRecover(msgHash, sig, recid) {
    _chk(msgHash, 32, 'msgHash'); _chk(sig, 64, 'sig'); this._alive();
    const pub = Buffer.alloc(33);
    this._throw(this._lib.ufsecp_ecdsa_recover(this._ctx, msgHash, sig, recid, pub), 'ecdsa_recover');
    return pub;
  }

  // ── Schnorr ───────────────────────────────────────────────────────────

  schnorrSign(msg, privkey, auxRand) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    const rawAuxRand = _normalizeSecretInput(auxRand);
    _chk(msg, 32, 'msg'); _chk(rawPrivkey, 32, 'privkey'); _chk(rawAuxRand, 32, 'auxRand'); this._alive();
    return this._withSecretCleanup([privkey, auxRand], () => {
      const sig = Buffer.alloc(64);
      this._throw(this._lib.ufsecp_schnorr_sign(this._ctx, msg, rawPrivkey, rawAuxRand, sig), 'schnorr_sign');
      return sig;
    });
  }

  schnorrVerify(msg, sig, pubkeyX) {
    _chk(msg, 32, 'msg'); _chk(sig, 64, 'sig'); _chk(pubkeyX, 32, 'pubkeyX'); this._alive();
    return this._lib.ufsecp_schnorr_verify(this._ctx, msg, sig, pubkeyX) === UFSECP_OK;
  }

  // ── ECDH ──────────────────────────────────────────────────────────────

  ecdh(privkey, pubkey) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    _chk(rawPrivkey, 32, 'privkey'); _chk(pubkey, 33, 'pubkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const out = Buffer.alloc(32);
      this._throw(this._lib.ufsecp_ecdh(this._ctx, rawPrivkey, pubkey, out), 'ecdh');
      return out;
    });
  }

  ecdhXonly(privkey, pubkey) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    _chk(rawPrivkey, 32, 'privkey'); _chk(pubkey, 33, 'pubkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const out = Buffer.alloc(32);
      this._throw(this._lib.ufsecp_ecdh_xonly(this._ctx, rawPrivkey, pubkey, out), 'ecdh_xonly');
      return out;
    });
  }

  ecdhRaw(privkey, pubkey) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    _chk(rawPrivkey, 32, 'privkey'); _chk(pubkey, 33, 'pubkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const out = Buffer.alloc(32);
      this._throw(this._lib.ufsecp_ecdh_raw(this._ctx, rawPrivkey, pubkey, out), 'ecdh_raw');
      return out;
    });
  }

  // ── Hashing ───────────────────────────────────────────────────────────

  sha256(data) {
    const out = Buffer.alloc(32);
    this._throw(this._lib.ufsecp_sha256(_ffiBytes(data), data.length, out), 'sha256');
    return out;
  }

  hash160(data) {
    const out = Buffer.alloc(20);
    this._throw(this._lib.ufsecp_hash160(_ffiBytes(data), data.length, out), 'hash160');
    return out;
  }

  taggedHash(tag, data) {
    const out = Buffer.alloc(32);
    this._throw(this._lib.ufsecp_tagged_hash(tag, _ffiBytes(data), data.length, out), 'tagged_hash');
    return out;
  }

  // ── Addresses ─────────────────────────────────────────────────────────

  addrP2PKH(pubkey, network = NET_MAINNET) {
    _chk(pubkey, 33, 'pubkey'); return this._getAddr('ufsecp_addr_p2pkh', pubkey, network);
  }

  addrP2WPKH(pubkey, network = NET_MAINNET) {
    _chk(pubkey, 33, 'pubkey'); return this._getAddr('ufsecp_addr_p2wpkh', pubkey, network);
  }

  addrP2TR(xonlyKey, network = NET_MAINNET) {
    _chk(xonlyKey, 32, 'xonlyKey'); return this._getAddr('ufsecp_addr_p2tr', xonlyKey, network);
  }

  // ── WIF ───────────────────────────────────────────────────────────────

  wifEncode(privkey, compressed = true, network = NET_MAINNET) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    _chk(rawPrivkey, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const buf = Buffer.alloc(128);
      const len = ref.alloc('size_t', 128);
      this._throw(this._lib.ufsecp_wif_encode(this._ctx, rawPrivkey, compressed ? 1 : 0, network, buf, len), 'wif_encode');
      return buf.toString('utf8', 0, len.deref());
    });
  }

  wifDecode(wif) {
    this._alive();
    const key = Buffer.alloc(32);
    const comp = ref.alloc('int');
    const net = ref.alloc('int');
    this._throw(this._lib.ufsecp_wif_decode(this._ctx, wif, key, comp, net), 'wif_decode');
    return { privkey: key, compressed: comp.deref() === 1, network: net.deref() };
  }

  // ── BIP-32 ────────────────────────────────────────────────────────────

  bip32Master(seed) {
    const raw = _normalizeSecretInput(seed);
    this._alive();
    if (raw.length < 16 || raw.length > 64) throw new RangeError('Seed must be 16-64 bytes');
    return this._withSecretCleanup([seed], () => {
      const key = Buffer.alloc(82);
      this._throw(this._lib.ufsecp_bip32_master(this._ctx, raw, raw.length, key), 'bip32_master');
      return key;
    });
  }

  bip32Derive(parent, index) {
    _chk(parent, 82, 'parent'); this._alive();
    const child = Buffer.alloc(82);
    this._throw(this._lib.ufsecp_bip32_derive(this._ctx, parent, index >>> 0, child), 'bip32_derive');
    return child;
  }

  bip32DerivePath(master, path) {
    _chk(master, 82, 'master'); this._alive();
    const key = Buffer.alloc(82);
    this._throw(this._lib.ufsecp_bip32_derive_path(this._ctx, master, path, key), 'bip32_derive_path');
    return key;
  }

  bip32Privkey(key) {
    _chk(key, 82, 'key'); this._alive();
    const priv = Buffer.alloc(32);
    this._throw(this._lib.ufsecp_bip32_privkey(this._ctx, key, priv), 'bip32_privkey');
    return priv;
  }

  bip32Pubkey(key) {
    _chk(key, 82, 'key'); this._alive();
    const pub = Buffer.alloc(33);
    this._throw(this._lib.ufsecp_bip32_pubkey(this._ctx, key, pub), 'bip32_pubkey');
    return pub;
  }

  // ── Taproot ───────────────────────────────────────────────────────────

  taprootOutputKey(internalKeyX, merkleRoot = null) {
    _chk(internalKeyX, 32, 'internalKeyX'); this._alive();
    const out = Buffer.alloc(32);
    const parity = ref.alloc('int');
    this._throw(this._lib.ufsecp_taproot_output_key(this._ctx, internalKeyX, merkleRoot, out, parity), 'taproot_output_key');
    return { outputKeyX: out, parity: parity.deref() };
  }

  taprootTweakSeckey(privkey, merkleRoot = null) {
    const rawPrivkey = _normalizeSecretInput(privkey);
    _chk(rawPrivkey, 32, 'privkey'); this._alive();
    return this._withSecretCleanup([privkey], () => {
      const out = Buffer.alloc(32);
      this._throw(this._lib.ufsecp_taproot_tweak_seckey(this._ctx, rawPrivkey, merkleRoot, out), 'taproot_tweak_seckey');
      return out;
    });
  }

  taprootVerify(outputKeyX, parity, internalKeyX, merkleRoot = null) {
    _chk(outputKeyX, 32, 'outputKeyX'); _chk(internalKeyX, 32, 'internalKeyX'); this._alive();
    const mrLen = merkleRoot ? merkleRoot.length : 0;
    return this._lib.ufsecp_taproot_verify(this._ctx, outputKeyX, parity, internalKeyX, merkleRoot, mrLen) === UFSECP_OK;
  }

  // ── Internal ──────────────────────────────────────────────────────────

  _alive() {
    if (this._destroyed) throw new Error('UfsecpContext already destroyed');
  }

  _throw(rc, op) {
    if (rc !== UFSECP_OK) throw new UfsecpError(op, rc);
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

  _getAddr(fnName, key, network) {
    this._alive();
    const buf = Buffer.alloc(128);
    const len = ref.alloc('size_t', 128);
    this._throw(this._lib[fnName](this._ctx, key, network, buf, len), 'address');
    return buf.toString('utf8', 0, len.deref());
  }
}

if (typeof Symbol.dispose === 'symbol') {
  Ufsecp.prototype[Symbol.dispose] = Ufsecp.prototype.destroy;
}

function _chk(buf, expected, name) {
  if (!Buffer.isBuffer(buf) && !(buf instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Buffer or Uint8Array`);
  }
  if (buf.length !== expected) {
    throw new RangeError(`${name} must be ${expected} bytes, got ${buf.length}`);
  }
}

module.exports = { Ufsecp, UfsecpError, NET_MAINNET, NET_TESTNET, SensitiveBytes, bestEffortZero };
