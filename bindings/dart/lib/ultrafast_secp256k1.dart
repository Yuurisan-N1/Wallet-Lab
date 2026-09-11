/// UltrafastSecp256k1 — Dart FFI bindings.
///
/// High-performance secp256k1 elliptic curve cryptography.
///
/// ```dart
/// import 'package:ultrafast_secp256k1/ultrafast_secp256k1.dart';
///
/// final lib = UltrafastSecp256k1();
/// final pubkey = lib.ecPubkeyCreate(Uint8List(32)..[31] = 1);
/// ```
library ultrafast_secp256k1;

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ── C typedefs ────────────────────────────────────────────────────────────

// Version / Init
typedef _VersionC = ffi.Pointer<Utf8> Function();
typedef _VersionDart = ffi.Pointer<Utf8> Function();
typedef _InitC = ffi.Int32 Function();
typedef _InitDart = int Function();

// Key ops
typedef _PubkeyCreateC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _PubkeyCreateDart = int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

typedef _PubkeyParseC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Pointer<ffi.Uint8>);
typedef _PubkeyParseDart = int Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);

typedef _SeckeyVerifyC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>);
typedef _SeckeyVerifyDart = int Function(ffi.Pointer<ffi.Uint8>);

typedef _PrivNegateC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>);
typedef _PrivNegateDart = int Function(ffi.Pointer<ffi.Uint8>);

typedef _PrivTweakC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _PrivTweakDart = int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

// ECDSA
typedef _EcdsaSignC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _EcdsaSignDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

typedef _EcdsaVerifyC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _EcdsaVerifyDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

typedef _SerializeDerC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Size>);
typedef _SerializeDerDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Size>);

// Recovery
typedef _SignRecoverableC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Int32>);
typedef _SignRecoverableDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Int32>);

typedef _RecoverC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Int32, ffi.Pointer<ffi.Uint8>);
typedef _RecoverDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);

// Schnorr
typedef _SchnorrSignC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _SchnorrSignDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

typedef _SchnorrVerifyC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _SchnorrVerifyDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

typedef _SchnorrPubkeyC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _SchnorrPubkeyDart = int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

// ECDH
typedef _EcdhC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _EcdhDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

// Hashing
typedef _Sha256C = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Pointer<ffi.Uint8>);
typedef _Sha256Dart = void Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);

typedef _Hash160C = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Pointer<ffi.Uint8>);
typedef _Hash160Dart = void Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);

typedef _TaggedHashC = ffi.Void Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Pointer<ffi.Uint8>);
typedef _TaggedHashDart = void Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);

// Addresses
typedef _AddressC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Int32, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Size>);
typedef _AddressDart = int Function(
    ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Size>);

// WIF
typedef _WifEncodeC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Int32, ffi.Int32, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Size>);
typedef _WifEncodeDart = int Function(
    ffi.Pointer<ffi.Uint8>, int, int, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Size>);

typedef _WifDecodeC = ffi.Int32 Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Int32>, ffi.Pointer<ffi.Int32>);
typedef _WifDecodeDart = int Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Int32>, ffi.Pointer<ffi.Int32>);

// BIP-32
typedef _Bip32MasterC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Pointer<ffi.Uint8>);
typedef _Bip32MasterDart = int Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);

typedef _Bip32DeriveChildC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Uint32, ffi.Pointer<ffi.Uint8>);
typedef _Bip32DeriveChildDart = int Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);

typedef _Bip32DerivePathC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>);
typedef _Bip32DerivePathDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<Utf8>, ffi.Pointer<ffi.Uint8>);

typedef _Bip32GetKeyC = ffi.Int32 Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _Bip32GetKeyDart = int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

// Taproot
typedef _TaprootOutputKeyC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Int32>);
typedef _TaprootOutputKeyDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Int32>);

typedef _TaprootTweakPrivC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _TaprootTweakPrivDart = int Function(
    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

typedef _TaprootVerifyC = ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>, ffi.Int32, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Size);
typedef _TaprootVerifyDart = int Function(
    ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, int);

// ── Library class ──────────────────────────────────────────────────────

/// Network type for address generation.
enum Network { mainnet, testnet }

/// Taproot output key result.
class TaprootOutputKeyResult {
  final Uint8List outputKeyX;
  final int parity;
  TaprootOutputKeyResult(this.outputKeyX, this.parity);
}

/// WIF decode result.
class WifDecodeResult {
  final Uint8List privkey;
  final bool compressed;
  final Network network;
  WifDecodeResult(this.privkey, this.compressed, this.network);
}

/// Recoverable ECDSA signature result.
class RecoverableSignature {
  final Uint8List signature;
  final int recoveryId;
  RecoverableSignature(this.signature, this.recoveryId);
}

/// Custom exception for secp256k1 errors.
class Secp256k1Exception implements Exception {
  final String message;
  Secp256k1Exception(this.message);
  @override
  String toString() => 'Secp256k1Exception: $message';
}

/// UltrafastSecp256k1 — Dart FFI bindings for high-performance ECC.
class UltrafastSecp256k1 {
  late final ffi.DynamicLibrary _lib;

  // Cached lookups
  late final _VersionDart _version;
  late final _InitDart _init;
  late final _PubkeyCreateDart _pubkeyCreate;
  late final _PubkeyCreateDart _pubkeyCreateUncompressed;
  late final _PubkeyParseDart _pubkeyParse;
  late final _SeckeyVerifyDart _seckeyVerify;
  late final _PrivNegateDart _privNegate;
  late final _PrivTweakDart _privTweakAdd;
  late final _PrivTweakDart _privTweakMul;
  late final _EcdsaSignDart _ecdsaSign;
  late final _EcdsaVerifyDart _ecdsaVerify;
  late final _SerializeDerDart _serializeDer;
  late final _SignRecoverableDart _signRecoverable;
  late final _RecoverDart _recover;
  late final _SchnorrSignDart _schnorrSign;
  late final _SchnorrVerifyDart _schnorrVerify;
  late final _SchnorrPubkeyDart _schnorrPubkey;
  late final _EcdhDart _ecdh;
  late final _EcdhDart _ecdhXonly;
  late final _EcdhDart _ecdhRaw;
  late final _Sha256Dart _sha256;
  late final _Hash160Dart _hash160;
  late final _TaggedHashDart _taggedHash;
  late final _AddressDart _addressP2pkh;
  late final _AddressDart _addressP2wpkh;
  late final _AddressDart _addressP2tr;
  late final _WifEncodeDart _wifEncode;
  late final _WifDecodeDart _wifDecode;
  late final _Bip32MasterDart _bip32Master;
  late final _Bip32DeriveChildDart _bip32DeriveChild;
  late final _Bip32DerivePathDart _bip32DerivePath;
  late final _Bip32GetKeyDart _bip32GetPrivkey;
  late final _Bip32GetKeyDart _bip32GetPubkey;
  late final _TaprootOutputKeyDart _taprootOutputKey;
  late final _TaprootTweakPrivDart _taprootTweakPriv;
  late final _TaprootVerifyDart _taprootVerify;

  /// Create a new instance, optionally providing a [libraryPath].
  ///
  /// If [libraryPath] is null, the default platform library name is used.
  UltrafastSecp256k1({String? libraryPath}) {
    _lib = ffi.DynamicLibrary.open(libraryPath ?? _defaultLibName());
    _bindAll();
    final rc = _init();
    if (rc != 0) throw Secp256k1Exception('Library selftest failed');
  }

  static String _defaultLibName() {
    if (Platform.isWindows) return 'ultrafast_secp256k1.dll';
    if (Platform.isMacOS) return 'libultrafast_secp256k1.dylib';
    return 'libultrafast_secp256k1.so';
  }

  void _bindAll() {
    _version = _lib.lookupFunction<_VersionC, _VersionDart>('secp256k1_version');
    _init = _lib.lookupFunction<_InitC, _InitDart>('secp256k1_init');
    _pubkeyCreate = _lib.lookupFunction<_PubkeyCreateC, _PubkeyCreateDart>('secp256k1_ec_pubkey_create');
    _pubkeyCreateUncompressed = _lib.lookupFunction<_PubkeyCreateC, _PubkeyCreateDart>('secp256k1_ec_pubkey_create_uncompressed');
    _pubkeyParse = _lib.lookupFunction<_PubkeyParseC, _PubkeyParseDart>('secp256k1_ec_pubkey_parse');
    _seckeyVerify = _lib.lookupFunction<_SeckeyVerifyC, _SeckeyVerifyDart>('secp256k1_ec_seckey_verify');
    _privNegate = _lib.lookupFunction<_PrivNegateC, _PrivNegateDart>('secp256k1_ec_privkey_negate');
    _privTweakAdd = _lib.lookupFunction<_PrivTweakC, _PrivTweakDart>('secp256k1_ec_privkey_tweak_add');
    _privTweakMul = _lib.lookupFunction<_PrivTweakC, _PrivTweakDart>('secp256k1_ec_privkey_tweak_mul');
    _ecdsaSign = _lib.lookupFunction<_EcdsaSignC, _EcdsaSignDart>('secp256k1_ecdsa_sign');
    _ecdsaVerify = _lib.lookupFunction<_EcdsaVerifyC, _EcdsaVerifyDart>('secp256k1_ecdsa_verify');
    _serializeDer = _lib.lookupFunction<_SerializeDerC, _SerializeDerDart>('secp256k1_ecdsa_signature_serialize_der');
    _signRecoverable = _lib.lookupFunction<_SignRecoverableC, _SignRecoverableDart>('secp256k1_ecdsa_sign_recoverable');
    _recover = _lib.lookupFunction<_RecoverC, _RecoverDart>('secp256k1_ecdsa_recover');
    _schnorrSign = _lib.lookupFunction<_SchnorrSignC, _SchnorrSignDart>('secp256k1_schnorr_sign');
    _schnorrVerify = _lib.lookupFunction<_SchnorrVerifyC, _SchnorrVerifyDart>('secp256k1_schnorr_verify');
    _schnorrPubkey = _lib.lookupFunction<_SchnorrPubkeyC, _SchnorrPubkeyDart>('secp256k1_schnorr_pubkey');
    _ecdh = _lib.lookupFunction<_EcdhC, _EcdhDart>('secp256k1_ecdh');
    _ecdhXonly = _lib.lookupFunction<_EcdhC, _EcdhDart>('secp256k1_ecdh_xonly');
    _ecdhRaw = _lib.lookupFunction<_EcdhC, _EcdhDart>('secp256k1_ecdh_raw');
    _sha256 = _lib.lookupFunction<_Sha256C, _Sha256Dart>('secp256k1_sha256');
    _hash160 = _lib.lookupFunction<_Hash160C, _Hash160Dart>('secp256k1_hash160');
    _taggedHash = _lib.lookupFunction<_TaggedHashC, _TaggedHashDart>('secp256k1_tagged_hash');
    _addressP2pkh = _lib.lookupFunction<_AddressC, _AddressDart>('secp256k1_address_p2pkh');
    _addressP2wpkh = _lib.lookupFunction<_AddressC, _AddressDart>('secp256k1_address_p2wpkh');
    _addressP2tr = _lib.lookupFunction<_AddressC, _AddressDart>('secp256k1_address_p2tr');
    _wifEncode = _lib.lookupFunction<_WifEncodeC, _WifEncodeDart>('secp256k1_wif_encode');
    _wifDecode = _lib.lookupFunction<_WifDecodeC, _WifDecodeDart>('secp256k1_wif_decode');
    _bip32Master = _lib.lookupFunction<_Bip32MasterC, _Bip32MasterDart>('secp256k1_bip32_master_key');
    _bip32DeriveChild = _lib.lookupFunction<_Bip32DeriveChildC, _Bip32DeriveChildDart>('secp256k1_bip32_derive_child');
    _bip32DerivePath = _lib.lookupFunction<_Bip32DerivePathC, _Bip32DerivePathDart>('secp256k1_bip32_derive_path');
    _bip32GetPrivkey = _lib.lookupFunction<_Bip32GetKeyC, _Bip32GetKeyDart>('secp256k1_bip32_get_privkey');
    _bip32GetPubkey = _lib.lookupFunction<_Bip32GetKeyC, _Bip32GetKeyDart>('secp256k1_bip32_get_pubkey');
    _taprootOutputKey = _lib.lookupFunction<_TaprootOutputKeyC, _TaprootOutputKeyDart>('secp256k1_taproot_output_key');
    _taprootTweakPriv = _lib.lookupFunction<_TaprootTweakPrivC, _TaprootTweakPrivDart>('secp256k1_taproot_tweak_privkey');
    _taprootVerify = _lib.lookupFunction<_TaprootVerifyC, _TaprootVerifyDart>('secp256k1_taproot_verify_commitment');
  }

  // ── Helpers ──────────────────────────────────────────────────────────

  ffi.Pointer<ffi.Uint8> _toNative(Uint8List data) {
    final ptr = calloc<ffi.Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }

  Uint8List _readBytes(ffi.Pointer<ffi.Uint8> ptr, int len) {
    final list = Uint8List(len);
    list.setAll(0, ptr.asTypedList(len));
    return list;
  }

  void _checkLen(Uint8List data, int expected, String name) {
    if (data.length != expected) {
      throw ArgumentError('$name must be $expected bytes, got ${data.length}');
    }
  }

  // ── Public API ──────────────────────────────────────────────────────

  /// Library version string.
  String get version => _version().toDartString();

  // ── Key Operations ──────────────────────────────────────────────────

  /// Create a compressed public key from a 32-byte private key.
  Uint8List ecPubkeyCreate(Uint8List privkey) {
    _checkLen(privkey, 32, 'privkey');
    final pk = _toNative(privkey);
    final out = calloc<ffi.Uint8>(33);
    try {
      final rc = _pubkeyCreate(pk, out);
      if (rc != 0) throw Secp256k1Exception('Invalid private key');
      return _readBytes(out, 33);
    } finally {
      calloc.free(pk);
      calloc.free(out);
    }
  }

  /// Create an uncompressed (65-byte) public key.
  Uint8List ecPubkeyCreateUncompressed(Uint8List privkey) {
    _checkLen(privkey, 32, 'privkey');
    final pk = _toNative(privkey);
    final out = calloc<ffi.Uint8>(65);
    try {
      final rc = _pubkeyCreateUncompressed(pk, out);
      if (rc != 0) throw Secp256k1Exception('Invalid private key');
      return _readBytes(out, 65);
    } finally {
      calloc.free(pk);
      calloc.free(out);
    }
  }

  /// Parse and compress a public key (33 or 65 bytes → 33 bytes).
  Uint8List ecPubkeyParse(Uint8List input) {
    final inp = _toNative(input);
    final out = calloc<ffi.Uint8>(33);
    try {
      final rc = _pubkeyParse(inp, input.length, out);
      if (rc != 0) throw Secp256k1Exception('Invalid public key');
      return _readBytes(out, 33);
    } finally {
      calloc.free(inp);
      calloc.free(out);
    }
  }

  /// Verify that a 32-byte scalar is a valid private key.
  bool ecSeckeyVerify(Uint8List privkey) {
    _checkLen(privkey, 32, 'privkey');
    final pk = _toNative(privkey);
    try {
      return _seckeyVerify(pk) == 1;
    } finally {
      calloc.free(pk);
    }
  }

  /// Negate a private key in-place (returns new buffer).
  Uint8List ecPrivkeyNegate(Uint8List privkey) {
    _checkLen(privkey, 32, 'privkey');
    final buf = _toNative(privkey);
    try {
      _privNegate(buf);
      return _readBytes(buf, 32);
    } finally {
      calloc.free(buf);
    }
  }

  /// Add tweak to private key.
  Uint8List ecPrivkeyTweakAdd(Uint8List privkey, Uint8List tweak) {
    _checkLen(privkey, 32, 'privkey');
    _checkLen(tweak, 32, 'tweak');
    final buf = _toNative(privkey);
    final tw = _toNative(tweak);
    try {
      final rc = _privTweakAdd(buf, tw);
      if (rc != 0) throw Secp256k1Exception('Tweak add failed');
      return _readBytes(buf, 32);
    } finally {
      calloc.free(buf);
      calloc.free(tw);
    }
  }

  /// Multiply private key by tweak.
  Uint8List ecPrivkeyTweakMul(Uint8List privkey, Uint8List tweak) {
    _checkLen(privkey, 32, 'privkey');
    _checkLen(tweak, 32, 'tweak');
    final buf = _toNative(privkey);
    final tw = _toNative(tweak);
    try {
      final rc = _privTweakMul(buf, tw);
      if (rc != 0) throw Secp256k1Exception('Tweak mul failed');
      return _readBytes(buf, 32);
    } finally {
      calloc.free(buf);
      calloc.free(tw);
    }
  }

  // ── ECDSA ──────────────────────────────────────────────────────────

  /// Sign a 32-byte message hash, returns a 64-byte compact signature.
  Uint8List ecdsaSign(Uint8List msgHash, Uint8List privkey) {
    _checkLen(msgHash, 32, 'msgHash');
    _checkLen(privkey, 32, 'privkey');
    final msg = _toNative(msgHash);
    final pk = _toNative(privkey);
    final sig = calloc<ffi.Uint8>(64);
    try {
      final rc = _ecdsaSign(msg, pk, sig);
      if (rc != 0) throw Secp256k1Exception('ECDSA signing failed');
      return _readBytes(sig, 64);
    } finally {
      calloc.free(msg);
      calloc.free(pk);
      calloc.free(sig);
    }
  }

  /// Verify an ECDSA signature.
  bool ecdsaVerify(Uint8List msgHash, Uint8List sig, Uint8List pubkey) {
    _checkLen(msgHash, 32, 'msgHash');
    _checkLen(sig, 64, 'sig');
    _checkLen(pubkey, 33, 'pubkey');
    final m = _toNative(msgHash);
    final s = _toNative(sig);
    final p = _toNative(pubkey);
    try {
      return _ecdsaVerify(m, s, p) == 1;
    } finally {
      calloc.free(m);
      calloc.free(s);
      calloc.free(p);
    }
  }

  /// Serialize a 64-byte compact signature to DER format.
  Uint8List ecdsaSerializeDer(Uint8List sig) {
    _checkLen(sig, 64, 'sig');
    final s = _toNative(sig);
    final der = calloc<ffi.Uint8>(72);
    final derLen = calloc<ffi.Size>();
    derLen.value = 72;
    try {
      final rc = _serializeDer(s, der, derLen);
      if (rc != 0) throw Secp256k1Exception('DER serialization failed');
      return _readBytes(der, derLen.value);
    } finally {
      calloc.free(s);
      calloc.free(der);
      calloc.free(derLen);
    }
  }

  // ── Recovery ────────────────────────────────────────────────────────

  /// Sign with recovery ID.
  RecoverableSignature ecdsaSignRecoverable(Uint8List msgHash, Uint8List privkey) {
    _checkLen(msgHash, 32, 'msgHash');
    _checkLen(privkey, 32, 'privkey');
    final msg = _toNative(msgHash);
    final pk = _toNative(privkey);
    final sig = calloc<ffi.Uint8>(64);
    final recid = calloc<ffi.Int32>();
    try {
      final rc = _signRecoverable(msg, pk, sig, recid);
      if (rc != 0) throw Secp256k1Exception('Recoverable signing failed');
      return RecoverableSignature(_readBytes(sig, 64), recid.value);
    } finally {
      calloc.free(msg);
      calloc.free(pk);
      calloc.free(sig);
      calloc.free(recid);
    }
  }

  /// Recover public key from a recoverable signature.
  Uint8List ecdsaRecover(Uint8List msgHash, Uint8List sig, int recid) {
    _checkLen(msgHash, 32, 'msgHash');
    _checkLen(sig, 64, 'sig');
    final msg = _toNative(msgHash);
    final s = _toNative(sig);
    final pub = calloc<ffi.Uint8>(33);
    try {
      final rc = _recover(msg, s, recid, pub);
      if (rc != 0) throw Secp256k1Exception('Recovery failed');
      return _readBytes(pub, 33);
    } finally {
      calloc.free(msg);
      calloc.free(s);
      calloc.free(pub);
    }
  }

  // ── Schnorr ─────────────────────────────────────────────────────────

  /// BIP-340 Schnorr sign.
  Uint8List schnorrSign(Uint8List msg, Uint8List privkey, Uint8List auxRand) {
    _checkLen(msg, 32, 'msg');
    _checkLen(privkey, 32, 'privkey');
    _checkLen(auxRand, 32, 'auxRand');
    final m = _toNative(msg);
    final pk = _toNative(privkey);
    final aux = _toNative(auxRand);
    final sig = calloc<ffi.Uint8>(64);
    try {
      final rc = _schnorrSign(m, pk, aux, sig);
      if (rc != 0) throw Secp256k1Exception('Schnorr signing failed');
      return _readBytes(sig, 64);
    } finally {
      calloc.free(m);
      calloc.free(pk);
      calloc.free(aux);
      calloc.free(sig);
    }
  }

  /// BIP-340 Schnorr verify.
  bool schnorrVerify(Uint8List msg, Uint8List sig, Uint8List pubkeyX) {
    _checkLen(msg, 32, 'msg');
    _checkLen(sig, 64, 'sig');
    _checkLen(pubkeyX, 32, 'pubkeyX');
    final m = _toNative(msg);
    final s = _toNative(sig);
    final p = _toNative(pubkeyX);
    try {
      return _schnorrVerify(m, s, p) == 1;
    } finally {
      calloc.free(m);
      calloc.free(s);
      calloc.free(p);
    }
  }

  /// Get x-only public key for Schnorr.
  Uint8List schnorrPubkey(Uint8List privkey) {
    _checkLen(privkey, 32, 'privkey');
    final pk = _toNative(privkey);
    final out = calloc<ffi.Uint8>(32);
    try {
      final rc = _schnorrPubkey(pk, out);
      if (rc != 0) throw Secp256k1Exception('Invalid private key');
      return _readBytes(out, 32);
    } finally {
      calloc.free(pk);
      calloc.free(out);
    }
  }

  // ── ECDH ────────────────────────────────────────────────────────────

  Uint8List _doEcdh(_EcdhDart fn, Uint8List privkey, Uint8List pubkey, String name) {
    _checkLen(privkey, 32, 'privkey');
    _checkLen(pubkey, 33, 'pubkey');
    final pk = _toNative(privkey);
    final pub = _toNative(pubkey);
    final out = calloc<ffi.Uint8>(32);
    try {
      final rc = fn(pk, pub, out);
      if (rc != 0) throw Secp256k1Exception('$name failed');
      return _readBytes(out, 32);
    } finally {
      calloc.free(pk);
      calloc.free(pub);
      calloc.free(out);
    }
  }

  /// ECDH shared secret (SHA-256 hashed).
  Uint8List ecdh(Uint8List privkey, Uint8List pubkey) =>
      _doEcdh(_ecdh, privkey, pubkey, 'ECDH');

  /// ECDH x-only variant.
  Uint8List ecdhXonly(Uint8List privkey, Uint8List pubkey) =>
      _doEcdh(_ecdhXonly, privkey, pubkey, 'ECDH xonly');

  /// ECDH raw (unhashed) shared secret.
  Uint8List ecdhRaw(Uint8List privkey, Uint8List pubkey) =>
      _doEcdh(_ecdhRaw, privkey, pubkey, 'ECDH raw');

  // ── Hashing ─────────────────────────────────────────────────────────

  /// SHA-256 hash.
  Uint8List sha256(Uint8List data) {
    final inp = data.isNotEmpty ? _toNative(data) : ffi.nullptr.cast<ffi.Uint8>();
    final out = calloc<ffi.Uint8>(32);
    try {
      _sha256(inp, data.length, out);
      return _readBytes(out, 32);
    } finally {
      if (data.isNotEmpty) calloc.free(inp);
      calloc.free(out);
    }
  }

  /// RIPEMD-160(SHA-256(data)) — Hash160.
  Uint8List hash160(Uint8List data) {
    final inp = data.isNotEmpty ? _toNative(data) : ffi.nullptr.cast<ffi.Uint8>();
    final out = calloc<ffi.Uint8>(20);
    try {
      _hash160(inp, data.length, out);
      return _readBytes(out, 20);
    } finally {
      if (data.isNotEmpty) calloc.free(inp);
      calloc.free(out);
    }
  }

  /// BIP-340 tagged hash.
  Uint8List taggedHash(String tag, Uint8List data) {
    final tagPtr = tag.toNativeUtf8();
    final inp = data.isNotEmpty ? _toNative(data) : ffi.nullptr.cast<ffi.Uint8>();
    final out = calloc<ffi.Uint8>(32);
    try {
      _taggedHash(tagPtr, inp, data.length, out);
      return _readBytes(out, 32);
    } finally {
      calloc.free(tagPtr);
      if (data.isNotEmpty) calloc.free(inp);
      calloc.free(out);
    }
  }

  // ── Addresses ───────────────────────────────────────────────────────

  String _getAddress(_AddressDart fn, Uint8List key, int keyLen, Network network) {
    _checkLen(key, keyLen, 'key');
    final k = _toNative(key);
    final buf = calloc<ffi.Uint8>(128);
    final len = calloc<ffi.Size>();
    len.value = 128;
    try {
      final rc = fn(k, network.index, buf, len);
      if (rc != 0) throw Secp256k1Exception('Address generation failed');
      final bytes = _readBytes(buf, len.value);
      return String.fromCharCodes(bytes);
    } finally {
      calloc.free(k);
      calloc.free(buf);
      calloc.free(len);
    }
  }

  /// P2PKH address.
  String addressP2pkh(Uint8List pubkey, {Network network = Network.mainnet}) =>
      _getAddress(_addressP2pkh, pubkey, 33, network);

  /// P2WPKH (Bech32) address.
  String addressP2wpkh(Uint8List pubkey, {Network network = Network.mainnet}) =>
      _getAddress(_addressP2wpkh, pubkey, 33, network);

  /// P2TR (Bech32m) address.
  String addressP2tr(Uint8List internalKeyX, {Network network = Network.mainnet}) =>
      _getAddress(_addressP2tr, internalKeyX, 32, network);

  // ── WIF ─────────────────────────────────────────────────────────────

  /// Encode a private key to WIF format.
  String wifEncode(Uint8List privkey, {bool compressed = true, Network network = Network.mainnet}) {
    _checkLen(privkey, 32, 'privkey');
    final pk = _toNative(privkey);
    final buf = calloc<ffi.Uint8>(128);
    final len = calloc<ffi.Size>();
    len.value = 128;
    try {
      final rc = _wifEncode(pk, compressed ? 1 : 0, network.index, buf, len);
      if (rc != 0) throw Secp256k1Exception('WIF encoding failed');
      final bytes = _readBytes(buf, len.value);
      return String.fromCharCodes(bytes);
    } finally {
      calloc.free(pk);
      calloc.free(buf);
      calloc.free(len);
    }
  }

  /// Decode a WIF string.
  WifDecodeResult wifDecode(String wif) {
    final wifPtr = wif.toNativeUtf8();
    final pk = calloc<ffi.Uint8>(32);
    final comp = calloc<ffi.Int32>();
    final net = calloc<ffi.Int32>();
    try {
      final rc = _wifDecode(wifPtr, pk, comp, net);
      if (rc != 0) throw Secp256k1Exception('Invalid WIF');
      return WifDecodeResult(
        _readBytes(pk, 32),
        comp.value == 1,
        net.value == 0 ? Network.mainnet : Network.testnet,
      );
    } finally {
      calloc.free(wifPtr);
      calloc.free(pk);
      calloc.free(comp);
      calloc.free(net);
    }
  }

  // ── BIP-32 ──────────────────────────────────────────────────────────

  /// Derive master key from seed (16-64 bytes).
  Uint8List bip32MasterKey(Uint8List seed) {
    if (seed.length < 16 || seed.length > 64) {
      throw ArgumentError('Seed must be 16-64 bytes');
    }
    final s = _toNative(seed);
    final key = calloc<ffi.Uint8>(79);
    try {
      final rc = _bip32Master(s, seed.length, key);
      if (rc != 0) throw Secp256k1Exception('Master key derivation failed');
      return _readBytes(key, 79);
    } finally {
      calloc.free(s);
      calloc.free(key);
    }
  }

  /// Derive child key at [index] (use |= 0x80000000 for hardened).
  Uint8List bip32DeriveChild(Uint8List parent, int index) {
    _checkLen(parent, 79, 'parent');
    final p = _toNative(parent);
    final child = calloc<ffi.Uint8>(79);
    try {
      final rc = _bip32DeriveChild(p, index, child);
      if (rc != 0) throw Secp256k1Exception('Child derivation failed');
      return _readBytes(child, 79);
    } finally {
      calloc.free(p);
      calloc.free(child);
    }
  }

  /// Derive key at [path] (e.g. "m/44'/0'/0'/0/0").
  Uint8List bip32DerivePath(Uint8List master, String path) {
    _checkLen(master, 79, 'master');
    final m = _toNative(master);
    final pathPtr = path.toNativeUtf8();
    final key = calloc<ffi.Uint8>(79);
    try {
      final rc = _bip32DerivePath(m, pathPtr, key);
      if (rc != 0) throw Secp256k1Exception('Path derivation failed: $path');
      return _readBytes(key, 79);
    } finally {
      calloc.free(m);
      calloc.free(pathPtr);
      calloc.free(key);
    }
  }

  /// Extract 32-byte private key from a BIP-32 key.
  Uint8List bip32GetPrivkey(Uint8List key) {
    _checkLen(key, 79, 'key');
    final k = _toNative(key);
    final pk = calloc<ffi.Uint8>(32);
    try {
      final rc = _bip32GetPrivkey(k, pk);
      if (rc != 0) throw Secp256k1Exception('Not a private key');
      return _readBytes(pk, 32);
    } finally {
      calloc.free(k);
      calloc.free(pk);
    }
  }

  /// Extract 33-byte compressed pubkey from a BIP-32 key.
  Uint8List bip32GetPubkey(Uint8List key) {
    _checkLen(key, 79, 'key');
    final k = _toNative(key);
    final pub = calloc<ffi.Uint8>(33);
    try {
      final rc = _bip32GetPubkey(k, pub);
      if (rc != 0) throw Secp256k1Exception('Pubkey extraction failed');
      return _readBytes(pub, 33);
    } finally {
      calloc.free(k);
      calloc.free(pub);
    }
  }

  // ── Taproot ─────────────────────────────────────────────────────────

  /// Compute taproot output key from internal key.
  TaprootOutputKeyResult taprootOutputKey(Uint8List internalKeyX, {Uint8List? merkleRoot}) {
    _checkLen(internalKeyX, 32, 'internalKeyX');
    final ik = _toNative(internalKeyX);
    final mr = merkleRoot != null ? _toNative(merkleRoot) : ffi.nullptr.cast<ffi.Uint8>();
    final out = calloc<ffi.Uint8>(32);
    final parity = calloc<ffi.Int32>();
    try {
      final rc = _taprootOutputKey(ik, mr, out, parity);
      if (rc != 0) throw Secp256k1Exception('Taproot output key failed');
      return TaprootOutputKeyResult(_readBytes(out, 32), parity.value);
    } finally {
      calloc.free(ik);
      if (merkleRoot != null) calloc.free(mr);
      calloc.free(out);
      calloc.free(parity);
    }
  }

  /// Tweak a private key for taproot spending.
  Uint8List taprootTweakPrivkey(Uint8List privkey, {Uint8List? merkleRoot}) {
    _checkLen(privkey, 32, 'privkey');
    final pk = _toNative(privkey);
    final mr = merkleRoot != null ? _toNative(merkleRoot) : ffi.nullptr.cast<ffi.Uint8>();
    final out = calloc<ffi.Uint8>(32);
    try {
      final rc = _taprootTweakPriv(pk, mr, out);
      if (rc != 0) throw Secp256k1Exception('Taproot tweak failed');
      return _readBytes(out, 32);
    } finally {
      calloc.free(pk);
      if (merkleRoot != null) calloc.free(mr);
      calloc.free(out);
    }
  }

  /// Verify a taproot commitment.
  bool taprootVerifyCommitment(
    Uint8List outputKeyX,
    int parity,
    Uint8List internalKeyX, {
    Uint8List? merkleRoot,
  }) {
    _checkLen(outputKeyX, 32, 'outputKeyX');
    _checkLen(internalKeyX, 32, 'internalKeyX');
    final ok = _toNative(outputKeyX);
    final ik = _toNative(internalKeyX);
    final mr = merkleRoot != null ? _toNative(merkleRoot) : ffi.nullptr.cast<ffi.Uint8>();
    final mrLen = merkleRoot?.length ?? 0;
    try {
      return _taprootVerify(ok, parity, ik, mr, mrLen) == 1;
    } finally {
      calloc.free(ok);
      calloc.free(ik);
      if (merkleRoot != null) calloc.free(mr);
    }
  }
}
