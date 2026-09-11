/**
 * React Native UltrafastSecp256k1 — JavaScript interface.
 *
 * Uses the native module bridge (TurboModule or NativeModules fallback).
 * All keys/sigs are hex strings for RN bridge compatibility.
 */

import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-ultrafast-secp256k1' doesn't seem to be linked. Make sure:\n\n` +
  Platform.select({ ios: "- Run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const NativeSecp256k1 =
  NativeModules.UltrafastSecp256k1 ??
  new Proxy(
    {},
    {
      get() {
        throw new Error(LINKING_ERROR);
      },
    }
  );

console.warn(
  'react-native-ultrafast-secp256k1/lib/index.js is a legacy stateless bridge with weaker secret-handling guarantees. Use the context-based react-native ufsecp binding for the standardized security model.'
);

// ── Helpers ──────────────────────────────────────────────────────────────────

function toHex(data) {
  if (typeof data === 'string') return data;
  if (data instanceof Uint8Array || Array.isArray(data)) {
    return Array.from(data)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  throw new TypeError('Expected hex string or Uint8Array');
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ── Public API ───────────────────────────────────────────────────────────────

export const NETWORK_MAINNET = 0;
export const NETWORK_TESTNET = 1;

/** Library version. */
export function version() {
  return NativeSecp256k1.version();
}

// ── Key Operations ───────────────────────────────────────────────────────────

/** Create compressed pubkey (33 bytes hex) from privkey (32 bytes hex). */
export async function ecPubkeyCreate(privkeyHex) {
  return NativeSecp256k1.ecPubkeyCreate(toHex(privkeyHex));
}

/** Create uncompressed pubkey (65 bytes hex). */
export async function ecPubkeyCreateUncompressed(privkeyHex) {
  return NativeSecp256k1.ecPubkeyCreateUncompressed(toHex(privkeyHex));
}

/** Parse compressed/uncompressed pubkey. Returns compressed hex. */
export async function ecPubkeyParse(pubkeyHex) {
  return NativeSecp256k1.ecPubkeyParse(toHex(pubkeyHex));
}

/** Verify private key validity. */
export async function ecSeckeyVerify(privkeyHex) {
  return NativeSecp256k1.ecSeckeyVerify(toHex(privkeyHex));
}

/** Negate private key. */
export async function ecPrivkeyNegate(privkeyHex) {
  return NativeSecp256k1.ecPrivkeyNegate(toHex(privkeyHex));
}

/** Add tweak to private key. */
export async function ecPrivkeyTweakAdd(privkeyHex, tweakHex) {
  return NativeSecp256k1.ecPrivkeyTweakAdd(toHex(privkeyHex), toHex(tweakHex));
}

/** Multiply private key by tweak. */
export async function ecPrivkeyTweakMul(privkeyHex, tweakHex) {
  return NativeSecp256k1.ecPrivkeyTweakMul(toHex(privkeyHex), toHex(tweakHex));
}

// ── ECDSA ────────────────────────────────────────────────────────────────────

/** Sign with ECDSA. Returns 64-byte compact sig hex. */
export async function ecdsaSign(msgHashHex, privkeyHex) {
  return NativeSecp256k1.ecdsaSign(toHex(msgHashHex), toHex(privkeyHex));
}

/** Verify ECDSA signature. */
export async function ecdsaVerify(msgHashHex, sigHex, pubkeyHex) {
  return NativeSecp256k1.ecdsaVerify(toHex(msgHashHex), toHex(sigHex), toHex(pubkeyHex));
}

/** Serialize to DER. */
export async function ecdsaSerializeDer(sigHex) {
  return NativeSecp256k1.ecdsaSerializeDer(toHex(sigHex));
}

// ── Recovery ─────────────────────────────────────────────────────────────────

/** Sign with recovery id. Returns { signature: hex, recid: number }. */
export async function ecdsaSignRecoverable(msgHashHex, privkeyHex) {
  return NativeSecp256k1.ecdsaSignRecoverable(toHex(msgHashHex), toHex(privkeyHex));
}

/** Recover pubkey from signature. */
export async function ecdsaRecover(msgHashHex, sigHex, recid) {
  return NativeSecp256k1.ecdsaRecover(toHex(msgHashHex), toHex(sigHex), recid);
}

// ── Schnorr ──────────────────────────────────────────────────────────────────

/** BIP-340 Schnorr sign. Returns 64-byte sig hex. */
export async function schnorrSign(msgHex, privkeyHex, auxRandHex) {
  return NativeSecp256k1.schnorrSign(toHex(msgHex), toHex(privkeyHex), toHex(auxRandHex));
}

/** Verify Schnorr signature. */
export async function schnorrVerify(msgHex, sigHex, pubkeyXHex) {
  return NativeSecp256k1.schnorrVerify(toHex(msgHex), toHex(sigHex), toHex(pubkeyXHex));
}

/** Get x-only pubkey. */
export async function schnorrPubkey(privkeyHex) {
  return NativeSecp256k1.schnorrPubkey(toHex(privkeyHex));
}

// ── ECDH ─────────────────────────────────────────────────────────────────────

/** ECDH shared secret. */
export async function ecdh(privkeyHex, pubkeyHex) {
  return NativeSecp256k1.ecdh(toHex(privkeyHex), toHex(pubkeyHex));
}

/** ECDH x-only. */
export async function ecdhXonly(privkeyHex, pubkeyHex) {
  return NativeSecp256k1.ecdhXonly(toHex(privkeyHex), toHex(pubkeyHex));
}

/** ECDH raw. */
export async function ecdhRaw(privkeyHex, pubkeyHex) {
  return NativeSecp256k1.ecdhRaw(toHex(privkeyHex), toHex(pubkeyHex));
}

// ── Hashing ──────────────────────────────────────────────────────────────────

/** SHA-256. */
export async function sha256(dataHex) {
  return NativeSecp256k1.sha256(toHex(dataHex));
}

/** HASH160. */
export async function hash160(dataHex) {
  return NativeSecp256k1.hash160(toHex(dataHex));
}

/** Tagged hash. */
export async function taggedHash(tag, dataHex) {
  return NativeSecp256k1.taggedHash(tag, toHex(dataHex));
}

// ── Addresses ────────────────────────────────────────────────────────────────

/** P2PKH address. */
export async function addressP2PKH(pubkeyHex, network = NETWORK_MAINNET) {
  return NativeSecp256k1.addressP2PKH(toHex(pubkeyHex), network);
}

/** P2WPKH address. */
export async function addressP2WPKH(pubkeyHex, network = NETWORK_MAINNET) {
  return NativeSecp256k1.addressP2WPKH(toHex(pubkeyHex), network);
}

/** P2TR address. */
export async function addressP2TR(internalKeyXHex, network = NETWORK_MAINNET) {
  return NativeSecp256k1.addressP2TR(toHex(internalKeyXHex), network);
}

// ── WIF ──────────────────────────────────────────────────────────────────────

/** Encode WIF. */
export async function wifEncode(privkeyHex, compressed = true, network = NETWORK_MAINNET) {
  return NativeSecp256k1.wifEncode(toHex(privkeyHex), compressed, network);
}

/** Decode WIF. Returns { privkey: hex, compressed: bool, network: number }. */
export async function wifDecode(wif) {
  return NativeSecp256k1.wifDecode(wif);
}

// ── BIP-32 ───────────────────────────────────────────────────────────────────

/** Master key from seed. Returns opaque hex key. */
export async function bip32MasterKey(seedHex) {
  return NativeSecp256k1.bip32MasterKey(toHex(seedHex));
}

/** Derive child by index. */
export async function bip32DeriveChild(parentKeyHex, index) {
  return NativeSecp256k1.bip32DeriveChild(toHex(parentKeyHex), index);
}

/** Derive from path string. */
export async function bip32DerivePath(masterKeyHex, path) {
  return NativeSecp256k1.bip32DerivePath(toHex(masterKeyHex), path);
}

/** Get privkey from extended key. */
export async function bip32GetPrivkey(keyHex) {
  return NativeSecp256k1.bip32GetPrivkey(toHex(keyHex));
}

/** Get pubkey from extended key. */
export async function bip32GetPubkey(keyHex) {
  return NativeSecp256k1.bip32GetPubkey(toHex(keyHex));
}

// ── Taproot ──────────────────────────────────────────────────────────────────

/** Taproot output key. Returns { outputKeyX: hex, parity: number }. */
export async function taprootOutputKey(internalKeyXHex, merkleRootHex = null) {
  return NativeSecp256k1.taprootOutputKey(toHex(internalKeyXHex), merkleRootHex ? toHex(merkleRootHex) : null);
}

/** Tweak privkey for Taproot. */
export async function taprootTweakPrivkey(privkeyHex, merkleRootHex = null) {
  return NativeSecp256k1.taprootTweakPrivkey(toHex(privkeyHex), merkleRootHex ? toHex(merkleRootHex) : null);
}

/** Verify Taproot commitment. */
export async function taprootVerifyCommitment(outputKeyXHex, parity, internalKeyXHex, merkleRootHex = null) {
  return NativeSecp256k1.taprootVerifyCommitment(
    toHex(outputKeyXHex), parity, toHex(internalKeyXHex),
    merkleRootHex ? toHex(merkleRootHex) : null
  );
}

// Re-export helpers
export { toHex, fromHex };
