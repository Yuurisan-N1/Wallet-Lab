# react-native-ultrafast-secp256k1

High-performance secp256k1 elliptic curve cryptography for React Native, powered by [UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1).

Uses native C/C++ through JSI (Android NDK + iOS) for maximum performance -- no bridge overhead.

## Features

- **ECDSA** -- sign, verify, recover (RFC 6979, low-S)
- **Schnorr** -- BIP-340 sign/verify
- **ECDH** -- shared secret derivation
- **BIP-32** -- HD key derivation
- **Taproot** -- BIP-341 output key tweaking
- **Addresses** -- P2PKH, P2WPKH, P2TR
- **WIF** -- encode/decode
- **Hashing** -- SHA-256, HASH160, tagged hash
- **Key tweaking** -- negate, add, multiply
- **Ethereum** -- Keccak-256, EIP-55 addresses, EIP-155 sign, ecrecover
- **BIP-39** -- mnemonic generation, validation, seed derivation
- **Multi-coin wallet** -- 7-coin address dispatch (BTC/LTC/DOGE/DASH/ETH/BCH/TRX)
- **Batch verification** -- ECDSA + Schnorr batch verify with invalid identification
- **MuSig2** -- BIP-327 multi-signatures (key agg, nonce gen, partial sign, aggregate)
- **FROST** -- threshold signatures (keygen, sign, aggregate, verify)
- **Adaptor signatures** -- Schnorr + ECDSA adaptor pre-sign, adapt, extract
- **Pedersen commitments** -- commit, verify, sum balance, switch commitments
- **ZK proofs** -- knowledge proof, DLEQ proof, Bulletproof range proof
- **Multi-scalar multiplication** -- Shamir's trick, MSM
- **Pubkey arithmetic** -- add, negate, combine N keys
- **SHA-512** -- full SHA-512 hash
- **Message signing** -- BIP-137 Bitcoin message sign/verify

## Install

```bash
npm install react-native-ultrafast-secp256k1
cd ios && pod install
```

## Quick Start

```js
import { UfsecpContext } from 'react-native-ultrafast-secp256k1/lib/ufsecp';

const ctx = await UfsecpContext.create();

// Generate public key from 32-byte private key
const privkey = Buffer.from('...', 'hex'); // use secure random source
const pubkey = await ctx.pubkeyCreate(privkey.toString('hex'));
```

The package root entrypoint is a legacy stateless bridge. Prefer the context-based `UfsecpContext` API for the standardized binding security model.

## ECDSA Sign & Verify

```js
const msgHash = await UfsecpContext.sha256(Buffer.from('hello world').toString('hex'));

// Sign
const sig = await ctx.ecdsaSign(msgHash, privkey.toString('hex'));

// Verify
const valid = await ctx.ecdsaVerify(msgHash, sig, pubkey);
console.log('valid:', valid); // true
```

## Schnorr (BIP-340)

```js
const xOnlyPub = await ctx.pubkeyXonly(privkey.toString('hex'));
const msg = await UfsecpContext.sha256(Buffer.from('schnorr message').toString('hex'));
const auxRand = Buffer.alloc(32); // use crypto.getRandomValues in production

const schnorrSig = await ctx.schnorrSign(msg, privkey.toString('hex'), auxRand.toString('hex'));
const ok = await ctx.schnorrVerify(msg, schnorrSig, xOnlyPub);
```

## Bitcoin Addresses

```js
const p2wpkh = await ctx.addrP2wpkh(pubkey, 0);   // bc1q...
const p2tr = await ctx.addrP2tr(xOnlyPub, 0);     // bc1p...
```

## BIP-32 HD Derivation

```js
const seed = Buffer.alloc(64); // use proper entropy
const master = await ctx.bip32Master(seed.toString('hex'));
const child = await ctx.bip32DerivePath(master, "m/44'/0'/0'/0/0");
const childPriv = await ctx.bip32Privkey(child);
```

## Platform Requirements

| Platform | Requirement |
|----------|-------------|
| Android | NDK, minSdkVersion 21+ |
| iOS | iOS 13+, CocoaPods |
| React Native | >= 0.71.0 |

## Smoke Validation

```bash
bash libs/UltrafastSecp256k1/scripts/validate_bindings.sh
```

The validator runs a default mock-bridge contract smoke in plain Node.js to verify the JavaScript bridge surface without requiring Android/iOS bootstrapping.

Set `UFSECP_VALIDATE_REACT_NATIVE=1` and provide a React Native/Jest test harness to additionally run the native React Native smoke suite against a real bridge.

## Architecture Note

The C ABI layer uses the **fast** (variable-time) implementation for maximum throughput. A constant-time (CT) layer with identical mathematical operations is available via the C++ headers for applications requiring timing-attack resistance.

## License

MIT

## Links

- [GitHub](https://github.com/shrec/UltrafastSecp256k1)
- [Benchmarks](https://github.com/shrec/UltrafastSecp256k1/blob/main/docs/BENCHMARKS.md)
- [Changelog](https://github.com/shrec/UltrafastSecp256k1/blob/main/CHANGELOG.md)
