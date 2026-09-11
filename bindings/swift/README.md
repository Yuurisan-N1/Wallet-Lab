# Ufsecp -- Swift

Swift binding for [UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1) -- high-performance secp256k1 elliptic curve cryptography via C interop.

## Features

- **ECDSA** -- sign, verify, recover, DER serialization (RFC 6979)
- **Schnorr** -- BIP-340 sign/verify
- **ECDH** -- compressed, x-only, raw shared secret
- **BIP-32** -- HD key derivation (master/derive/path/privkey/pubkey)
- **Taproot** -- output key tweaking, verification (BIP-341)
- **Addresses** -- P2PKH, P2WPKH, P2TR
- **WIF** -- encode/decode
- **Hashing** -- SHA-256 (hardware-accelerated), HASH160, tagged hash
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

## Quick Start

```swift
let ctx = try UfsecpContext()
defer { ctx.destroy() }

let privkey = Data(repeating: 0, count: 31) + Data([0x01])
let pubkey = try ctx.pubkeyCreate(privkey: privkey)
let msgHash = try UfsecpContext.sha256(Data("hello".utf8))
let sig = try ctx.ecdsaSign(msgHash: msgHash, privkey: privkey)
let valid = try ctx.ecdsaVerify(msgHash: msgHash, sig: sig, pubkey: pubkey)
```

## Local Smoke Validation

```bash
bash libs/UltrafastSecp256k1/scripts/validate_bindings.sh
```

This runs the current C#, Java, and Swift smoke suites against the local build tree on a prepared developer machine.

## ECDSA Recovery

```swift
let rs = try ctx.ecdsaSignRecoverable(msgHash: msgHash, privkey: privkey)
let recovered = try ctx.ecdsaRecover(msgHash: msgHash, sig: rs.signature, recid: rs.recoveryId)
```

## Schnorr (BIP-340)

```swift
let xonly = try ctx.pubkeyXonly(privkey: privkey)
let schnorrSig = try ctx.schnorrSign(msg: msgHash, privkey: privkey, auxRand: auxRand)
let ok = try ctx.schnorrVerify(msg: msgHash, sig: schnorrSig, pubkeyX: xonly)
```

## Taproot (BIP-341)

```swift
let tok = try ctx.taprootOutputKey(internalX: xonly, merkleRoot: nil)
let tweaked = try ctx.taprootTweakSeckey(privkey: privkey, merkleRoot: nil)
let tapValid = try ctx.taprootVerify(outputX: tok.outputKeyX, parity: tok.parity, internalX: xonly, merkleRoot: nil)
```

## Architecture Note

The C ABI layer uses the **fast** (variable-time) implementation for maximum throughput. A constant-time (CT) layer with identical mathematical operations is available via the C++ headers for applications requiring timing-attack resistance.

## Performance Tuning

When building the native library from source, you can tune scalar multiplication (k*P) performance via the GLV window width:

```bash
cmake -S . -B build -DSECP256K1_GLV_WINDOW_WIDTH=6
```

| Window | Default On | Tradeoff |
|--------|-----------|----------|
| w=4 | ESP32, WASM | Smaller tables, more point additions |
| w=5 | x86-64, ARM64, RISC-V | Balanced (default) |
| w=6 | -- | Larger tables, fewer additions |

See [docs/PERFORMANCE_GUIDE.md](../../docs/PERFORMANCE_GUIDE.md) for detailed benchmarks and per-platform tuning advice.

## License

MIT
