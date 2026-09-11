# ufsecp -- Go

Go (CGo) binding for [UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1) -- high-performance secp256k1 elliptic curve cryptography.

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

```go
import "github.com/shrec/UltrafastSecp256k1/bindings/go"

ctx, err := ufsecp.NewContext()
if err != nil { panic(err) }
defer ctx.Destroy()

privkey := make([]byte, 32)
privkey[31] = 1

pubkey, err := ctx.PubkeyCreate(privkey)
msgHash, _ := ufsecp.Sha256([]byte("hello"))
sig, err := ctx.EcdsaSign(msgHash, privkey)
valid, err := ctx.EcdsaVerify(msgHash, sig, pubkey)
```

## ECDSA Recovery

```go
sig, recid, err := ctx.EcdsaSignRecoverable(msgHash, privkey)
recovered, err := ctx.EcdsaRecover(msgHash, sig, recid)
```

## Taproot (BIP-341)

```go
outputKey, parity, err := ctx.TaprootOutputKey(xonlyPub, nil)
tweaked, err := ctx.TaprootTweakSeckey(privkey, nil)
valid, err := ctx.TaprootVerify(outputKey, parity, xonlyPub, nil)
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

## Smoke Validation

```bash
bash libs/UltrafastSecp256k1/scripts/validate_bindings.sh
```

## License

MIT
