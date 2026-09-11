# Ufsecp -- PHP

PHP FFI binding for [UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1) -- high-performance secp256k1 elliptic curve cryptography.

This is the **reference binding** with 100% API coverage.

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
- **Context** -- create, destroy, clone, last_error, ctx_size
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

## Requirements

- PHP 7.4+ with FFI extension enabled
- `libufsecp.so` / `ufsecp.dll` / `libufsecp.dylib`

## Quick Start

```php
use Ultrafast\Ufsecp;

$ctx = new Ufsecp();

$privkey = str_repeat("\x00", 31) . "\x01";
$pubkey = $ctx->pubkeyCreate($privkey);
$msgHash = Ufsecp::sha256("hello");
$sig = $ctx->ecdsaSign($msgHash, $privkey);
$valid = $ctx->ecdsaVerify($msgHash, $sig, $pubkey);

$ctx->destroy();
```

## ECDSA Recovery

```php
[$sig, $recid] = $ctx->ecdsaSignRecoverable($msgHash, $privkey);
$recovered = $ctx->ecdsaRecover($msgHash, $sig, $recid);
```

## Taproot (BIP-341)

```php
[$outputKey, $parity] = $ctx->taprootOutputKey($xonlyPub);
$tweaked = $ctx->taprootTweakSeckey($privkey);
$valid = $ctx->taprootVerify($outputKey, $parity, $xonlyPub);
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
