# ultrafast_secp256k1 -- C API

Standalone C header-only API for [UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1) -- high-performance secp256k1 elliptic curve cryptography.

This is a **stateless** API with `secp256k1_*` naming (no context object). It differs from the main `ufsecp_*` context-based API.

> Warning: this legacy stateless surface is not the standardized secure binding model.
> For secret-bearing integrations, prefer the `ufsecp_*` context-based ABI and the binding standard in `docs/BINDINGS_USAGE_STANDARD.md`.

## Features

- **ECDSA** -- sign, verify, DER serialization (RFC 6979)
- **Schnorr** -- BIP-340 sign/verify
- **ECDH** -- shared secret
- **BIP-32** -- HD key derivation
- **Taproot** -- output key tweaking, commitment verification (BIP-341)
- **Addresses** -- P2PKH, P2WPKH, P2TR
- **WIF** -- encode/decode
- **Hashing** -- SHA-256, HASH160
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

```c
#include "ultrafast_secp256k1.h"

secp256k1_init();

uint8_t privkey[32] = {0};
privkey[31] = 1;

uint8_t pubkey[33];
secp256k1_ec_pubkey_create(privkey, pubkey);

uint8_t msg[32] = {0};
uint8_t sig[64];
secp256k1_ecdsa_sign(msg, privkey, sig);

int ok = secp256k1_ecdsa_verify(msg, sig, pubkey);
```

## API Differences

| Feature | `ufsecp_*` (main) | `secp256k1_*` (this) |
|---------|-------------------|----------------------|
| Context | Required | None (global init) |
| Init | `ufsecp_ctx_create()` | `secp256k1_init()` |
| Naming | `ufsecp_ecdsa_sign` | `secp256k1_ecdsa_sign` |
| Thread safety | Per-context | Global state |

## Architecture Note

This legacy API uses the **fast** (variable-time) implementation for maximum throughput. For secret-bearing integrations, use the `ufsecp_*` context-based ABI, which is the standardized stable surface with explicit context lifecycle and constant-time secret routing.

## Performance Tuning

When building the shared library from source, you can tune scalar multiplication (k*P) performance via the GLV window width:

```bash
cmake -S bindings/c_api -B bindings/c_api/build -DSECP256K1_GLV_WINDOW_WIDTH=6
```

| Window | Default On | Tradeoff |
|--------|-----------|----------|
| w=4 | ESP32, WASM | Smaller tables, more point additions |
| w=5 | x86-64, ARM64, RISC-V | Balanced (default) |
| w=6 | -- | Larger tables, fewer additions |

See [docs/PERFORMANCE_GUIDE.md](../../docs/PERFORMANCE_GUIDE.md) for detailed benchmarks and per-platform tuning advice.

## License

MIT
