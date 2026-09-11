# UltrafastSecp256k1 — Litecoin Core Backend Shim

Drop-in secp256k1 backend for Litecoin Core.

## Integration

```bash
cmake -B build -DSECP256K1_BACKEND=ultrafast
cmake --build build
```

## API Coverage

| Header | Coverage |
|--------|----------|
| `secp256k1.h` | ✅ full |
| `secp256k1_schnorrsig.h` | ✅ BIP-340 (Taproot + MWEB) |
| `secp256k1_extrakeys.h` | ✅ x-only pubkeys, keypairs |
| `secp256k1_ecdh.h` | ✅ |
| `secp256k1_recovery.h` | ✅ |
| `secp256k1_ellswift.h` | ✅ (future P2P privacy) |
| `secp256k1_musig.h` | ✅ MuSig2 BIP-327 |

## Performance (i5-14400F, GCC 14, LTO)

| Operation | libsecp256k1 | Ultra | Δ |
|-----------|-------------|-------|---|
| CT ECDSA sign | 59.7 µs | 21.6 µs | **+2.76×** |
| CT Schnorr sign | 46.5 µs | 18.1 µs | **+2.57×** |
| Schnorr verify | 84.3 µs | 84.3 µs | equal |
| ConnectBlock (LTO) | baseline | **+1.2%** | |

## MWEB (MimbleWimble Extension Blocks)

Litecoin MWEB uses Pedersen commitments + Bulletproofs.
UltrafastSecp256k1 provides:
- `secp256k1::pedersen_commit()` — Pedersen commitment
- `secp256k1::zk::range_prove/verify()` — Bulletproofs
- `secp256k1::zk::knowledge_prove/verify()` — knowledge proofs

MWEB integration module: `SECP256K1_BUILD_MWEB=ON` (coming soon)

## Divergences from libsecp256k1

See [SHIM_KNOWN_DIVERGENCES.md](../../docs/SHIM_KNOWN_DIVERGENCES.md)

## Repository

https://github.com/shrec/UltrafastSecp256k1
