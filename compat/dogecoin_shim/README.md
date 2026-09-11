# UltrafastSecp256k1 — Dogecoin Core Backend

Dogecoin Core (autotools build) — optional backend integration.

## Build

```bash
# In dogecoin-core-dev/:
git submodule update --init src/ultrafast_secp256k1
bash contrib/ultrafast-secp256k1/build.sh

./autogen.sh
./configure \
    --enable-ultrafast-secp256k1 \
    SECP256K1_LIBS="-L$(pwd)/contrib/ultrafast-secp256k1/out -lsecp256k1_shim -lstdc++ -lpthread"
make -j$(nproc)
```

## Performance (i5-14400F, GCC 14, Release)

| | bundled | ultrafast | Δ |
|--|---------|-----------|---|
| CT ECDSA sign | 59.7 µs | 21.6 µs | **+2.76×** |
| Dogecoin tx volume (~5M tx/day) | baseline | **+2.76×** faster signing |

## Dogecoin fork

`github.com/shrec/dogecoin` — branch `feature/ultrafast-secp256k1-backend`

## API compatibility

secp256k1.h | secp256k1_extrakeys.h | secp256k1_schnorrsig.h | secp256k1_ecdh.h | secp256k1_recovery.h
