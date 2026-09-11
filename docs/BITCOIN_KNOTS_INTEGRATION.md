# Bitcoin Knots Integration Guide

How to use UltrafastSecp256k1 as the secp256k1 backend in **Bitcoin Knots** — with
**zero Bitcoin Knots source changes**.

> Like Bitcoin Core, this is an optional compile-time backend swap, not a replacement.
> Knots' default build keeps its vendored `src/secp256k1` unless you opt in.
>
> The engine installs under **our own name** `ultrafast_secp256k1` and exports the
> libsecp256k1 `secp256k1_*` ABI under that name. It **never** installs a file named
> `libsecp256k1` (`libsecp256k1.so` / `libsecp256k1.pc`), so it cannot overwrite or shadow
> a system libsecp256k1. The sanctioned integration path is the explicit bundled-tree
> alias, not a pkg-config drop-in.

---

## TL;DR

**Recommended path — explicit bundled-tree alias (no patch to Knots's secp256k1 seam, nothing
named `libsecp256k1` installed):** add the engine to Knots's build as a subdirectory and alias the
`secp256k1` target onto the shim:
```cmake
add_subdirectory(UltrafastSecp256k1)
add_library(secp256k1 ALIAS secp256k1_shim)
```
This is the sanctioned route because the engine never ships a `libsecp256k1.pc`, so Knots'
`pkg_check_modules(libsecp256k1 ...)` seam (below) will not auto-resolve on its own.

Knots also exposes `-DWITH_SYSTEM_LIBSECP256K1=ON`, which makes its top-level CMake do
```cmake
pkg_check_modules(libsecp256k1 REQUIRED IMPORTED_TARGET libsecp256k1)
add_library(secp256k1 ALIAS PkgConfig::libsecp256k1)
```
The engine does **not** ship a `libsecp256k1.pc`, so this seam resolves only if **the integrator
creates their own** `libsecp256k1.pc` (or symlink) pointing at the installed `ultrafast_secp256k1`
package — **at their own risk**. We do not ship it.

```bash
# 1. Build + install the engine under OUR name (self-contained .so + ABI headers + .pc)
cmake -S UltrafastSecp256k1 -B build-shim -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DSECP256K1_USE_ULTRAFAST=ON \
      -DSECP256K1_SHIM_BUILD_SHARED=ON \
      -DCMAKE_INSTALL_PREFIX=$HOME/.local/ufsecp
cmake --build build-shim --target ultrafast_secp256k1_shared -j"$(nproc)"
cmake --install build-shim
# installs: libultrafast_secp256k1.so + ultrafast_secp256k1.pc
#           + secp256k1*.h ABI headers under <includedir>/ultrafast_secp256k1/

# 2. (Optional, integrator-provided) Create your OWN libsecp256k1 alias over the installed
#    ultrafast_secp256k1 — at your own risk; the engine does not ship a libsecp256k1.pc:
#      cp ultrafast_secp256k1.pc libsecp256k1.pc   # then edit Name:/Cflags:/Libs: as needed
#      (or: ln -s libultrafast_secp256k1.so libsecp256k1.so)
export PKG_CONFIG_PATH=$HOME/.local/ufsecp/lib/pkgconfig:$PKG_CONFIG_PATH
cmake -S bitcoin-knots -B build-knots -DWITH_SYSTEM_LIBSECP256K1=ON
cmake --build build-knots -j"$(nproc)"
# at runtime: LD_LIBRARY_PATH=$HOME/.local/ufsecp/lib (or install the .so to a system libdir)
```

`-DSECP256K1_USE_ULTRAFAST=ON` turns on `SECP256K1_BUILD_SHIM`, `SECP256K1_CORE_BACKEND_MODE`
(CT-mandatory + strict BIP-340 + reproducible), and the shim build. `SECP256K1_SHIM_BUILD_SHARED`
adds the self-contained `libultrafast_secp256k1.so` (the libsecp256k1 ABI whole-archived from the
engine), and the install step ships `ultrafast_secp256k1.pc` + the `secp256k1*.h` ABI headers (the
libsecp256k1 ABI under our name); the engine never installs a `libsecp256k1.pc`.

---

## Why this works (verified)

Bitcoin Knots **v29.3.knots20260508** (Bitcoin Core 29 base) vendors **libsecp256k1 0.6.0** and
enables exactly: ECDSA (core), **recovery (ON)**, schnorrsig, extrakeys, ellswift; ECDH and MuSig
are **OFF**. That is a strict subset of the shim's ABI surface, so the swap is total.

When configured with `WITH_SYSTEM_LIBSECP256K1=ON` against the integrator's `libsecp256k1` alias
over the installed `ultrafast_secp256k1`, Knots' own module-presence check reports (real output —
produced only after the integrator creates that alias, since the engine ships no `libsecp256k1.pc`):

```
-- Checking for module 'libsecp256k1'
--   Found libsecp256k1, version 0.6.0
-- Checking for required libsecp256k1 modules
--   Looking for secp256k1_ellswift_create - found
--   Looking for secp256k1_xonly_pubkey_parse - found
--   Looking for secp256k1_ecdsa_recover - found
--   Looking for secp256k1_schnorrsig_verify - found
-- Checking for required libsecp256k1 modules - all were found
```
…and the configure completes successfully. A C consumer exercising Knots' exact API set
(`secp256k1_ecdsa_sign`/`_verify`, `_ecdsa_sign_recoverable`, `_schnorrsig_sign32`/`_verify`,
`_keypair_xonly_pub`, `_ellswift_encode`) compiles, links, and runs against the integrator's
`libsecp256k1` alias over the installed `ultrafast_secp256k1`.

The secp256k1 0.6.0 subtree Knots vendors is the same one Bitcoin Core uses; the shim is already
differential-tested and passes Bitcoin Core's full `test_bitcoin` suite (749/749 — see
`docs/BITCOIN_CORE_INTEGRATION.md`). Knots adds node-level features but does not change the
secp256k1 API surface.

---

## Covered API surface (vs. what Knots requires)

| Module | Knots | Shim |
|--------|-------|------|
| ECDSA (sign/verify/parse/normalize/DER) | required | ✅ |
| `recovery` | **ON** | ✅ |
| `schnorrsig` (BIP-340) | required | ✅ |
| `extrakeys` (x-only / keypair, BIP-340/341) | required | ✅ |
| `ellswift` (BIP-324) | required | ✅ |
| `ecdh` | OFF | ✅ (present, unused) |
| `musig` | OFF | ✅ (present, unused) |

---

## Two integration styles

1. **Bundled-tree alias (sanctioned / recommended default — same as Bitcoin Core).** Mirror the
   Core PR approach: add a `SECP256K1_BACKEND={bundled,ultrafast}` option that, when `ultrafast`,
   builds `compat/libsecp256k1_shim` and `add_library(secp256k1 ALIAS secp256k1_shim)` instead of
   `add_subdirectory(src/secp256k1)`. See `docs/BITCOIN_CORE_INTEGRATION.md`. This is the
   recommended default for Knots because the engine ships nothing named `libsecp256k1` for the
   pkg-config seam to find — the explicit alias is unambiguous and does not depend on an installed
   `.pc`.
2. **Integrator-provided `libsecp256k1` alias over the installed `ultrafast_secp256k1` (at your own
   risk).** Uses Knots' built-in `WITH_SYSTEM_LIBSECP256K1` + pkg-config. No longer the recommended
   path: the engine does **not** ship a `libsecp256k1.pc`, so the integrator must create their own
   `libsecp256k1.pc` (or symlink) pointing at the installed `ultrafast_secp256k1` package before
   the `pkg_check_modules(libsecp256k1 ...)` seam will resolve. Nothing in Knots' source changes.

---

## Minimal profile — `-DSECP256K1_BUILD_KNOTS=ON` (smallest binary)

A single flag compiles **only** the modules Knots needs (ecdsa core + recovery + schnorrsig +
extrakeys + ellswift) and strips everything else (MuSig2, FROST, ZK, ECIES, BIP-352, Adaptor, HD
wallet, Ethereum, GPU, tests, benchmarks, bindings). Measured: the drop-in `.so` shrinks from
**1.83 MB → ~1.27 MB** (stock libsecp256k1 0.6.0 is 1.26 MB) with **identical verify/sign speed**.

```bash
# Module/subtree build (default): engine compiles AS AN OBJECT LIBRARY whose objects
# link straight into bitcoind — not a separate .so. Pair with the bundled-tree ALIAS (style 1):
cmake -S UltrafastSecp256k1 -B build-knots -DSECP256K1_BUILD_KNOTS=ON
#   add_subdirectory(UltrafastSecp256k1) ; add_library(secp256k1 ALIAS secp256k1_shim)
# Knots' own --gc-sections then drops any unreferenced module from the final binary.

# Or the installable ultrafast_secp256k1 .so (+ ultrafast_secp256k1.pc) — minimal modules, no static-table bloat:
cmake -S UltrafastSecp256k1 -B build-knots-so -DSECP256K1_BUILD_KNOTS=ON \
      -DSECP256K1_SHIM_BUILD_SHARED=ON -DCMAKE_INSTALL_PREFIX=$HOME/.local/ufsecp
cmake --build build-knots-so --target ultrafast_secp256k1_shared && cmake --install build-knots-so
```

`SECP256K1_BUILD_KNOTS` sets CT-mandatory signing + strict BIP-340 (like `USE_ULTRAFAST`) but does
**not** enable `SECP256K1_CORE_BACKEND_MODE` — that mode bakes a static `w=8` ecmult table into the
binary (~0.85 MB of `.rodata`) for deterministic/shared-RAM startup, which would *inflate* the file
to ~2.3 MB. The runtime-built table keeps the binary at stock-libsecp parity. Opt into the static
table explicitly with `-DSECP256K1_CORE_BACKEND_MODE=ON` only if cold-start/shared-RAM matters more
than file size. (Note: `SECP256K1_BUILD_KNOTS` keeps `-O3`; the ecmult precompute is the size floor,
not code — `-Os/-Oz` would slow the hot path for no real size win.)

---

## Notes

- **Version:** the installed `ultrafast_secp256k1.pc` reports `0.6.0` to match the Knots/Core
  libsecp256k1 0.6.x subtree; if an integrator creates their own `libsecp256k1` alias/.pc for the
  `pkg_check_modules(libsecp256k1 ...)` seam, that version carries through. The engine itself does
  not ship a `libsecp256k1.pc`. Knots' `pkg_check_modules(libsecp256k1 ...)` carries no
  minimum-version constraint.
- **Runtime:** ship `libultrafast_secp256k1.so` next to `bitcoind`/`bitcoin-qt` (or install it
  into a system libdir / set `RPATH`). It is self-contained (the engine is whole-archived in).
- **Constant-time / strict encoding:** `SECP256K1_USE_ULTRAFAST=ON` forces CT-mandatory signing
  and strict BIP-340 (reject `r>=p`, `s>=n`), matching consensus expectations.
- **Determinism:** `SECP256K1_CORE_BACKEND_MODE` implies reproducible-build flags.
- This guide and the installed `ultrafast_secp256k1.pc` (plus the integrator's `libsecp256k1`
  alias, where used) were verified against Bitcoin Knots `v29.3.knots20260508` on GCC 14.
