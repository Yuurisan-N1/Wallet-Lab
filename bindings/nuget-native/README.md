# UltrafastSecp256k1 — native (MSVC) static-lib NuGet packages

Native C++ NuGet packages that ship UltrafastSecp256k1 as a **libsecp256k1-ABI
static library** for a specific Visual Studio toolset, in the exact convention
libbitcoin already consumes for its `secp256k1` dependency.

## Why

libbitcoin-system builds on Windows/MSVC against NuGet packages it maintains.
`builds/msvc/vs2022/libbitcoin-system/packages.config` references:

```xml
<package id="secp256k1_vc143" version="0.6.1" targetFramework="Native" />
```

and the `.vcxproj` imports `secp256k1_vc143.0.6.1\build\native\secp256k1_vc143.targets`.
From the integration discussion (evoskuil), to wire UltrafastSecp256k1 in as a
secp256k1 backend behind `WITH_ULTRAFAST`:

> *"visual studio with vc++ dependencies … would be greatly facilitated by
> **vc145 and vc143 native intel and arm NuGet packages**."*

So these packages mirror `secp256k1_vc143` exactly, for **our** static lib.

## Drop-in surface

For the **singular libsecp256k1 ABI** (sign / verify / recover / ECDH / xonly /
keypair) the consumer-facing surface is identical to `secp256k1_vc143`, so the
only change is the package id + import path:

| Aspect | Value (identical to upstream package) |
|--------|----------------------------------------|
| Headers | `<secp256k1.h>`, `<secp256k1_recovery.h>`, `<secp256k1_schnorrsig.h>`, `<secp256k1_extrakeys.h>`, `<secp256k1_ecdh.h>`, `<secp256k1_ellswift.h>`, `<secp256k1_musig.h>` |
| Project property | `Linkage-secp256k1` = `static` / `ltcg` |
| Link | handled entirely by the package `.targets` — the consumer never names the `.lib` |

The two packages are **mutually exclusive** (both define `Linkage-secp256k1`);
exactly one is referenced, chosen by `WITH_ULTRAFAST`. Per evoskuil, the
libbitcoin-side cmake/vcxproj edits stay on their side ("generated code") and are
gated on `WITH_ULTRAFAST`; this repo only provides the package(s).

> **Scope of the swap.** The package id + import swap covers the *singular*
> libsecp256k1 ABI only. libbitcoin's `WITH_ULTRAFAST` block in
> `src/crypto/secp256k1.cpp` *additionally* pulls in the **libbitcoin bridge**
> (`ufsecp_libbitcoin.h` + the `ufsecp_lbtc_*` batch-verify symbols) for GPU/CPU
> batch script-sig verification. That bridge lives in `compat/libbitcoin_bridge/`
> and is **not** part of this secp256k1 NuGet package — it is delivered
> separately (its own header + lib).

> **Header set.** `secp256k1_schnorrsig.h` transitively includes
> `secp256k1_extrakeys.h`, and `secp256k1.h` transitively includes
> `secp256k1_ellswift.h` — both must be packaged even though libbitcoin never
> includes them directly. We also ship `secp256k1_batch.h` (extra, additive).
> `secp256k1_preallocated.h` is **not** shipped: the four preallocated-context
> symbols are already implemented in the lib (`shim_context.cpp`) — only the
> declaration header is omitted — and **libbitcoin-system does not use the
> preallocated API** (it uses `secp256k1_context_create`/`_destroy`), so this is
> not a blocker for the libbitcoin drop-in. Add a thin `secp256k1_preallocated.h`
> only if upstream-parity with the full header set is wanted.

> **C++ header tree.** Unlike upstream's pure-C `secp256k1_vc143`, our
> `secp256k1.h` pulls in C++ engine headers under `__cplusplus` (for the inlined
> `secp256k1_pubkey_precomp`), so the package include dir also ships the
> `src/cpu/include/secp256k1/` tree and the generated `secp256k1_features.h`.
> The CI link-test compiles a C++ consumer against **only the package include
> dir** to prove this is self-contained.

> **`SECP256K1_STATIC`.** The `.targets` defines it for static/ltcg linkage to
> mirror upstream, but our headers define `SECP256K1_API` unconditionally as
> `extern` — so the macro is a harmless no-op (it would only matter for a real
> DLL variant, which this package does not ship).

## Package layout (generated)

Mirrors evoskuil's `secp256k1_vc143` package byte-for-byte in structure:

```
ultrafast_secp256k1_vc143/
  ultrafast_secp256k1_vc143.nuspec
  build/native/
    ultrafast_secp256k1_vc143.targets   ← include + per-config lib selection
    package.xml                          ← Linkage-secp256k1 dropdown (static/ltcg/dynamic)
    include/secp256k1*.h                 ← libsecp256k1 ABI headers
    bin/ultrafast_secp256k1-<plat>-<toolset>-<rt>-<ver4>.<linkage>.lib
```

Lib filename convention (mirrors `secp256k1-x64-v143-mt-s-0_6_1_0.static.lib`):

```
ultrafast_secp256k1-<plat>-<toolset>-<rt>-<ver4>.<linkage>.lib
  plat    = x86 | x64 | arm64           (evoskuil asked for intel + arm)
  toolset = v143 | v145                 (MSBuild $(PlatformToolset); pkg id uses vc143/vc145)
  rt      = mt-s (Release /MT) | mt-sgd (Debug /MTd)   ← static runtime
  ver4    = dotted version, dots→underscores, 4 parts (4_1_0_0)
  linkage = static | ltcg
```

The generator emits a `.targets` link condition **only for the libs actually
present**, so a partial build still produces a valid package.

## How the static lib is produced

`fastsecp256k1` built with `-DSECP256K1_BUILD_SHIM=ON` compiles the
libsecp256k1-compatible shim sources directly into the engine
(`src/cpu/CMakeLists.txt`: *"the shim is part of the engine — not a separate
library"*). The resulting `fastsecp256k1.lib` is a single, self-contained
static lib exporting the full libsecp256k1 C ABI — exactly what gets packaged.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DSECP256K1_BUILD_SHIM=ON -DCMAKE_POLICY_DEFAULT_CMP0091=NEW \
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded         # /MT (static runtime)
cmake --build build --target fastsecp256k1
# -> build/.../fastsecp256k1.lib  (rename into the convention above)
```

## Generate a package

```bash
python3 bindings/nuget-native/gen_nuget_native.py \
    --staging out/ultrafast_secp256k1_vc143 \
    --toolset vc143 --version 4.1.0
nuget pack out/ultrafast_secp256k1_vc143/ultrafast_secp256k1_vc143.nuspec \
    -BasePath out/ultrafast_secp256k1_vc143 -OutputDirectory nupkgs
```

## CI

`.github/workflows/nuget-native.yml` (manual `workflow_dispatch`) builds the
matrix (x64 + arm64, Release + Debug, static + ltcg), **link-tests** each static
lib against a real libsecp256k1-ABI consumer before packing, generates the
package, and uploads the `.nupkg` as a workflow artifact.

Deliberately **separate from `release.yml`** so it can never block a release, and
**manual** until it is proven green on a real Windows run.

### Caveats / open items

- **v145 toolset** (VS2026) is not on GitHub-hosted runners yet — build the
  `vc145` variant on a self-hosted runner that has it, or once a hosted image
  ships v145. The `vc143` variant builds on `windows-2022`.
- **Not auto-published.** The workflow uploads the `.nupkg` as an artifact only.
  Publishing to nuget.org is a separate, owner-authorized step.
- **Release `static` == `ltcg`.** The top-level CMake adds `/GL` (whole-program
  optimization) for every MSVC **Release** build, so the Release `static` lib is
  also `/GL`-built and a consumer linking it must use `/LTCG` (same as `ltcg`).
  The distinction is only real for **Debug**. Making Release `static` a clean
  non-LTCG archive would require gating the unconditional `/GL` in the top-level
  CMakeLists — deferred (it affects all MSVC Release builds).
- **arm64 uses the portable field path.** `src/cpu/src/field_asm_arm64.cpp` is
  GNU inline asm that MSVC cannot compile, so the arm64 legs build with
  `-DSECP256K1_USE_ASM=OFF` (portable `__int128`/C++ field path). x64 keeps the
  MSVC-compatible MASM path. Long-term: guard that file with `!defined(_MSC_VER)`.
- The MSVC build matrix has not yet been validated by a real CI run; the package
  *definition* (nuspec/targets/package.xml) and generator are validated locally.
  The CI link-test (compile+link a C++ consumer against only the package include
  dir) is the gate that proves the shipped headers + lib are self-contained.
