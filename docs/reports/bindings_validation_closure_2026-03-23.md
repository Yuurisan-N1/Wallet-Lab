# Bindings Validation Closure — 2026-03-23

## Scope

This note closes the multi-language binding validation and documentation sync pass for the stable `ufsecp` C ABI bindings.

Covered bindings:
- C#
- Java
- Swift
- Python
- Go
- Rust
- Node.js
- PHP
- Ruby
- Dart
- React Native

## Validation Outcome

The shared validator now passes end to end via:

```bash
bash libs/UltrafastSecp256k1/scripts/validate_bindings.sh
```

Verified lanes:
- C# smoke suite
- Java smoke suite
- Swift smoke suite
- Python smoke suite
- Go smoke suite
- Rust smoke suite
- Node.js smoke suite
- PHP smoke suite
- Ruby smoke suite
- Dart smoke suite
- React Native mock-bridge contract smoke suite

Opt-in lane retained:
- React Native native smoke remains gated behind `UFSECP_VALIDATE_REACT_NATIVE=1`

## Key Fixes Applied During Closure

### Cross-binding FFI hardening

- Zero-length hashing inputs were hardened so wrappers do not pass null pointers for empty buffers.
- This affected the wrappers that needed placeholder allocations for empty hashing inputs.

### Go

- Isolated legacy package conflict behind the legacy build tag.
- Updated smoke test import/module/API usage to match the current package surface.

### Node.js

- Updated smoke tests to the current `Ufsecp` export and verify semantics.
- Fixed empty-input hashing buffer handling.

### Rust

- Fixed wrapper compile errors in error initializers.
- Fixed sys crate linker search so `/usr/local/lib` is picked up automatically when present.

### PHP

- Fixed smoke-test drift for recoverable signature return shape and `sha256` usage.
- Fixed zero-length FFI allocation behavior.

### Ruby

- Updated smoke tests to current keyword-argument calling style.

### React Native

- Added a default plain-Node mock-bridge contract smoke path.
- Kept full native React Native smoke as an explicit opt-in lane.
- Updated docs to prefer the context-based `UfsecpContext` API.

### Dart

- Fixed zero-length native buffer allocation in the Dart FFI wrapper.
- Fixed `NativeFinalizer.attach(...)` usage by making `UfsecpContext` implement `ffi.Finalizable`.
- Added a standalone deterministic smoke runner at `bindings/dart/tool/smoke_runner.dart`.
- Updated the shared validator to use the standalone Dart smoke runner.
- Repaired the local Dart SDK installation issue where `dartvm` and `gen_snapshot` were extracted without execute bits.

## Documentation Sync Completed

The following docs were aligned with the verified state:
- `docs/BINDINGS.md`
- `docs/BINDINGS_USAGE_STANDARD.md`
- `docs/BINDINGS_EXAMPLES.md`
- `docs/BINDINGS_PACKAGING.md`
- `README.md`
- `bindings/dart/README.md`
- `bindings/react-native/README.md`

Main doc corrections:
- Dart package name corrected to `ultrafast_secp256k1`
- React Native package name corrected to `react-native-ultrafast-secp256k1`
- Context-based APIs documented as the current standard surface
- Validation matrix updated to reflect smoke coverage instead of outdated optional/compile-only framing

## Final State

- The stable binding matrix is documented as smoke-validated across desktop/server bindings plus Dart.
- React Native has a practical default validation path through contract smoke, with the native bridge lane still opt-in.
- Canonical binding docs no longer describe Dart as effectively optional or React Native as only a compile/type-check surface.

## Follow-up Boundaries

This note closes the binding validation and binding docs sync topic.

It does not claim:
- full automated real-device React Native runtime coverage by default
- publication to registries as part of this pass
- a release cut; this work is positioned for the current `dev` branch and upcoming release flow
