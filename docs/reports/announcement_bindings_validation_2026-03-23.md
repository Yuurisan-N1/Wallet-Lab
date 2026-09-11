# Draft Announcement — Binding Validation Closure

## Title

Stable binding validation matrix completed across Dart, React Native, and the remaining language bindings

## What

- Unified the shared binding validator so the stable `ufsecp` bindings now run smoke coverage across C#, Java, Swift, Python, Go, Rust, Node.js, PHP, Ruby, and Dart.
- Added a practical default React Native contract-smoke path in plain Node.js, while keeping full native React Native smoke available as an opt-in lane.
- Fixed wrapper drift and FFI edge cases discovered during the pass, including zero-length hashing buffers, Rust linker/search-path issues, stale smoke assumptions, and Dart finalizer/runtime problems.
- Synchronized the canonical binding docs, examples, packaging notes, and README surfaces to the validated package names and current context-based APIs.

## Numbers

- Shared validator coverage: 11 binding lanes green by default
- Dart smoke runner: 12/12 checks passing
- React Native contract smoke: 12/12 checks passing
- Canonical bindings parity matrix: 42/42 stable C ABI functions documented as covered per binding

## How To Get It

- Branch: `dev`
- Validation entrypoint: `bash libs/UltrafastSecp256k1/scripts/validate_bindings.sh`
- Release path: intended for the current development line heading toward the next release cut

## Short Form

The stable binding layer is now documented and validated as one coherent matrix instead of a partially verified set of wrappers. Dart is no longer treated as a conditional afterthought, and React Native now has a default contract-validation lane that can run without full mobile bootstrapping.
