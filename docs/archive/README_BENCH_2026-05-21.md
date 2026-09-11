# Archived 2026-05-21 bench_unified artifacts

Both files moved out of `docs/bench_unified_*.json` canonical glob on 2026-05-24
per `FINAL_AGGREGATED_REVIEW_2026-05-24-v9.md` P0-C / BENCH-001 / BENCH-003.

## `bench_unified_2026-05-21_gcc14_x86-64_TURBO_UNKNOWN.json`
- Original name: `bench_unified_2026-05-21_gcc14_x86-64.json`
- Reason archived: metadata `turbo` field reads
  `"unknown (sysfs not available on this runner)"`. Fails BENCH-PROTOCOL
  turbo-locked requirement. Superseded by `bench_unified_2026-05-23_gcc14_x86-64.json`
  which is turbo-locked.

## `bench_unified_2026-05-21_gcc14_x86-64_v2_ORPHAN.json`
- Original name: `bench_unified_2026-05-21_gcc14_x86-64_v2.json`
- Reason archived: metadata block was missing `generated_by`, `date`, and
  `turbo` keys entirely. Timings ~2× faster than the contemporary v1 and
  the 05-23 canonical — likely a hot-cache run that was never properly
  certified. Violated KB constraint `BENCH-CANONICAL`. Orphan; do not use.

The canonical source-of-truth is now `docs/bench_unified_2026-05-23_gcc14_x86-64.json`
referenced from `docs/canonical_numbers.json._canonical_bench_artifact`.
