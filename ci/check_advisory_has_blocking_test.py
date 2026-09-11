#!/usr/bin/env python3
"""CAAS-FG-01 guard: shim security PoC standalones must register in a SHIM build.

Root CMakeLists adds `audit/` BEFORE `compat/libsecp256k1_shim/`, so a bare
`if(TARGET secp256k1_shim)` guard around test registration in audit/CMakeLists.txt
is ALWAYS FALSE while audit/ is processed — the test silently never becomes a CTest
target and its security property runs in no blocking job (a false-green). The fix is
to guard registration on `SECP256K1_BUILD_SHIM` (the cache variable, set before any
add_subdirectory) so the standalone registers; `secp256k1_shim` resolves at generate
time for linking.

ENFORCED (fail-closed):
  - The `shim_exploit_test(...)` macro block (which registers the named shim security
    PoC standalones — CFB context-flag-bypass, MUS musig-unknown-signer) must be
    guarded by a condition that includes `SECP256K1_BUILD_SHIM`, not a bare
    `if(TARGET secp256k1_shim)`.
  - Every `shim_exploit_test(...)` call must reference a test source file that exists.

ENFORCED (fail-closed): there must be ZERO bare `if(TARGET secp256k1_shim)` blocks
that guard test registration (add_test/add_executable). The 2026-06-01 systemic
refactor converted all 31 of them to `OR SECP256K1_BUILD_SHIM` (and fixed/validated
the bit-rotted tests they exposed — see docs/REVIEW_VALIDATED_FINDINGS.md), so any new
bare guard is a regression: audit/ is processed before compat/libsecp256k1_shim/, so a
bare guard is always FALSE in the main build and silently drops the test from every
blocking job (a false-green). Use `if(TARGET secp256k1_shim OR SECP256K1_BUILD_SHIM)`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDIT_CMAKE = ROOT / "audit" / "CMakeLists.txt"


def main() -> int:
    if not AUDIT_CMAKE.exists():
        sys.stderr.write(f"::error::{AUDIT_CMAKE} not found\n")
        return 2

    lines = AUDIT_CMAKE.read_text(errors="replace").splitlines()
    failures: list[str] = []

    # --- locate the shim_exploit_test macro + the if() that guards it -------------
    macro_line = next((i for i, l in enumerate(lines)
                       if "macro(shim_exploit_test" in l), None)
    if macro_line is None:
        sys.stderr.write("::error::shim_exploit_test macro not found in audit/CMakeLists.txt\n")
        return 2

    # The nearest preceding `if(...)` is the guard for the macro + its calls.
    guard = next((lines[i] for i in range(macro_line, -1, -1)
                  if lines[i].lstrip().startswith("if(")), "")
    if "SECP256K1_BUILD_SHIM" not in guard:
        failures.append(
            "shim_exploit_test macro is guarded by "
            f"`{guard.strip()}` which does NOT include SECP256K1_BUILD_SHIM. "
            "Root CMake adds audit/ before compat/libsecp256k1_shim/, so a bare "
            "`if(TARGET secp256k1_shim)` is always false here and the shim security "
            "PoC standalones are silently dropped (CAAS-FG-01). Use "
            "`if(TARGET secp256k1_shim OR SECP256K1_BUILD_SHIM)`.")

    # --- every shim_exploit_test(...) call must reference an existing source ------
    body = "\n".join(lines)
    for m in re.finditer(r"shim_exploit_test\(\s*\w+\s+([\w./]+\.cpp)", body):
        src = m.group(1)
        if not (ROOT / "audit" / src).exists():
            failures.append(f"shim_exploit_test references missing source: audit/{src}")

    # --- ENFORCE: zero bare if(TARGET secp256k1_shim) registration blocks ----------
    bare_lines: list[int] = []
    for i, l in enumerate(lines):
        if l.strip() == "if(TARGET secp256k1_shim)":
            blk = "\n".join(lines[i:i + 14])
            if "add_test(" in blk or "add_executable(" in blk:
                bare_lines.append(i + 1)

    print("CAAS-FG-01 advisory-blocking-twin guard")
    print(f"  shim_exploit_test guard: {guard.strip()[:70]}")
    if bare_lines:
        failures.append(
            f"{len(bare_lines)} bare `if(TARGET secp256k1_shim)` registration block(s) "
            f"remain (audit/CMakeLists.txt lines {bare_lines}). audit/ is processed "
            "before compat/libsecp256k1_shim/, so a bare guard is always FALSE in the "
            "main build and silently drops the test from every blocking job (false-green). "
            "Convert to `if(TARGET secp256k1_shim OR SECP256K1_BUILD_SHIM)`.")

    if failures:
        for f in failures:
            print(f"  [FAIL] {f}")
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
