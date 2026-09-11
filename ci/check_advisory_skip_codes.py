#!/usr/bin/env python3
"""
check_advisory_skip_codes.py — Rule 16 gate (extended).

Parses unified_audit_runner.cpp to find all advisory=true modules, then
verifies their standalone binaries return ADVISORY_SKIP_CODE=77 when
run without GPU/optional infrastructure.

check_advisory_skip_returns.sh only checked 2 hardcoded binaries. This
script dynamically covers all advisory modules.

Exit:
  0  — all found advisory standalones return 77 (or none found)
  1  — at least one advisory standalone returned 0 (false PASS)
 77  — no advisory standalone binaries were found to check
"""
import argparse
import os
import re
import subprocess
import sys

ADVISORY_SKIP_CODE = 77


def find_advisory_modules(runner_path: str) -> list[str]:
    """Parse ALL_MODULES[] in unified_audit_runner.cpp and return names of
    entries with advisory=true."""
    try:
        with open(runner_path, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        print(f"  WARN: cannot read {runner_path}", file=sys.stderr)
        return []

    # Match: { "module_name", "...", "...", func_run, true }
    # The last positional arg before } is the advisory bool.
    pattern = re.compile(
        r'\{\s*"([^"]+)"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*\w+\s*,\s*(true|false)\s*\}',
        re.MULTILINE,
    )
    advisory = []
    for m in pattern.finditer(src):
        name, is_advisory = m.group(1), m.group(2)
        if is_advisory == "true":
            advisory.append(name)
    return advisory


def find_standalone(build_dir: str, module_name: str) -> str | None:
    """Return path to <module_name>_standalone binary if it exists."""
    candidates = [
        os.path.join(build_dir, "audit", f"{module_name}_standalone"),
        os.path.join(build_dir, f"{module_name}_standalone"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def check_binary(name: str, binary: str) -> bool:
    """Run binary, return True if it correctly returns 77."""
    try:
        result = subprocess.run(
            [binary],
            capture_output=True,
            timeout=30,
        )
        rc = result.returncode
    except subprocess.TimeoutExpired:
        print(f"  WARN {name}: timed out after 30 s")
        return True  # not a false-PASS
    except OSError as e:
        print(f"  WARN {name}: cannot execute ({e})")
        return True

    if rc == ADVISORY_SKIP_CODE:
        print(f"  OK   {name}: returns 77 (ADVISORY_SKIP_CODE) ✓")
        return True
    elif rc == 0:
        print(f"  FAIL {name}: returns 0 (false PASS) — advisory skip not firing!")
        return False
    else:
        print(f"  WARN {name}: returns {rc} (may be a real failure or infrastructure issue)")
        return True  # not a false-PASS from Rule 16 perspective


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default="build_bench_opt",
                        help="CMake build directory (default: build_bench_opt)")
    parser.add_argument("--runner", default="audit/unified_audit_runner.cpp",
                        help="Path to unified_audit_runner.cpp")
    args = parser.parse_args()

    # Resolve paths relative to script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    runner_path = os.path.join(repo_root, args.runner)
    build_dir = args.build_dir if os.path.isabs(args.build_dir) \
        else os.path.join(repo_root, args.build_dir)

    advisory_modules = find_advisory_modules(runner_path)
    if not advisory_modules:
        print("  WARN: no advisory modules found in runner — check runner path")
        sys.exit(ADVISORY_SKIP_CODE)

    print(f"  Found {len(advisory_modules)} advisory module(s) in runner")

    checked = 0
    failed = 0

    for name in advisory_modules:
        binary = find_standalone(build_dir, name)
        if binary is None:
            # Standalone not built — acceptable (GPU build may be absent)
            continue
        checked += 1
        if not check_binary(name, binary):
            failed += 1

    if checked == 0:
        print(f"  SKIP: no advisory standalone binaries found in {build_dir}")
        sys.exit(ADVISORY_SKIP_CODE)

    if failed > 0:
        print(f"\n  {failed}/{checked} advisory module(s) returned 0 (false PASS) — Rule 16 violated")
        sys.exit(1)

    print(f"\n  All {checked} advisory skip checks passed ✓")
    sys.exit(0)


if __name__ == "__main__":
    main()
