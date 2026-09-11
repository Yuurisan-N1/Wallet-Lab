#!/usr/bin/env python3
"""
test_check_advisory_skip_ceiling.py — unit test for ci/check_advisory_skip_ceiling.py.

Guards the meta-gate against silent loosening: the advisory-module ceiling must stay
TIGHT (== actual count, no unreviewed slack), the frozen twin must match, and the gate
must FAIL when the advisory count exceeds the ceiling.

Self-contained. Exit 0 = pass, 1 = fail.
"""
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "ci", "check_advisory_skip_ceiling.py")

failures = []


def check(cond, msg):
    print(("  ok  : " if cond else "  FAIL: ") + msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    spec = importlib.util.spec_from_file_location("chk", GATE)
    chk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chk)  # import-time assert(CEILING == FROZEN) runs here

    # 1. Frozen twin matches (silent loosening is blocked at import).
    check(chk.ADVISORY_CEILING == chk.ADVISORY_CEILING_FROZEN,
          f"ceiling == frozen twin ({chk.ADVISORY_CEILING})")

    # 2. Ceiling is TIGHT: no slack above the actual advisory count in the runner.
    actual = chk.count_advisory_modules(chk.ROOT / chk.RUNNER_PATH
                                        if hasattr(chk, "ROOT") else chk.RUNNER_PATH)
    if actual < 0:  # runner path may be relative to repo root
        actual = chk.count_advisory_modules(chk.RUNNER_PATH)
    check(actual >= 0, f"advisory count is readable ({actual})")
    check(chk.ADVISORY_CEILING == actual,
          f"ceiling is tight: ceiling({chk.ADVISORY_CEILING}) == actual({actual}) "
          f"(no unreviewed slack)")

    print("\n" + ("ALL PASS" if not failures else f"FAILURES: {len(failures)}"))
    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
