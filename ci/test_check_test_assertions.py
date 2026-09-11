#!/usr/bin/env python3
"""test_check_test_assertions.py — unit test for the non-asserting-probe scanner.

Validates ci/check_test_assertions.py: it must flag a printf that carries a
non-asserting marker, must NOT flag a clean asserting test, and must NOT flag a
marker that appears only in a comment. This is the paired test that makes the
scanner (and the run_fast_gates.sh wiring that runs it) verifiable.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "cta", Path(__file__).resolve().parent / "check_test_assertions.py")
cta = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cta)


def _write(text: str) -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False)
    f.write(text)
    f.close()
    return Path(f.name)


def main() -> int:
    fails = 0

    # BAD: a printf whose string carries a non-asserting marker -> must be flagged.
    bad = _write('void t(){ std::printf("psig=%d non-asserting documented open\\n", x); }\n')
    if not cta.scan_file(bad):
        print("FAIL: scanner did NOT flag a non-asserting printf"); fails += 1
    else:
        print("ok: bad probe flagged")
    bad.unlink()

    # GOOD: a real CHECK plus a plain printf -> must NOT be flagged.
    good = _write('void t(){ CHECK(x==0,"ok"); std::printf("done\\n"); }\n')
    if cta.scan_file(good):
        print("FAIL: scanner flagged a clean asserting test"); fails += 1
    else:
        print("ok: clean test not flagged")
    good.unlink()

    # COMMENT: marker only inside a comment -> must NOT be flagged.
    cmt = _write('// non-asserting historical note\nvoid t(){ CHECK(x,"y"); }\n')
    if cta.scan_file(cmt):
        print("FAIL: scanner flagged a comment-only marker"); fails += 1
    else:
        print("ok: comment-only marker not flagged")
    cmt.unlink()

    print("PASS" if fails == 0 else f"{fails} check(s) FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
