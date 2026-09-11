#!/usr/bin/env python3
"""check_test_assertions.py — flag non-asserting "documented open" test probes.

A security/regression test that PRINTS an open-issue marker (MED-3, "documented
open", "non-asserting", "always passes regardless", "INFO-only", "cannot detect")
but never CHECK()s the underlying value is a false-green: it passes while the
behaviour it describes can silently regress. This is the MSI-4 anti-pattern
(test_regression_musig2_signer_index_validation.cpp before it was made asserting).

The scanner flags any printf/cout call in audit/test_*.cpp (and tests/*.cpp) whose
string literal contains a non-asserting marker phrase. The fix is to replace the
printf with a real CHECK(condition, ...) — or, if the behaviour is a genuinely
open advisory item, split it into a separate module that returns ADVISORY_SKIP_CODE
(77), never a silent module-level pass.

Usage:
    python3 ci/check_test_assertions.py            # exit 1 if any non-asserting probe found
    python3 ci/check_test_assertions.py --list     # list scanned files, then check
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Tell-tale phrases of a non-asserting probe (case-insensitive). A printf/cout that
# explains why it is NOT asserting is the false-green smell we want to forbid.
MARKERS = [
    "non-asserting",
    "always passes regardless",
    "info-only",
    "info only",
    "cannot detect",
    "documented open behavior",
    "documented open behaviour",
    "printed but not check",
]

# A call is a print if it invokes one of these.
PRINT_RE = re.compile(r"\b(std::)?printf\s*\(|\bstd::(cout|cerr)\b|\bfprintf\s*\(")
MARKER_RE = re.compile("|".join(re.escape(m) for m in MARKERS), re.IGNORECASE)


def scan_file(path: Path) -> list[tuple[int, str]]:
    """Return (line_no, text) for every print whose argument carries a marker phrase.

    Comments (lines starting with // or *) are skipped: it is the runtime printf —
    not the explanatory comment — that makes a test silently pass."""
    hits: list[tuple[int, str]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return hits
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        if PRINT_RE.search(line) and MARKER_RE.search(line):
            hits.append((i, line.strip()))
    return hits


def collect_test_files() -> list[Path]:
    files: list[Path] = []
    for d in (ROOT / "audit", ROOT / "tests", ROOT / "src" / "cpu" / "tests"):
        if d.exists():
            files.extend(sorted(d.glob("test_*.cpp")))
    # compat/*/tests/ (shim + bridge conformance tests) were previously unscanned, so a
    # non-asserting probe there could pass undetected. Mirror TEST-006 in
    # audit_test_quality_scanner.py.
    compat = ROOT / "compat"
    if compat.exists():
        files.extend(sorted(compat.glob("*/tests/test_*.cpp")))
    return files


def main() -> int:
    list_mode = "--list" in sys.argv
    files = collect_test_files()
    if list_mode:
        print(f"[check_test_assertions] scanning {len(files)} test files")

    findings: list[tuple[Path, int, str]] = []
    for f in files:
        for ln, text in scan_file(f):
            findings.append((f, ln, text))

    if findings:
        print("FAIL: non-asserting test probe(s) found "
              "(a printf that explains why it is NOT asserting — MSI-4 anti-pattern):")
        for f, ln, text in findings:
            print(f"  {f.relative_to(ROOT)}:{ln}: {text[:120]}")
        print("\nFix: replace the printf with CHECK(condition, ...), or split the open")
        print("item into a separate advisory module that returns ADVISORY_SKIP_CODE (77),")
        print("never a silent module-level pass. See AUDIT_CHANGELOG 2026-05-31 (MED-3).")
        return 1

    print(f"check_test_assertions: OK ({len(files)} test files, 0 non-asserting probes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
