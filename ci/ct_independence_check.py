#!/usr/bin/env python3
"""
G-8: CT Tool Independence Agreement Check.

Reads verdict JSON files produced by independent CT tools and decides whether
INDEPENDENCE is actually established. Independence requires that at least
--min-tools (default 2) DISTINCT non-SKIP tools verdict PASS. A single PASS
(with the other tools SKIP or missing) does NOT establish independence — it is
reported as INCONCLUSIVE (exit 2), never as PASS. This closes the false-green
where one tool PASSing while a second SKIPs (e.g. dudect not yet wired) was
reported as a passing independence gate.

  - Any FAIL                                    → FAIL  (leakage / tool disagreement)
  - A --require-tools entry missing or not PASS  → FAIL  (cannot prove independence)
  - Fewer than --min-tools distinct PASS         → SKIP  (INCONCLUSIVE, not PASS)
  - >= --min-tools distinct PASS, no FAIL        → PASS

This proves that multiple independent analysis methodologies — binary taint,
statistical timing, compile-time verification — reach the same conclusion
about the CT properties of the signing implementation.

Usage:
    python3 ci/ct_independence_check.py <verdict_a.json> [<verdict_b.json> ...] \
        [--min-tools N] [--require-tools name,name] [--json]

Exit codes:
    0  independence established: >= min-tools tools PASS, none FAIL
    1  a tool detected leakage (FAIL), tools disagree, or a required tool is missing/not PASS
    2  inconclusive: fewer than min-tools tools produced a PASS (no FAIL)

Verdict JSON format (emitted by each CT tool job):
    {
        "tool": "valgrind-memcheck-ct",
        "methodology": "binary-taint",
        "verdict": "PASS",       # PASS | FAIL | SKIP
        "exit_code": 0,
        "details": "...",
        "commit": "<sha>",
        "runner": "Linux-X64"
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_verdict(path: Path) -> dict | None:
    if not path.exists():
        print(f"WARN: verdict file not found: {path}", file=sys.stderr)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"WARN: cannot parse verdict JSON {path}: {e}", file=sys.stderr)
        return None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="G-8: CT tool independence agreement check."
    )
    parser.add_argument("verdicts", nargs="+", help="Verdict JSON files from CT tools")
    parser.add_argument("--json", action="store_true", help="Emit JSON result to stdout")
    parser.add_argument(
        "--min-tools", type=int, default=2,
        help="Minimum distinct non-SKIP tools that must PASS to establish independence "
             "(default 2). Fewer PASSes (e.g. one tool SKIPped) → INCONCLUSIVE, never PASS.",
    )
    parser.add_argument(
        "--require-tools", default="",
        help="Comma-separated tool names that MUST be present and PASS "
             "(e.g. 'valgrind-memcheck-ct,dudect'). A missing or non-PASS required tool fails the gate.",
    )
    args = parser.parse_args(argv[1:])

    loaded: list[dict] = []
    for p in args.verdicts:
        v = load_verdict(Path(p))
        if v is not None:
            loaded.append(v)

    if not loaded:
        print("ERROR: no verdict files could be loaded", file=sys.stderr)
        return 2

    passes = [v for v in loaded if v.get("verdict") == "PASS"]
    fails = [v for v in loaded if v.get("verdict") == "FAIL"]
    skips = [v for v in loaded if v.get("verdict") == "SKIP"]

    # Independence is about distinct methodologies — de-duplicate PASSes by tool name.
    passed_tools = sorted({v.get("tool", "?") for v in passes})
    required = [t.strip() for t in args.require_tools.split(",") if t.strip()]
    missing_required = [t for t in required if t not in passed_tools]

    # Gate logic (fail-closed, independence-aware). A single PASS with the other
    # tools SKIP/missing does NOT establish independence — it is INCONCLUSIVE (SKIP),
    # not PASS. This is the PASS6-CT-002 / P7-CAAS-001 false-green fix.
    if fails:
        overall = "FAIL"
    elif missing_required:
        overall = "FAIL"
    elif len(passed_tools) < args.min_tools:
        overall = "SKIP"
    else:
        overall = "PASS"

    if args.json:
        result = {
            "overall": overall,
            "min_tools": args.min_tools,
            "tools_evaluated": len(loaded),
            "pass_count": len(passes),
            "distinct_pass_tools": passed_tools,
            "fail_count": len(fails),
            "skip_count": len(skips),
            "missing_required": missing_required,
            "verdicts": [
                {
                    "tool": v.get("tool", "?"),
                    "methodology": v.get("methodology", "?"),
                    "verdict": v.get("verdict", "?"),
                    "details": v.get("details", ""),
                }
                for v in loaded
            ],
        }
        print(json.dumps(result, indent=2))
        return 0 if overall == "PASS" else (2 if overall == "SKIP" else 1)

    print(f"CT Tool Independence Check — {len(loaded)} tool(s) evaluated:")
    for v in loaded:
        tool = v.get("tool", "?")
        method = v.get("methodology", "?")
        verdict = v.get("verdict", "?")
        details = v.get("details", "")
        status = {"PASS": "OK", "FAIL": "FAIL", "SKIP": "SKIP"}.get(verdict, verdict)
        print(f"  [{status}] {tool} ({method})")
        if details:
            print(f"         {details}")

    if fails:
        tools = ", ".join(v.get("tool", "?") for v in fails)
        print(f"\nFAIL: {len(fails)} tool(s) detected CT leakage: {tools}")
        print("      Tools disagree or implementation is not constant-time")
        return 1

    if missing_required:
        print(f"\nFAIL: required tool(s) missing or not PASS: {', '.join(missing_required)}")
        print("      Cannot establish CT independence without them.")
        return 1

    if overall == "SKIP":
        names = ", ".join(passed_tools) if passed_tools else "none"
        print(f"\nINCONCLUSIVE: only {len(passed_tools)} tool(s) PASSed "
              f"(need >= {args.min_tools} for independence): {names}")
        print("      A single tool cannot establish independence — NOT reporting PASS.")
        return 2

    print(f"\nPASS: {len(passed_tools)} independent CT tool(s) found no timing leakage")
    methodologies = [v.get("methodology", "?") for v in passes]
    print(f"      Methodologies that agree: {', '.join(methodologies)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
