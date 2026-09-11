#!/usr/bin/env python3
"""
test_check_tag_conformance.py — unit test for ci/check_tag_conformance.py.

Verifies the systemic tagged-hash tag-conformance gate actually catches the bug class
it exists to prevent (the "self-consistent but spec-divergent" tag bugs:
MuSig/nonceblinding and BP/*), and passes clean on the current tree.

Self-contained (no pytest). Exit 0 = pass, 1 = fail.
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "ci", "check_tag_conformance.py")

failures = []


def check(cond, msg):
    if cond:
        print(f"  ok  : {msg}")
    else:
        print(f"  FAIL: {msg}")
        failures.append(msg)


def main() -> int:
    spec = importlib.util.spec_from_file_location("chk", GATE)
    chk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chk)

    # 1. The two bugs that actually shipped MUST be banned with the correct value.
    check(chk.BANNED_TAGS.get("MuSig/nonceblinding") == "MuSig/noncecoef",
          "MuSig/nonceblinding banned -> MuSig/noncecoef")
    for bad, good in (("BP/y", "Bulletproof/y"), ("BP/z", "Bulletproof/z"),
                      ("BP/x", "Bulletproof/x"), ("BP/ip", "Bulletproof/ip")):
        check(chk.BANNED_TAGS.get(bad) == good, f"{bad} banned -> {good}")

    # 2. The correct canonical tags MUST be registered (and not also banned).
    for tag in ("MuSig/noncecoef", "BIP0340/challenge", "Bulletproof/y",
                "KeyAgg coefficient", "TapTweak", "BIP0352/SharedSecret",
                "bip324_ellswift_xonly_ecdh"):
        check(tag in chk.CANONICAL_TAGS, f"canonical tag registered: {tag}")
        check(tag not in chk.BANNED_TAGS, f"canonical tag not also banned: {tag}")

    # 3. No tag may be in BOTH sets (a wrong tag must never be accepted).
    overlap = set(chk.BANNED_TAGS) & set(chk.CANONICAL_TAGS)
    check(not overlap, f"BANNED and CANONICAL are disjoint (overlap={overlap or 'none'})")

    # 4. The gate must PASS on the current tree (all production tags canonical).
    rc = chk.main()
    check(rc == 0, "gate passes clean on the current tree (rc == 0)")

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + str(len(failures))}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
