#!/usr/bin/env python3
"""
check_zk_tag_conformance.py — guard ZK (Bulletproof / DLEQ) Fiat-Shamir tagged-hash
tag strings across ALL backends (CPU + CUDA + OpenCL + Metal).

WHY: a range proof's Fiat-Shamir challenges (y, z, x, inner-product) are derived with
BIP-340-style tagged hashes. The PROVER and the VERIFIER must use byte-identical tag
strings or the recomputed challenges differ and the proof never verifies — a SILENT
divergence that passes self-consistent single-backend tests but breaks cross-backend
and prove-vs-verify interop.

This actually happened: the Metal CT range-prove (secp256k1_ct_zk.h) and the OpenCL CT
range-prove (secp256k1_ct_zk.cl) used the abbreviated tags "BP/y" / "BP/z" / "BP/x" /
"BP/ip" while every verifier (CPU, CUDA, OpenCL, Metal) recomputes with the canonical
"Bulletproof/y" / "Bulletproof/z" / "Bulletproof/x" / "Bulletproof/ip". So GPU-produced
proofs failed verification everywhere. This gate prevents that class from returning.

RULE: the abbreviated "BP/<chal>" tag form is BANNED. The canonical Bulletproof
Fiat-Shamir tag is "Bulletproof/<chal>". Detects both quoted string literals
("BP/y") and C/Metal/OpenCL byte-array literals ({'B','P','/','y'}).

Exit 0 = clean, exit 1 = violation(s) found.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_DIRS = ["src/cpu", "src/cuda", "src/opencl", "src/metal"]
EXTS = (".cpp", ".hpp", ".h", ".cc", ".cu", ".cl", ".metal", ".cuh", ".inc")

# Banned abbreviated tag prefix (canonical is "Bulletproof/")
BANNED_QUOTED = re.compile(r'"(BP/[A-Za-z]+)"')
BYTEARRAY = re.compile(r"\{\s*('(?:[^']|\\.)'(?:\s*,\s*'(?:[^']|\\.)')*)\s*\}")


def decode_bytearray(seg: str) -> str:
    chars = re.findall(r"'([^']|\\.)'", seg)
    out = []
    for c in chars:
        if c.startswith("\\"):
            try:
                out.append(c.encode().decode("unicode_escape"))
            except Exception:
                out.append(c)
        else:
            out.append(c)
    return "".join(out)


def main() -> int:
    violations = []
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dp, _, files in os.walk(base):
            if any(x in dp for x in (os.sep + "out", os.sep + ".git", "worktree", os.sep + "build")):
                continue
            for f in files:
                if not f.endswith(EXTS):
                    continue
                p = os.path.join(dp, f)
                try:
                    text = open(p, errors="replace").read()
                except OSError:
                    continue
                for n, line in enumerate(text.split("\n"), 1):
                    for m in BANNED_QUOTED.finditer(line):
                        violations.append((p, n, m.group(1), "quoted"))
                    for m in BYTEARRAY.finditer(line):
                        s = decode_bytearray(m.group(1))
                        if s.startswith("BP/"):
                            violations.append((p, n, s, "byte-array"))

    if violations:
        print("FAIL: abbreviated 'BP/<challenge>' Fiat-Shamir tag(s) found.")
        print("      The canonical Bulletproof tag is 'Bulletproof/<challenge>'.")
        print("      Prover and verifier MUST use byte-identical tags or proofs never verify.")
        for p, n, tag, kind in violations:
            rel = os.path.relpath(p, ROOT)
            print(f"  {rel}:{n}: {kind} tag \"{tag}\"  ->  use \"Bulletproof/{tag[3:]}\"")
        return 1

    print("OK: no abbreviated 'BP/' ZK tags — all Bulletproof Fiat-Shamir tags canonical.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
