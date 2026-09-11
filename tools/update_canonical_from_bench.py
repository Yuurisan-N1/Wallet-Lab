#!/usr/bin/env python3
"""Refresh canonical_numbers.json bench-derived fields from a bench_unified JSON.

Usage: update_canonical_from_bench.py <bench_unified_*.json> [--apply]

Without --apply it only prints the OLD->NEW diff (dry run). With --apply it
rewrites docs/canonical_numbers.json (indent=2, ensure_ascii=False, trailing
newline — byte-identical round-trip for unchanged fields).
"""
import json, sys, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANON = ROOT / "docs" / "canonical_numbers.json"

def load_bench(p):
    d = json.load(open(p))
    m = {}
    for e in d["results"]:
        m[(e["section"], e["name"])] = e.get("ns")
    return d, m

def main():
    if len(sys.argv) < 2:
        print("usage: update_canonical_from_bench.py <bench.json> [--apply]"); return 2
    bench_path = sys.argv[1]
    apply = "--apply" in sys.argv[2:]
    rel = "docs/" + Path(bench_path).name
    bd, m = load_bench(bench_path)

    def g(sec, name):
        v = m.get((sec, name))
        if v is None:
            raise KeyError(f"missing bench entry: [{sec}] {name}")
        return v

    # --- pull values -------------------------------------------------------
    fast_ecdsa_sign = g("ECDSA -- Ultra FAST", "ecdsa_sign")
    fast_schnorr_sign = g("SCHNORR / BIP-340 -- Ultra FAST", "schnorr_sign")
    ct_ecdsa = g("CT SIGNING (Ultra CT)", "ct::ecdsa_sign")
    ct_schnorr = g("CT SIGNING (Ultra CT)", "ct::schnorr_sign")
    libsecp_ecdsa_sign = g("libsecp256k1 (bitcoin-core)", "ecdsa_sign")
    libsecp_schnorr_sign = g("libsecp256k1 (bitcoin-core)", "schnorr_sign (BIP-340)")
    ecdsa_ratio = round(libsecp_ecdsa_sign / ct_ecdsa, 2)
    schnorr_ratio = round(libsecp_schnorr_sign / ct_schnorr, 2)
    sb4 = g("BATCH VERIFICATION (FAST)", "schnorr_batch_verify(N=4)")
    sb64 = g("BATCH VERIFICATION (FAST)", "schnorr_batch_verify(N=64)")
    sb192 = g("BATCH VERIFICATION (FAST)", "schnorr_batch_verify(N=192)")

    updates = {
        "_canonical_bench_artifact": rel,
        "primitives_gcc": {
            "field_mul_ns": g("FIELD ARITHMETIC (Ultra)", "field_mul"),
            "field_sqr_ns": g("FIELD ARITHMETIC (Ultra)", "field_sqr"),
            "field_inv_ns": g("FIELD ARITHMETIC (Ultra)", "field_inv"),
            "scalar_mul_ns": g("SCALAR ARITHMETIC (Ultra)", "scalar_mul"),
            "point_dbl_ns": g("POINT ARITHMETIC (Ultra)", "point_dbl"),
            "scalar_mul_kP_ns": g("POINT ARITHMETIC (Ultra)", "scalar_mul (k*P)"),
            "dual_mul_ns": g("POINT ARITHMETIC (Ultra)", "dual_mul (a*G + b*P)"),
            "libsecp_field_mul_ns": g("libsecp256k1 (bitcoin-core)", "field_mul"),
            "libsecp_scalar_mul_ns": g("libsecp256k1 (bitcoin-core)", "scalar_mul"),
            "libsecp_point_dbl_ns": g("libsecp256k1 (bitcoin-core)", "point_dbl (gej_double_var)"),
            "_artifact": rel,
        },
        "sign_verify_gcc": {
            "ecdsa_sign_ns": fast_ecdsa_sign,
            "ecdsa_verify_ns": g("ECDSA -- Ultra FAST", "ecdsa_verify"),
            "ecdsa_verify_cached_ns": g("ECDSA -- Ultra FAST", "ecdsa_verify (cached EcdsaPublicKey)"),
            "schnorr_sign_ns": fast_schnorr_sign,
            "schnorr_verify_cached_ns": g("SCHNORR / BIP-340 -- Ultra FAST", "schnorr_verify (cached xonly)"),
            "libsecp_ecdsa_sign_ns": libsecp_ecdsa_sign,
            "libsecp_ecdsa_verify_ns": g("libsecp256k1 (bitcoin-core)", "ecdsa_verify"),
            "_artifact": rel,
        },
        "ct_signing_gcc": {
            "ecdsa_ratio": ecdsa_ratio,
            "schnorr_ratio": schnorr_ratio,
            "speedup_min_x": min(ecdsa_ratio, schnorr_ratio),
            "speedup_max_x": max(ecdsa_ratio, schnorr_ratio),
            "artifact": rel,
        },
        "ct_signing_gcc_detail": {
            "ct_ecdsa_sign_ns": ct_ecdsa,
            "ct_schnorr_sign_ns": ct_schnorr,
            "ct_scalar_inverse_ns": g("CT POINT ARITHMETIC (sub-ops)", "ct::scalar_inverse (SafeGCD)"),
            "ct_overhead_ecdsa": round(ct_ecdsa / fast_ecdsa_sign, 4),
            "ct_overhead_schnorr": round(ct_schnorr / fast_schnorr_sign, 4),
            "_artifact": rel,
        },
        "protocols_gcc": {
            "keccak256_32b_ns": g("ETHEREUM OPERATIONS", "keccak256 (32B)"),
            "ecdsa_sign_recoverable_ns": g("ETHEREUM OPERATIONS", "ecdsa_sign_recoverable"),
            "_artifact": rel,
        },
        "batch_verify_gcc": {
            "schnorr_per_sig_n4_ns": round(sb4 / 4, 2),
            "schnorr_per_sig_n64_ns": round(sb64 / 64, 2),
            "schnorr_per_sig_n192_ns": round(sb192 / 192, 2),
            "_artifact": rel,
        },
    }

    raw = open(CANON, encoding="utf-8").read()
    canon = json.loads(raw)

    print(f"{'field':52s} {'OLD':>14s} {'NEW':>14s}")
    print("-" * 84)
    def show(path, old, new):
        os_ = f"{old:.2f}" if isinstance(old, (int, float)) else str(old)
        ns_ = f"{new:.2f}" if isinstance(new, (int, float)) else str(new)
        flag = "" if str(old) == str(new) else "  <-- changed"
        print(f"{path:52s} {os_[:14]:>14s} {ns_[:14]:>14s}{flag}")

    for top, val in updates.items():
        if isinstance(val, dict):
            for k, newv in val.items():
                old = canon.get(top, {}).get(k)
                show(f"{top}.{k}", old, newv)
                if apply:
                    canon[top][k] = newv
        else:
            show(top, canon.get(top), val)
            if apply:
                canon[top] = val

    if apply:
        out = json.dumps(canon, indent=2, ensure_ascii=False) + "\n"
        open(CANON, "w", encoding="utf-8").write(out)
        print("\nAPPLIED to", CANON)
    else:
        print("\n(dry run — pass --apply to write)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
