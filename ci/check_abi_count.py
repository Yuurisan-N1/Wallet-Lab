#!/usr/bin/env python3
"""check_abi_count.py — REL-04 regression gate.

The stable C ABI surface is every `UFSECP_API ufsecp_*(` declaration in
include/ufsecp/ufsecp.h. Documentation that states a function COUNT or lists
function NAMES must stay in sync with that header. This gate caught REL-04:
docs/ABI_VERSIONING.md §5 claimed "42 functions" (real: 153) and listed
fabricated names (address_p2pkh, bip32_master_key, sha256_init, selftest_run),
and the nuspec repeated "42 stable C ABI functions".

Checks (run from repo root):
  1. docs/ABI_VERSIONING.md "There are **N** such functions" == header count.
  2. packaging/nuget/*.nuspec "N stable C ABI functions" == header count.
  3. Every backticked short-name in the §5 "Stable ABI Surface" table resolves
     to a real `ufsecp_<name>` declaration (no fabricated names).
  4. §8 binding matrix must not cite a stale "NN-fn" count that disagrees.

Exit 0 = OK, 1 = mismatch.
"""
import re
import sys
from pathlib import Path

HEADER = Path("include/ufsecp/ufsecp.h")
ABI_DOC = Path("docs/ABI_VERSIONING.md")
NUSPEC = Path("packaging/nuget/UltrafastSecp256k1.Native.nuspec")


def fail(msg: str) -> None:
    print(f"::error::check_abi_count: {msg}")


def main() -> int:
    if not HEADER.exists():
        print(f"check_abi_count: {HEADER} not found — run from repo root")
        return 1

    htxt = HEADER.read_text()
    names = re.findall(r"UFSECP_API[^;]*?\b(ufsecp_[A-Za-z0-9_]+)\s*\(", htxt)
    name_set = set(names)
    count = len(names)
    short_set = {n[len("ufsecp_"):] for n in name_set}
    print(f"check_abi_count: header declares {count} UFSECP_API functions")

    errors = 0

    # 1 + 3 + 4: ABI_VERSIONING.md
    if ABI_DOC.exists():
        dtxt = ABI_DOC.read_text()
        m = re.search(r"There are \*\*(\d+)\*\* such functions", dtxt)
        if not m:
            fail("docs/ABI_VERSIONING.md missing 'There are **N** such functions' header")
            errors += 1
        elif int(m.group(1)) != count:
            fail(f"ABI_VERSIONING.md §5 count {m.group(1)} != header count {count}")
            errors += 1

        # §5 region: between "### Stable ABI Surface" and "### Unstable"
        start = dtxt.find("### Stable ABI Surface")
        end = dtxt.find("### Unstable", start) if start >= 0 else -1
        if start >= 0 and end > start:
            region = dtxt[start:end]
            # backticked short names that look like function names
            for tok in set(re.findall(r"`([a-z][a-z0-9_]{2,})`", region)):
                if tok == "ufsecp_":          # the bare prefix mention, not a name
                    continue
                if tok in short_set:          # short name (table style: `ctx_create`)
                    continue
                if tok in name_set:           # fully-qualified `ufsecp_ctx_create`
                    continue
                if ("ufsecp_" + tok) in name_set:
                    continue
                fail(f"ABI_VERSIONING.md §5 lists `{tok}` which is NOT a real "
                     f"UFSECP_API function (fabricated/renamed name)")
                errors += 1

        # §8: any "NN-fn" coverage count must equal header count
        for m8 in re.finditer(r"(\d+)-fn\b", dtxt):
            if int(m8.group(1)) != count:
                fail(f"ABI_VERSIONING.md cites stale '{m8.group(1)}-fn' "
                     f"(header count is {count})")
                errors += 1
                break
    else:
        fail(f"{ABI_DOC} not found")
        errors += 1

    # 2: nuspec
    if NUSPEC.exists():
        ntxt = NUSPEC.read_text()
        m = re.search(r"(\d+)\s+stable C ABI functions", ntxt)
        if m and int(m.group(1)) != count:
            fail(f"nuspec says '{m.group(1)} stable C ABI functions' "
                 f"!= header count {count}")
            errors += 1

    if errors:
        print(f"check_abi_count: {errors} mismatch(es) — update docs/nuspec to "
              f"the real ABI count ({count}) and remove fabricated names.")
        return 1
    print("check_abi_count: OK — docs and nuspec match the header ABI surface.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
