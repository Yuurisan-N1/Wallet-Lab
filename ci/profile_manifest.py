#!/usr/bin/env python3
"""Loader + validator for ci/profiles.json (single-source-of-truth deployment profiles).

Other CI scripts should import `load()` to get the parsed manifest plus a
guaranteed-consistent cross-reference set against CMakePresets.json and
ci/caas_runner.py. Running the module as a script invokes the validator
and exits non-zero on any inconsistency — wire it into ci_local.sh and the
preflight workflow so manifest drift fails closed.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

LIB_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = LIB_ROOT / "ci" / "profiles.json"
CMAKE_PRESETS_PATH = LIB_ROOT / "CMakePresets.json"
CAAS_RUNNER_PATH = LIB_ROOT / "ci" / "caas_runner.py"


def load() -> dict[str, Any]:
    """Parse ci/profiles.json and return the profiles section."""
    with MANIFEST_PATH.open() as fh:
        data = json.load(fh)
    return data["profiles"]


def _cmake_preset_names() -> set[str]:
    with CMAKE_PRESETS_PATH.open() as fh:
        data = json.load(fh)
    return {p["name"] for p in data.get("configurePresets", [])}


def _caas_profile_names() -> set[str]:
    """Best-effort regex parse of ci/caas_runner.py PROFILES top-level keys.

    The runner imports cleanly only when its full dependency graph is
    available — we keep this script self-contained by reading the source
    file textually, which is fine for a name-set check.
    """
    src = CAAS_RUNNER_PATH.read_text()
    # PROFILES: dict[str, dict] = {  "default": {  "bitcoin-core-backend": {  ...
    start = src.find("PROFILES: dict[str, dict] = {")
    if start < 0:
        return set()
    # Find first matching brace pair after the dict declaration.
    open_idx = src.find("{", start)
    depth, i = 0, open_idx
    while i < len(src):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    block = src[open_idx + 1 : i]
    # Top-level keys are the dict keys at depth-0 inside `block`.
    names, depth = set(), 0
    for match in re.finditer(r'(?:^|\n)([ \t]*)"([\w-]+)"\s*:', block):
        # Use indentation: top-level keys have exactly 4 spaces (matches the file style).
        if len(match.group(1)) == 4:
            names.add(match.group(2))
    return names


def validate(*, verbose: bool = True) -> int:
    """Cross-check the manifest against CMakePresets.json and caas_runner.py.

    Returns 0 on success, 1 on the first failure (verbose output makes the
    failure self-diagnostic — no need to re-run with more flags).
    """
    profiles = load()
    cmake_names = _cmake_preset_names()
    caas_names = _caas_profile_names()
    errors: list[str] = []

    for key, prof in profiles.items():
        preset = prof.get("cmake_preset")
        if not preset:
            errors.append(f"{key}: missing cmake_preset field")
        elif preset not in cmake_names:
            errors.append(
                f"{key}: cmake_preset='{preset}' not found in CMakePresets.json "
                f"(known: {sorted(cmake_names)[:6]}...)"
            )

        caas = prof.get("caas_profile")
        if caas and caas not in caas_names:
            errors.append(
                f"{key}: caas_profile='{caas}' not found in ci/caas_runner.py PROFILES "
                f"(known: {sorted(caas_names)})"
            )

        enabled = set(prof.get("enabled_modules", []))
        disabled = set(prof.get("disabled_modules", []))
        overlap = enabled & disabled
        if overlap:
            errors.append(
                f"{key}: enabled_modules and disabled_modules overlap: {sorted(overlap)}"
            )

    if errors:
        for err in errors:
            print(f"FAIL  {err}")
        print(f"\nci/profiles.json: {len(errors)} inconsistency/inconsistencies found.")
        return 1

    if verbose:
        print(f"PASS  ci/profiles.json: {len(profiles)} profiles cross-checked")
        print(f"      cmake_preset    -> all resolve in CMakePresets.json")
        print(f"      caas_profile    -> all resolve in ci/caas_runner.py PROFILES")
        print(f"      enabled/disabled -> no overlapping module names")
    return 0


def main(argv: list[str]) -> int:
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--quiet", action="store_true", help="suppress success summary")
    args = p.parse_args(argv)
    return validate(verbose=not args.quiet)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
