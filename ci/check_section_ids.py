#!/usr/bin/env python3
"""
check_section_ids.py
====================
Validates that every section ID used in ALL_MODULES[] entries in
audit/unified_audit_runner.cpp is declared in the SECTIONS[] array.

Exit codes:
  0  — all section IDs in ALL_MODULES are declared in SECTIONS
  1  — unregistered section IDs found (printed to stderr)
  77 — skip (unified_audit_runner.cpp not found)

Usage:
  python3 ci/check_section_ids.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER_CPP = ROOT / "audit" / "unified_audit_runner.cpp"


def parse_sections(text: str) -> set[str]:
    """Extract section IDs from the SECTIONS[] array.

    Each entry looks like:
        { "section_id", "title_ka...", "title_en..." },
    We capture the first quoted field of each entry inside the SECTIONS[] block.
    """
    # Find the SECTIONS[] block: from 'static const SectionInfo SECTIONS[] = {'
    # to the matching closing '};'
    sections_block_match = re.search(
        r"static\s+const\s+SectionInfo\s+SECTIONS\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;",
        text,
        re.DOTALL,
    )
    if not sections_block_match:
        return set()

    block = sections_block_match.group(1)
    # Each entry: { "id", ... } — capture first quoted field
    ids: set[str] = set()
    for m in re.finditer(r'\{\s*"([^"]+)"', block):
        ids.add(m.group(1))
    return ids


def parse_all_modules_sections(text: str) -> list[tuple[str, str]]:
    """Extract (module_id, section_id) pairs from ALL_MODULES[] entries.

    Each non-conditional entry looks like:
        { "module_id", "description...", "section_id", fn_ptr, advisory },
    We capture the first and third quoted fields of each entry.

    Preprocessor lines (#if, #ifdef, #else, #endif) are stripped before
    parsing so conditional entries are included.
    """
    # Find the ALL_MODULES[] block
    all_modules_match = re.search(
        r"static\s+const\s+AuditModule\s+ALL_MODULES\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;",
        text,
        re.DOTALL,
    )
    if not all_modules_match:
        return []

    block = all_modules_match.group(1)

    # Strip preprocessor directives so entries inside #if blocks are included
    block = re.sub(r"^\s*#[^\n]*$", "", block, flags=re.MULTILINE)

    pairs: list[tuple[str, str]] = []
    # Match aggregate-init entries: { "id", "desc...", "section", fn, bool }
    # We need 3 quoted strings: id, description, section.
    # The description can contain escaped chars, special chars.
    # Pattern: open-brace, first quoted string (id), comma, second quoted (desc),
    #          comma, third quoted (section).
    for m in re.finditer(
        r'\{\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*"([^"]+)"',
        block,
    ):
        module_id = m.group(1)
        section_id = m.group(3)
        pairs.append((module_id, section_id))

    return pairs


def main() -> int:
    if not RUNNER_CPP.exists():
        print(
            f"SKIP: {RUNNER_CPP} not found — cannot validate section IDs",
            file=sys.stderr,
        )
        return 77

    text = RUNNER_CPP.read_text(encoding="utf-8")

    declared_sections = parse_sections(text)
    if not declared_sections:
        print(
            "ERROR: SECTIONS[] array not found or empty in unified_audit_runner.cpp",
            file=sys.stderr,
        )
        return 1

    module_section_pairs = parse_all_modules_sections(text)
    if not module_section_pairs:
        print(
            "ERROR: ALL_MODULES[] array not found or empty in unified_audit_runner.cpp",
            file=sys.stderr,
        )
        return 1

    # Find any section IDs used in ALL_MODULES but not declared in SECTIONS
    undeclared: list[tuple[str, str]] = []
    seen_undeclared: set[str] = set()
    for module_id, section_id in module_section_pairs:
        if section_id not in declared_sections and section_id not in seen_undeclared:
            undeclared.append((module_id, section_id))
            seen_undeclared.add(section_id)

    if undeclared:
        print(
            f"check_section_ids: {len(undeclared)} unregistered section ID(s) found\n"
        )
        for module_id, section_id in undeclared:
            print(
                f"  UNREGISTERED SECTION [{section_id!r}]\n"
                f"    First used by module: {module_id!r}\n"
                f"    Fix: add an entry to SECTIONS[] in audit/unified_audit_runner.cpp"
            )
        print(
            f"\nDeclared sections: {sorted(declared_sections)}\n"
            f"Fix: add missing section IDs to the SECTIONS[] array."
        )
        return 1

    print(
        f"check_section_ids: OK — {len(declared_sections)} declared section(s), "
        f"{len(module_section_pairs)} ALL_MODULES entries validated"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
