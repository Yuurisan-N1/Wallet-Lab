# AI Tooling Guide — Source Graph + Knowledge Base

> **This guide is for AI agents, Claude Code instances, and subagents working in
> this repository. Read before touching any code.**

This repository has two complementary AI tools:
- **source_graph** — WHERE is the code? (location, callers, body, cross-references)
- **knowledge_base** — WHY is it written this way? (decisions, constraints, findings)

Neither alone is sufficient. Together they give complete context in seconds.

---

## 1. Session Bootstrap (always do this first)

```bash
# Step 1: What knowledge already exists?
python3 tools/knowledge_base/knowledge_base.py stats

# Step 2: Query for the area you're about to touch
python3 tools/knowledge_base/knowledge_base.py for "schnorr_sign"   # ← replace with your symbol

# Step 3: Restore session state (if non-trivial task)
python3 tools/session_state/session_state.py restore --format text

# Step 4: Find the code
python3 tools/source_graph_kit/source_graph.py func "schnorr_sign"
python3 tools/source_graph_kit/source_graph.py body "schnorr_sign"
```

---

## 2. Source Graph — Reference

```bash
# Find function by name (location + signature)
python3 tools/source_graph_kit/source_graph.py func "FUNCTION_NAME"

# Read function body
python3 tools/source_graph_kit/source_graph.py body "FUNCTION_NAME"

# Find all callers / usages of a symbol
python3 tools/source_graph_kit/source_graph.py api "SYMBOL_NAME"

# Search for a string/pattern inside function bodies
python3 tools/source_graph_kit/source_graph.py bodygrep "secure_erase"

# Find a file by partial name
python3 tools/source_graph_kit/source_graph.py file "bench_unified"

# Full file context (all symbols)
python3 tools/source_graph_kit/source_graph.py context src/cpu/src/schnorr.cpp

# Full-text search across all indexed code
python3 tools/source_graph_kit/source_graph.py find "ct::scalar_add"

# Rebuild graph (after adding new files or if results seem missing)
python3 tools/source_graph_kit/source_graph.py build -i
```

**RULE: grep / rg / find are BANNED. Use source_graph_kit ONLY.**
Direct `Read` on a known path is the only permitted fallback.

---

## 3. Knowledge Base — Reference

```bash
# All entries linked to a source symbol
python3 tools/knowledge_base/knowledge_base.py for "schnorr_sign"

# Query by category (constraint / decision / finding / insight / tradeoff)
python3 tools/knowledge_base/knowledge_base.py query --category constraint
python3 tools/knowledge_base/knowledge_base.py query --category constraint --tag CT
python3 tools/knowledge_base/knowledge_base.py query --symbol "musig2_partial_sig_agg"

# Full-text search
python3 tools/knowledge_base/knowledge_base.py search "constant-time nonce"

# Read a specific entry
python3 tools/knowledge_base/knowledge_base.py recall "CT-VERIFY"

# Store a new entry (MANDATORY after security fixes and architectural decisions)
python3 tools/knowledge_base/knowledge_base.py store MY-ID category "title" "body" \
  --symbol "function_name,other_symbol" \
  --file "path/to/file.cpp" \
  --tag "CT,security,P1" \
  --severity P1 --status fixed

# List all entries
python3 tools/knowledge_base/knowledge_base.py list --limit 50

# Stats
python3 tools/knowledge_base/knowledge_base.py stats
```

### Categories
| Category | Use for |
|----------|---------|
| `constraint` | ABSOLUTE rules (CT paths, signing, workflow) |
| `decision` | Architectural choices with rationale |
| `finding` | Security bugs with severity and status |
| `insight` | Non-obvious facts a reviewer would miss |
| `tradeoff` | Known cost/benefit design decisions |
| `regression` | Fixed bugs — what broke and why |

### When to write (MANDATORY)
- **Security fix** → `finding` with `--severity P1 --status fixed`
- **CT boundary choice** → `decision` linked to affected symbol
- **"Why VT here?"** → `decision` referencing CT-VERIFY constraint
- **Performance tradeoff** → `tradeoff` with expected impact
- **Non-obvious invariant** → `insight` so next agent doesn't break it
- **Protocol rule** → `constraint` if it must never be violated

---

## 4. The Combined Workflow

### "Why is this code written this way?"

```bash
SYMBOL="rfc6979_nonce_hedged"

# Step 1: knowledge_base — WHY
python3 tools/knowledge_base/knowledge_base.py for "$SYMBOL"
# → RFC6979-FIXED: both variants use fixed 2-iter + ct::scalar_select
# → CT-001: hedged variant was fixed 2026-05-21 (had VT early-exit loop)

# Step 2: source_graph — WHERE and WHAT
python3 tools/source_graph_kit/source_graph.py body "$SYMBOL"
# → shows the actual 2-iter implementation

# Step 3: callers — WHO depends on it?
python3 tools/source_graph_kit/source_graph.py api "$SYMBOL"
# → ct::ecdsa_sign_hedged, secp256k1_ecdsa_sign (when ndata!=NULL)
```

### "Should I use CT here?"

```bash
# Check the constraint
python3 tools/knowledge_base/knowledge_base.py recall "CT-VERIFY"
# → Verify paths MUST use variable-time. CT on verify is a performance BUG.

python3 tools/knowledge_base/knowledge_base.py recall "CT-VERIFY-METADATA"
# → Source graph ct_sensitive=1 on verify functions is WRONG metadata. Ignore it.

# Decision tree:
# Is any input secret (private key, nonce, share)? → MUST be ct::
# Is this a verify path (ecdsa_verify, schnorr_verify)?  → MUST be VT
# Is the tweak public (Taproot TapTweak)? → VT is CORRECT
```

### "I'm about to touch file X"

```bash
FILE="src/cpu/src/musig2.cpp"

# What's in this file?
python3 tools/source_graph_kit/source_graph.py context "$FILE"

# What knowledge exists for its symbols?
python3 tools/knowledge_base/knowledge_base.py search "musig2"
python3 tools/knowledge_base/knowledge_base.py for "musig2_partial_sig_agg"
# → MUSIG2-AGG-CT: ct::scalar_add required (not operator+=)
# → MUSIG2-SIGNER-IDX: partial_sign validates sk↔signer_index via CT pubkey derivation
```

### "I made a security fix"

```bash
# 1. Write the test (MANDATORY — same commit as fix)
# 2. Wire it to unified_audit_runner + CMakeLists + stubs
# 3. Run gates
python3 ci/check_exploit_wiring.py   # must PASS
python3 ci/sync_module_count.py      # if ALL_MODULES changed
./ci/ci_local.sh                     # all fast gates

# 4. Record in knowledge_base
python3 tools/knowledge_base/knowledge_base.py store MY-SEC-001 finding \
  "function: what was wrong" \
  "detailed explanation of the vulnerability, how it was fixed, why the fix is correct" \
  --symbol "affected_function" \
  --file "path/to/affected/file.cpp" \
  --tag "security,CT,P1" \
  --severity P1 --status fixed

# 5. Update AUDIT_CHANGELOG.md
# 6. Commit + push immediately
git push --no-verify origin dev
```

---

## 5. Critical Constants (secp256k1)

| Constant | Value |
|----------|-------|
| Field prime p | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F` |
| Group order n | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` |
| p mod 4 | `3` (→ sqrt: `x^((p+1)/4) mod p`) |
| Valid private key range | `[1, n-1]` (parse_bytes_strict_nonzero enforces this) |
| Generator G_x | `79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798` |

---

## 6. Key Architectural Decisions (summary — full details in knowledge_base)

| Area | Rule | Knowledge Base Entry |
|------|------|---------------------|
| CT vs VT | Signing/ECDH/BIP32 privkey → CT. Verify → VT (correct). | `CT-VERIFY`, `RFC6979-FIXED` |
| Nonce generation | Fixed 2-iter + `ct::scalar_select`. No early exit. | `RFC6979-FIXED`, `CT-001` |
| Schnorr secret cleanup | Erase: d_bytes, t_hash, t, k_prime, k, **e_hash**, **e** | `SCHNORR-CLEANUP` |
| Blinding nonce | `ct::generator_mul_blinded` for R=k\*G in ALL sign paths | `GENERATOR-MUL-CT` |
| Shim pubkey validation | `pubkey_data_to_point` validates y²=x³+7 | `PUBKEY-CURVE-CHECK` |
| Tweak=0 | Valid (libsecp allows it). Use `parse_bytes_strict`, NOT `parse_bytes_strict_nonzero` | `TWEAK-ZERO-ALLOWED` |
| Batch fail-closed | Zero all outputs before processing; NULL aux_rands → error | `BATCH-SIGN-FAILCLOSED` |
| Canonical benchmark | Must have `generated_by: "bench_unified --json"` | `BENCH-CANONICAL` |
| Module count sync | Run `ci/sync_module_count.py` after every ALL_MODULES change | `SYNC-MODULE-COUNT` |
| Exploit test wiring | 7-step checklist per CLAUDE.md; enforced by check_exploit_wiring.py | `EXPLOIT-WIRING` |

---

## 7. Full Audit Flow for New Security Findings

When you find or fix a security issue:

```
1. Read the function body:
   source_graph.py body "affected_function"

2. Check existing knowledge:
   knowledge_base.py for "affected_function"
   knowledge_base.py search "vulnerability type"

3. Implement the fix in the source file

4. Write the test (same commit):
   - audit/test_exploit_NAME.cpp or test_regression_NAME.cpp
   - int test_NAME_run() entry point
   - #ifdef STANDALONE_TEST int main() { return test_NAME_run(); }

5. Wire the test:
   - Forward declaration in unified_audit_runner.cpp
   - ALL_MODULES entry (section=exploit_poc or ct_analysis etc., advisory=false)
   - target_sources(unified_audit_runner PRIVATE test_NAME.cpp) in CMakeLists.txt
   - Stub in shim_run_stubs_unified.cpp or feature_run_stubs_unified.cpp if needed

6. Update docs:
   - docs/AUDIT_CHANGELOG.md (one-liner entry)
   - docs/EXPLOIT_TEST_CATALOG.md (for exploit_poc tests)

7. Sync counts:
   python3 ci/sync_module_count.py

8. Run gates:
   python3 ci/check_exploit_wiring.py  → must PASS
   ./ci/ci_local.sh                    → must PASS

9. Record in knowledge_base:
   knowledge_base.py store ID finding "title" "explanation" \
     --symbol "func" --severity P1 --status fixed

10. Commit + push to dev
```

---

## 8. Common Mistakes to Avoid

| Mistake | Correct |
|---------|---------|
| `grep -r "pattern" .` | `source_graph.py bodygrep "pattern"` |
| Using `ct::` on `ecdsa_verify` | `ecdsa_verify` is VT by design — CT here is a BUG |
| `Scalar::from_bytes` on private key | `Scalar::parse_bytes_strict_nonzero` (rejects >=n AND 0) |
| `is_zero()` on tweaked private key | `is_zero_ct()` — no data-dependent branch |
| `s += si` in signature aggregation | `s = ct::scalar_add(s, si)` — operator+= is VT |
| `Scalar::from_bytes` on blinding seed | `parse_bytes_strict_nonzero` — avoids VT mod-n |
| Hand-crafted bench JSON | Run `bench_unified --json out.json` — `generated_by` field required |
| Committing without a test | Every `src/cpu/src/` change needs a test in the same commit |
| Creating a feature branch | All work on `dev` directly — no feature branches |

---

*DB path: `tools/knowledge_base/knowledge_base.db` (local-only, gitignored)*
*Source graph: `tools/source_graph_kit/source_graph.db`*
*Last updated: 2026-05-21*
