# Phase 1 Hardening v5 Agent Graph Advisory

- Run: `run-19fd15873e4-4`
- Graph: `recursive-agent-phase1-hardening-v5-council`
- Version: `sha256:bef9c4c8f451d5aa766b3f1916ca4156eee2a5a60520f17911b4b81f4396674e`
- Observed execution: success=true; llm_calls=5; nodes=7; wall_clock_ms=35487
- Evidence class: model-generated advisory; not source verification
- Degradation: final synthesis was token-truncated mid residual-risk table; do not treat it as complete

# IMPLEMENTATION ADMISSION MEMO — PHASE 1

**Date:** [Current Date]
**Subject:** Synthesis of Hostile Reviews — Mandatory Requirements for Phase 1 Admission
**Status:** Pre-Admission — No source verification claimed

---

## CRITICAL DESIGN REQUIREMENTS

The following invariants are **non-negotiable** and must be satisfied prior to Phase 1 admission:

### R1: Permit Hierarchy Integrity
- **I1**: `child_permit.deadline <= parent_permit.deadline` — transitive, monotonic
- **I2**: `child_permit.budget_remaining <= parent_permit.budget_remaining` at all times
- **I3**: `child_permit.attenuation ⊆ parent_permit.attenuation` — no privilege addition
- **I6**: `permit_generation(parent) < permit_generation(child)` — child always newer
- **I7**: No child can extend, renew, or refresh its own permit without fresh parent signature

### R2: Budget Accounting
- **I5**: `budget_consumed + budget_committed <= budget_allocated` — no overcommit
- Budget state must use atomic operations (CAS or DB transactions)
- Append-only budget ledger for audit and idempotency

### R3: Revocation Semantics
- **I4**: Parent revocation ⇒ all descendants revoked (cascade, atomic, synchronous)
- Offline verification must check generation/epoch counters
- No async propagation windows

### R4: Execution Byte Binding
- Permits must bind `(fd, digest, path)` triple
- Execution via `execveat(fd, "", AT_EMPTY_PATH)` — NOT `execve(path)`
- Same fd used for hashing and execution

### R5: Ingress Constraints
- Regular files only (`S_IFREG`), reject symlinks/FIFOs/sockets/devices
- `O_NOFOLLOW` + `O_CLOEXEC` on every open
- Size cap: ≤ 1 MiB (default 256 KiB)
- Closed schemas: whitelist-only, type-strict, no YAML anchors/aliases/tags

### R6: Monotonic Clock
- **I8**: All deadline checks use monotonic time, never wall-clock

---

## MUST-NOT SHORTCUTS

The following are explicitly **forbidden** in Phase 1:

| # | Prohibited Shortcut | Rationale | Mandated Alternative |
|---|---|---|---|
| 1 | Using `time.Now()` for deadline checks | Clock skew allows extension | `time.monotonic()` |
| 2 | Copy-on-write permits without deep clone | Shared mutable deadline field | Immutable permits; new object on attenuation |
| 3 | Budget as plain `int64` without CAS | Race condition double-spend | Atomic compare-and-swap or DB transaction |
| 4 | Async revocation via event bus | Window of unauthorized execution | Synchronous revocation check at validation |
| 5 | Lazy parent state reads | Stale revocation not seen | Always validate against current parent state |
| 6 | Grandchild permits referencing child budget without parent tracking | Budget escape | Parent tracks transitive closure or child reports grandchild usage |
| 7 | Serialization omitting `deny_list`/attenuation metadata | Attenuation lost on IPC | Canonical serialization with field-preservation test |
| 8 | Key rotation without generation counter | Old key still validates | Embed `key_generation` in permit; reject if < current |
| 9 | O_PATH/inode-only verification | Doesn't bind executed bytes | `(fd, digest, path)` triple + `execveat(fd)` |
| 10 | Pre-spawn hash without fd binding | TOCTOU window | Same fd for hash and execveat |
| 11 | Runtime feature flags for MCP/daemon | Code present in binary | Compile-time `#[cfg]` gates only |
| 12 | Path-based duplicate detection | Misses content duplicates | Content-addressable registry (SHA-256) |
| 13 | `execve(path)` after hashing | File can be swapped | `execveat(fd, "", AT_EMPTY_PATH)` |
| 14 | Accepting any file type at ingress | Symlink/FIFO attacks | `lstat()` + `O_NOFOLLOW` + `fstat()` match |

---

## ACCEPTANCE TEST MATRIX

### A. Permit Hierarchy Tests

| Test ID | Description | Expected Result | Priority |
|---------|-------------|----------------|----------|
| T1 | Deadline extension attack (direct modification, clock manipulation) | REJECT — immutable permit, monotonic check | **BLOCKER** |
| T2 | Budget overcommit via 50 concurrent threads (100 units, 10 each) | Exactly 10 succeed, 40 fail; no negative balance | **BLOCKER** |
| T3 | Attenuation bypass (delegate beyond scope, strip deny_list) | REJECT — subset check + canonical serialization | **BLOCKER** |
| T4 | Revocation cascade (3 levels, synchronous) | ALL REJECTED immediately; offline also rejected | **BLOCKER** |
| T5 | Grandchild budget escape (10 grandchildren × 50, parent=100) | REJECT — overcommit detection | **BLOCKER** |
| T6 | Key rotation forgery (old generation, forged new) | REJECT — generation check + signature fail | **BLOCKER** |
| T7 | Crash consistency (kill between check and consume) | Either rolled-back or atomic-consume; never double-spend | **BLOCKER** |
| T8 | Offline verification epoch mismatch | REJECT — epoch/generation counter check | **BLOCKER** |

### B. Execution Byte-Binding Tests

| Test ID | Description | Expected Result | Priority |
|---------|-------------|----------------|----------|
| E1 | Content mutation post-hash | Permit REJECTED (digest mismatch) | **BLOCKER** |
| E2 | Rename-replace TOCTOU | Permit REJECTED (inode changed) | **BLOCKER** |
| E3 | Hard-link attack into trusted dir | Trust rule REJECTS | **BLOCKER** |
| E4 | Same-inode different-path modification | Permit REJECTED (digest mismatch) | **BLOCKER** |
| E5 | Executed bytes = hashed bytes (fd binding) | Hashes differ → execveat uses NEW bytes, permit invalid | **BLOCKER** |

### C. Ingress Tests

| Test ID | Description | Expected Result | Priority |
|---------|-------------|----------------|----------|
| I1 | Symlink rejection | Exit non-zero, no read | **BLOCKER** |
| I2 | FIFO rejection (blocking hazard) | Timeout/exit non-zero | **BLOCKER** |
| I3 | Size cap (2 MiB file) | Reject "size exceeded" | **BLOCKER** |
| I4 | Duplicate content (same hash, different path) | Reject second as duplicate | **BLOCKER** |
| I5 | Recursive include cycle | Detect cycle, exit non-zero | **BLOCKER** |
| I6 | Unknown field in YAML | Hard rejection | **BLOCKER** |
| I7 | Wrong type (string vs array) | Type error rejection | **BLOCKER** |
| I8 | Array length exceeded (1000 elements) | Reject | **BLOCKER** |
| I9 | Concurrent ingest bomb (20 processes) | ≤4 succeed, rest rejected | **BLOCKER** |
| I10 | Path traversal (`../../etc/passwd`) | Reject | **BLOCKER** |
| I11 | Hard-link to sensitive file | Reject (st_nlink > 1) | **BLOCKER** |
| I12 | Procfs/fd injection | Reject non-regular mount | **BLOCKER** |
| I13 | YAML bomb (aliases) | Immediate reject | **BLOCKER** |
| I14 | UTF-16/BOM smuggling | Reject non-UTF-8 | **BLOCKER** |
| I15 | NUL bytes in strings | Reject | **BLOCKER** |
| I16 | Deep nesting (1000 levels) | Reject at depth limit | **BLOCKER** |

### D. Build/Compile-Time Tests

| Test ID | Description | Expected Result | Priority |
|---------|-------------|----------------|----------|
| B1 | Default build — `nm` grep for "mcp" | MUST output nothing | **BLOCKER** |
| B2 | Default build — `nm` grep for "daemon" | MUST output nothing | **BLOCKER** |
| B3 | Feature build with adapters | MUST succeed, symbols present | Required |
| B4 | `--mcp-bind` flag in default build | MUST fail "feature not compiled" | **BLOCKER** |
| B5 | `--daemon-mode` flag in default build | MUST fail "feature not compiled" | **BLOCKER** |
| B6 | No listening sockets from default build | `ss -tlnp` shows nothing | **BLOCKER** |

---

## RESIDUAL THREAT ASSUMPTIONS

The following are **explicitly accepted** as residual risk for Phase 1:

| # | Assumption | Risk if Violated | Mitigation |
|---|-----------|------------------|------------|
|