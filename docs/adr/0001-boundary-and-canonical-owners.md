# ADR-0001 — Boundary and Canonical Owners

## Decision

`recursive-agent` depends on canonical Libraries crates for canonical
truth and creates new crates only for things not owned anywhere in
Libraries. The new crates coordinate, compose, and persist — they do not
reimplement canonical semantics.

## Owners

| Concern | Owner crate (path) | What we wrap or use |
|---|---|---|
| Canonical JSON / boundary | `boundary-compiler` 0.1.0 | direct dep |
| Material IDs | `stack-ids` 0.1.1 | direct dep |
| Bitemporal | `bitemporal-runtime` 0.1.0 | direct dep, in-memory view in M0 |
| Claim / evidence | `claim-ledger` 0.1.0 | direct dep, envelope only |
| Run orchestration | new | `recursive-agent-runner` |
| Receipt chain | new | `recursive-agent-ledger` |
| Tool plane | new | `recursive-agent-tools` |
| Policy | new | `recursive-agent-policy` |
| CLI | new | `recursive-agent-cli` |

## Forbidden

- Reimplementing RFC 8785 JCS, family-qualified IDs, or hash chains.
- Bypassing `boundary-compiler` at any typed boundary.
- Generating material IDs that are not family-qualified.
- Panics, `unwrap`, `expect`, or `todo!` in `lib.rs` paths.
- Provider calls of any kind in M0.

## Consequences

- Changes to canonical semantics happen in the owner crate, not here.
- This workspace can be reproduced by checking out the same path deps
  and rebuilding from scratch.
- `cargo clippy --workspace -- -D warnings` is the source of "no unsafe
  / no panic" claims; it is part of the M0 release gate.
