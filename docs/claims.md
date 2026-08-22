# Recursive Agent Claim Fence

**Authority:** This file governs capability language for the current dirty
`recursive-agent` working tree. It is a documentation fence, not a release
receipt.

**Evidence cutoff:** 2026-08-22. Current observed command outcomes are recorded
in `docs/receipts/closeout-20260822/VALIDATION_MATRIX.csv` and
`docs/receipts/closeout-20260822/VERIFICATION_RECEIPT.json`.
Historical receipts and source inspection do not promote a current claim.

## Evidence states

- **observed pass** — an exact command was reported as passing against this
  working tree at the cutoff; it proves only that command's stated scope.
- **fixture-observed** — a local fixture exercised a named path; it does not
  prove a real provider, deployment, reliability, or user-facing integration.
- **blocked** — a named gate failed or a required tool/dependency was absent.
- **degraded** — a partial check exists but its required companion scope did not
  complete.
- **unverified** — code, a type, a prior receipt, or a description exists, but
  the required criterion has not been met.
- **not claimed** — outside the admitted evidence boundary.

## Rules

1. A claim is criterion-referenced: it must name the public boundary, exact
   evidence, and the scope it proves.
2. Passing workspace tests, Clippy, or formatting does not prove production
   readiness, reliability, safety certification, provider behavior, or
   integration behavior.
3. Fixture-backed native submission does not prove autonomous recursion, native
   child lineage, a real provider interaction, model quality, or unattended
   operation.
4. Recorded replay is not provider-deterministic replay and does not re-execute
   providers.
5. A blocked/degraded gate remains visible and cannot be summarized as a pass.
6. `production`, `reliable`, `autonomous`, `recursive`, `integrated`,
   `secure`, `durable`, and `verified` require the corresponding criterion;
   otherwise use the state below.

## Current claim ledger

| Claim ID | Capability | State | Admissible language | Evidence / blocker | Promotion criterion |
|---|---|---|---|---|---|
| RA-C001 | Workspace tests | observed pass, local command scope | `cargo test --workspace --all-targets --locked --no-fail-fast` passed at the cutoff | `docs/receipts/closeout-20260822/VALIDATION_MATRIX.csv` | Independent rerun from identified source plus required release gates |
| RA-C002 | Strict Clippy | observed pass, local command scope | `cargo clippy --workspace --all-targets --locked -- -D warnings` passed at the cutoff | current verification matrix | Independent rerun from identified source plus required release gates |
| RA-C003 | Formatting | observed pass, local command scope | `cargo fmt --all -- --check` passed at the cutoff | current verification matrix | Independent rerun from identified source plus required release gates |
| RA-C004 | Supply-chain policy | observed pass, local command scope | Cargo-deny advisories, bans, licenses, and sources checks passed | current verification matrix; exit 0 | Independent rerun from identified source plus required release gates |
| RA-C005 | Bounded ingress fuzzing | observed pass, bounded local scope | Receipt and sandbox-spec corpus runs completed without crash artifacts | current verification matrix; 1,281 and 1,448 executions | Longer, policy-defined fuzz campaign if required by release criteria |
| RA-C006 | Model fixture → native submit | fixture-observed | A local model fixture reached native submit | `runtime_service_model_loop_executes_fixture_plan_through_native_submit` recorded in the autonomous packet | Public CLI path plus positive/negative real-provider evidence under an authorized endpoint |
| RA-C007 | Provider-facing autonomous loop | unverified | Experimental bounded local CLI surface only | No live provider call or provider-response evidence in the current packet | Authorized real-provider acceptance and failure cases, retained artifacts, independent rerun |
| RA-C008 | Autonomous recursion / native child lineage | unverified | No autonomy-recursion or child-lineage claim | Specialist consensus records these as unverified | Explicit lineage/attenuation/cancellation/restart acceptance evidence through public entry points |
| RA-C009 | Reliability / unattended operation | unverified | No reliability, availability, or unattended-agent claim | Local checks and a fixture do not measure reliability | Defined reliability criteria, fault matrix, and independent recorded execution |
| RA-C010 | Hermes / external integration | unverified | No real plugin-loader or external integration claim | Real installed plugin-loader admission remains unverified | Isolated installed-host admission and smoke receipt |
| RA-C011 | Three-owner conformance | observed pass, disposable offline scope | Generated Recursive Agent bytes were accepted by ClaimLedger and Mnemes with idempotency/tamper checks | `docs/receipts/closeout-20260822/phase5-generated/phase5-conformance.json` | Independent rerun plus any production-owner acceptance criteria |
| RA-C012 | Recorded offline replay / pack | scope-limited, unverified for current change | Recorded artifacts may be replayed without re-calling a provider; no provider determinism claim | Historical baseline design is not current proof for the dirty autonomous change | Current public-boundary pack/replay/tamper evidence with receipt and independent rerun |
| RA-C013 | Production / release readiness | blocked | In-development dirty workspace; not production-ready | real provider/public CLI, installed-host integration, reliability, and release authority remain unverified | All required acceptance gates and explicit release authority |

## Mandatory wording

> `recursive-agent` is an in-development local execution-kernel workspace.
> At the 2026-08-22 cutoff, workspace tests, strict Clippy, formatting,
> cargo-deny, bounded ingress fuzzing, PackVault recovery, MCTS selection,
> child-lineage regression, and disposable generated three-owner offline
> conformance were observed to pass locally. A model-fixture-to-native-submit
> path was observed, but real provider operation, public CLI acceptance,
> installed-host integration, reliability, and production readiness remain
> unverified or blocked.

Do not use “production-ready,” “reliable,” “provider-backed autonomous loop,”
“recursive autonomous system,” “Hermes integrated,” “secure sandbox,” or
“deterministic provider replay” for this tree.
