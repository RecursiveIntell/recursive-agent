# Phase 5 status — offline owner-conformance harness

## Verified local result

`python3 scripts/phase5_offline_conformance.py --root .hermes/runs/witnessed-workbench-phase5-20260810` exited 0 on **2026-08-10T05:15:27Z** and emitted `phase5-conformance.json` with digest:

`906e3f5c7b217929159d76f8b3a99f1a4d8d461872f9e4c93cdabfd1c9e17a30`

The five matrix rows passed:

1. Recursive Agent, ClaimLedger, and Mnemes fixture copies have the same SHA-256: `fb91e2bdee8f14162b3cf09992070fd07697d29d0742d2e1175ab374303e49f5`.
2. Recursive Agent creates a deterministic run, exports a pack, deletes the client run, and recorded-replays the copied pack offline.
3. Recursive Agent vault admission/verification rejects tampering and has a quarantine path.
4. ClaimLedger requires a server admission witness, is idempotent for exact retry, and rejects forged/tampered projection inputs before durable write.
5. Mnemes requires authenticated, HMAC-attested observation import and covers idempotence plus rejection through both library and temporary HTTP-server surfaces.

## Claimed boundary

This is **owner conformance**, not a clean-host deployment proof. The script deliberately does not claim a live Hermes session, shared production storage, a single cross-process transaction, a final run-pack retrieval document, service deployment, network egress prohibition for every non-Rust dependency, or disaster recovery from real server snapshots.

## Remaining Phase 5 roadmap delta — P0 blockers

The canonical roadmap's full Phase 5 gate is **not admitted**. A subsequent read-only feasibility audit established these concrete blockers:

1. **PackVault crash window — P0.** `crates/recursive-agent-ledger/src/lib.rs` renames the staged object to its final path before appending `admissions.ndjson`. A crash in that interval leaves an object without an admission receipt; duplicate detection only consults the receipt file. The required interruption/retry gate is therefore unproven.
2. **ClaimLedger crash window — P0.** `claim_ledger/importers/run_pack.py` writes the bundle and preliminary receipt before append, then rewrites the receipt with its `ledger_append_receipt_ref` after the durable append. A crash in that post-append rewrite window leaves a ledger event whose retained receipt does not contain the stated durable ledger reference. No recovery test defines whether that state is valid or repairs it.
3. **No genuine three-owner integration fixture — P0 for the roadmap claim.** The committed script intentionally drives owner-local gates over one frozen fixture. It does not carry a newly generated `VaultAdmission::build_evidence_projection` result through ClaimLedger and Mnemes, nor restore the full server-side state.

After the two crash protocols are made recoverable and separately fault-injected, the full gate still needs final retrieval projection coverage, copy/verify/import/index fault injection, and a restore drill using only a vault plus ClaimLedger/Mnemes snapshots.

## Rollback

Remove `scripts/phase5_offline_conformance.py` and this receipt directory; the generated `.hermes/runs/witnessed-workbench-phase5-20260810/` packet is disposable. No host state, credentials, service configuration, or remote state was changed.
