# Phase 6 — deployment admission packet (not authorized)

**Status:** `blocked/unknown` — documentation-only preparation. No host, network listener, service identity, credential, firewall, Tailscale, systemd, database migration, or data-root change was performed.

## Required authority before execution

The operator must explicitly name and approve:

1. target host and accountable owner;
2. vault, ClaimLedger, and Mnemes data roots plus encryption and retention policy;
3. backup destination and an offline restore target;
4. separate least-privilege service identities and secret delivery mechanism;
5. allowed listener bindings and any tailnet/public exposure;
6. rollback owner and data-retention/quarantine decision.

## Admission evidence required

- target disk capacity and encrypted-at-rest posture;
- documented threat model and recovery objective;
- service-unit and filesystem-permission review;
- no credentials in logs, fixtures, receipts, run packs, or source;
- clean-host drill: create deterministic pack, admit it, delete client root, restore vault plus both database/index snapshots into a fresh root, then verify and recorded-replay offline;
- integrity, capacity, retention, health, and backup-restore checks with receipts.

## Stop conditions

Stop rather than deploy if the design requires a public listener, remote executor, shared credential, automatic updater, ambient production configuration, or a mutable shared development store without separate approval.

## Proposed rollback after authorized deployment

Stop the three services, revoke the scoped credentials, preserve encrypted snapshots and vault objects according to the approved retention policy, and render affected projections `pack_unavailable` or `quarantined` rather than deleting provenance.
