# Operator status ladder

Operator output is a capability report, not an adapter assertion. Each field is
computed by the native runtime or is explicitly marked unavailable/degraded:

1. `native_verified` — the native run identity and receipt chain verify.
2. `vault_available` — the portable run pack is present and readable.
3. `claim_supported` / `claim_unknown` / `claim_degraded` — ClaimLedger support
   is reported only when its owner API/readback is available; adapters never
   promote this field.
4. `mnemes_observed` — Mnemes observation is present, without treating it as
   canonical execution truth.
5. `replay_verified` — recorded replay was verified from authoritative bytes.

Unavailable or tampered packs must render `degraded`, never `complete`. IPC
clients must select `embedded` or `ipc` explicitly; a failed IPC connection
must not silently execute embedded. Cancellation is a typed request and the
runtime response distinguishes `cancellation_requested` from
`already_terminal`.

A clean-host restore consists of copying only the verified Run Pack into a new
root, removing the source run, and running pack verification/replay there. The
result is valid only if verification succeeds without provider or network
access.
