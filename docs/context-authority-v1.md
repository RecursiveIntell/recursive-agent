# Scoped external authority V1

`DurablePermitStore` owns context-scoped external admission in the existing
external output-root namespace. Initialization is an explicit operator action:

```
ra-daemon initialize-context-authority --root /absolute/native/output-root
```

It returns a native incarnation digest and permanently fences legacy admission
in that namespace. Initialization refuses any legacy consumed permit because V1
does not establish its conversation scope or independently confirmed settlement.
An ordinary restart preserves the incarnation. A copied state file in a different
directory is rejected; copying it is not an authority migration.

The operator supplies an owned, bounded, mode-0600
`ContextAuthorityConfigurationV1` file using `serve --context-authority-file`.
The configuration includes the incarnation, monotonic revision, exact production
approval-verifier digest, and grants binding each Ares store/profile/root to an
Ed25519 controller key, actor, policy version/digest, write root, initial head,
expiry and effect/transition caps. The production verifier enrollment and write
root remain separate startup inputs. The runtime rejects missing or mismatched
production verifier material. No IPC request enrolls a scope, approves a grant,
or replaces a key.

Controller authority permits only context binding and monotonic retirement or
activation. It does not approve effects. Every issuance still requires the
separate, unmodified Desktop Ed25519 V1 per-call witness. Native policy verifies
both authorities and reserves the original V1 approval identity globally for
one scoped permit. Rewrapping it after a rebase, key change or scope change does
not create another use. The scoped permit binds current approval-verifier
provenance; changing that verifier requires a new configuration revision and
fences older live daemon instances.

Retirement moves to a higher, sealed successor generation and returns an exact
immutable receipt. Activation requires that retirement receipt and the same
sealed head. A prepublication abort must retire again to a fresh higher parent
generation. Neither operation restores old tokens. A lost ACK is reconciled by
exact transition readback; a receipt is not a dispatch capability.

Consumption checks scope, incarnation, grant, policy, generation, mode, exact
call, current verifier and expiry under `.permit.lock`, sampling the trusted
clock after waiting and again before mutation. Legacy issue and consume APIs
also check the persistent fence. Already-consumed scoped effects retain their
original outcome path after retirement, revocation and restart. Immutable
reported outcomes do not claim independently confirmed external success.
Retirement/snapshot inventories retain every consumed obligation, including
ambiguous and reported-success outcomes, as exact bounded receipt references.

All scoped mutations replace one canonical, fsynced state file. Its ordered
configuration/transition history reconstructs the current grant, admission head,
retirement reference and active membership. On read, the owner checks signatures,
material IDs, counters and historical obligation references. This detects
inconsistent records; it does not isolate authority from an operator replacing
the entire store and its history. Limits are 32 MiB state, 256 scopes, 1,024
effects and 4,096 transitions per namespace; supersession preserves charges and
cannot widen a scope's caps, actor or write root.

The new scoped IPC variants never downgrade to V1. `context_call_prepare`,
`context_transition_prepare` and `context_store_identity` only return typed
canonical signing material or a nonce digest. They perform no enrollment or
admission. Ares must bind signing to its actual SessionDB owner and persist its
exact transition intent before native mutation, then require the native receipt
and consumed inventory before local readiness. These native primitives alone
do not qualify an installed Ares continuation route or an endurance run.
