# Run Pack discovery / owner matrix

## Finding

The existing ledger `ChainMeta`, receipt descriptors, and verification snapshots are
**authoritative run evidence**, not an export projection. They describe chain state and
artifact references but do not bind a portable directory's complete safe-relative file
set, generated result files, or manifest schema. Reusing them would either omit files
or make the ledger metadata ambiguous. `RunPackManifestV1` is therefore additive and
immutable: it binds bytes already admitted by the ledger without reimplementing chain
semantics.

| Candidate | Existing responsibility | Why not owner of pack manifest | Decision |
|---|---|---|---|
| `ChainMeta` / `ChainVerification` | receipt-chain state and verification | no filesystem inventory or export boundary | ledger remains verifier |
| `ArtifactDescriptorV1` | one referenced artifact's identity/size/type | cannot describe receipts, metadata, provenance, or generated files | retain as nested evidence |
| runner lifecycle types | run execution and terminal transitions | export must be read-only and cannot own chain truth | no runner changes |
| CLI | argument/result translation | must not own canonical semantics | no CLI changes |
| contracts | typed boundary/JCS schemas | correct owner for portable wire contract | add `RunPack*V1` |
| ledger | canonical evidence admission and filesystem safety | correct owner for plan/export/pack-only verification | implementation target for Tasks 3–5 |

## Locked invariants

The ledger must verify the source run before planning/export, copy exact bytes through a
same-parent temporary directory, validate every manifest entry and actual filesystem
entry (regular files only; no symlinks, traversal, duplicates, extras, or missing
paths), then atomically rename. Pack verification must use only pack bytes and delegate
receipt/artifact semantics to existing ledger verification; it must never fall back to
the source run.
