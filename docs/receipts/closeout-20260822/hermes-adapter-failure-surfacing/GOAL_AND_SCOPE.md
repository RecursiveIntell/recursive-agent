# Goal and scope

## Goal

Surface daemon-derived terminal and transcript failure details through the Hermes-native adapter without changing execution authority.

## Non-goals

- no runner or contract/schema changes; daemon response-owner changes are allowed
- no protocol/schema widening
- no provider, deployment, installation, gateway, credential, or release effects
- no edits to unrelated dirty paths
- no promotion of real-provider, reliability, or production claims

## Allowed paths

- `integrations/hermes-native/client.py`
- `integrations/hermes-native/__init__.py`
- `integrations/hermes-native/tests/test_registration.py`
- `crates/recursive-agent-daemon/src/server.rs`
- `crates/recursive-agent-daemon/tests/ipc_runtime.rs`
- additive files under this run packet

## Forbidden paths

- `crates/recursive-agent-runner/src/runtime.rs`
- `integrations/hermes-native/schema.py`
- all credentials, deployment, gateway, and unrelated dirty paths

## Acceptance boundary

A transport error remains unavailable. A daemon-confirmed terminal non-success or strict-verification rejection is returned as a structured failure that preserves raw daemon-owned status/verification fields and uses `verified: false`; it is not reported as daemon unavailability.
