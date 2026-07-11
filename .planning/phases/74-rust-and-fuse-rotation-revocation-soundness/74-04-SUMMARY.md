---
phase: 74-rust-and-fuse-rotation-revocation-soundness
plan: 04
subsystem: api
tags: [rust, api-client, reqwest, shares, rotation, sc2]

# Dependency graph
requires:
  - phase: 74-rust-and-fuse-rotation-revocation-soundness
    provides: FuseRotationDeps trait + re_mint_grants_rooted_at engine wiring (74-01/70.1-09) that will call these wire functions
provides:
  - "ApiClient::authenticated_patch<T: Serialize>(&self, path, body) -> Result<Response, ApiError>"
  - "ApiClient::authenticated_delete(&self, path) -> Result<Response, ApiError>"
  - "shares::update_grant(client, share_id, encrypted_read_key, root_generation) -> Result<(), ApiError>"
  - "shares::revoke_share(client, share_id) -> Result<(), ApiError>"
affects: [74-05, fuse-rotation-deps, api-client]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Raw-TCP one-shot capturing mock HTTP server for api-client wire-function tests (no wiremock/mockito dependency), mirroring crates/fuse/src/write_ops/implementation/delete.rs's spawn_mock_rotation_server pattern"

key-files:
  created: []
  modified:
    - crates/api-client/src/client.rs
    - crates/api-client/src/shares.rs

key-decisions:
  - "No mock-HTTP crate exists in cipherbox-api-client's dev-dependencies; added a minimal raw std::net::TcpListener capturing mock server inside shares.rs's #[cfg(test)] module (mirrors the same pattern already used in crates/fuse's delete.rs tests) rather than pulling in wiremock/mockito"
  - "root_generation accepted as u64 (not the DTO's raw string) and formatted to a decimal string at the wire boundary, matching UpdateGrantDto's @IsNumberString/BIGINT_MAX server-side contract"
  - "update_grant/revoke_share do zero key-material handling — encrypted_read_key arrives as already-ECIES-wrapped hex from the caller (engine.rs re_mint_grants_rooted_at); these functions only forward it"

patterns-established:
  - "Wire-function pairs in shares.rs mirror revoke_shares_for_items's POST-then-status-check shape verbatim for PATCH/DELETE variants"

requirements-completed: [SC2]

coverage:
  - id: D1
    description: "ApiClient gains authenticated_patch and authenticated_delete verb helpers mirroring authenticated_post's auth-header + reqwest builder shape"
    verification:
      - kind: unit
        ref: "crates/api-client/src/shares.rs#update_grant_patches_grant_path_with_read_key_only_body"
        status: pass
      - kind: unit
        ref: "crates/api-client/src/shares.rs#revoke_share_deletes_share_path"
        status: pass
    human_judgment: false
  - id: D2
    description: "update_grant issues PATCH /shares/:shareId/grant with a body carrying only encryptedReadKey + rootGeneration (write-key fields absent) and treats 204 as success"
    requirement: SC2
    verification:
      - kind: unit
        ref: "crates/api-client/src/shares.rs#update_grant_patches_grant_path_with_read_key_only_body"
        status: pass
      - kind: unit
        ref: "crates/api-client/src/shares.rs#update_grant_non_2xx_maps_to_api_response_error"
        status: pass
    human_judgment: false
  - id: D3
    description: "revoke_share issues DELETE /shares/:shareId and treats 204 as success, mapping non-2xx (404/500) to ApiError::ApiResponse"
    requirement: SC2
    verification:
      - kind: unit
        ref: "crates/api-client/src/shares.rs#revoke_share_deletes_share_path"
        status: pass
      - kind: unit
        ref: "crates/api-client/src/shares.rs#revoke_share_non_2xx_maps_to_api_response_error"
        status: pass
      - kind: unit
        ref: "crates/api-client/src/shares.rs#revoke_share_500_maps_to_api_response_error"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-11
status: complete
---

# Phase 74 Plan 04: Api-client update_grant/revoke_share Wire Functions Summary

**PATCH/DELETE verb helpers on `ApiClient` plus `update_grant`/`revoke_share` wire functions in `crates/api-client/src/shares.rs`, closing the api-client half of the desktop grant re-mint transport gap (SC2)**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-11T03:44:46Z (approx.)
- **Completed:** 2026-07-11T03:59:46Z (approx.)
- **Tasks:** 2 (RED + GREEN)
- **Files modified:** 2

## Accomplishments

- `ApiClient::authenticated_patch<T: Serialize>` and `ApiClient::authenticated_delete` added to `crates/api-client/src/client.rs`, mirroring `authenticated_post`'s bearer-auth-header + `X-Client-Type: desktop` + reqwest builder shape, using `.patch(...)`/`.delete(...)` verbs.
- `shares::update_grant(client, share_id, encrypted_read_key, root_generation)` — PATCHes `/shares/{shareId}/grant` with an `UpdateGrantRequest` body serializing to exactly `{"encryptedReadKey": ..., "rootGeneration": "<decimal string>"}` (camelCase, write-key fields intentionally omitted). Treats HTTP 204 as `Ok(())`; non-2xx maps to `ApiError::ApiResponse { status, message: "update_grant failed: {body}" }`.
- `shares::revoke_share(client, share_id)` — DELETEs `/shares/{shareId}`, treats 204 as `Ok(())`, non-2xx maps to `ApiError::ApiResponse { status, message: "revoke_share failed: {body}" }`.
- Added a raw-TCP one-shot capturing mock HTTP server to `shares.rs`'s test module (no new crate dependency) to assert the exact method/path/JSON-body-key-set sent on the wire — not just canned-response behavior.

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Failing unit tests for update_grant + revoke_share** - `5be5ca11d` (test) — added the capturing mock server + 5 new test functions referencing not-yet-existing `update_grant`/`revoke_share`; confirmed genuine RED via `cargo test -p cipherbox-api-client shares::` (5x `E0425: cannot find function`).
2. **Task 2 (GREEN): Add PATCH/DELETE verbs + update_grant/revoke_share wire functions** - `d8124acf7` (feat) — added `authenticated_patch`/`authenticated_delete` to `client.rs` and `UpdateGrantRequest`/`update_grant`/`revoke_share` to `shares.rs`; scoped suite green (35/35, including the 15 `shares::` tests).

_TDD plan: RED (Task 1) → GREEN (Task 2). No REFACTOR commit needed — GREEN implementation matched the plan's target shape with no further cleanup required._

## Files Created/Modified

- `crates/api-client/src/client.rs` — added `authenticated_patch<T: Serialize>` and `authenticated_delete` methods on `ApiClient`.
- `crates/api-client/src/shares.rs` — added `UpdateGrantRequest` DTO, `update_grant`, `revoke_share` wire functions, and their unit tests (including the new raw-TCP capturing mock server helper).

## Signatures for Plan 74-05

```rust
// crates/api-client/src/shares.rs
pub async fn update_grant(
    client: &ApiClient,
    share_id: &str,
    encrypted_read_key: &str,
    root_generation: u64,
) -> Result<(), ApiError>;

pub async fn revoke_share(client: &ApiClient, share_id: &str) -> Result<(), ApiError>;
```

`update_grant`'s `encrypted_read_key` MUST already be ECIES-wrapped hex ciphertext — the caller (`re_mint_grants_rooted_at` in `crates/sdk/src/rotation/engine.rs`) performs the `cipherbox_crypto::wrap_key` call before invoking this function; `update_grant` does zero key-material handling. `root_generation` is a `u64` here (not a pre-formatted string) — the function formats it to the DTO's required numeric-string shape internally.

## Decisions Made

- No mock-HTTP crate (wiremock/mockito/httpmock) is a dependency of `cipherbox-api-client`, and the plan's `read_first` reference to "any existing `#[cfg(test)]` mock-server harness in this file" did not exist prior to this plan (the existing `shares.rs` tests only cover unreachable-host transport errors and pure serialization/deserialization, not live method/path/body assertions). Rather than adding a new external mock-HTTP crate dependency, a minimal raw `std::net::TcpListener`-based one-shot capturing mock server was added directly to the test module, mirroring the already-established project pattern in `crates/fuse/src/write_ops/implementation/delete.rs` (`spawn_mock_rotation_server`) — adapted to capture the inbound request (via an `mpsc` channel) rather than dispatch canned fixtures by path, since these tests need to assert the exact outbound method/path/JSON-body-key-set.
- `root_generation` is accepted as `u64` at the `update_grant` boundary and formatted to a decimal string internally, matching `UpdateGrantDto`'s `@IsNumberString`/`IsNonNegativeBigIntConstraint` (0..=`i64::MAX`) server contract exactly.

## Deviations from Plan

None — plan executed exactly as written. The mock-server harness decision above is a Rule 3 (blocking-issue) auto-fix: the plan referenced a test harness that did not exist, so a minimal one was added following an existing in-repo pattern rather than introducing new architecture or a new dependency.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required. No `pnpm api:generate` needed (hand-structured Rust crate, no OpenAPI surface change, per plan's own `<verification>` note).

## Next Phase Readiness

- `crates/api-client::shares::{update_grant, revoke_share}` are ready for Plan 74-05's `FuseRotationDeps::update_grant`/`delete_grant` to call directly — signatures match the plan's `must_haves.key_links` exactly (`update_grant -> authenticated_patch -> PATCH /shares/:shareId/grant`, `revoke_share -> authenticated_delete -> DELETE /shares/:shareId`).
- No blockers. `cargo test -p cipherbox-api-client` is green (35/35).

---
*Phase: 74-rust-and-fuse-rotation-revocation-soundness*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: `.planning/phases/74-rust-and-fuse-rotation-revocation-soundness/74-04-SUMMARY.md`
- FOUND: commit `5be5ca11d` (RED)
- FOUND: commit `d8124acf7` (GREEN)
- FOUND: `ApiClient::authenticated_patch`/`authenticated_delete` in `crates/api-client/src/client.rs`
- FOUND: `shares::update_grant`/`shares::revoke_share` in `crates/api-client/src/shares.rs`
