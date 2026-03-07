# Pitfalls Research

**Domain:** IPFS infrastructure improvements -- replacing delegated routing, migrating DB state to IPFS/IPNS, BYO-IPFS node support, and performance baselines for an existing zero-knowledge encrypted storage app
**Researched:** 2026-03-07
**Confidence:** HIGH for routing/migration pitfalls (verified against codebase + IPFS docs), MEDIUM for BYO-IPFS (fewer production precedents), MEDIUM for instrumentation (well-understood domain but CipherBox-specific interactions need validation)

**Context:** CipherBox v1.0 shipped 2026-03-05 with 423K lines of TypeScript + Rust across 698 source files. IPNS is already deeply integrated: the `folder_ipns` table tracks per-folder and per-file IPNS records with sequence numbers for optimistic concurrency, the `ipns_republish_schedule` table drives TEE republishing every 6 hours, and `delegated-ipfs.dev` is the sole external routing provider (known unreliable, with DB-cached CID fallback). The database stores auth, vault keys, shares, device approvals, pinned CIDs for quota tracking, and all IPNS state. The recovery tool (`recovery.html`) directly resolves IPNS via `delegated-ipfs.dev` without any API intermediary.

---

## Critical Pitfalls

Mistakes that cause data loss, break existing functionality, or require rearchitecting completed features.

---

### Pitfall 1: Sequence Number Divergence When Switching Routing Providers

**What goes wrong:**
The system currently has two sources of truth for IPNS sequence numbers: the `folder_ipns` PostgreSQL table and the DHT/delegated routing network. When replacing `delegated-ipfs.dev` with a self-hosted Someguy instance or Kubo DHT, the new routing endpoint may return different sequence numbers than the DB cache for a transition period. The `resolveRecord()` method in `ipns.service.ts` (line 290-350) already compares DB and network sequence numbers, taking the higher one. But during the switch, the new provider may have _no_ records (it has not seen previous publishes), causing resolution to return null from the network while the DB has valid data. If the resolution logic treats "null from network" differently than "null from delegated-ipfs.dev" -- or if the new provider starts returning stale records it picked up from DHT propagation with lower sequence numbers -- the system could serve outdated metadata, causing the client to see old folder contents or triggering false conflict detection (409 Conflict).

The TEE republishing service (`republish.service.ts`) further complicates this: it publishes signed records to delegated routing and then syncs the sequence number back to `folder_ipns`. If the old and new routing providers are both receiving publishes during a transition window, the sequence number in each may diverge independently.

**Why it happens:**

- Developers assume a clean cutover is possible -- swap one URL for another
- IPNS records propagate through the DHT with eventual consistency; a new Someguy instance must discover existing records through DHT lookups, which takes time
- The TEE republisher runs on a 6-hour cycle and may publish to the old provider after the API has switched to the new one, creating a split-publish window

**How to avoid:**

1. Run the new routing provider in read-parallel mode first: configure it alongside `delegated-ipfs.dev` and compare results for at least 48 hours (one full DHT record expiry cycle) before cutting writes over
2. Seed the new provider by having the TEE republisher publish to BOTH providers during the transition. The `publishSignedRecord()` method at line 200-204 sends to one delegated routing client; extend this to dual-write
3. Only cut over reads after the new provider consistently returns sequence numbers >= the DB cache for a representative sample of IPNS names
4. Keep DB cache as the authoritative fallback throughout -- this already works and should remain the primary resolution path

**Warning signs:**

- IPNS resolve latency spikes or increased null-from-network responses in Prometheus metrics (`cipherbox_ipns_resolves_total` by `source` label)
- 409 Conflict errors on publish that were not present before the switch
- Recovery tool fails to resolve IPNS records (it bypasses the API and hits the routing provider directly)

**Phase to address:** IPNS Reliability phase (first phase of the milestone)

---

### Pitfall 2: Moving rootFolderKey to IPFS Creates a Hard Dependency on IPNS for Login

**What goes wrong:**
Today, `rootFolderKey` is stored as ECIES-wrapped bytes in the `vaults` table (`encrypted_root_folder_key` column in `vault.entity.ts`). The login flow retrieves it via a direct PostgreSQL query -- fast, reliable, always available. The proposal to move it to an IPFS blob pointed at by the root vault IPNS record means that login now requires: (1) HKDF derivation of IPNS key, (2) IPNS resolution to get the CID, (3) IPFS fetch of the blob, (4) ECIES unwrapping. Steps 2 and 3 are network operations against infrastructure that has documented reliability issues.

If IPNS resolution fails (which it does -- the entire motivation for this milestone), the user cannot log in because they cannot get their root folder key. The DB-cached CID fallback helps, but it means the database still stores CIDs pointing to encrypted root folder key blobs -- you have not actually eliminated the DB dependency, you have just moved what the DB stores from "ECIES-wrapped key bytes" to "CID of IPFS blob containing ECIES-wrapped key bytes." The net reduction in server-side state is zero unless you also eliminate the CID cache, at which point login depends entirely on IPNS reliability.

**Why it happens:**

- The goal of "minimize database to auth-only" is laudable but creates a conflict with the reliability requirement
- The rootFolderKey is unique: unlike IPNS private keys which are HKDF-derivable, the root folder key is a random AES-256 key. It literally cannot be rederived. Losing access to it means losing the entire vault.
- Developers see the encryption key as "just data that should live on IPFS" without recognizing it is the single most critical piece of data in the entire system

**How to avoid:**

1. Keep `encrypted_root_folder_key` in the database as the primary source. Optionally mirror it to IPFS for recovery tool independence, but the DB copy is canonical for login.
2. If the goal is recovery-tool independence from the server, embed the wrapped key in the IPFS vault blob AND keep the DB copy. The recovery tool reads from IPFS; the normal login reads from the DB. Both paths work.
3. Never make the sole access path for root folder key depend on IPNS resolution. This is a "both, not either" situation.
4. Per `METADATA_EVOLUTION_PROTOCOL.md`, this is a breaking change to the root vault blob format. Version the blob format so old clients can still decrypt old-format blobs during migration.

**Warning signs:**

- Login latency increases from <100ms to multi-second (IPNS resolve is median 11s on DHT per ProbeLab measurements)
- Login failure rate correlates with IPNS availability instead of being independent
- Recovery tool works but normal login fails (or vice versa)

**Phase to address:** Database Minimization phase -- but this pitfall argues for NOT moving rootFolderKey off the DB at all, or at minimum maintaining a dual-write pattern

---

### Pitfall 3: Migrating Shares to IPFS Breaks Recipient-Initiated Discovery

**What goes wrong:**
The `shares` table enables recipient-initiated share discovery: a recipient calls `GET /shares/received` and the API queries `WHERE recipient_id = :userId`. If shares migrate to IPFS/IPNS (e.g., each user has an "inbox" IPNS record listing shares offered to them), the recipient must now know _where_ to look. In the current model, the server knows; in the IPFS model, either:

(a) The sharer publishes to the recipient's inbox IPNS record -- but the sharer does not hold the recipient's IPNS private key and cannot sign the record, so this is architecturally impossible without a new key-sharing protocol.

(b) The sharer publishes to their own IPNS record and the recipient polls all potential sharers -- but the recipient does not know who might share with them.

(c) A server-side index maps recipients to share IPNS records -- but this puts the discovery mechanism back in the database, negating the migration.

Additionally, the `share_keys` table stores per-file and per-subfolder ECIES-wrapped keys. Each key is specific to a recipient's public key. These cannot simply be "moved to IPFS" because they reference database UUIDs (`share_id`, `item_id`) for relational joins. The IPFS blob would need to embed all relationship data that currently lives in foreign keys and indices.

**Why it happens:**

- The mental model "move everything to IPFS" does not account for relational operations like indexed queries on foreign keys
- Share discovery is fundamentally a server-side operation in a system where users cannot enumerate other users' IPNS records
- The existing share-revocation flow uses soft-delete with `revoked_at` timestamp and lazy key rotation -- this stateful lifecycle is hard to model in immutable IPFS blobs

**How to avoid:**

1. Accept that shares, share_keys, and share_invites are server-side state that SHOULD stay in the database. They are access-control metadata, not user content. The server already sees `sharer_id`, `recipient_id`, and `ipns_name` in plaintext -- moving them to IPFS does not improve privacy.
2. If serverless share discovery is a goal (for BYO-IPFS or full decentralization), research CRDT-based IPNS inbox patterns BEFORE attempting migration. The todo at `2026-02-22-crdt-ipns-inbox-sharing.md` correctly flags this as research-only for this milestone.
3. Categorize DB tables into "can migrate" vs "must stay":
   - **Can migrate:** `folder_ipns` (IPNS tracking), `pinned_cids` (quota tracking if BYO replaces it), vault keys (if dual-written)
   - **Must stay:** `shares`, `share_keys`, `share_invites` (relational discovery), `device_approvals` (cross-device MFA), `users`, `auth_methods`, `refresh_tokens` (auth)

**Warning signs:**

- Design documents propose "share IPNS records" without specifying how recipients discover them
- The words "poll all sharers" appear in a design doc (quadratic complexity)
- Share acceptance latency goes from instant (DB query) to seconds (IPNS resolution)

**Phase to address:** Database Minimization phase -- but the actual prevention is to scope "minimize database" more narrowly than "move everything off"

---

### Pitfall 4: BYO-IPFS Bypasses Server-Side Optimistic Concurrency

**What goes wrong:**
CipherBox's conflict detection works because ALL IPNS publishes go through the API, which checks `expectedSequenceNumber` against the `folder_ipns` table before accepting a publish (lines 177-189 of `ipns.service.ts`). When a user configures a BYO-IPFS node and publishes IPNS records directly (client-to-node without API relay), the server never sees the publish and cannot check sequence numbers. Two devices could publish conflicting metadata for the same folder, and the DHT will keep whichever has the higher sequence number -- but neither device knows about the conflict.

Worse: the TEE republishing service tracks sequence numbers in `ipns_republish_schedule`. If a BYO user publishes directly to their node, the TEE's sequence number becomes stale. The next TEE republish will create a record with a LOWER sequence number than what the user published, causing the DHT to reject it (or worse, a race where different DHT nodes hold different records). The user's IPNS records silently stop being republished.

**Why it happens:**

- BYO-IPFS is designed for user sovereignty, but the entire concurrency model assumes server mediation
- The provider interface (`IpfsProvider`) only abstracts pin/unpin/fetch -- it does not abstract IPNS publishing, which is handled separately through `DelegatedRoutingClient`
- Client-direct upload to a user's Kubo node is the simplest implementation, but it bypasses every server-side check

**How to avoid:**

1. Even with BYO-IPFS, require IPNS publishes to go through the API. The server does not need to contact the user's IPFS node for IPNS -- it just needs to see the publish request for concurrency checking and TEE enrollment.
2. Separate the concerns: BYO-IPFS is about WHERE data is pinned, not about HOW metadata is published. Pin encrypted blobs to the user's node; publish IPNS records through the API.
3. If client-direct IPNS publishing is a requirement (full decentralization), implement client-side conflict detection: before publishing, resolve the current IPNS record, compare sequence numbers, and abort on mismatch. This is weaker than server-side checks (no atomicity guarantee) but better than nothing.
4. Add a "last known sequence number" field to the BYO-IPFS configuration so the client can detect when the TEE's sequence diverges from the user's actual sequence.

**Warning signs:**

- BYO users report "stale" folder contents on other devices
- TEE republish success rate drops for BYO users specifically
- Sequence numbers in `ipns_republish_schedule` are lower than what IPNS resolves to

**Phase to address:** BYO-IPFS phase -- design decision required before implementation begins

---

### Pitfall 5: DHT Record Expiry During Routing Provider Migration

**What goes wrong:**
IPNS records on the DHT expire after 48 hours regardless of the validity field in the record. Kubo's default republish period is 4 hours, and CipherBox's TEE republishes every 6 hours. During a routing provider migration, if there is a gap where neither the old provider nor the new provider successfully publishes records, the 48-hour expiry clock keeps ticking. If the gap exceeds 48 hours (e.g., a weekend deployment where the new provider is misconfigured), ALL IPNS records for ALL users expire from the DHT simultaneously. Recovery requires republishing every single record -- but the TEE processes records in batches of 100 with a 6-hour cycle, so catching up on thousands of records takes many cycles.

The DB-cached CID fallback saves resolution, but only for users going through the API. The recovery tool (`recovery.html`) and any future BYO-IPFS clients resolving directly from the DHT will get nothing.

**Why it happens:**

- The 48-hour DHT expiry is not widely known -- developers assume IPNS records persist until explicitly replaced
- The TEE republish cycle (6 hours) provides comfortable margin (48/6 = 8 missed cycles before expiry), creating false confidence
- Migration testing often happens on small test datasets where a full republish cycle completes quickly, masking the problem at scale

**How to avoid:**

1. Never take the old routing provider offline until the new one has successfully processed at least one full republish cycle for ALL enrolled records
2. Monitor the `cipherbox_republish_schedule_total` gauge by status during migration -- any spike in `retrying` or `stale` status indicates the new provider is not accepting publishes
3. Before migration, calculate the worst-case catch-up time: `(total enrolled records / BATCH_SIZE) * republish_interval = (N / 100) * 6 hours`. For 1000 records, that is 60 hours to fully catch up from scratch -- already past the 48-hour expiry
4. Consider a one-time "emergency republish" endpoint that processes all records immediately (bypassing the 6-hour schedule) after a provider switch
5. Reduce BATCH_SIZE temporarily during migration to process more records per cycle, or run catch-up cycles more frequently

**Warning signs:**

- `ipns_republish_schedule` entries accumulating in `retrying` or `stale` status
- IPNS resolution returning null for records that were previously resolvable
- Recovery tool stops working for all users simultaneously

**Phase to address:** IPNS Reliability phase -- must be addressed in the migration runbook

---

### Pitfall 6: Quota Tracking Becomes Unenforceable with BYO-IPFS

**What goes wrong:**
CipherBox tracks storage quota via the `pinned_cids` table: every upload goes through `IpfsController`, which calls `pinFile()` on the server-managed Kubo node and records the CID + size in `pinned_cids`. The user's total is summed against a 500 MiB limit. With BYO-IPFS, if uploads go directly to the user's node (client-direct), the server never sees the upload and cannot record the CID. The `pinned_cids` table becomes incomplete. Quota enforcement is either (a) impossible, (b) advisory only, or (c) requires the client to self-report, which is trivially forgeable.

The deeper issue: quota tracking exists to protect the CipherBox operator's IPFS node from unbounded storage consumption. If the user is pinning to their own node, the CipherBox operator has no storage cost and does not need to enforce quota. But the system currently conflates "enforce quota" with "track what the user has stored" -- and that tracking is also used for the recycle bin's CID unpinning (30-day retention + cleanup).

**Why it happens:**

- The existing quota model assumes all storage flows through the server
- Client-direct upload is the most obvious BYO architecture but breaks server-side bookkeeping
- Developers may add BYO pinning without considering that quota, recycle bin, and orphan cleanup all depend on the `pinned_cids` table

**How to avoid:**

1. For BYO-IPFS users, skip server-side quota enforcement entirely. The user manages their own node's capacity.
2. Still require BYO uploads to be reported to the API (POST with CID + size after client-side pin succeeds). This maintains the `pinned_cids` ledger for features that depend on it (recycle bin, orphan detection) without requiring the server to handle the actual data.
3. Mark `pinned_cids` entries with a `provider` column ("server" | "byo") so the system knows which CIDs it can directly unpin vs. which require the client to unpin.
4. Accept that unpinning on a BYO node requires client cooperation -- the server cannot reach into the user's node. Document this limitation clearly.

**Warning signs:**

- BYO users show 0 bytes used in quota display despite having files
- Recycle bin emptying fails silently for BYO-pinned CIDs (unpin calls go to the wrong node)
- Orphan CID detection reports all BYO CIDs as orphans

**Phase to address:** BYO-IPFS phase

---

## Technical Debt Patterns

Shortcuts that seem reasonable but create long-term problems.

| Shortcut                                                             | Immediate Benefit                 | Long-term Cost                                                                                             | When Acceptable                                                                                                                                                                         |
| -------------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dual-write to old and new routing provider "forever"                 | Safe migration                    | Double the publish latency, double the failure surface, code complexity of maintaining two routing clients | Only during migration transition; set a hard deadline to remove the old provider within 2 weeks of cutover                                                                              |
| Skip IPNS signature verification on DB-cached resolutions            | Faster resolve, simpler code      | DB-cached CIDs are not cryptographically verified -- a compromised DB could serve malicious CIDs           | Acceptable only if the DB is trusted infrastructure. The web client at `ipns.service.ts:160-169` already verifies signatures from network resolves but skips it for DB-fallback results |
| BYO users self-report CID sizes for quota                            | Simple client-direct architecture | Users can lie about sizes; quota is advisory only                                                          | Acceptable for tech demonstrator. For production, require server verification of at least one byte-range to confirm size                                                                |
| Use DB-cached CID as primary resolution (skip IPNS network entirely) | Instant resolve, no DHT latency   | DB becomes single point of truth for metadata location; IPNS becomes decorative                            | Acceptable as interim step. The current code already prefers DB when it has a newer sequence number. Making this explicit reduces complexity                                            |
| Hardcode Someguy URL instead of making it configurable               | Faster initial implementation     | Cannot switch providers without code change and redeploy                                                   | Never -- use `DELEGATED_ROUTING_URL` env var (already exists in `delegated-routing.client.ts:22-25`). Zero cost to keep it configurable                                                 |
| Measure performance baselines during staging only                    | No production impact              | Staging has different latency, load, and network characteristics than production                           | Never for baselines intended to represent production. Staging baselines are useful only for relative comparison (before/after a change)                                                 |

---

## Integration Gotchas

Common mistakes when connecting to external services or changing existing integrations.

| Integration                             | Common Mistake                                                                                                                                                                                                                    | Correct Approach                                                                                                                                                                                                          |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Someguy (self-hosted delegated routing) | Deploying Someguy without DHT bootstrap peers, resulting in an isolated node that cannot resolve any existing IPNS records                                                                                                        | Configure Someguy with the Amino DHT bootstrap peers. Run it alongside Kubo so it benefits from Kubo's established DHT connections. Verify resolution of known IPNS names before cutting over                             |
| Kubo DHT direct (Routing.Type=auto)     | Assuming the existing Kubo node already participates in DHT for IPNS. CipherBox's Kubo may be configured with DHT disabled (using only delegated routing)                                                                         | Check `Routing.Type` in Kubo config. If it is "none" or "custom" with only delegated HTTP routers, IPNS DHT publishing/resolution is not happening through Kubo itself                                                    |
| IPFS Pinning Service API (for BYO)      | Treating the Pinning Service API as equivalent to Kubo's `/api/v0/add`. The Pinning Service API is async -- `POST /pins` returns a `requestid` and pinning happens in the background                                              | Poll pin status before assuming content is available. The CID may not be retrievable from the BYO node until pinning completes. Upload UX must reflect this ("pinning..." not "uploaded")                                 |
| Recovery tool (`recovery.html`)         | Changing the API's routing provider but forgetting the recovery tool resolves IPNS directly at line 363. The recovery tool is a standalone HTML file with no build system -- it does not use the API client                       | Update the recovery tool's default gateway URL. Better: make the recovery tool configurable to use the same routing provider as the API, or provide a recovery-specific resolve endpoint                                  |
| TEE republishing during provider switch | The TEE worker calls the API's `publishSignedRecord()` method, which calls `DelegatedRoutingClient.publish()`. If the URL changes, the TEE's publishes go to the new provider but existing DHT records on the old provider expire | During transition, have the republisher publish to both providers. The TEE itself does not need to change -- only the API's publish path needs to dual-write                                                              |
| Prometheus metrics endpoint             | Adding IPNS latency histograms that create high-cardinality labels (e.g., per-ipnsName timings)                                                                                                                                   | Use fixed label values (e.g., `operation=publish/resolve`, `source=network/db_cache`). The existing `httpRequestDuration` histogram correctly normalizes routes. Follow the same pattern for new IPNS-specific histograms |

---

## Performance Traps

Patterns that work at small scale but fail as usage grows.

| Trap                                                           | Symptoms                                                                                                                                                                                       | Prevention                                                                                                                                                                                               | When It Breaks                                                                                                                                                                                                                                |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full DHT resolution on every IPNS resolve                      | Login takes 11+ seconds (DHT median); folder navigation feels frozen                                                                                                                           | Use DB-cached CID as primary resolve path; DHT resolve as background refresh (the current code approximates this but still blocks on DHT first)                                                          | Immediately -- median 11s latency per ProbeLab measurements on Amino DHT. Already broken for UX                                                                                                                                               |
| TEE republishing all records in sequence                       | Republish cycle exceeds the 6-hour interval for users with many folders/files; records start expiring before the next cycle                                                                    | The current BATCH_SIZE=100 with concurrency helps. Monitor `republish_entries_processed_total` vs cycle duration. Add per-user prioritization                                                            | At ~600+ enrolled records per cycle (100 batches x 6s avg per batch = 600s = 10 min total, still fine; but network issues or TEE latency can push individual batches to 60s+, at which point 100 batches x 60s = 100 min, approaching limits) |
| Instrumenting every IPFS operation with synchronous logging    | Console.log/warn calls on hot paths (the codebase has 50+ console calls per CONCERNS.md) block the event loop; adding structured logging to IPFS pin/unpin adds latency to user-facing uploads | Use async log shipping (not synchronous console). Instrument at the histogram level (timing), not the log level (string formatting). The existing Prometheus setup is the right model                    | Immediately -- any synchronous logging on IPFS hot paths adds measurable latency                                                                                                                                                              |
| Client-side performance measurement using `Date.now()`         | Sub-millisecond operations appear as 0ms; timer coarsening in browsers hides real variance                                                                                                     | Use `performance.now()` for client-side timing, `process.hrtime.bigint()` for server-side (already used in `http-metrics.interceptor.ts:13`). Set histogram buckets appropriately for the expected range | Immediately -- `Date.now()` has millisecond resolution which is insufficient for sub-ms operations                                                                                                                                            |
| Baseline measurements taken during development with hot caches | Baselines show artificially good numbers because Kubo's blockstore cache, OS page cache, and browser cache are warm                                                                            | Always include cold-start measurements: restart Kubo, clear browser cache, flush OS page cache. Report both cold and warm baselines                                                                      | When baselines are used to set SLO thresholds -- warm-cache numbers are artificially optimistic                                                                                                                                               |
| BYO-IPFS with user's home node behind NAT                      | Pin succeeds locally but content is not retrievable by other peers because the node is not reachable. User reports "upload succeeded but file is missing"                                      | Verify content availability after pin by attempting retrieval from a different peer. Warn users about NAT traversal requirements. Kubo's relay/AutoNAT helps but is not guaranteed                       | Immediately for any user behind consumer NAT (most home connections)                                                                                                                                                                          |

---

## Security Mistakes

Domain-specific security issues beyond general web security, relevant to the IPFS infrastructure changes.

| Mistake                                                                                         | Risk                                                                                                                                                    | Prevention                                                                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exposing Kubo API (port 5001) to BYO users for "direct pinning"                                 | Kubo API has no authentication. Any client with network access can pin/unpin/add content, exhaust disk, or read any pinned content                      | Never expose Kubo API directly. Use the IPFS Pinning Service API (port-separated, auth-capable) or proxy through the CipherBox API with JWT auth                                                                                                          |
| Storing BYO-IPFS node credentials (API tokens, auth headers) in the database without encryption | Server compromise exposes all BYO users' IPFS node credentials                                                                                          | Encrypt BYO config with the user's publicKey (ECIES). Store only the wrapped blob. The client unwraps and uses the credentials client-side                                                                                                                |
| Self-hosted Someguy without rate limiting                                                       | DoS vector: anyone can flood the delegated routing endpoint with publish/resolve requests, exhausting DHT connections                                   | Deploy Someguy behind a reverse proxy with rate limiting. The existing `delegated-routing.client.ts` handles 429 responses (lines 62-69), so rate-limited responses are gracefully retried                                                                |
| Performance baselines that include auth tokens in timing data                                   | Timing side-channels could reveal information about token validation (e.g., shorter response for invalid tokens vs. valid tokens with expired sessions) | Exclude auth endpoints from public-facing performance dashboards. Report only aggregate histograms, not per-request timings. The existing Prometheus setup correctly does this                                                                            |
| IPNS records signed with leaked TEE epoch keys                                                  | If a previous-epoch TEE private key is compromised, an attacker could forge IPNS records for any user whose key was encrypted with that epoch           | The 4-week grace period for epoch rotation means old keys are eventually discarded. Ensure the new routing provider validates IPNS record signatures (Someguy does this inherently via the IPNS spec). Monitor for unexpected sequence number regressions |

---

## UX Pitfalls

Common user experience mistakes when adding these infrastructure features.

| Pitfall                                                                       | User Impact                                                                                                         | Better Approach                                                                                                                                                                                      |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Showing IPNS resolution latency as a loading spinner without explanation      | Users see a 3-11 second spinner after every folder navigation and assume the app is broken                          | Show folder contents from DB cache immediately, then refresh in background when IPNS resolves. The current 30-second polling partially achieves this, but initial navigation still blocks on resolve |
| BYO-IPFS setup requires knowing Kubo API URL, authentication, and IPNS config | Only technically sophisticated users can configure it; everyone else is stuck with default                          | Provide auto-detection: if user enters a hostname, probe standard ports (5001 for Kubo API, 9097 for Pinning Service API). Offer presets for common providers (web3.storage, Filebase, Pinata)       |
| Performance baseline results displayed as raw numbers                         | Users see "IPNS resolve: 11234ms" and panic, not understanding this is a DHT operation                              | Present baselines as traffic-light indicators (green/yellow/red) with context: "IPNS resolve: 11.2s (typical for DHT; cached resolves are <100ms)"                                                   |
| Silent fallback from IPNS to DB cache with no indication                      | User thinks they have "real IPFS" but resolution always falls back to the database. False sense of decentralization | Show a subtle indicator when resolution source is DB-cache vs. IPNS network. Log it in a diagnostics panel for advanced users                                                                        |
| BYO-IPFS node goes offline and user loses access to files                     | User pinned files to their home node, it crashes, content is lost because no other node has copies                  | Warn users that BYO means single-point-of-failure unless they also pin to a backup. Offer "pin to both server and BYO" as default mode                                                               |

---

## "Looks Done But Isn't" Checklist

Things that appear complete but are missing critical pieces.

- [ ] **Routing provider replacement:** New provider resolves IPNS names -- but verify it also PUBLISHES reliably. Resolution can fall back to DB; publishing cannot. Test publish + resolve round-trip, not just resolve.
- [ ] **DB-to-IPFS migration for folder_ipns:** folder_ipns rows exist in IPFS blobs -- but verify the TEE republish service still works. It reads `encrypted_ipns_key` and `sequence_number` from the schedule table, not from IPFS. These columns cannot be eliminated if TEE republishing continues.
- [ ] **BYO-IPFS pin integration:** Files pin to user's node -- but verify they are retrievable by the CipherBox API for serving to other devices. Content must be discoverable on the IPFS network, not just locally pinned.
- [ ] **Performance baselines recorded:** Histograms populated in Prometheus -- but verify baselines include error cases. A P99 that excludes 502/504 errors paints a falsely rosy picture.
- [ ] **Recovery tool updated for new routing:** recovery.html points to new routing endpoint -- but verify it works WITHOUT the CipherBox API running. The entire point of the recovery tool is server-independent vault access.
- [ ] **Orphaned IPNS cleanup:** IPNS records migrated off DB -- but verify the orphaned IPNS records from pre-migration are cleaned up. The CONCERNS.md already flags orphaned IPNS records as tech debt.
- [ ] **Sequence number continuity:** After migration, first publish from client succeeds -- but verify the sequence number is correctly incremented from the pre-migration value, not reset to 1. A reset would cause the DHT to prefer the old (higher-sequence) record.
- [ ] **BYO quota display:** Settings page shows BYO config -- but verify the vault storage usage display updates correctly. If `pinned_cids` is incomplete, the UI shows wrong usage.

---

## Recovery Strategies

When pitfalls occur despite prevention, how to recover.

| Pitfall                                                         | Recovery Cost                                        | Recovery Steps                                                                                                                                                                                                                                                        |
| --------------------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sequence number divergence after provider switch                | LOW                                                  | DB is authoritative. Force-republish all records from DB state to new provider. Client-side sequence numbers in Zustand stores may be stale -- user must refresh (F5).                                                                                                |
| rootFolderKey inaccessible (IPNS resolution failure)            | CRITICAL if DB copy removed; LOW if DB copy retained | If DB copy exists: serve from DB (already the fallback). If DB copy was removed: user must use recovery tool with their private key to re-derive IPNS key, resolve from DHT (may be expired), and fetch from IPFS. If both fail: vault is permanently inaccessible.   |
| Shares unreachable after migration to IPFS                      | HIGH                                                 | Must revert to DB-backed shares. If DB tables were dropped: reconstruct from IPFS blobs by scanning each user's share IPNS records, but recipient discovery requires the server index to be rebuilt from scratch.                                                     |
| BYO concurrency conflict (two devices wrote different metadata) | MEDIUM                                               | Detect by comparing IPNS records from multiple DHT lookups. The record with the higher sequence number wins. The losing device must fetch the winning metadata and re-apply its changes on top (manual merge). No automated merge exists in the current architecture. |
| 48-hour DHT expiry (all records lost from DHT)                  | MEDIUM                                               | DB-cached CIDs still work for API-mediated resolution. To restore DHT records: trigger emergency republish of all entries. At BATCH_SIZE=100, 1000 records = 10 batches. If each batch takes 30s, full recovery = 5 minutes for TEE signing + publishing time.        |
| Quota tracking broken for BYO users                             | LOW                                                  | Run a reconciliation job: for each BYO user, fetch their folder metadata from IPNS, enumerate all CIDs, check pin status on their node, update `pinned_cids` table. Can be run as a one-time migration or periodic background job.                                    |
| False performance baselines from observer effect                | LOW                                                  | Re-run baselines with instrumentation disabled, compare. If overhead > 5%, switch to sampling-based measurement (10% sample rate). Document the measurement methodology alongside the baseline numbers.                                                               |

---

## Pitfall-to-Phase Mapping

How roadmap phases should address these pitfalls.

| Pitfall                                    | Prevention Phase      | Verification                                                                                                                                                   |
| ------------------------------------------ | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1: Sequence number divergence             | IPNS Reliability      | Run dual-provider for 48+ hours; compare sequence numbers across providers for 100% of IPNS names                                                              |
| P2: rootFolderKey on IPNS                  | Database Minimization | Verify login works when IPNS is completely down (kill Someguy, disable DHT); login must still succeed via DB                                                   |
| P3: Share discovery on IPFS                | Database Minimization | N/A -- prevention is to NOT migrate shares. Verify shares still work after other tables are migrated                                                           |
| P4: BYO bypasses concurrency               | BYO-IPFS              | Simulate two BYO devices publishing simultaneously; verify conflict is detected and one publish is rejected or flagged                                         |
| P5: DHT record expiry during migration     | IPNS Reliability      | Before cutover, verify new provider has successfully republished all records at least once. Check that zero `stale` entries exist in `ipns_republish_schedule` |
| P6: Quota tracking with BYO                | BYO-IPFS              | Upload 10 files via BYO, verify `pinned_cids` table has 10 entries with correct sizes. Empty recycle bin, verify CIDs are unpinned on user's node              |
| P7: Instrumentation overhead               | Performance Baselines | Run baseline suite with and without instrumentation. Verify overhead < 5% on P95 latency. If higher, reduce sampling rate                                      |
| P8: Recovery tool broken by routing change | IPNS Reliability      | Run full recovery flow using ONLY recovery.html (no API) with the new routing provider. Verify all files are recoverable                                       |

---

## Sources

- [IPFS IPNS Concepts](https://docs.ipfs.tech/concepts/ipns/) -- DHT expiry (48h), TTL, republishing behavior
- [Measuring IPNS Performance on the Public Amino DHT](https://www.probelab.network/blog/ipns-performance-amino-dht) -- Median 11s retrieval latency, 100% retrieval success rate
- [Someguy - Delegated Routing V1 server](https://github.com/ipfs/someguy) -- Self-hosted delegated routing, proxies to DHT and IPNI
- [Kubo Delegated Routing docs](https://github.com/ipfs/kubo/blob/master/docs/delegated-routing.md) -- Routing.Type auto/dht/custom configuration
- [IPFS Public Utilities](https://docs.ipfs.tech/concepts/public-utilities/) -- delegated-ipfs.dev as public good endpoint
- [Shipyard 2025 Year in Review](https://ipshipyard.com/blog/2025-shipyard-ipfs-year-in-review/) -- IPIP-476, IPIP-513, Someguy improvements
- [IPFS Pinning Service API spec](https://ipfs.github.io/pinning-services-api-spec/) -- Async pinning, standard API for BYO integration
- [Multiple users publish to IPNS at the same time](https://github.com/ipfs/kubo/issues/8433) -- Concurrent publish conflict, sequence number semantics
- [IPNS Record and Protocol spec](https://specs.ipfs.tech/ipns/ipns-record/) -- Sequence number comparison, record validation
- [Empirical study on performance overhead of code instrumentation (2025)](https://www.sciencedirect.com/science/article/pii/S0164121225002420) -- Up to 8.4% throughput reduction, 20-49% latency increase from instrumentation
- [How to Reduce OpenTelemetry Performance Overhead in Production](https://oneuptime.com/blog/post/2026-02-06-reduce-opentelemetry-performance-overhead-production/view) -- Sampling strategies, batch processing
- [OpenTelemetry NestJS Implementation Guide](https://signoz.io/blog/opentelemetry-nestjs/) -- NestJS-specific OTel setup and sampling
- CipherBox codebase: `apps/api/src/ipns/ipns.service.ts`, `apps/api/src/ipns/delegated-routing.client.ts`, `apps/api/src/republish/republish.service.ts`, `apps/web/src/services/ipns.service.ts`, `apps/web/public/recovery.html`
- CipherBox project context: `.planning/PROJECT.md`, `.planning/codebase/CONCERNS.md`, `.planning/todos/pending/` (IPNS alternatives, BYO-IPFS, move rootFolderKey)

---

_Pitfalls research for: CipherBox v1.1 IPFS Infrastructure_
_Researched: 2026-03-07_
