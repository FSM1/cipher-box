# Research Goals — Grant Delivery, Rotation, and the Role of the Relay

Status: research/prototyping sprint charter (pre-decision)
Owner: Michael
Created: 2026-07-16

## 1. Purpose & how to use this document

CipherBox's sharing model has grown to the point where **where grant key-material
lives**, **how it is delivered and updated on rotation**, and **how much the
API/relay is trusted to make sharing work** are entangled decisions that are
currently made implicitly. Recent work (Phase 80 recipient-pins; the file-share
re-mint gap) surfaced concrete bugs that are *symptoms* of those implicit
decisions rather than isolated defects.

This document defines a focused research + prototyping sprint to decide, on
evidence, the target architecture for grant delivery and rotation. It is meant to
stand alone: a researcher who has not seen the originating discussion should be
able to run the sprint from this document plus the code references in Appendix C.

How to use it:

- Sections 2–6 are grounding: the current model, the core tension, the concrete
  evidence, and the invariants/subtleties any solution must respect.
- Sections 7–10 are the actual work: research questions, hypotheses,
  prototyping tracks, and the decision framework.
- The appendices give a **canonical test scenario** and **flow traces** every
  prototype must validate against, so results are comparable.

The sprint's output is a recommendation (an ADR) backed by working prototypes and
measurements — not a production implementation.

## 2. Background — the current architecture (grounding)

### 2.1 The v3 node model (two encryption planes)

Every folder/file is a `PublishedNode` on IPFS, addressed by an IPNS name, with
two independently-sealed bodies:

- **Read-body** (sealed under the node's `readKey`, AES-256-GCM): for folders,
  `children: SealedChildRef[]`; for files, `content` (fileKey, size, versions).
- **Write-body** (`NodeWriteBody`, sealed under the node's `writeKey`):
  `{ ipnsPrivateKey, writeChildren: WriteChildRef[], recipientPins: string[] }`.

Per-node keys:

- `readKey` (AES-256) — decrypts the read-body.
- `writeKey` (AES-256) — decrypts the write-body.
- `ipnsPrivateKey` (Ed25519 seed) — signs IPNS records; its public key **is** the
  IPNS name (`deriveIpnsName(pub)`). It lives **inside** the write-body, so it is
  recoverable only via the `writeKey`.

Two derivation chains let a single grant cover a whole subtree:

- **Read-chain:** `SealedChildRef.readKeySealed = sealChildReadKey(rk_child, rk_parent, …)`.
  A reader with a parent `readKey` derives every descendant `readKey` on demand.
- **Write-chain:** `WriteChildRef.writeKeySealed = sealChildWriteKey(wk_child, wk_parent, …)`.
  A writer with a parent `writeKey` derives every descendant `writeKey` — and hence
  each descendant's `ipnsPrivateKey` (from that node's write-body).

Key relationship (important): the `writeKey` is the **shareable, subtree-scoped
envelope**; the `ipnsPrivateKey` is the write-specific signing secret carried
*inside* it. You never distribute the signing key directly — you distribute the
`writeKey` that unlocks it. This is the write-plane analog of `readKey` + read-chain.

### 2.2 How sharing works today

A share grants an entire subtree with a single ECIES wrap of the subtree root's key:

- **Read share:** `encryptedReadKey = hex(ECIES_wrap(rk_root, recipientPub))`.
- **Write share:** additionally `encryptedWriteKey = hex(ECIES_wrap(wk_root, recipientPub))`.
- The grant is stored **in the relay** (`/shares` table):
  `{ shareId, recipientPublicKey, encryptedReadKey, encryptedWriteKey?, rootNodeId, shareRootIpnsName, rootGeneration }`.
- For **folder** shares, the owner also seals the recipient's pubkey into the shared
  node's write-body `recipientPins` (anti-relay-substitution defense, Phase 80),
  pin-FIRST then grant. **File** shares are pin-exempt (a file leaf's write-body is
  not reachable via the folder-only pin API — the accepted carve-out).

So authorization *authority* (pins) already lives in metadata; grant *key material*
lives only in the relay. The relay is also the **discovery** channel
(`GET /shares/received`). The relay is zero-knowledge w.r.t. key material (all
blobs are ECIES to the recipient) but sees the sharing graph and can attempt
recipient substitution (which pins defend against on re-mint).

### 2.3 Rotation and re-mint

- **Read rotation** (`rotateReadFromNode`, scope-exit trigger `maybeRotateOnScopeExit`):
  fires on covered scope-exit mutations (rename/delete/move/createSubfolder) on a
  grant-root folder. It rekeys the folder **and its whole subtree** (BFS), keeping
  every `writeKey`, `ipnsPrivateKey`, and IPNS **name** stable. Then it **re-mints**
  grants rooted at each rotated node — re-wrapping the new `readKey` for surviving
  recipients (`PATCH /shares/:id/grant`) and deleting revoked ones.
- **Write rotation** (`rotateWriteFromNode`): mints a **new** `ipnsPrivateKey`
  (→ new name) + new `writeKey` per node, republishes under new names, and
  **tombstones** the old names. Required to truly revoke a writer (who may have
  already extracted the stable signing key).
- **Revocation is lazy** (ADR 0002): a pure revoke deletes the grant row; the
  actual read-key cut is deferred to the next covered mutation's rotation.

## 3. The core tension (problem statement)

The relay has drifted from an intended "temporary key transport" into a
**load-bearing store of the sharing graph and grant key-material**. Two forces are
in tension:

1. **Grants-in-relay (status quo).** Grant key-material lives in `/shares`;
   rotation must reach back out and `PATCH` each grant. This makes re-mint a
   separate, out-of-band write that must be kept in sync with the metadata rotation,
   and it makes the relay integral to every share and every rotation.

2. **Grants-in-metadata (original intent).** Owner-sealed grant material lives in
   node metadata (extending `recipientPins`), so rotation's re-seal carries the
   re-minted grants **for free**, atomically, for files and folders alike — and the
   relay shrinks toward a **swappable, integrity-untrusted pointer/notification bus**.

Cutting across both: **key delivery and discovery are separable.** Delivery of key
material can plausibly move into metadata, while notification/discovery ("you have a
new share; here is where it is") is the genuinely hard, IPFS-unfriendly part — the
"inbox" problem the relay currently solves and that any decentralization goal must
confront.

And a third axis: **hygiene vs revoking rotations.** A non-revoking (hygiene) rekey
can plausibly be delivered purely in metadata (chain the new key under the old key,
readable forward by any current holder). A revoking rotation cannot (the revoked
party holds the old key), and must re-deliver per surviving recipient out-of-band.

The sprint must decide where CipherBox should land on these axes and prove it works.

## 4. Evidence — concrete gaps that motivate this

These are real, code-confirmed issues that are *symptoms* of the grants-in-relay
model (see Appendix C for exact locations):

- **Gap C — re-mint encoding mismatch (fixed on branch, but instructive).**
  `reMintGrantsRootedAt` emitted base64 while `PATCH /shares/:id/grant` requires
  hex, so **every** re-mint PATCH 400'd — including the folder-grant reconcile
  sweep, which had therefore silently never worked. It existed only because re-mint
  is an out-of-band relay write with its own wire format; unit tests mocked the
  transport, so no test caught it. (Rust already emitted hex — a cross-language
  parity divergence.)

- **Gap B — file leaves cannot be read-rotated on web.** The rotation BFS enqueues
  every child including files, keyed only via web's `nodeKeySource`, which reads only
  `folderTree` (folders). A file leaf has no `ipnsPrivateKey`/`writeKey` available →
  `rotateOne` fail-closes → on web, scope-exit rotation of *any shared folder
  containing files* throws. Latent only because v2.0 web rotation isn't fully live.
  Desktop/FUSE works because its host (`RotationDeps`) resolves any node's key by
  name from the mounted tree. This is a host-data-model divergence, not a protocol
  one; the intended "Phase 65 write-body key derivation" landed for folders but not
  file leaves in the walk.

- **Write-plane sibling.** `rotateWriteFromNode` re-wraps co-writer keys with the
  same base64-vs-hex shape (engine.ts:2833) and the same relay-PATCH dependency —
  likely the same class of latent bug on the write plane.

- **Whole-subtree blast radius.** Because scope-exit rotation rekeys the entire
  subtree, an **independently-shared descendant** (e.g. a file shared to a different
  set of recipients) is rekeyed by an unrelated action on its ancestor folder, and
  its grants *must* be re-minted or those recipients silently lose access.

## 5. Invariants & constraints (non-negotiable)

Any candidate architecture MUST preserve these unless the sprint explicitly argues
to change one (with justification):

- **Zero-knowledge server.** The relay/API never sees plaintext keys or content.
  All grant material is ECIES to the recipient; all content is AES-256-GCM.
- **Primitives.** ECIES (secp256k1) for key wrapping; AES-256-GCM (+AAD) for
  content and body sealing. No hand-rolled crypto.
- **No plaintext signing keys at rest.** `ipnsPrivateKey` is only ever stored
  sealed inside a write-body.
- **IPNS name = f(Ed25519 pub).** Read rotation keeps names stable; only write
  rotation changes names (with tombstones).
- **Lazy-revocation stance (ADR 0002).** Ciphertext already published under an old
  key is presumed leaked; rotation revokes *future* derivation, not the past.
- **Cross-language parity.** Rust (desktop/FUSE) and TypeScript (web/sdk) engines
  must produce byte-compatible published records and grant encodings.
- **Recipient-pin anti-substitution defense.** The owner-sealed authorization must
  remain the authority a re-mint verifies against — the relay-fed recipient is never
  trusted blindly.
- **Two independent planes.** Read and write revocation stay separable (read
  rotation must not force a write-plane/name change).
- **Forward-only migration is acceptable.** Staging is reset to a clean slate at
  milestone completion; the sprint may assume no legacy shares to migrate (but must
  still describe the cutover for a future production migration).

## 6. Hard-won subtleties any solution must handle (failure modes)

These are the traps discovered so far; a candidate that ignores one is disqualified:

1. **Bootstrap chicken-egg.** An initial grant cannot be sealed under the node's own
   `readKey` — a brand-new recipient has no key to open it. Initial delivery is
   irreducibly ECIES-to-pubkey through a channel reachable without the node key.
2. **Revocation-under-old-key leak.** For a *revoking* rotation, the new key cannot
   be sealed under the old key (the revoked party holds it too) — it must be
   re-wrapped per surviving recipient.
3. **Hygiene rekeys are different.** A non-revoking rekey *can* chain new-under-old
   in metadata, avoiding the relay and any public exposure. Distinguishing the two
   cases correctly is itself a research question.
4. **Name stability on read rotation.** Grant *pointers* (`shareRootIpnsName`)
   survive read rotation; only the wrapped key must update. Solutions must not
   accidentally require pointer churn on read rotation.
5. **File-leaf key recovery.** Rotating/republishing a file leaf needs its
   `ipnsPrivateKey` (to sign) and `writeKey` (to reseal), recoverable via the
   write-chain: parent `writeKey` → `WriteChildRef.writeKeySealed` → child `writeKey`
   → child write-body → child `ipnsPrivateKey`.
6. **Whole-subtree blast radius.** Independently-shared descendants are always in the
   blast radius of an ancestor rotation; re-mint must reach them or they lose access.
7. **File pin carve-out.** Files structurally can't carry `recipientPins` today, so
   file-share grants are unprotected against relay substitution. Any solution should
   either extend protection to files or make the exposure explicit.
8. **Sharing-graph privacy.** Depending on where grants live, the relay, arbitrary
   IPFS observers, or recipients may learn who-shares-what-with-whom. This is a
   design axis, not an afterthought.
9. **Cross-platform key sourcing.** Web (`folderTree`, folder-only, no parent chain)
   and desktop (full mounted tree) have different data models; a solution should
   converge them rather than deepen the divergence.

## 7. Research questions

Answer these with evidence (prototypes, measurements, threat models), not opinion.

- **RQ1 — Grant locus.** Where should grant key-material live: relay table,
  owner-sealed node metadata, per-recipient inbox, or a hybrid? Evaluate each
  against re-mint atomicity, privacy, availability, and complexity.

- **RQ2 — Delivery vs discovery.** Can key *delivery* move to metadata while
  *notification/discovery* remains a swappable, integrity-untrusted relay/inbox?
  What is the minimal irreducible relay role that remains?

- **RQ3 — Rotation re-mint mechanics.** For hygiene rekeys, can new-key-under-old-key
  metadata chaining replace the relay `PATCH`? How should the system classify a
  rotation as hygiene vs revoking, and handle each? Does this eliminate Gap B/C for
  the common case?

- **RQ4 — File-leaf key sourcing / parity.** Should the rotation engine derive child
  (file) keys from the write-chain (engine-side, host-agnostic) rather than rely on a
  host callback? What design unifies web + desktop and produces identical output?
  (Directly resolves Gap B.)

- **RQ5 — Rotation scope.** Is whole-subtree read rotation on every covered
  scope-exit mutation necessary for correctness, or can it be scoped/incremental/lazy
  without weakening revocation? What is the exact correctness boundary?

- **RQ6 — Decentralized inbox.** Is a viable IPFS/IPNS/libp2p-native owner→recipient
  delivery mechanism feasible (append-only log, per-pair rendezvous, pubsub, etc.)?
  What are its write-authority, persistence, availability, and privacy properties?
  Can it replace the relay's discovery role, and at what cost?

- **RQ7 — Sharing-graph privacy.** For each candidate, precisely who learns the
  sharing graph (relay, IPFS observers, recipients)? Can exposure be minimized (e.g.
  grants in encrypted metadata rather than plaintext, unlinkable inbox addresses)?

- **RQ8 — Write-plane unification.** Do the write-plane re-mint issues (encoding at
  engine.ts:2833, relay dependency, name churn) have the same root, and should the
  chosen solution cover both planes uniformly?

- **RQ9 — Migration & cutover.** What is the forward-only cutover for the chosen
  target, and what would a future production migration (with legacy shares) require?
  What is the cross-language (Rust/TS) implementation surface?

## 8. Hypotheses to test (falsifiable)

- **H1.** Sealing owner-encrypted grant blobs into node metadata makes re-mint a
  byproduct of the rotation re-seal, eliminating Gap C entirely and removing the
  sweep/inline split — at the cost of O(recipients) metadata that re-publishes on
  rotation.

- **H2.** For non-revoking rotations, new-key-under-old-key chaining in the read-body
  lets current holders (including independently-shared descendants) recover the new
  key with **zero** relay interaction and no public exposure; only revoking rotations
  need out-of-band per-survivor delivery.

- **H3.** Engine-side write-chain key derivation makes file-leaf rotation work
  identically on web and desktop with byte-compatible output, removing the
  `nodeKeySource` divergence — and it is the smaller long-term surface than making
  `nodeKeySource` async + giving web a parent-chain lookup.

- **H4.** A minimal relay reduced to "notify + point" (no key material) preserves all
  current functionality with strictly less trust, provided an acceptable discovery
  mechanism exists.

- **H5.** Whole-subtree rotation can be replaced by root-cut + lazy per-node rekey on
  next access without weakening revocation, materially reducing rotation cost.
  (This one may well be *falsified* — testing the correctness boundary is the point.)

## 9. Prototyping tracks

Each prototype is a throwaway spike validated against the Appendix A scenario and
Appendix B flows. Prefer the smallest artifact that answers its question.

- **P1 — Metadata-sealed grants.** Store ECIES grant blobs in owner-sealed node
  metadata; make rotation re-seal them. Measure: does re-mint disappear as a separate
  step? Metadata size/churn per rotation? Privacy (who can enumerate recipients)?
  Does it cover file leaves for free?

- **P2 — Hygiene-rekey chaining.** Implement new-key-under-old-key delivery in the
  read-body for non-revoking rotations. Verify current holders (incl. Darren/Eugene
  on `b.txt`) recover the new key with no relay call; verify a *revoking* rotation
  correctly falls back to per-survivor ECIES. Measure relay-call elimination rate.

- **P3 — Engine-side write-chain key derivation.** Make the TS rotation walk derive
  file-leaf `writeKey`/`ipnsPrivateKey` from the write-chain (fix Gap B host-agnostically).
  Prove byte-parity of published output with the Rust path; benchmark added
  fetch/unseal cost per file leaf. (This is the one track that could also ship as the
  interim Gap B fix if the sprint decides to keep grants-in-relay.)

- **P4 — Decentralized inbox spike.** Evaluate 2–3 owner→recipient delivery
  mechanisms on IPFS/IPNS/libp2p against a written threat model. Deliverable is a
  feasibility memo + one working proof-of-concept for the most promising option, not
  production code.

- **P5 — Rotation-scope experiment.** Prototype root-cut + lazy per-node rekey and
  compare against whole-subtree rotation on the scenario. Produce a correctness
  argument (or counterexample) for revocation completeness, plus a cost comparison.

## 10. Evaluation framework / decision matrix

Score every candidate architecture across these dimensions (define a rubric per
dimension before scoring; keep evidence, not vibes):

| Dimension | What to measure |
| --- | --- |
| Correctness | Revocation completeness; no silent access loss; no key leak to revoked parties; handles all Appendix B flows |
| Zero-knowledge / privacy | Who learns the sharing graph (relay / IPFS observers / recipients); metadata leakage |
| Decentralization alignment | Residual relay trust; is the relay swappable and integrity-untrusted |
| Complexity | Engine surface; cross-language duplication; cognitive load; number of moving parts |
| Cross-platform parity | Web / desktop-FUSE / Windows behave identically; single source of truth for key sourcing |
| Performance | Rotation cost; metadata churn/size; delivery/poll latency; network round-trips |
| Migration cost & risk | Forward-only cutover effort; future production-migration path; blast radius |

The sprint produces a scored matrix and a single recommended target with rationale.

## 11. Sprint deliverables

1. An **ADR** recommending the target architecture for grant delivery + rotation,
   with the scored decision matrix and explicit tradeoffs.
2. The **prototypes** (P1–P5) with their measurements and threat models.
3. A **de-risked implementation plan** for the recommendation, including the
   cross-language (Rust/TS) surface and the forward-only cutover.
4. A decision on the **interim question**: keep grants-in-relay and ship the Gap B/C
   fixes on the current PR, or freeze that work pending the target. (P3 informs this.)

## 12. Out of scope for this sprint

- Production implementation of the chosen target (that follows the ADR).
- Billing, mobile, real-time collaboration, team accounts (milestone-out-of-scope).
- Changing the content-encryption scheme (AES-256-GCM) or the ECIES key-wrap choice.
- The TEE republishing mechanism (unaffected by grant locus).

## 13. Open questions / unknowns

- Does the "hygiene vs revoking" classification have a clean, tamper-proof definition
  the client can compute, or is it owner-asserted (and thus abusable)?
- Can metadata-sealed grants avoid O(recipients) republish cost via a per-recipient
  side-index that is still owner-sealed and self-certifying?
- Is there an unlinkable inbox address scheme (per owner-recipient pair) that hides
  the sharing graph from the relay without a trusted setup?
- How does file-share pin protection (currently carved out) fit the chosen target —
  does grants-in-metadata make file pins natural?
- What is the interaction with versioning and the version-floor anti-rollback gate
  when keys/fileKeys rotate?

---

## Appendix A — Canonical test scenario

All prototypes validate against this exact setup so results are comparable.

Alice's private vault:

```text
root
├─ folderA
│   ├─ a.txt
│   └─ b.txt
└─ folderB
    ├─ c.txt
    └─ d.txt
```

Shares Alice creates:

- folderA → **Bob** (read-only)
- folderA → **Charlie** (read + write)
- folderA/b.txt → **Darren** (read-only)
- folderA/b.txt → **Eugene** (read + write)

Resulting relay `/shares` rows and metadata state:

| # | recipient | encryptedReadKey | encryptedWriteKey | rootNodeId | shareRootIpnsName |
| --- | --- | --- | --- | --- | --- |
| 1 | Bob | wrap(rk_A) | — | id_A | name_A |
| 2 | Charlie | wrap(rk_A) | wrap(wk_A) | id_A | name_A |
| 3 | Darren | wrap(rk_b) | — | id_b | name_b |
| 4 | Eugene | wrap(rk_b) | wrap(wk_b) | id_b | name_b |

Metadata changes: folderA write-body `recipientPins = [Bob.pub, Charlie.pub]`
(folderA republished per pin). `b.txt` unchanged (file shares add no pins/metadata).
Everything else untouched.

Two structural facts this bakes in:

1. `b.txt` is reachable by **two independent key paths** — Bob/Charlie derive `rk_b`
   from `rk_A` down the read-chain (no b.txt grant), while Darren/Eugene hold `rk_b`
   directly (rows 3/4). folderA's metadata knows nothing about Darren/Eugene.
2. **Asymmetric substitution protection** — folderA grants are pinned; b.txt grants
   are not (file carve-out).

## Appendix B — Reference flow traces

Candidates must produce correct behavior for each.

- **Content edit (no rotation).** Charlie edits `a.txt` content → new version under
  `name_a`; does not touch folderA (a file-content publish never rewrites the parent).
  No rotation.

- **Covered scope-exit mutation (the main event).** Charlie deletes `a.txt` from
  folderA → `rotateReadFromNode(folderA)` rekeys the remaining subtree
  `{folderA, b.txt}`: `rk_A→rk_A'`, `rk_b→rk_b'` (+ fresh `fileKey_b'`); write plane,
  `ik`s, and names unchanged. Re-mint: folderA grants (Bob/Charlie, pin-verified,
  hex) and b.txt grants (Darren/Eugene, file-exempt, hex). **This is where Gap B
  (file-leaf `ik_b`/`wk_b` recovery) and Gap C (hex PATCH) bite, and where Darren/
  Eugene silently lose access to `b.txt` if re-mint doesn't reach them.**

- **Lazy revocation.** Alice revokes Bob → delete row 1; `rk_A` unchanged; the actual
  key cut is deferred to the next covered mutation, which re-mints only survivors.

- **Write revocation (contrast).** Revoking Charlie's write access needs
  `rotateWriteFromNode`: new `ik`/names + tombstones + pointer rewrites in root's refs
  and every affected grant — a much larger cascade than read rotation.

- **Shared-write on a file.** Eugene edits `b.txt` → publishes a new version under
  `name_b` (recovers `ik_b` via `wk_b`); no rotation, does not touch folderA.

## Appendix C — Key code references (as of 2026-07-16)

- `packages/core/src/node/types.ts` — `SealedChildRef`, `WriteChildRef`,
  `NodeWriteBody { ipnsPrivateKey, writeChildren, recipientPins }`.
- `packages/sdk-core/src/rotation/engine.ts`
  - `reMintGrantsRootedAt` (~586) — read-grant re-mint; encoding at ~648 (Gap C,
    fixed base64→hex); file pin carve-out via `nodeKind`.
  - `rotateOne` D-01 IPNS-key guard (~1090) — where file leaves fail closed (Gap B).
  - child enqueue keyed by `nodeKeySource` (~1959); walk driver `rotateReadFromNode`
    (~1323).
  - `rotateWriteFromNode` co-writer re-wrap encoding (~2833) — write-plane sibling.
  - `mintFileKeyOnRotate` (~546); write rotation new keypair/name (~2632).
- `packages/sdk/src/client.ts`
  - `performScopeExitRotation` (~2065) and `nodeKeySource` (folderTree-only, ~2115).
  - `getRecipientPubkeyPins` (~4021), `addRecipientPubkeyPin` (~3969).
  - `resolveChildIdentity` (file share key resolution), `resolveShareEncryptedWriteKey`.
  - file-leaf key recovery pattern (`updateSharedFile`, ~5584) — parent write-body →
    `WriteChildRef` → child `writeKey` → child write-body → `ipnsPrivateKey`.
- `crates/sdk/src/rotation/engine.rs`
  - `re_mint_grants_rooted_at` hex encode (~704, "must be hex, NOT base64").
  - `rotate_one_inner` (~428), `enqueue_child` (~2321), `seal_and_publish` — Rust
    delegates per-node key resolution to `RotationDeps` (host), unlike TS.
- `apps/api/src/shares/shares.controller.ts` — `POST /shares`, `PATCH /shares/:id/grant`
  (`UpdateGrantDto` requires even-length hex), `DELETE /shares/:id`, `GET /shares/{sent,received}`.
- `apps/web/src/services/owner-reconcile.service.ts`,
  `apps/web/src/services/rotation-driver.service.ts` — web re-mint wiring.
- `docs/METADATA_SCHEMAS.md`, `docs/FILESYSTEM_SPECIFICATION.md`,
  `docs/AUTHENTICATION_ARCHITECTURE.md` — canonical model docs.
