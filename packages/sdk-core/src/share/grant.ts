/**
 * Read-grant issuance and invite-claim re-wrap crypto primitives.
 *
 * Implements READ-01 (issueReadGrant), READ-05 / D-07 (claimInviteReadKey),
 * and D-06 (claimInvite — the full invite-claim service flow).
 *
 * issueReadGrant: ONE ECIES wrap of the share-root readKey → encryptedReadKey.
 *   - ZERO node resolves, ZERO seal/unseal, ZERO IPNS publishes (READ-01 / §3.2).
 *   - Granting a single-file root is structurally identical to granting a deep folder.
 *   - Transport-decoupled behind an injected insertShareFn callback (D-05).
 *
 * claimInviteReadKey: unwrap readKey with URL-fragment ephemeral private key,
 *   re-wrap to claimer's public key → standard grant encryptedReadKey (READ-05 / §3.11).
 *   - Crypto primitive only.
 *   - Emits ONE re-wrapped root readKey — no per-child key fan-out (D-07).
 *
 * claimInvite: full service-flow wrapper around claimInviteReadKey (D-06 / §3.11).
 *   - Fetches invite data via injected getInviteDataFn callback.
 *   - Calls claimInviteReadKey to produce the claimer-wrapped encryptedReadKey.
 *   - Persists ONE standard grant row via injected insertShareFn (D-02 transport seam).
 *   - ONE re-wrapped root readKey per claimer — no per-child key fan-out (D-06).
 */

import { wrapKey, reWrapKey, bytesToBase64, base64ToBytes } from '@cipherbox/crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Grant payload passed to the insertShareFn callback (the D-05 transport seam).
 *
 * The API consumes this to persist a share row; actual shares persistence waits
 * for Phase 66 (the encryptedReadKey column cutover). The callback is injected
 * so unit tests pass a vi.fn() without importing the API client.
 */
export type ReadGrantPayload = {
  /** Recipient's 65-byte uncompressed secp256k1 public key. */
  recipientPublicKey: Uint8Array;
  /** UUID of the grant root node (folder or file — structurally identical). */
  rootNodeId: string;
  /** IPNS k51 name of the grant root node. */
  shareRootIpnsName: string;
  /** Node generation at which this grant is anchored (staleness witness). */
  rootGeneration: number;
  /** Base64-encoded ECIES-wrapped share-root readKey (the grant encrypted key). */
  encryptedReadKey: string;
};

// ---------------------------------------------------------------------------
// issueReadGrant — READ-01 / §3.2
// ---------------------------------------------------------------------------

/**
 * Issue a read grant by ECIES-wrapping the share-root readKey under the
 * recipient's secp256k1 public key.
 *
 * ONE ECIES wrap → encryptedReadKey. Zero node resolves, zero seal/unseal,
 * zero IPNS publishes. Granting a single-file root is structurally identical
 * to granting a deep folder (READ-01 / §3.2): the grant always covers
 * whatever subtree is rooted at rootNodeId, regardless of tree depth.
 *
 * The API call is injected as `insertShareFn` so unit tests can pass a
 * vi.fn() mock without any API-client coupling (D-05 transport-decoupled seam).
 *
 * @param params.shareRootReadKey - 32-byte AES-256 read key for the grant root node
 * @param params.recipientPublicKey - 65-byte uncompressed secp256k1 public key
 * @param params.rootNodeId - UUID of the grant root node
 * @param params.shareRootIpnsName - IPNS k51 name of the grant root node
 * @param params.rootGeneration - Node generation at grant issuance (staleness witness)
 * @param params.insertShareFn - Injected callback that persists the grant row and
 *   returns the assigned shareId. Never called on crypto failure.
 *
 * @returns `{ shareId, encryptedReadKey }` — the assigned share identifier and
 *   the base64 ECIES-wrapped grant encrypted key.
 *
 * @security Does NOT zero `shareRootReadKey` — the caller is the terminal owner
 *   of that buffer and must zero it on their own lifecycle boundary (D-09).
 */
export async function issueReadGrant(params: {
  shareRootReadKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  rootNodeId: string;
  shareRootIpnsName: string;
  rootGeneration: number;
  insertShareFn: (payload: ReadGrantPayload) => Promise<{ shareId: string }>;
}): Promise<{ shareId: string; encryptedReadKey: string }> {
  // Input validation — reject malformed keys before any crypto work or persistence.
  if (params.shareRootReadKey.length !== 32) {
    throw new Error(
      `issueReadGrant: shareRootReadKey must be 32 bytes, got ${params.shareRootReadKey.length}`
    );
  }
  if (params.recipientPublicKey.length !== 65) {
    throw new Error(
      `issueReadGrant: recipientPublicKey must be 65 bytes (uncompressed secp256k1), got ${params.recipientPublicKey.length}`
    );
  }
  if (!Number.isInteger(params.rootGeneration) || params.rootGeneration < 0) {
    throw new Error(
      `issueReadGrant: rootGeneration must be a non-negative integer, got ${params.rootGeneration}`
    );
  }

  // ONE ECIES wrap — the only crypto op in grant issuance (READ-01).
  // wrapKey: secp256k1 ECDH ephemeral + HKDF + AES-GCM. Each call produces
  // a fresh ciphertext; the recipient's private key is the sole decryption key.
  let wrapped: Uint8Array;
  try {
    wrapped = await wrapKey(params.shareRootReadKey, params.recipientPublicKey);
  } catch (err) {
    throw new Error('issueReadGrant: key wrapping failed', { cause: err });
  }
  const encryptedReadKey = bytesToBase64(wrapped);

  // Persist the grant row via the injected callback (D-05 transport seam).
  const result = await params.insertShareFn({
    recipientPublicKey: params.recipientPublicKey,
    rootNodeId: params.rootNodeId,
    shareRootIpnsName: params.shareRootIpnsName,
    rootGeneration: params.rootGeneration,
    encryptedReadKey,
  });

  return { shareId: result.shareId, encryptedReadKey };
}

// ---------------------------------------------------------------------------
// claimInviteReadKey — READ-05 / D-07 / §3.11
// ---------------------------------------------------------------------------

/**
 * Invite-claim re-wrap primitive.
 *
 * Unwraps the share-root readKey from the URL-fragment ephemeral private key
 * and re-wraps it under the claimer's secp256k1 public key, producing a
 * standard grant encryptedReadKey (identical in shape to issueReadGrant's output).
 *
 * This is a crypto primitive only. Full invite create/claim service wiring
 * (link generation, invite row storage, server-side re-wrap coordination) is
 * deferred to Phase 65 (D-07). No per-child key fan-out array is produced
 * here or elsewhere in this module (D-07 / T-63-07).
 *
 * ADR 0002: read-revocation protects future content only. A replayed invite
 * link re-wraps the same root readKey per claimer; revocation is achieved via
 * rotation (Plan 03/05), not link invalidation (T-63-06 / §3.11).
 *
 * @param params.encryptedReadKey - Base64 ECIES-wrapped share-root readKey
 *   from the invite link (encrypted to the URL-fragment ephemeral public key)
 * @param params.ephemeralPrivateKey - 32-byte secp256k1 private key from the
 *   URL fragment; caller-owned, NOT zeroed here (D-09)
 * @param params.claimerPublicKey - 65-byte uncompressed secp256k1 public key
 *   of the claimer; caller-owned, NOT zeroed here (D-09)
 *
 * @returns Base64 encryptedReadKey encrypted to the claimer's public key —
 *   the input to a standard grant row (same shape as issueReadGrant's output).
 *
 * @security This function MINTS the intermediate share-root readKey buffer.
 *   It is the terminal owner of that intermediate. `reWrapKey` zeroes the
 *   intermediate on both the success and failure (catch) paths, so it is
 *   never left in memory after use (T-63-05 mitigation). Caller-supplied
 *   `ephemeralPrivateKey` and `claimerPublicKey` are NEVER zeroed here (D-09).
 */
export async function claimInviteReadKey(params: {
  encryptedReadKey: string;
  ephemeralPrivateKey: Uint8Array;
  claimerPublicKey: Uint8Array;
}): Promise<string> {
  // Input validation — reject malformed keys before any crypto work.
  if (params.ephemeralPrivateKey.length !== 32) {
    throw new Error(
      `claimInviteReadKey: ephemeralPrivateKey must be 32 bytes (secp256k1 private key), got ${params.ephemeralPrivateKey.length}`
    );
  }
  if (params.claimerPublicKey.length !== 65) {
    throw new Error(
      `claimInviteReadKey: claimerPublicKey must be 65 bytes (uncompressed secp256k1), got ${params.claimerPublicKey.length}`
    );
  }

  let inviteWrapped: Uint8Array;
  try {
    inviteWrapped = base64ToBytes(params.encryptedReadKey);
  } catch (err) {
    throw new Error('claimInviteReadKey: failed to decode encryptedReadKey', { cause: err });
  }

  // reWrapKey: unwrap with ephemeralPrivateKey → share-root readKey (intermediate,
  // minted here), then re-wrap with claimerPublicKey. The intermediate is zeroed
  // in reWrapKey's finally block — this function delegates terminal ownership
  // of that buffer to reWrapKey (T-63-05).
  let claimerWrapped: Uint8Array;
  try {
    claimerWrapped = await reWrapKey(
      inviteWrapped,
      params.ephemeralPrivateKey,
      params.claimerPublicKey
    );
  } catch (err) {
    throw new Error('claimInviteReadKey: key re-wrap failed', { cause: err });
  }

  return bytesToBase64(claimerWrapped);
}

// ---------------------------------------------------------------------------
// claimInvite — D-06 / §3.11 full service flow
// ---------------------------------------------------------------------------

/**
 * Invite-claim service flow.
 *
 * Fetches invite data via an injected callback, re-wraps the share-root readKey
 * to the claimer's public key using the existing `claimInviteReadKey` primitive,
 * and persists a single standard grant row via an injected `insertShareFn`.
 *
 * Per D-06: ONE re-wrapped root readKey per claimer; a multi-claim invite mints
 * one standard grant per claimer of the same readKey. Revocation is achieved by
 * rotating the readKey (Plan 06 / ADR 0002), not by link invalidation.
 *
 * All transport is injected as callbacks (D-02 mock seam):
 * - `getInviteDataFn` is called once with `inviteToken` to obtain the invite's
 *   encryptedReadKey (ECIES-wrapped to the URL-fragment ephemeral public key).
 * - `insertShareFn` is called exactly once to persist the claimer's grant row.
 *   It is NEVER called on crypto failure.
 *
 * Emits ONE re-wrapped root readKey — no per-child key fan-out (D-06 / §3.11).
 * The generated api-client models retain the legacy column for Phase 66 cutover only.
 *
 * @param params.inviteToken - Opaque invite token (passed to getInviteDataFn)
 * @param params.ephemeralPrivateKey - 32-byte secp256k1 private key from URL fragment;
 *   caller-owned, NOT zeroed here (D-09)
 * @param params.claimerPublicKey - 65-byte uncompressed secp256k1 public key of the claimer;
 *   caller-owned, NOT zeroed here (D-09)
 * @param params.rootNodeId - UUID of the grant root node
 * @param params.shareRootIpnsName - IPNS k51 name of the grant root node
 * @param params.rootGeneration - Node generation at which this grant is anchored
 * @param params.getInviteDataFn - Injected callback: receives inviteToken, returns { encryptedReadKey }
 * @param params.insertShareFn - Injected callback: persists the standard grant row, returns { shareId }
 *
 * @returns `{ shareId, encryptedReadKey }` — the assigned share identifier and the
 *   base64 ECIES-wrapped grant encrypted key re-encrypted to the claimer's public key.
 */
export async function claimInvite(params: {
  inviteToken: string;
  ephemeralPrivateKey: Uint8Array;
  claimerPublicKey: Uint8Array;
  rootNodeId: string;
  shareRootIpnsName: string;
  rootGeneration: number;
  getInviteDataFn: (token: string) => Promise<{ encryptedReadKey: string }>;
  insertShareFn: (payload: ReadGrantPayload) => Promise<{ shareId: string }>;
}): Promise<{ shareId: string; encryptedReadKey: string }> {
  // Input validation — reject malformed keys before any I/O or crypto work.
  if (params.ephemeralPrivateKey.length !== 32) {
    throw new Error(
      `claimInvite: ephemeralPrivateKey must be 32 bytes (secp256k1 private key), got ${params.ephemeralPrivateKey.length}`
    );
  }
  if (params.claimerPublicKey.length !== 65) {
    throw new Error(
      `claimInvite: claimerPublicKey must be 65 bytes (uncompressed secp256k1), got ${params.claimerPublicKey.length}`
    );
  }
  if (!Number.isInteger(params.rootGeneration) || params.rootGeneration < 0) {
    throw new Error(
      `claimInvite: rootGeneration must be a non-negative integer, got ${params.rootGeneration}`
    );
  }
  if (params.inviteToken.trim().length === 0) {
    throw new Error('claimInvite: inviteToken must be non-empty');
  }
  if (params.rootNodeId.trim().length === 0) {
    throw new Error('claimInvite: rootNodeId must be non-empty');
  }
  if (params.shareRootIpnsName.trim().length === 0) {
    throw new Error('claimInvite: shareRootIpnsName must be non-empty');
  }

  // Snapshot trimmed root identifiers (FIX #12: persist trimmed, not raw whitespace-padded input).
  const rootNodeId = params.rootNodeId.trim();
  const shareRootIpnsName = params.shareRootIpnsName.trim();

  // Snapshot key buffers BEFORE the first await so a caller that reuses or zeroes
  // these Uint8Arrays mid-await cannot corrupt the subsequent re-wrap (FIX #11).
  // We own the copies; ephemeralPrivateKeyCopy is zeroed in the finally block below.
  const ephemeralPrivateKeyCopy = params.ephemeralPrivateKey.slice();
  const claimerPublicKeyCopy = params.claimerPublicKey.slice();

  try {
    // Step 1: Fetch invite data via the injected transport callback (D-02).
    const inviteData = await params.getInviteDataFn(params.inviteToken);

    // Step 2: Re-wrap using snapshotted buffers (not caller-owned params).
    // Delegates to the existing claimInviteReadKey primitive — NOT reimplemented here (D-07).
    // The intermediate readKey buffer is zeroed inside reWrapKey (T-63-05).
    const claimerEncryptedReadKey = await claimInviteReadKey({
      encryptedReadKey: inviteData.encryptedReadKey,
      ephemeralPrivateKey: ephemeralPrivateKeyCopy,
      claimerPublicKey: claimerPublicKeyCopy,
    });

    // Step 3: Persist ONE standard grant row via the injected callback (D-02).
    // The payload shape is identical to issueReadGrant's output — ONE root readKey only.
    const result = await params.insertShareFn({
      recipientPublicKey: claimerPublicKeyCopy,
      rootNodeId,
      shareRootIpnsName,
      rootGeneration: params.rootGeneration,
      encryptedReadKey: claimerEncryptedReadKey,
    });

    return { shareId: result.shareId, encryptedReadKey: claimerEncryptedReadKey };
  } finally {
    // Zero our owned copy of the ephemeral private key (caller-owned params.ephemeralPrivateKey
    // is NOT zeroed here per D-09 — we only zero the copy minted above).
    ephemeralPrivateKeyCopy.fill(0);
  }
}
