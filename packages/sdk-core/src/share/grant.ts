/**
 * Read-grant issuance and invite-claim re-wrap crypto primitives.
 *
 * Implements READ-01 (issueReadGrant) and READ-05 / D-07 (claimInviteReadKey).
 *
 * issueReadGrant: ONE ECIES wrap of the share-root readKey → readDescriptorRef.
 *   - ZERO node resolves, ZERO seal/unseal, ZERO IPNS publishes (READ-01 / §3.2).
 *   - Granting a single-file root is structurally identical to granting a deep folder.
 *   - Transport-decoupled behind an injected insertShareFn callback (D-05).
 *
 * claimInviteReadKey: unwrap readKey with URL-fragment ephemeral private key,
 *   re-wrap to claimer's public key → standard grant readDescriptorRef (READ-05 / §3.11).
 *   - Crypto primitive only; full service wiring deferred to Phase 65 (D-07).
 *   - Emits ONE re-wrapped root readKey — no per-child key fan-out (D-07).
 */

import { wrapKey, reWrapKey } from '@cipherbox/crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Grant payload passed to the insertShareFn callback (the D-05 transport seam).
 *
 * The API consumes this to persist a share row; actual shares persistence waits
 * for Phase 66 (the readDescriptorRef column cutover). The callback is injected
 * so unit tests pass a vi.fn() without importing the API client.
 */
export type ReadGrantPayload = {
  /** Recipient's 65-byte uncompressed secp256k1 public key. */
  recipientPublicKey: Uint8Array;
  /** UUID of the grant root node (folder or file — structurally identical). */
  rootNodeId: string;
  /** IPNS k51 name of the grant root node. */
  rootIpnsName: string;
  /** Node generation at which this grant is anchored (staleness witness). */
  rootGeneration: number;
  /** Base64-encoded ECIES-wrapped share-root readKey (the grant descriptor). */
  readDescriptorRef: string;
};

// ---------------------------------------------------------------------------
// Internal encoding helpers
// ---------------------------------------------------------------------------

/**
 * Encodes a Uint8Array to a base64 string.
 * Processes in chunks to avoid call-stack overflow on large ECIES ciphertexts.
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunkSize, bytes.length)));
  }
  return btoa(binary);
}

/** Decodes a base64 string to a Uint8Array. */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// issueReadGrant — READ-01 / §3.2
// ---------------------------------------------------------------------------

/**
 * Issue a read grant by ECIES-wrapping the share-root readKey under the
 * recipient's secp256k1 public key.
 *
 * ONE ECIES wrap → readDescriptorRef. Zero node resolves, zero seal/unseal,
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
 * @param params.rootIpnsName - IPNS k51 name of the grant root node
 * @param params.rootGeneration - Node generation at grant issuance (staleness witness)
 * @param params.insertShareFn - Injected callback that persists the grant row and
 *   returns the assigned shareId. Never called on crypto failure.
 *
 * @returns `{ shareId, readDescriptorRef }` — the assigned share identifier and
 *   the base64 ECIES-wrapped grant descriptor.
 *
 * @security Does NOT zero `shareRootReadKey` — the caller is the terminal owner
 *   of that buffer and must zero it on their own lifecycle boundary (D-09).
 */
export async function issueReadGrant(params: {
  shareRootReadKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  rootNodeId: string;
  rootIpnsName: string;
  rootGeneration: number;
  insertShareFn: (payload: ReadGrantPayload) => Promise<{ shareId: string }>;
}): Promise<{ shareId: string; readDescriptorRef: string }> {
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
  const readDescriptorRef = bytesToBase64(wrapped);

  // Persist the grant row via the injected callback (D-05 transport seam).
  const result = await params.insertShareFn({
    recipientPublicKey: params.recipientPublicKey,
    rootNodeId: params.rootNodeId,
    rootIpnsName: params.rootIpnsName,
    rootGeneration: params.rootGeneration,
    readDescriptorRef,
  });

  return { shareId: result.shareId, readDescriptorRef };
}

// ---------------------------------------------------------------------------
// claimInviteReadKey — READ-05 / D-07 / §3.11
// ---------------------------------------------------------------------------

/**
 * Invite-claim re-wrap primitive.
 *
 * Unwraps the share-root readKey from the URL-fragment ephemeral private key
 * and re-wraps it under the claimer's secp256k1 public key, producing a
 * standard grant readDescriptorRef (identical in shape to issueReadGrant's output).
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
 * @param params.readDescriptorRef - Base64 ECIES-wrapped share-root readKey
 *   from the invite link (encrypted to the URL-fragment ephemeral public key)
 * @param params.ephemeralPrivateKey - 32-byte secp256k1 private key from the
 *   URL fragment; caller-owned, NOT zeroed here (D-09)
 * @param params.claimerPublicKey - 65-byte uncompressed secp256k1 public key
 *   of the claimer; caller-owned, NOT zeroed here (D-09)
 *
 * @returns Base64 readDescriptorRef encrypted to the claimer's public key —
 *   the input to a standard grant row (same shape as issueReadGrant's output).
 *
 * @security This function MINTS the intermediate share-root readKey buffer.
 *   It is the terminal owner of that intermediate. `reWrapKey` zeroes the
 *   intermediate on both the success and failure (catch) paths, so it is
 *   never left in memory after use (T-63-05 mitigation). Caller-supplied
 *   `ephemeralPrivateKey` and `claimerPublicKey` are NEVER zeroed here (D-09).
 */
export async function claimInviteReadKey(params: {
  readDescriptorRef: string;
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
    inviteWrapped = base64ToBytes(params.readDescriptorRef);
  } catch (err) {
    throw new Error('claimInviteReadKey: failed to decode readDescriptorRef', { cause: err });
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
