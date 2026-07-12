/**
 * @cipherbox/core - Unified Node Type Model (v3)
 *
 * Defines the canonical Node type replacing legacy FolderMetadata / FileMetadata /
 * FilePointer / FolderEntry shapes. All metadata trees are modelled as a discriminated
 * union keyed on `kind` so the read-chain and rotation logic share a single code path.
 *
 * Design references: 2026-06-26-sharing-read-keychaining-design.md §2.3, §2.4, §2.6
 * Requirements: NODE-01, NODE-02, NODE-03, NODE-04
 */

// ---------------------------------------------------------------------------
// Scalar unions (string literals — no TS enums per project convention)
// ---------------------------------------------------------------------------

/** Discriminator for the three node kinds. */
export type NodeKind = 'folder' | 'file' | 'root';

/**
 * Encryption mode used for file content and version entries.
 * Both modes must survive codec round-trip (NODE-02).
 */
export type EncryptionMode = 'GCM' | 'CTR';

// ---------------------------------------------------------------------------
// Version history
// ---------------------------------------------------------------------------

/**
 * One historical version of a file node's content.
 *
 * `fileKey` is a raw 32-byte AES key **inside** the sealed read-body —
 * it is NOT an ECIES hex string (semantic type change from the legacy model, D-07/NODE-02).
 * `encryptionMode` is mandatory; do not normalise to GCM-only (CTR drives range reads).
 */
export type VersionEntry = {
  versionId: string;
  cid: string;
  fileIv: string;
  size: number;
  createdAt: number;
  /** Mandatory: 'GCM' (default) or 'CTR' (large-file range reads). */
  encryptionMode: EncryptionMode;
  /** Raw 32-byte AES key; stored inside the sealed body — never ECIES-wrapped here. */
  fileKey: Uint8Array;
};

// ---------------------------------------------------------------------------
// File content
// ---------------------------------------------------------------------------

/**
 * Content descriptor for a file node (read-body, sealed under the file node's readKey).
 *
 * `fileKey` and each `VersionEntry.fileKey` are raw 32-byte AES keys (D-07/NODE-02).
 */
export type NodeContent = {
  cid: string;
  fileIv: string;
  size: number;
  mimeType: string;
  /** Mandatory: 'GCM' or 'CTR'. */
  encryptionMode: EncryptionMode;
  /** Raw 32-byte AES key; stored inside the sealed body. */
  fileKey: Uint8Array;
  versions: VersionEntry[];
};

// ---------------------------------------------------------------------------
// Read-chain link (read-only — no write field)
// ---------------------------------------------------------------------------

/**
 * A sealed reference to a child node stored inside the parent's read-body.
 *
 * Field set is FROZEN to exactly {name, ipnsName, generation, versionFloor,
 * readKeySealed} — NO `writeKeySealed`, `size`, `modifiedAt`, or any other
 * write/display field (NODE-03, design §2.2/§2.6). A prior interim revision
 * (commit ba3e0229a) added optional `size`/`modifiedAt` display mirrors;
 * these were reverted (D-08/68.2-12) in favor of `ResolvedChild`
 * (`@cipherbox/sdk`'s `folder-listing.ts`), which resolves each child's own
 * Node once per folder-load instead of maintaining a second, independently
 * stale mirror inside the parent's sealed read-body.
 *
 * `versionFloor` is a bigint matching the IPNS sequenceNumber convention (D-08).
 * `generation` is a convergence/staleness witness mirror; the authoritative value
 * lives on the child's own published envelope (design §2.7).
 */
export type SealedChildRef = {
  /** Display name of the child (plaintext within the sealed parent read-body). */
  name: string;
  /** IPNS k51 name of the child node. */
  ipnsName: string;
  /**
   * Staleness witness for the child's read-key epoch (D-07 invariant 1).
   * Never used as an independent source; only compared against the child envelope.
   * Range: [0, 2^32-1] integers (u32-safe).
   */
  generation: number;
  /**
   * Owner-vouched IPNS sequence-number floor, bound at (re)share (design §6.5).
   * bigint: mirrors IPNS sequenceNumber type convention.
   */
  versionFloor: bigint;
  /**
   * AES-GCM seal of the child's readKey under the parent readKey.
   * Base64; AAD role = 0x02 child-readkey.
   */
  readKeySealed: string;
};

// ---------------------------------------------------------------------------
// Write-body (sealed separately under the node's writeKey)
// ---------------------------------------------------------------------------

/**
 * Write-chain link stored inside the parent's write-body.
 * The `writeKeySealed` conveys the child's writeKey sealed under the parent writeKey.
 * This field is NEVER in SealedChildRef (NODE-03, design §2.2).
 */
export type WriteChildRef = {
  /** Hyphenated UUID of the child node. */
  childId: string;
  /**
   * AES-GCM seal of the child's writeKey under the parent writeKey.
   * Base64; AAD role = 0x04 child-writekey.
   */
  writeKeySealed: string;
};

/**
 * Write-body for a node — sealed under the node's writeKey (separate from readKey).
 * Absent on read-only nodes (the read grant never conveys writeKey).
 */
export type NodeWriteBody = {
  /** Raw Ed25519 signing seed (inside the sealed write-body — never exposed in read grants). */
  ipnsPrivateKey: Uint8Array;
  /** Write chain to child nodes; mirrors the read chain in SealedChildRef. */
  writeChildren: WriteChildRef[];
  /**
   * Recipient-pubkey pins bound at share/re-mint (D-03b) — each entry a raw
   * compressed secp256k1 public key, base64-encoded on the wire.
   *
   * Additive OPTIONAL field (METADATA_EVOLUTION_PROTOCOL §3.1): omitted from the
   * wire when absent or empty so the frozen empty-pin KAT (seal_vectors[0]) is
   * preserved byte-for-byte, and defaulted to `[]` on decode so older/newer
   * readers never fail-closed on it. Twin of the Rust
   * `NodeWriteBody.recipient_pins` (`Vec<Vec<u8>>`, base64 `recipientPins` wire).
   */
  recipientPins?: string[];
};

// ---------------------------------------------------------------------------
// Unified Node (discriminated by kind)
// ---------------------------------------------------------------------------

/**
 * The unified in-memory Node shape (decrypted, plaintext).
 *
 * `generation` is a per-node read-key rotation clock in [0, 2^32-1].
 * Range is enforced fail-closed in `decodeReadBody` / `validateNode` (D-08, NODE-04),
 * mirroring the guard in `buildNodeAad`.
 *
 * `children` is present for folder/root kinds; `content` is present for file kind.
 * `writeBody` is omitted on read-only nodes (the read grant never delivers writeKey).
 */
export type Node = {
  schema: 'node/v3';
  kind: NodeKind;
  /** Hyphenated UUID (RFC-4122). */
  id: string;
  /**
   * Per-node read-key rotation clock.
   * Must be a non-negative integer ≤ 0xffffffff (u32-safe, D-08).
   */
  generation: number;
  createdAt: number;
  modifiedAt: number;
  /** Sealed references to child nodes; present for folder and root kinds. */
  children?: SealedChildRef[];
  /** File content descriptor; present for file kind only. */
  content?: NodeContent;
  /** Write-body (IPNS signing material + write-chain); absent on read-only nodes. */
  writeBody?: NodeWriteBody;
};

// ---------------------------------------------------------------------------
// Published envelope (plaintext wrapper over the two sealed bodies)
// ---------------------------------------------------------------------------

/**
 * The on-wire published node as stored in IPFS/IPNS.
 *
 * `schema`, `kind`, `id`, `generation`, and `aeadVersion` are plaintext and AAD inputs
 * (tamper-evident via the IPNS signature chain). `readSealed` and `writeSealed` are the
 * two AES-256-GCM sealed bodies (design §2.4, NODE-04).
 */
export type PublishedNode = {
  schema: 'node/v3';
  kind: NodeKind;
  /** Hyphenated UUID. */
  id: string;
  /** Plaintext + AAD-bound generation; lets honest readers detect staleness. */
  generation: number;
  /** AEAD primitive version tag (always 1 for this implementation). */
  aeadVersion: 1;
  /**
   * Base64 of IV ‖ ciphertext ‖ tag for the read-body.
   * Sealed with AES-256-GCM; AAD = buildNodeAad(id, kind, generation, role=0x01 body).
   */
  readSealed: string;
  /**
   * Base64 of IV ‖ ciphertext ‖ tag for the write-body.
   * Absent on read-only nodes (no writeKey).
   * Sealed with AES-256-GCM under writeKey; same role byte 0x01.
   */
  writeSealed?: string;
};
