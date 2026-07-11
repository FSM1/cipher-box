import { create } from 'zustand';

/**
 * A received share from another CipherBox user.
 *
 * v2.0 grant shape (Phase 68 / ROT-07): the API now returns encrypted-key +
 * generation fields (`encryptedReadKey`, `rootGeneration`, `rootNodeId`)
 * instead of the legacy per-share wrapped key (`encryptedKey`/
 * `encryptedIpnsKey`). `encryptedKey` is kept (optional, unpopulated) for
 * back-compat since nothing in the web app reads it anymore — the
 * encrypted-key path replaces the per-mutation key fan-out entirely (SC#2).
 * The legacy `encryptedIpnsKey` field (paired with the now-removed
 * `updateSharePermission` orphaned wrapper) was dropped entirely (77-06).
 * `itemType` has no source in the v2.0 DTO (the Node model no longer exposes
 * a file/folder discriminant at the grant layer) and is left optional/
 * undefined until a real data path exists.
 */
export type ReceivedShare = {
  shareId: string;
  sharerPublicKey: string;
  /** @deprecated no source in the v2.0 grant DTO; undefined until re-derived */
  itemType?: 'folder' | 'file';
  ipnsName: string;
  /** Decrypted display name (plaintext projection; never persisted in this form) */
  itemName: string;
  /** Hex-encoded ECIES ciphertext of the display name (wrapped for this recipient) */
  itemNameEncrypted?: string | null;
  /** @deprecated legacy per-share wrapped key; superseded by encryptedReadKey (SC#2) */
  encryptedKey?: string;
  /** Permission level: read-only or read-write (derived from encryptedWriteKey presence) */
  permission: 'read' | 'write';
  createdAt: string;
  /** Hex-encoded ECIES encrypted key for read access (D-07 grant data path) */
  encryptedReadKey: string;
  /**
   * Hex-encoded ECIES encrypted key for write access, or null for read-only
   * shares (68.1-20, SHARE-WRITE-KEY recipient side). Unwrapped with the
   * recipient's vault private key to recover the shared-root writeKey on
   * navigation entry — never persisted unwrapped.
   */
  encryptedWriteKey?: string | null;
  /**
   * Generation of the root node at share creation. Parsed from the DTO's
   * numeric string with an isFinite guard — a non-numeric/absent value is
   * `undefined`, never coerced to NaN/0 (V5 fail-closed floor seed, T-68-21).
   */
  rootGeneration?: number;
  /** UUID of the root shared node (D-07 grant data path) */
  rootNodeId: string;
};

/**
 * A share sent by the current user to another CipherBox user.
 *
 * v2.0 grant shape (Phase 68 / ROT-07) — see {@link ReceivedShare} doc for
 * the legacy-field back-compat rationale.
 */
export type SentShare = {
  shareId: string;
  recipientPublicKey: string;
  /** @deprecated no source in the v2.0 grant DTO; undefined until re-derived */
  itemType?: 'folder' | 'file';
  ipnsName: string;
  /** Display name (plaintext projection for the owner's own list) */
  itemName: string;
  /** Hex-encoded ECIES ciphertext of the display name (wrapped for the recipient) */
  itemNameEncrypted?: string | null;
  /** Permission level: read-only or read-write (derived from encryptedWriteKey presence) */
  permission: 'read' | 'write';
  createdAt: string;
  /** Hex-encoded ECIES encrypted key for read access (D-07 grant data path) */
  encryptedReadKey: string;
  /**
   * Generation of the root node at share creation. Parsed from the DTO's
   * numeric string with an isFinite guard — a non-numeric/absent value is
   * `undefined`, never coerced to NaN/0 (V5 fail-closed floor seed, T-68-21).
   */
  rootGeneration?: number;
  /** UUID of the root shared node (D-07 grant data path) */
  rootNodeId: string;
};

type ShareState = {
  receivedShares: ReceivedShare[];
  sentShares: SentShare[];
  isLoadingReceived: boolean;
  isLoadingSent: boolean;
  lastReceivedFetchedAt: number | null;
  lastSentFetchedAt: number | null;

  // Actions
  setReceivedShares: (shares: ReceivedShare[]) => void;
  setSentShares: (shares: SentShare[]) => void;
  setLoadingReceived: (loading: boolean) => void;
  setLoadingSent: (loading: boolean) => void;
  addSentShare: (share: SentShare) => void;
  removeSentShare: (shareId: string) => void;
  removeReceivedShare: (shareId: string) => void;
  updateSentSharePermission: (shareId: string, permission: 'read' | 'write') => void;
  clearShares: () => void;
};

/**
 * Share store for managing sent/received share state.
 *
 * Maintains the in-memory lists of shares the user has
 * sent to others and received from others.
 *
 * Call clearShares() on logout to reset state.
 */
export const useShareStore = create<ShareState>((set) => ({
  // State
  receivedShares: [],
  sentShares: [],
  isLoadingReceived: false,
  isLoadingSent: false,
  lastReceivedFetchedAt: null,
  lastSentFetchedAt: null,

  // Actions
  setReceivedShares: (shares) =>
    set({ receivedShares: shares, isLoadingReceived: false, lastReceivedFetchedAt: Date.now() }),

  setSentShares: (shares) =>
    set({ sentShares: shares, isLoadingSent: false, lastSentFetchedAt: Date.now() }),

  setLoadingReceived: (loading) => set({ isLoadingReceived: loading }),

  setLoadingSent: (loading) => set({ isLoadingSent: loading }),

  addSentShare: (share) =>
    set((state) => ({
      sentShares: [...state.sentShares, share],
    })),

  removeSentShare: (shareId) =>
    set((state) => ({
      sentShares: state.sentShares.filter((s) => s.shareId !== shareId),
    })),

  removeReceivedShare: (shareId) =>
    set((state) => ({
      receivedShares: state.receivedShares.filter((s) => s.shareId !== shareId),
    })),

  updateSentSharePermission: (shareId, permission) =>
    set((state) => ({
      sentShares: state.sentShares.map((s) => (s.shareId === shareId ? { ...s, permission } : s)),
    })),

  clearShares: () =>
    set({
      receivedShares: [],
      sentShares: [],
      isLoadingReceived: false,
      isLoadingSent: false,
      lastReceivedFetchedAt: null,
      lastSentFetchedAt: null,
    }),
}));
