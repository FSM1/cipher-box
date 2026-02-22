import { create } from 'zustand';

/**
 * A received share from another CipherBox user.
 * Contains the ECIES-wrapped item key for decryption.
 */
export type ReceivedShare = {
  shareId: string;
  sharerPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  itemName: string;
  /** Hex-encoded ECIES ciphertext of the item key */
  encryptedKey: string;
  createdAt: string;
};

/**
 * A share sent by the current user to another CipherBox user.
 * Does not contain the encrypted key (sharer already has access).
 */
export type SentShare = {
  shareId: string;
  recipientPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  itemName: string;
  createdAt: string;
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
