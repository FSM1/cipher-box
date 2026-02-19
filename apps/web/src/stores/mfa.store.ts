import { create } from 'zustand';

type MfaState = {
  /** Whether MFA is active for the current user */
  isMfaEnabled: boolean;
  /** True during enableMFA() call */
  isEnrolling: boolean;
  /** Total factors from getKeyDetails() */
  factorCount: number;
  /** Threshold from getKeyDetails() */
  threshold: number;
  /** Whether user has dismissed the enrollment prompt this session */
  hasSeenPrompt: boolean;

  setMfaEnabled: (enabled: boolean) => void;
  setEnrolling: (enrolling: boolean) => void;
  setFactorDetails: (count: number, threshold: number) => void;
  dismissPrompt: () => void;
  reset: () => void;
};

export const useMfaStore = create<MfaState>((set) => ({
  isMfaEnabled: false,
  isEnrolling: false,
  factorCount: 0,
  threshold: 0,
  hasSeenPrompt: false,

  setMfaEnabled: (enabled) => set({ isMfaEnabled: enabled }),
  setEnrolling: (enrolling) => set({ isEnrolling: enrolling }),
  setFactorDetails: (count, threshold) => set({ factorCount: count, threshold }),
  dismissPrompt: () => set({ hasSeenPrompt: true }),
  reset: () =>
    set({
      isMfaEnabled: false,
      isEnrolling: false,
      factorCount: 0,
      threshold: 0,
      hasSeenPrompt: false,
    }),
}));
