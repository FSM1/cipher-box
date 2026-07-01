import { create } from 'zustand';

/**
 * Presentation-only rotation status for the header badge (D-02/D-03).
 *
 * This store does NOT read IndexedDB or drive any crypto operation — it is a
 * plain state machine that downstream driver plans (68-08) call into: on a
 * rotation-triggering mutation, call `beginRootCut()`, then `beginTailWalk()`
 * once the synchronous root step completes, then `reset()` on completion. On
 * page load, the 68-08 driver calls `markResuming()` when a durable
 * in-progress job record is found in `rotation-state.service.ts`.
 */
export type RotationStatus = 'idle' | 'root-cut' | 'tail-walk' | 'resuming';

type RotationState = {
  status: RotationStatus;
  beginRootCut: () => void;
  beginTailWalk: () => void;
  markResuming: () => void;
  reset: () => void;
};

export const useRotationStore = create<RotationState>((set) => ({
  status: 'idle',

  beginRootCut: () => set({ status: 'root-cut' }),

  beginTailWalk: () => set({ status: 'tail-walk' }),

  markResuming: () => set({ status: 'resuming' }),

  reset: () => set({ status: 'idle' }),
}));
