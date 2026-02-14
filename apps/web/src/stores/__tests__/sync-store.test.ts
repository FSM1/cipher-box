import { describe, it, expect, beforeEach } from 'vitest';
import { useSyncStore } from '../sync.store';

describe('Sync Store', () => {
  beforeEach(() => {
    useSyncStore.getState().reset();
  });

  it('starts with initialSyncComplete = false', () => {
    expect(useSyncStore.getState().initialSyncComplete).toBe(false);
  });

  it('completeInitialSync sets initialSyncComplete to true', () => {
    useSyncStore.getState().completeInitialSync();
    expect(useSyncStore.getState().initialSyncComplete).toBe(true);
  });

  it('reset clears initialSyncComplete back to false', () => {
    useSyncStore.getState().completeInitialSync();
    expect(useSyncStore.getState().initialSyncComplete).toBe(true);

    useSyncStore.getState().reset();
    expect(useSyncStore.getState().initialSyncComplete).toBe(false);
  });

  it('full lifecycle: idle → syncing → success → complete → reset', () => {
    const store = useSyncStore;

    // Initial state
    expect(store.getState().status).toBe('idle');
    expect(store.getState().initialSyncComplete).toBe(false);

    // Start sync
    store.getState().startSync();
    expect(store.getState().status).toBe('syncing');
    expect(store.getState().syncError).toBeNull();

    // Sync succeeds
    store.getState().syncSuccess();
    expect(store.getState().status).toBe('success');
    expect(store.getState().lastSyncTime).toBeInstanceOf(Date);

    // Mark initial sync complete
    store.getState().completeInitialSync();
    expect(store.getState().initialSyncComplete).toBe(true);

    // Reset (logout)
    store.getState().reset();
    expect(store.getState().status).toBe('idle');
    expect(store.getState().lastSyncTime).toBeNull();
    expect(store.getState().syncError).toBeNull();
    expect(store.getState().initialSyncComplete).toBe(false);
  });

  it('syncFailure does not mark initialSyncComplete', () => {
    useSyncStore.getState().startSync();
    useSyncStore.getState().syncFailure('Network error');

    expect(useSyncStore.getState().status).toBe('error');
    expect(useSyncStore.getState().syncError).toBe('Network error');
    expect(useSyncStore.getState().initialSyncComplete).toBe(false);
  });
});
