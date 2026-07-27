import { afterEach, describe, expect, it, vi } from 'vitest';

import { requestStoragePersistence } from './storagePersistence.js';

function mount(storage: unknown): void {
  vi.stubGlobal('navigator', { storage });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('requestStoragePersistence', () => {
  it('reports denied when the browser has no StorageManager', async () => {
    mount(undefined);
    expect(await requestStoragePersistence()).toBe(false);
  });

  it('does not re-request once the origin is already persistent', async () => {
    const persist = vi.fn(() => Promise.resolve(false));
    mount({ persisted: () => Promise.resolve(true), persist });

    expect(await requestStoragePersistence()).toBe(true);
    expect(persist).not.toHaveBeenCalled();
  });

  it('requests the grant and reports the answer', async () => {
    mount({ persisted: () => Promise.resolve(false), persist: () => Promise.resolve(true) });
    expect(await requestStoragePersistence()).toBe(true);

    mount({ persisted: () => Promise.resolve(false), persist: () => Promise.resolve(false) });
    expect(await requestStoragePersistence()).toBe(false);
  });

  it('reports denied rather than throwing when the request fails', async () => {
    mount({
      persisted: () => Promise.resolve(false),
      persist: () => Promise.reject(new Error('blocked')),
    });
    expect(await requestStoragePersistence()).toBe(false);
  });
});
