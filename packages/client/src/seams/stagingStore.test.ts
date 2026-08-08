/**
 * Constrained-IO behaviour of the OPFS staging store against a fake sync access
 * handle — the short-count and thrown-storage-error signals a constrained write
 * reports, and the failed commit. The real OPFS round trip and the seam's
 * failed-put kit case run in the browser conformance suite.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { OpfsStagingStore, StagingIoError } from './stagingStore.js';

interface Limits {
  /** Cap on bytes one `write` accepts (a quota-constrained short write). */
  maxWrite?: number;
  /** Cap on bytes one `read` returns (a short read). */
  maxRead?: number;
  /** Handle method that raises `QuotaExceededError` instead of succeeding. */
  throwFrom?: 'write' | 'flush';
}

class FakeFile {
  bytes = new Uint8Array(0);
}

class FakeSyncHandle {
  closed = false;

  constructor(
    private readonly file: FakeFile,
    private readonly limits: Limits
  ) {}

  private quotaGuard(method: Limits['throwFrom']): void {
    if (this.limits.throwFrom === method) {
      throw new DOMException('quota exceeded', 'QuotaExceededError');
    }
  }

  write(buffer: ArrayBufferView, options?: { at?: number }): number {
    this.quotaGuard('write');
    const source = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const at = options?.at ?? 0;
    const count = Math.min(source.byteLength, this.limits.maxWrite ?? source.byteLength);
    const next = new Uint8Array(Math.max(this.file.bytes.byteLength, at + count));
    next.set(this.file.bytes);
    next.set(source.subarray(0, count), at);
    this.file.bytes = next;
    return count;
  }

  read(buffer: ArrayBufferView, options?: { at?: number }): number {
    const available = this.file.bytes.subarray(options?.at ?? 0);
    const count = Math.min(
      buffer.byteLength,
      available.byteLength,
      this.limits.maxRead ?? available.byteLength
    );
    new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).set(
      available.subarray(0, count)
    );
    return count;
  }

  getSize(): number {
    return this.file.bytes.byteLength;
  }

  flush(): void {
    this.quotaGuard('flush');
  }

  close(): void {
    this.closed = true;
  }
}

class FakeDirectory {
  readonly files = new Map<string, FakeFile>();
  readonly handles: FakeSyncHandle[] = [];
  limits: Limits = {};
  removeFails = false;
  moveFails = false;

  async *keys(): AsyncIterableIterator<string> {
    for (const name of [...this.files.keys()]) yield name;
  }

  getDirectoryHandle(): Promise<FakeDirectory> {
    return Promise.resolve(this);
  }

  getFileHandle(name: string, options?: { create?: boolean }): Promise<unknown> {
    let file = this.files.get(name);
    if (!file) {
      if (!options?.create) return Promise.reject(new DOMException('missing', 'NotFoundError'));
      file = new FakeFile();
      this.files.set(name, file);
    }
    const target = file;
    return Promise.resolve({
      createSyncAccessHandle: (): Promise<FakeSyncHandle> => {
        const handle = new FakeSyncHandle(target, this.limits);
        this.handles.push(handle);
        return Promise.resolve(handle);
      },
      getFile: (): Promise<{ size: number }> => Promise.resolve({ size: target.bytes.byteLength }),
      move: (to: string): Promise<void> => {
        if (this.moveFails) return Promise.reject(new DOMException('busy', 'InvalidStateError'));
        this.files.delete(name);
        this.files.set(to, target);
        return Promise.resolve();
      },
    });
  }

  removeEntry(name: string): Promise<void> {
    if (this.removeFails) return Promise.reject(new Error('remove failed'));
    if (!this.files.delete(name)) {
      return Promise.reject(new DOMException('missing', 'NotFoundError'));
    }
    return Promise.resolve();
  }
}

function mount(): FakeDirectory {
  const dir = new FakeDirectory();
  vi.stubGlobal('navigator', { storage: { getDirectory: () => Promise.resolve(dir) } });
  return dir;
}

const key = new Uint8Array([1, 2, 3, 4]);
const payload = new Uint8Array([9, 8, 7, 6, 5]);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('OpfsStagingStore staged bytes', () => {
  it('round-trips a full write and read', async () => {
    mount();
    const store = new OpfsStagingStore('test');
    await store.putStagedBytes(key, payload);
    expect(await store.stagedBytes(key)).toEqual(payload);
  });

  it('rejects a short write and drops the partial file', async () => {
    const dir = mount();
    dir.limits.maxWrite = 2;
    const store = new OpfsStagingStore('test');

    await expect(store.putStagedBytes(key, payload)).rejects.toThrow(StagingIoError);
    expect(dir.files.size).toBe(0);
    expect(dir.handles.every((handle) => handle.closed)).toBe(true);
  });

  it('reports the short-write error even when dropping the partial file fails', async () => {
    const dir = mount();
    dir.limits.maxWrite = 2;
    dir.removeFails = true;
    const store = new OpfsStagingStore('test');

    const error = await store.putStagedBytes(key, payload).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(StagingIoError);
    expect((error as StagingIoError).cause).toBeInstanceOf(Error);
  });

  it.each(['write', 'flush'] as const)(
    'rejects a throwing %s and drops the partial file',
    async (method) => {
      const dir = mount();
      dir.limits.throwFrom = method;
      const store = new OpfsStagingStore('test');

      const error = await store.putStagedBytes(key, payload).catch((thrown: unknown) => thrown);
      expect(error).toBeInstanceOf(StagingIoError);
      expect((error as StagingIoError).cause).toBeInstanceOf(DOMException);
      expect(dir.files.size).toBe(0);
      expect(dir.handles.every((handle) => handle.closed)).toBe(true);
    }
  );

  it('keeps the storage error as the cause when dropping the partial file also fails', async () => {
    const dir = mount();
    dir.limits.throwFrom = 'write';
    dir.removeFails = true;
    const store = new OpfsStagingStore('test');

    const error = await store.putStagedBytes(key, payload).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(StagingIoError);
    expect((error as StagingIoError).cause).toBeInstanceOf(DOMException);
    expect((error as StagingIoError).cause).toMatchObject({ name: 'QuotaExceededError' });
  });

  it.each([
    ['the write is short', (dir: FakeDirectory): void => void (dir.limits.maxWrite = 2)],
    ['the write throws', (dir: FakeDirectory): void => void (dir.limits.throwFrom = 'write')],
    ['the commit fails', (dir: FakeDirectory): void => void (dir.moveFails = true)],
  ])('leaves the previous bytes readable when %s', async (_case, arm) => {
    const dir = mount();
    const store = new OpfsStagingStore('test');
    await store.putStagedBytes(key, payload);
    arm(dir);

    await expect(store.putStagedBytes(key, new Uint8Array([1, 1, 1, 1, 1, 1]))).rejects.toThrow(
      StagingIoError
    );
    expect(await store.stagedBytes(key)).toEqual(payload);
    expect(await store.stagedKeys()).toEqual([key]);
    expect(await store.stagedBytesTotal()).toBe(payload.byteLength);
  });

  it('rejects a short read rather than returning zero-padded bytes', async () => {
    const dir = mount();
    const store = new OpfsStagingStore('test');
    await store.putStagedBytes(key, payload);
    dir.limits.maxRead = 3;

    await expect(store.stagedBytes(key)).rejects.toThrow(StagingIoError);
    expect(dir.handles.every((handle) => handle.closed)).toBe(true);
  });

  it('reads back null for an absent key and tolerates removing one', async () => {
    mount();
    const store = new OpfsStagingStore('test');
    expect(await store.stagedBytes(key)).toBeNull();
    await expect(store.removeStagedBytes(key)).resolves.toBeUndefined();
  });
});
