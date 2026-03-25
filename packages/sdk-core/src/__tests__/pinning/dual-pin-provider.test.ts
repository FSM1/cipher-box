import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DualPinProvider } from '../../pinning/dual-pin-provider';
import type { PinningProvider } from '../../pinning/types';

function createMockProvider(overrides: Partial<PinningProvider> = {}): PinningProvider {
  return {
    pin: vi.fn().mockResolvedValue({ cid: 'bafymock', size: 100 }),
    unpin: vi.fn().mockResolvedValue(undefined),
    status: vi.fn().mockResolvedValue({ cid: 'bafymock', status: 'pinned' }),
    get: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
    ...overrides,
  };
}

describe('DualPinProvider', () => {
  let primary: PinningProvider;
  let secondary: PinningProvider;
  let dual: DualPinProvider;

  beforeEach(() => {
    primary = createMockProvider({
      pin: vi.fn().mockResolvedValue({ cid: 'bafyPrimary', size: 256 }),
      status: vi.fn().mockResolvedValue({ cid: 'bafyPrimary', status: 'pinned' }),
      get: vi.fn().mockResolvedValue(new Uint8Array([10, 20, 30])),
    });
    secondary = createMockProvider({
      pin: vi.fn().mockResolvedValue({ cid: 'bafySecondary', size: 256 }),
    });
    dual = new DualPinProvider(primary, secondary);
  });

  describe('pin()', () => {
    it('calls primary.pin then secondary.pin and returns primary result with secondarySuccess: true', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const result = await dual.pin(data, 'test-file');

      expect(primary.pin).toHaveBeenCalledWith(data, 'test-file');
      expect(secondary.pin).toHaveBeenCalledWith(data, 'test-file');
      expect(result).toEqual({
        cid: 'bafyPrimary',
        size: 256,
        secondarySuccess: true,
        secondaryError: undefined,
      });
    });

    it('returns secondarySuccess: false and secondaryError when secondary throws', async () => {
      (secondary.pin as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Secondary node offline')
      );

      const data = new Uint8Array([1, 2, 3]);
      const result = await dual.pin(data);

      expect(primary.pin).toHaveBeenCalled();
      expect(secondary.pin).toHaveBeenCalled();
      expect(result.cid).toBe('bafyPrimary');
      expect(result.secondarySuccess).toBe(false);
      expect(result.secondaryError).toBe('Secondary node offline');
    });

    it('throws when primary fails (does not attempt secondary)', async () => {
      (primary.pin as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Primary node down'));

      await expect(dual.pin(new Uint8Array([1]))).rejects.toThrow('Primary node down');
      expect(secondary.pin).not.toHaveBeenCalled();
    });

    it('handles non-Error thrown by secondary (converts to string)', async () => {
      (secondary.pin as ReturnType<typeof vi.fn>).mockRejectedValue('string error');

      const result = await dual.pin(new Uint8Array([1]));

      expect(result.secondarySuccess).toBe(false);
      expect(result.secondaryError).toBe('string error');
    });
  });

  describe('unpin()', () => {
    it('calls both primary.unpin and secondary.unpin', async () => {
      await dual.unpin('bafyToRemove');

      expect(primary.unpin).toHaveBeenCalledWith('bafyToRemove');
      expect(secondary.unpin).toHaveBeenCalledWith('bafyToRemove');
    });

    it('succeeds when secondary.unpin fails', async () => {
      (secondary.unpin as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Secondary unpin failed')
      );

      // Should not throw
      await expect(dual.unpin('bafyToRemove')).resolves.toBeUndefined();
      expect(primary.unpin).toHaveBeenCalledWith('bafyToRemove');
    });

    it('throws when primary.unpin fails', async () => {
      (primary.unpin as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Primary unpin failed')
      );

      await expect(dual.unpin('bafyToRemove')).rejects.toThrow('Primary unpin failed');
    });
  });

  describe('status()', () => {
    it('delegates to primary only', async () => {
      const result = await dual.status('bafyCheck');

      expect(primary.status).toHaveBeenCalledWith('bafyCheck');
      expect(secondary.status).not.toHaveBeenCalled();
      expect(result).toEqual({ cid: 'bafyPrimary', status: 'pinned' });
    });
  });

  describe('get()', () => {
    it('delegates to primary only', async () => {
      const result = await dual.get('bafyFetch');

      expect(primary.get).toHaveBeenCalledWith('bafyFetch');
      expect(secondary.get).not.toHaveBeenCalled();
      expect(result).toEqual(new Uint8Array([10, 20, 30]));
    });
  });
});
