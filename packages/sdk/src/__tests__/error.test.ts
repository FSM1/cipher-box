import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  isForbiddenError,
  isConflictError,
  withRevocationGuard,
  withConflictRetry,
} from '../error';

describe('isForbiddenError', () => {
  it('returns true for object with status 403', () => {
    expect(isForbiddenError({ status: 403 })).toBe(true);
  });

  it('returns false for object with different status', () => {
    expect(isForbiddenError({ status: 404 })).toBe(false);
    expect(isForbiddenError({ status: 200 })).toBe(false);
  });

  it('returns false for null', () => {
    expect(isForbiddenError(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isForbiddenError(undefined)).toBe(false);
  });

  it('returns false for non-object types', () => {
    expect(isForbiddenError('403')).toBe(false);
    expect(isForbiddenError(403)).toBe(false);
    expect(isForbiddenError(true)).toBe(false);
  });

  it('returns false for object without status property', () => {
    expect(isForbiddenError({ message: 'forbidden' })).toBe(false);
  });

  it('returns false for status as string "403"', () => {
    expect(isForbiddenError({ status: '403' })).toBe(false);
  });

  it('returns true for axios-style error with response.status 403', () => {
    expect(isForbiddenError({ response: { status: 403 } })).toBe(true);
  });

  it('returns false for response.status !== 403', () => {
    expect(isForbiddenError({ response: { status: 404 } })).toBe(false);
  });

  it('returns false for null response', () => {
    expect(isForbiddenError({ response: null })).toBe(false);
  });
});

describe('isConflictError', () => {
  it('returns true for object with status 409', () => {
    expect(isConflictError({ status: 409 })).toBe(true);
  });

  it('returns true for nested response.status 409', () => {
    expect(isConflictError({ response: { status: 409 } })).toBe(true);
  });

  it('returns false for different status codes', () => {
    expect(isConflictError({ status: 404 })).toBe(false);
    expect(isConflictError({ status: 403 })).toBe(false);
  });

  it('returns false for nested response with different status', () => {
    expect(isConflictError({ response: { status: 200 } })).toBe(false);
  });

  it('returns false for null', () => {
    expect(isConflictError(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isConflictError(undefined)).toBe(false);
  });

  it('returns false for non-object types', () => {
    expect(isConflictError('409')).toBe(false);
    expect(isConflictError(409)).toBe(false);
  });

  it('returns false for null response property', () => {
    expect(isConflictError({ response: null })).toBe(false);
  });

  it('returns false for non-object response property', () => {
    expect(isConflictError({ response: 'conflict' })).toBe(false);
  });

  it('prefers top-level status over nested response', () => {
    // Top-level status 409 should match even if response.status differs
    expect(isConflictError({ status: 409, response: { status: 200 } })).toBe(true);
  });
});

describe('withRevocationGuard', () => {
  it('returns operation result on success', async () => {
    const onRevoked = vi.fn();
    const result = await withRevocationGuard(() => Promise.resolve('ok'), onRevoked);
    expect(result).toBe('ok');
    expect(onRevoked).not.toHaveBeenCalled();
  });

  it('calls onRevoked and throws descriptive error on 403', async () => {
    const onRevoked = vi.fn();
    const operation = () => Promise.reject({ status: 403 });

    await expect(withRevocationGuard(operation, onRevoked)).rejects.toThrow('Write access revoked');
    expect(onRevoked).toHaveBeenCalledOnce();
  });

  it('preserves original error as cause on 403', async () => {
    const onRevoked = vi.fn();
    const original = { status: 403, message: 'forbidden' };
    const operation = () => Promise.reject(original);

    try {
      await withRevocationGuard(operation, onRevoked);
    } catch (err) {
      expect((err as Error).cause).toBe(original);
    }
  });

  it('re-throws non-403 errors without calling onRevoked', async () => {
    const onRevoked = vi.fn();
    const originalError = new Error('network failure');
    const operation = () => Promise.reject(originalError);

    await expect(withRevocationGuard(operation, onRevoked)).rejects.toThrow('network failure');
    expect(onRevoked).not.toHaveBeenCalled();
  });

  it('re-throws non-object errors without calling onRevoked', async () => {
    const onRevoked = vi.fn();
    const operation = () => Promise.reject('string error');

    await expect(withRevocationGuard(operation, onRevoked)).rejects.toBe('string error');
    expect(onRevoked).not.toHaveBeenCalled();
  });
});

describe('withConflictRetry', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns result on first successful attempt', async () => {
    const resync = vi.fn();
    const result = await withConflictRetry(() => Promise.resolve('done'), resync);

    expect(result).toBe('done');
    expect(resync).not.toHaveBeenCalled();
  });

  it('retries on 409 and returns result on second attempt', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    const preRetry = vi.fn();
    let attempt = 0;
    const perform = () => {
      attempt++;
      if (attempt === 1) return Promise.reject({ status: 409 });
      return Promise.resolve('retry-ok');
    };

    const promise = withConflictRetry(perform, resync, preRetry);
    // Catch to prevent unhandled rejection, then re-await
    promise.catch(() => {});
    await vi.advanceTimersByTimeAsync(500);
    const result = await promise;

    expect(result).toBe('retry-ok');
    expect(resync).toHaveBeenCalledOnce();
    expect(preRetry).toHaveBeenCalledOnce();
  });

  it('throws user-friendly message on double 409', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    const perform = () => Promise.reject({ status: 409 });

    const assertion = expect(withConflictRetry(perform, resync)).rejects.toThrow(
      'Folder was modified by another device'
    );
    await vi.advanceTimersByTimeAsync(500);
    await assertion;
    expect(resync).toHaveBeenCalledOnce();
  });

  it('re-throws non-409 errors without retrying', async () => {
    const resync = vi.fn();
    const originalError = new Error('server down');

    await expect(withConflictRetry(perform, resync)).rejects.toThrow('server down');
    expect(resync).not.toHaveBeenCalled();

    function perform() {
      return Promise.reject(originalError);
    }
  });

  it('re-throws non-409 error from retry attempt', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    let attempt = 0;
    const perform = () => {
      attempt++;
      if (attempt === 1) return Promise.reject({ status: 409 });
      return Promise.reject(new Error('unexpected retry error'));
    };

    const assertion = expect(withConflictRetry(perform, resync)).rejects.toThrow(
      'unexpected retry error'
    );
    await vi.advanceTimersByTimeAsync(500);
    await assertion;
  });

  it('works without preRetry callback', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    let attempt = 0;
    const perform = () => {
      attempt++;
      if (attempt === 1) return Promise.reject({ status: 409 });
      return Promise.resolve('ok');
    };

    const promise = withConflictRetry(perform, resync);
    promise.catch(() => {});
    await vi.advanceTimersByTimeAsync(500);
    expect(await promise).toBe('ok');
  });

  it('handles 409 via nested response.status', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    let attempt = 0;
    const perform = () => {
      attempt++;
      if (attempt === 1) return Promise.reject({ response: { status: 409 } });
      return Promise.resolve('ok');
    };

    const promise = withConflictRetry(perform, resync);
    promise.catch(() => {});
    await vi.advanceTimersByTimeAsync(500);
    expect(await promise).toBe('ok');
    expect(resync).toHaveBeenCalledOnce();
  });
});
