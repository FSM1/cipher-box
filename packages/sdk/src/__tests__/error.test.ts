import { describe, it, expect, vi } from 'vitest';
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

    await expect(withRevocationGuard(operation, onRevoked)).rejects.toThrow('write access revoked');
    expect(onRevoked).toHaveBeenCalledOnce();
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

    const result = await withConflictRetry(perform, resync, preRetry);

    expect(result).toBe('retry-ok');
    expect(resync).toHaveBeenCalledOnce();
    expect(preRetry).toHaveBeenCalledOnce();
  });

  it('throws user-friendly message on double 409', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    const perform = () => Promise.reject({ status: 409 });

    await expect(withConflictRetry(perform, resync)).rejects.toThrow(
      'Folder was modified by another device'
    );
    expect(resync).toHaveBeenCalledOnce();
  });

  it('re-throws non-409 errors without retrying', async () => {
    const resync = vi.fn();
    const originalError = new Error('server down');
    const perform = () => Promise.reject(originalError);

    await expect(withConflictRetry(perform, resync)).rejects.toThrow('server down');
    expect(resync).not.toHaveBeenCalled();
  });

  it('re-throws non-409 error from retry attempt', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    let attempt = 0;
    const perform = () => {
      attempt++;
      if (attempt === 1) return Promise.reject({ status: 409 });
      return Promise.reject(new Error('unexpected retry error'));
    };

    await expect(withConflictRetry(perform, resync)).rejects.toThrow('unexpected retry error');
  });

  it('works without preRetry callback', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    let attempt = 0;
    const perform = () => {
      attempt++;
      if (attempt === 1) return Promise.reject({ status: 409 });
      return Promise.resolve('ok');
    };

    const result = await withConflictRetry(perform, resync);
    expect(result).toBe('ok');
  });

  it('handles 409 via nested response.status', async () => {
    const resync = vi.fn().mockResolvedValue(undefined);
    let attempt = 0;
    const perform = () => {
      attempt++;
      if (attempt === 1) return Promise.reject({ response: { status: 409 } });
      return Promise.resolve('ok');
    };

    const result = await withConflictRetry(perform, resync);
    expect(result).toBe('ok');
    expect(resync).toHaveBeenCalledOnce();
  });
});
