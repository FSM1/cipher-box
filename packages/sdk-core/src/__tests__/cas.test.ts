import { describe, it, expect, vi, beforeEach } from 'vitest';
import { publishWithCas } from '../cas';
import { ConflictError } from '../errors';
import { createMockContext } from './helpers';

// ---------------------------------------------------------------------------
// Module mocks for publishWithCas tests
// vi.mock calls are hoisted to the top of the file by vitest.
// vi.hoisted() is hoisted before vi.mock() so its result is available in factories.
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
}));

vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  batchPublishIpnsRecords: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

type TestData = { value: string; versions?: string[] };

function makeParams(overrides?: Partial<Parameters<typeof publishWithCas<TestData>>[0]>) {
  const localData: TestData = { value: 'local' };
  const baseData: TestData = { value: 'base' };

  return {
    ipnsName: 'k51test',
    ipnsPrivateKey: new Uint8Array(32).fill(1),
    sequenceNumber: 5n,
    ctx: createMockContext(),
    maxAttempts: 4,
    backoff: false, // default off so tests don't need timer mocks unless testing backoff
    encodeAndUpload: vi.fn().mockResolvedValue('bafy-cid-1'),
    decodeRemote: vi.fn(),
    merge: vi.fn().mockReturnValue({ merged: { value: 'merged' } }),
    localData,
    baseData,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('publishWithCas', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('Test 1: succeeds on first attempt without calling merge', async () => {
    const params = makeParams();
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ sequenceNumber: 6n });

    const result = await publishWithCas(params);

    expect(params.encodeAndUpload).toHaveBeenCalledTimes(1);
    expect(params.encodeAndUpload).toHaveBeenCalledWith(params.localData);
    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledTimes(1);
    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedSequenceNumber: '5',
        ipnsName: 'k51test',
      })
    );
    expect(params.merge).not.toHaveBeenCalled();
    expect(result).toEqual({
      cid: 'bafy-cid-1',
      newSequenceNumber: 6n,
      publishedData: params.localData,
      prunedCids: [],
    });
  });

  it('Test 2: 409 triggers merge and succeeds on retry', async () => {
    const remoteData: TestData = { value: 'remote' };
    const mergedData: TestData = { value: 'merged' };
    const params = makeParams({
      merge: vi.fn().mockReturnValue({ merged: mergedData }),
    });

    const conflictError = { response: { status: 409 } };
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(conflictError)
      .mockResolvedValueOnce({ sequenceNumber: 7n });
    mockFns.resolveIpnsRecord.mockResolvedValue({ cid: 'bafy-remote', sequenceNumber: 6n });
    params.decodeRemote.mockResolvedValue(remoteData);
    params.encodeAndUpload.mockResolvedValueOnce('bafy-cid-1').mockResolvedValueOnce('bafy-cid-2');

    const result = await publishWithCas(params);

    expect(mockFns.resolveIpnsRecord).toHaveBeenCalledWith('k51test', params.ctx);
    expect(params.decodeRemote).toHaveBeenCalledWith('bafy-remote');
    expect(params.merge).toHaveBeenCalledWith(params.baseData, params.localData, remoteData);
    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledTimes(2);
    expect(result.publishedData).toEqual(mergedData);
  });

  it('Test 3: throws ConflictError after exhausting all attempts', async () => {
    const params = makeParams({ maxAttempts: 4 });
    const conflictError = { response: { status: 409 } };
    mockFns.createAndPublishIpnsRecord.mockRejectedValue(conflictError);
    mockFns.resolveIpnsRecord.mockResolvedValue({ cid: 'bafy-remote', sequenceNumber: 6n });
    params.decodeRemote.mockResolvedValue({ value: 'remote' });
    params.encodeAndUpload.mockResolvedValue('bafy-cid');

    await expect(publishWithCas(params)).rejects.toThrow(ConflictError);

    try {
      await publishWithCas(params);
    } catch (err) {
      expect(err).toBeInstanceOf(ConflictError);
      expect((err as ConflictError).attempts).toBe(4);
      expect((err as ConflictError).ipnsName).toBe('k51test');
    }
  });

  it('Test 4: prunedCids from merge callback propagate through return', async () => {
    const params = makeParams({
      merge: vi.fn().mockReturnValue({ merged: { value: 'merged' }, prunedCids: ['cidA', 'cidB'] }),
    });
    const conflictError = { response: { status: 409 } };
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(conflictError)
      .mockResolvedValueOnce({ sequenceNumber: 7n });
    mockFns.resolveIpnsRecord.mockResolvedValue({ cid: 'bafy-remote', sequenceNumber: 6n });
    params.decodeRemote.mockResolvedValue({ value: 'remote' });
    params.encodeAndUpload.mockResolvedValue('bafy-cid');

    const result = await publishWithCas(params);

    expect(result.prunedCids).toContain('cidA');
    expect(result.prunedCids).toContain('cidB');
  });

  it('Test 5: non-409 error is rethrown immediately without retry', async () => {
    const params = makeParams();
    const serverError = { status: 500 };
    mockFns.createAndPublishIpnsRecord.mockRejectedValue(serverError);

    await expect(publishWithCas(params)).rejects.toEqual(serverError);

    expect(mockFns.resolveIpnsRecord).not.toHaveBeenCalled();
    expect(params.merge).not.toHaveBeenCalled();
    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledTimes(1);
  });

  it('Test 6: backoff:false skips setTimeout; backoff:true schedules a delay', async () => {
    vi.useFakeTimers();
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');

    try {
      const conflictError = { response: { status: 409 } };

      // backoff: false — no timeout should be called between attempts
      const paramsNoBackoff = makeParams({ backoff: false });
      mockFns.createAndPublishIpnsRecord
        .mockRejectedValueOnce(conflictError)
        .mockResolvedValueOnce({ sequenceNumber: 7n });
      mockFns.resolveIpnsRecord.mockResolvedValue({ cid: 'bafy-remote', sequenceNumber: 6n });
      paramsNoBackoff.decodeRemote.mockResolvedValue({ value: 'remote' });
      paramsNoBackoff.encodeAndUpload.mockResolvedValue('bafy-cid');

      await publishWithCas(paramsNoBackoff);
      const callsWithoutBackoff = setTimeoutSpy.mock.calls.length;

      vi.clearAllMocks();
      setTimeoutSpy.mockClear();

      // backoff: true — setTimeout should be called at least once for the delay
      const paramsWithBackoff = makeParams({ backoff: true });
      mockFns.createAndPublishIpnsRecord
        .mockRejectedValueOnce(conflictError)
        .mockResolvedValueOnce({ sequenceNumber: 7n });
      mockFns.resolveIpnsRecord.mockResolvedValue({ cid: 'bafy-remote', sequenceNumber: 6n });
      paramsWithBackoff.decodeRemote.mockResolvedValue({ value: 'remote' });
      paramsWithBackoff.encodeAndUpload.mockResolvedValue('bafy-cid');

      // runAllTimersAsync advances fake timers and flushes microtasks in lockstep
      const promise = publishWithCas(paramsWithBackoff);
      await vi.runAllTimersAsync();
      await promise;
      const callsWithBackoff = setTimeoutSpy.mock.calls.length;

      expect(callsWithoutBackoff).toBe(0);
      expect(callsWithBackoff).toBeGreaterThan(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
