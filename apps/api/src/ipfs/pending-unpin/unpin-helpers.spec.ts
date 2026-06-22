import { withCidLock, refcountAndMaybeUnpin } from './unpin-helpers';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { IpfsProvider } from '../providers/ipfs-provider.interface';

describe('withCidLock', () => {
  it('executes the exact pg_advisory_xact_lock SQL with [cid] and returns fn result', async () => {
    const mockQuery = jest.fn().mockResolvedValue([]);
    const mockManager = { query: mockQuery, getRepository: jest.fn() } as any;
    const fn = jest.fn().mockResolvedValue('result');

    const result = await withCidLock(mockManager, 'bafk...', fn);

    expect(mockQuery).toHaveBeenCalledWith('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [
      'bafk...',
    ]);
    expect(fn).toHaveBeenCalled();
    expect(result).toBe('result');
  });
});

describe('refcountAndMaybeUnpin', () => {
  const mockPinnedCidRepository = { count: jest.fn() };
  const mockPendingUnpinRepository = { delete: jest.fn() };
  const mockManager = {
    query: jest.fn(),
    getRepository: jest.fn((Entity: unknown) => {
      if (Entity === PinnedCid) return mockPinnedCidRepository;
      if (Entity === PendingUnpin) return mockPendingUnpinRepository;
      return {};
    }),
  } as any;
  const mockIpfsProvider = { unpinFile: jest.fn<Promise<void>, [string]>() };
  const ipfsProvider = mockIpfsProvider as unknown as IpfsProvider;

  beforeEach(() => {
    jest.clearAllMocks();
    mockManager.getRepository.mockImplementation((Entity: unknown) => {
      if (Entity === PinnedCid) return mockPinnedCidRepository;
      if (Entity === PendingUnpin) return mockPendingUnpinRepository;
      return {};
    });
  });

  it('skips unpin and deletes outbox row when refs > 0', async () => {
    mockPinnedCidRepository.count.mockResolvedValue(2);
    mockPendingUnpinRepository.delete.mockResolvedValue({ affected: 1 });

    const result = await refcountAndMaybeUnpin(mockManager, 'bafkcid', ipfsProvider);

    expect(mockIpfsProvider.unpinFile).not.toHaveBeenCalled();
    expect(mockPendingUnpinRepository.delete).toHaveBeenCalledWith({ cid: 'bafkcid' });
    expect(result).toEqual({ outcome: 'skipped-repinned', refs: 2 });
  });

  it('calls unpinFile then deletes outbox row when refs === 0', async () => {
    mockPinnedCidRepository.count.mockResolvedValue(0);
    mockIpfsProvider.unpinFile.mockResolvedValue(undefined);
    mockPendingUnpinRepository.delete.mockResolvedValue({ affected: 1 });

    const result = await refcountAndMaybeUnpin(mockManager, 'bafkcid', ipfsProvider);

    expect(mockIpfsProvider.unpinFile).toHaveBeenCalledWith('bafkcid');
    expect(mockPendingUnpinRepository.delete).toHaveBeenCalledWith({ cid: 'bafkcid' });
    expect(result).toEqual({ outcome: 'unpinned', refs: 0 });
  });
});
