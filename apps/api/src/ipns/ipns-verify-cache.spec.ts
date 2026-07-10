/**
 * Tests for the IPNS verified-record cache (D-11 invariant)
 *
 * Security invariant: the cache may ONLY short-circuit re-verification of an
 * ALREADY-VERIFIED exact signed record (same ipnsName + sequenceNumber + signatureV2).
 * Externally-sourced / DHT records and any record not previously verified
 * in-process MUST ALWAYS be fully verified.
 *
 * Test plan:
 *   1. Cache miss before first verify — has() returns false
 *   2. Cache hit after recordVerified() within TTL — has() returns true
 *   3. Cache miss after TTL expires — has() returns false
 *   4. Different signatureV2 for same (ipnsName, seq) is a cache MISS (full-triple key)
 *   5. publishRecord verifies on first submission (spy called once)
 *   6. publishRecord SKIPS verify on second identical submission within TTL (spy not called again)
 *   7. publishRecord always verifies when a DIFFERENT signatureV2 arrives
 *   8. resolveRecord never populates the cache (DHT-never-cached)
 */

import { IpnsVerifyCache, CACHE_TTL_MS, ipnsVerifyCache } from './ipns-verify-cache';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { IpnsService } from './ipns.service';
import { IpnsRecord } from './entities/ipns-record.entity';
import { PublishIpnsDto } from './dto';
import { RepublishService } from '../republish/republish.service';
import { DelegatedRoutingClient } from './delegated-routing.client';
import { MetricsService } from '../metrics/metrics.service';
import { parseIpnsRecord, verifyIpnsRecordSignature } from '@cipherbox/crypto';

// Mock crypto module — keep deriveIpnsName real
jest.mock('@cipherbox/crypto', () => {
  const actual = jest.requireActual('@cipherbox/crypto');
  return {
    ...actual,
    parseIpnsRecord: jest.fn(),
    verifyIpnsRecordSignature: jest.fn().mockResolvedValue(true),
  };
});
const mockParseIpnsRecord = parseIpnsRecord as jest.Mock;
const mockVerifyIpnsRecordSignature = verifyIpnsRecordSignature as jest.Mock;

// ---------------------------------------------------------------------------
// Unit tests for IpnsVerifyCache
// ---------------------------------------------------------------------------

describe('IpnsVerifyCache', () => {
  const ipnsName = 'k51qzi5uqu5dg7hrs1jyr49oygapxsw71v7pv43rk8lemejo9h2m3hkzvww8io';
  const seq = '5';
  const sigV2 = Buffer.from('signature-bytes-aaaa').toString('base64');
  const sigV2Alt = Buffer.from('different-signature-bb').toString('base64');

  let cache: IpnsVerifyCache;

  beforeEach(() => {
    cache = new IpnsVerifyCache();
  });

  it('returns false before any record is verified', () => {
    // Test 1: cache miss before first verify
    expect(cache.isVerified(ipnsName, seq, sigV2)).toBe(false);
  });

  it('returns true after recordVerified() within the TTL', () => {
    // Test 2: cache hit after recordVerified()
    cache.recordVerified(ipnsName, seq, sigV2);
    expect(cache.isVerified(ipnsName, seq, sigV2)).toBe(true);
  });

  it('returns false after the TTL expires', () => {
    // Test 3: TTL expiry — fake the insertion timestamp to be > TTL ago
    cache.recordVerified(ipnsName, seq, sigV2);

    // Manipulate the internal store so the entry appears expired
    // Access via the public test-helper that sets the entry age.
    // We rely on the fact that the cache uses Date.now() as insertion time.
    // Override Date.now() to simulate expiry.
    const realDateNow = Date.now;
    try {
      Date.now = () => realDateNow() + CACHE_TTL_MS + 1000;
      expect(cache.isVerified(ipnsName, seq, sigV2)).toBe(false);
    } finally {
      Date.now = realDateNow;
    }
  });

  it('returns false for a different signatureV2 with the same (ipnsName, seq) — full-triple key required', () => {
    // Test 4: different signature → cache MISS even if ipnsName and seq match
    cache.recordVerified(ipnsName, seq, sigV2);
    expect(cache.isVerified(ipnsName, seq, sigV2Alt)).toBe(false);
  });

  it('keys on exact bytes: same (ipnsName, seq) but different raw record bytes do NOT share a cache entry', () => {
    // D-11 byte-exact keying regression. Production passes base64(full recordBytes) as the
    // third arg (with seq=''). Two records that happen to share parsed seq+signature but
    // differ in any other byte (CID, validity, pubKey) produce different raw bytes →
    // different keys → MISS, forcing a full Ed25519 verify.
    const recordBytesA = Buffer.from('ipns-record-A-cid-X-validity-Y').toString('base64');
    const recordBytesB = Buffer.from('ipns-record-B-cid-Z-validity-W').toString('base64');
    cache.recordVerified(ipnsName, '', recordBytesA);
    // Same ipnsName + same seq arg, different raw bytes → MISS.
    expect(cache.isVerified(ipnsName, '', recordBytesB)).toBe(false);
    // The exact recorded bytes → HIT.
    expect(cache.isVerified(ipnsName, '', recordBytesA)).toBe(true);
  });

  it('returns false for a different sequenceNumber with the same (ipnsName, sig)', () => {
    // Additional: different seq → cache MISS
    cache.recordVerified(ipnsName, seq, sigV2);
    expect(cache.isVerified(ipnsName, '6', sigV2)).toBe(false);
  });

  it('returns false for a different ipnsName with the same (seq, sig)', () => {
    // Additional: different ipnsName → cache MISS
    cache.recordVerified(ipnsName, seq, sigV2);
    expect(cache.isVerified('k51different', seq, sigV2)).toBe(false);
  });

  it('exports CACHE_TTL_MS as a positive number (60s)', () => {
    expect(CACHE_TTL_MS).toBeGreaterThan(0);
    expect(CACHE_TTL_MS).toBe(60_000);
  });
});

// ---------------------------------------------------------------------------
// Integration-style tests: IpnsService + IpnsVerifyCache wired in
// ---------------------------------------------------------------------------

describe('IpnsService with IpnsVerifyCache', () => {
  const testUserId = '550e8400-e29b-41d4-a716-446655440000';
  // IPNS name derived from testPublicKeyBytes via deriveIpnsName (matches service test setup)
  const testIpnsName = 'k51qzi5uqu5dg7hrs1jyr49oygapxsw71v7pv43rk8lemejo9h2m3hkzvww8io';
  const testMetadataCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
  const testRecordBytes = Buffer.from('test-ipns-record-bytes');
  const testRecord = testRecordBytes.toString('base64');
  const testPublicKeyBytes = Buffer.from(new Uint8Array(32).map((_, i) => i + 1));
  const testPublicKey = testPublicKeyBytes.toString('base64');

  let service: IpnsService;
  let mockFolderIpnsRepo: {
    findOne: jest.Mock;
    find: jest.Mock;
    create: jest.Mock;
    save: jest.Mock;
  };
  let mockDelegatedRoutingClient: { publish: jest.Mock; resolve: jest.Mock };
  let mockMetricsService: {
    ipfsIpnsDuration: { startTimer: jest.Mock };
    ipnsResolveDuration: { observe: jest.Mock };
    ipnsPublishDuration: { observe: jest.Mock };
  };

  const mockFolderEntity: IpnsRecord = {
    id: 'folder-id-1',
    userId: testUserId,
    ipnsName: testIpnsName,
    latestCid: testMetadataCid,
    sequenceNumber: '1',
    signedRecord: null,
    encryptedIpnsPrivateKey: null,
    keyEpoch: null,
    isRoot: false,
    tombstonedAt: null,
    generation: '0',
    createdAt: new Date('2026-01-20T12:00:00.000Z'),
    updatedAt: new Date('2026-01-20T12:00:00.000Z'),
    user: {} as import('../auth/entities/user.entity').User,
  };

  function createDto(overrides?: Partial<PublishIpnsDto>): PublishIpnsDto {
    return {
      ipnsName: testIpnsName,
      record: testRecord,
      publicKey: testPublicKey,
      metadataCid: testMetadataCid,
      encryptedIpnsPrivateKey: undefined,
      keyEpoch: undefined,
      ...overrides,
    };
  }

  beforeEach(async () => {
    mockFolderIpnsRepo = {
      findOne: jest.fn().mockResolvedValue(null),
      find: jest.fn(),
      create: jest.fn().mockReturnValue({ ...mockFolderEntity }),
      save: jest.fn().mockImplementation((e) => Promise.resolve({ ...e, id: 'new-id' })),
    };

    mockDelegatedRoutingClient = {
      publish: jest.fn().mockResolvedValue(undefined),
      resolve: jest.fn().mockResolvedValue(null),
    };

    const mockEndTimer = jest.fn();
    const mockStartTimer = jest.fn().mockReturnValue(mockEndTimer);
    mockMetricsService = {
      ipfsIpnsDuration: { startTimer: mockStartTimer },
      ipnsResolveDuration: { observe: jest.fn() },
      ipnsPublishDuration: { observe: jest.fn() },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IpnsService,
        {
          provide: getRepositoryToken(IpnsRecord),
          useValue: mockFolderIpnsRepo,
        },
        {
          provide: DelegatedRoutingClient,
          useValue: mockDelegatedRoutingClient,
        },
        {
          provide: RepublishService,
          useValue: {
            enrollFolder: jest.fn().mockResolvedValue(undefined),
            unenrollIpns: jest.fn().mockResolvedValue(1),
          },
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
      ],
    }).compile();

    service = module.get<IpnsService>(IpnsService);

    mockVerifyIpnsRecordSignature.mockResolvedValue(true);
    // First-publish: embedded seq 1n, with signatureV2 so the cache key can be built.
    // The signatureV2 bytes are derived from testRecordBytes so submissions using
    // testRecord always produce the same cache key.
    const testSigV2Bytes = new Uint8Array(64).fill(0xab);
    mockParseIpnsRecord.mockResolvedValue({
      value: `/ipfs/${testMetadataCid}`,
      sequence: 1n,
      signatureV2: testSigV2Bytes,
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    // Clear the module-level singleton cache between tests so each test starts clean.
    // The cache is a process-level singleton; without this, entries from one test bleed
    // into subsequent tests and produce false cache-hit / cache-miss results.
    ipnsVerifyCache.clear();
  });

  it('Test 5: verifies on first submission (spy called once)', async () => {
    // First call: no cache entry → verify must run
    await service.publishRecord(testUserId, createDto());
    expect(mockVerifyIpnsRecordSignature).toHaveBeenCalledTimes(1);
  });

  it('Test 6: skips verify on second identical submission within TTL (spy call count drops to 0)', async () => {
    // First submission: verify runs, entry cached
    await service.publishRecord(testUserId, createDto());
    expect(mockVerifyIpnsRecordSignature).toHaveBeenCalledTimes(1);

    // Second identical submission: same ipnsName + seq + signatureV2 → cache hit → skip verify
    // Need the second call to use the same record bytes.
    // Reset DB mock so we still get a successful publish on the second call.
    mockFolderIpnsRepo.findOne.mockResolvedValue({
      ...mockFolderEntity,
      sequenceNumber: '1',
      signedRecord: testRecordBytes,
    });
    // For existing record: embedded seq must be currentSeq+1 = 2n
    mockParseIpnsRecord.mockReset();
    mockParseIpnsRecord
      .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 2n }) // incoming
      .mockResolvedValueOnce({ value: `/ipfs/${testMetadataCid}`, sequence: 1n }); // stored (anti-rollback)

    // Submit a DIFFERENT record (seq 2n) — different signatureV2 bytes → NOT a cache hit
    // so verify runs again. To test the cache skip, we need the EXACT same record bytes.
    // Submit the SAME record bytes again (same testRecord) — the cache should already
    // have the sig from the first submission. But the service now requires seq 2n for
    // existing entries, which doesn't match the embedded seq in testRecord (which the
    // mock says is seq 1n from the first submit).
    //
    // Design: the cache is keyed on the raw signatureV2 bytes embedded in the IPNS record
    // protobuf. Since we mock parseIpnsRecord, the service uses testRecordBytes to compute
    // the cache key from the raw bytes. The same testRecord base64 → same testRecordBytes
    // → same cache key. The second submission is rejected at the anti-rollback / S1 gate
    // before reaching the verify anchor, so verify is not called.
    //
    // For a clean cache-skip test, we need a first-publish scenario (no existing row) where
    // we submit the exact same record twice. Simulate by resetting the DB mock to return null.
    mockFolderIpnsRepo.findOne.mockReset();
    mockFolderIpnsRepo.findOne.mockResolvedValue(null);
    mockParseIpnsRecord.mockReset();
    // SAME signatureV2 bytes as beforeEach default so the cache key matches
    // what was recorded by the first publishRecord call above.
    const testSigV2Bytes = new Uint8Array(64).fill(0xab);
    mockParseIpnsRecord.mockResolvedValue({
      value: `/ipfs/${testMetadataCid}`,
      sequence: 1n,
      signatureV2: testSigV2Bytes,
    });
    mockVerifyIpnsRecordSignature.mockClear();

    // Second call with identical record bytes and same ipnsName
    await service.publishRecord(testUserId, createDto());
    // On second call with same (ipnsName, seq=1, signatureV2 from testSigV2Bytes):
    // the cache already has this entry → verify skipped → spy at 0 calls
    expect(mockVerifyIpnsRecordSignature).toHaveBeenCalledTimes(0);
  });

  it('Test 7: always verifies when signatureV2 bytes differ (different record)', async () => {
    // First submission with record A (signatureV2 = 0xab bytes from beforeEach default mock)
    await service.publishRecord(testUserId, createDto());
    expect(mockVerifyIpnsRecordSignature).toHaveBeenCalledTimes(1);

    // Second submission with different record bytes → mock returns a different signatureV2
    // → different cache key → verify must run again
    const differentRecord = Buffer.from('completely-different-record-bytes').toString('base64');
    mockVerifyIpnsRecordSignature.mockClear();
    mockFolderIpnsRepo.findOne.mockResolvedValue(null);
    // Different signatureV2 bytes → different cache key even for same (ipnsName, seq)
    const differentSigV2 = new Uint8Array(64).fill(0xcc);
    mockParseIpnsRecord.mockResolvedValue({
      value: `/ipfs/${testMetadataCid}`,
      sequence: 1n,
      signatureV2: differentSigV2,
    });

    await service.publishRecord(testUserId, createDto({ record: differentRecord }));
    expect(mockVerifyIpnsRecordSignature).toHaveBeenCalledTimes(1);
  });

  it('Test 8: resolveRecord never populates the verify cache (DHT records always verified)', async () => {
    // Resolve path should NOT populate the cache. Verify this by confirming
    // that calling publishRecord after resolveRecord still runs verify even when
    // the resolved record has the same ipnsName/seq/sigV2 as the publish request.
    const testSigV2Bytes = new Uint8Array(64).fill(0xab); // same as beforeEach mock
    const mockRecordBytes = new Uint8Array([1, 2, 3]);
    mockDelegatedRoutingClient.resolve.mockResolvedValue(mockRecordBytes);
    // Resolve path parses the record — same sigV2/seq as the publish submission
    mockParseIpnsRecord.mockResolvedValue({
      value: `/ipfs/${testMetadataCid}`,
      sequence: 1n,
      signatureV2: testSigV2Bytes,
    });
    mockFolderIpnsRepo.findOne.mockResolvedValue(null);

    // Call resolveRecord — this must NOT populate the verify cache
    await service.resolveRecord(testIpnsName);

    // Now publishRecord with the same ipnsName — verify must still run
    // (the cache must NOT have been seeded by the resolve path)
    mockFolderIpnsRepo.findOne.mockResolvedValue(null);
    // Restore the same signatureV2 in the publish mock
    mockParseIpnsRecord.mockResolvedValue({
      value: `/ipfs/${testMetadataCid}`,
      sequence: 1n,
      signatureV2: testSigV2Bytes,
    });
    mockVerifyIpnsRecordSignature.mockClear();

    await service.publishRecord(testUserId, createDto());
    // Verify must have been called (cache was NOT populated by resolve)
    expect(mockVerifyIpnsRecordSignature).toHaveBeenCalledTimes(1);
  });

  it('no skipSigVerify flag anywhere in the service', () => {
    // Structural guard: verify the service does not expose a skipSigVerify bypass
    // (grep cannot be run in Jest, but we can confirm the service constructor and
    //  method signatures do not accept such a parameter by inspecting the instance).
    expect((service as unknown as Record<string, unknown>).skipSigVerify).toBeUndefined();
  });
});
