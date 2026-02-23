import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { TeeService, RepublishEntry, RepublishResult } from './tee.service';
import { TeeKeyStateService } from './tee-key-state.service';
import { TeeKeyState } from './tee-key-state.entity';

// Valid 65-byte uncompressed secp256k1 public key: 0x04 prefix + 64 bytes
const VALID_PUBLIC_KEY_HEX = '04' + 'ab'.repeat(64);

const TEE_WORKER_URL = 'http://tee-worker:3001';
const TEE_WORKER_SECRET = 'test-secret-token';

describe('TeeService', () => {
  let service: TeeService;
  let configService: jest.Mocked<Partial<ConfigService>>;
  let teeKeyStateService: jest.Mocked<Partial<TeeKeyStateService>>;
  let fetchMock: jest.Mock;

  beforeEach(async () => {
    fetchMock = jest.fn();
    global.fetch = fetchMock;

    const mockConfigService = {
      get: jest.fn((key: string, defaultValue?: string) => {
        const config: Record<string, string> = {
          TEE_WORKER_URL: TEE_WORKER_URL,
          TEE_WORKER_SECRET: TEE_WORKER_SECRET,
        };
        return config[key] ?? defaultValue;
      }),
    };

    const mockTeeKeyStateService = {
      getCurrentState: jest.fn(),
      initializeEpoch: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TeeService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: TeeKeyStateService, useValue: mockTeeKeyStateService },
      ],
    }).compile();

    service = module.get<TeeService>(TeeService);
    configService = module.get(ConfigService);
    teeKeyStateService = module.get(TeeKeyStateService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Helper to create a mock Response
  // ---------------------------------------------------------------------------
  function mockResponse(body: unknown, status = 200): Response {
    return {
      ok: status >= 200 && status < 300,
      status,
      json: jest.fn().mockResolvedValue(body),
    } as unknown as Response;
  }

  // ---------------------------------------------------------------------------
  // getHealth()
  // ---------------------------------------------------------------------------
  describe('getHealth', () => {
    it('should return health data on successful response', async () => {
      const healthData = { healthy: true, epoch: 5 };
      fetchMock.mockResolvedValue(mockResponse(healthData));

      const result = await service.getHealth();

      expect(result).toEqual({ healthy: true, epoch: 5 });
      expect(fetchMock).toHaveBeenCalledWith(
        `${TEE_WORKER_URL}/health`,
        expect.objectContaining({
          method: 'GET',
          headers: { Authorization: `Bearer ${TEE_WORKER_SECRET}` },
          signal: expect.any(AbortSignal),
        })
      );
    });

    it('should throw on non-OK HTTP response', async () => {
      fetchMock.mockResolvedValue(mockResponse({}, 503));

      await expect(service.getHealth()).rejects.toThrow('TEE worker health check failed: HTTP 503');
    });

    it('should throw on network error', async () => {
      fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));

      await expect(service.getHealth()).rejects.toThrow('ECONNREFUSED');
    });
  });

  // ---------------------------------------------------------------------------
  // getPublicKey(epoch)
  // ---------------------------------------------------------------------------
  describe('getPublicKey', () => {
    it('should return a Uint8Array for a valid 65-byte key with 0x04 prefix', async () => {
      fetchMock.mockResolvedValue(mockResponse({ publicKey: VALID_PUBLIC_KEY_HEX }));

      const result = await service.getPublicKey(1);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(65);
      expect(result[0]).toBe(0x04);
      expect(fetchMock).toHaveBeenCalledWith(
        `${TEE_WORKER_URL}/public-key?epoch=1`,
        expect.objectContaining({
          method: 'GET',
          signal: expect.any(AbortSignal),
        })
      );
    });

    it('should throw on invalid key length (too short)', async () => {
      // 33 bytes (compressed key) instead of 65
      const shortKeyHex = '04' + 'ab'.repeat(32);
      fetchMock.mockResolvedValue(mockResponse({ publicKey: shortKeyHex }));

      await expect(service.getPublicKey(1)).rejects.toThrow(
        'Invalid TEE public key: expected 65 bytes with 0x04 prefix, got 33 bytes'
      );
    });

    it('should throw on invalid key prefix (not 0x04)', async () => {
      // 65 bytes but starts with 0x02 instead of 0x04
      const wrongPrefixHex = '02' + 'ab'.repeat(64);
      fetchMock.mockResolvedValue(mockResponse({ publicKey: wrongPrefixHex }));

      await expect(service.getPublicKey(1)).rejects.toThrow(
        'Invalid TEE public key: expected 65 bytes with 0x04 prefix, got 65 bytes'
      );
    });

    it('should throw on empty key', async () => {
      fetchMock.mockResolvedValue(mockResponse({ publicKey: '' }));

      await expect(service.getPublicKey(1)).rejects.toThrow(
        'Invalid TEE public key: expected 65 bytes with 0x04 prefix, got 0 bytes'
      );
    });

    it('should throw on non-OK HTTP response', async () => {
      fetchMock.mockResolvedValue(mockResponse({}, 404));

      await expect(service.getPublicKey(99)).rejects.toThrow(
        'TEE worker public key request failed: HTTP 404'
      );
    });

    it('should pass the epoch as a query parameter', async () => {
      fetchMock.mockResolvedValue(mockResponse({ publicKey: VALID_PUBLIC_KEY_HEX }));

      await service.getPublicKey(42);

      expect(fetchMock).toHaveBeenCalledWith(
        `${TEE_WORKER_URL}/public-key?epoch=42`,
        expect.any(Object)
      );
    });
  });

  // ---------------------------------------------------------------------------
  // republish(entries)
  // ---------------------------------------------------------------------------
  describe('republish', () => {
    const sampleEntries: RepublishEntry[] = [
      {
        encryptedIpnsKey: 'base64-encrypted-key-1',
        keyEpoch: 1,
        ipnsName: 'k51qzi5uqu5abc',
        latestCid: 'bafybeiabc',
        sequenceNumber: '10',
        currentEpoch: 1,
        previousEpoch: null,
      },
      {
        encryptedIpnsKey: 'base64-encrypted-key-2',
        keyEpoch: 1,
        ipnsName: 'k51qzi5uqu5def',
        latestCid: 'bafybeighi',
        sequenceNumber: '5',
        currentEpoch: 1,
        previousEpoch: null,
      },
    ];

    const sampleResults: RepublishResult[] = [
      {
        ipnsName: 'k51qzi5uqu5abc',
        success: true,
        signedRecord: 'base64-signed-record-1',
        newSequenceNumber: '11',
      },
      {
        ipnsName: 'k51qzi5uqu5def',
        success: false,
        error: 'Decryption failed',
      },
    ];

    it('should send entries and return results', async () => {
      fetchMock.mockResolvedValue(mockResponse({ results: sampleResults }));

      const results = await service.republish(sampleEntries);

      expect(results).toEqual(sampleResults);
      expect(results).toHaveLength(2);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(false);
    });

    it('should POST to /republish with JSON body', async () => {
      fetchMock.mockResolvedValue(mockResponse({ results: sampleResults }));

      await service.republish(sampleEntries);

      expect(fetchMock).toHaveBeenCalledWith(
        `${TEE_WORKER_URL}/republish`,
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            Authorization: `Bearer ${TEE_WORKER_SECRET}`,
          }),
          body: JSON.stringify({ entries: sampleEntries }),
          signal: expect.any(AbortSignal),
        })
      );
    });

    it('should throw on non-OK HTTP response', async () => {
      fetchMock.mockResolvedValue(mockResponse({}, 500));

      await expect(service.republish(sampleEntries)).rejects.toThrow(
        'TEE worker republish failed: HTTP 500'
      );
    });

    it('should handle empty entries array', async () => {
      fetchMock.mockResolvedValue(mockResponse({ results: [] }));

      const results = await service.republish([]);

      expect(results).toEqual([]);
    });

    it('should handle all-successful results', async () => {
      const allSuccessResults: RepublishResult[] = [
        { ipnsName: 'k51abc', success: true, signedRecord: 'rec1', newSequenceNumber: '2' },
        { ipnsName: 'k51def', success: true, signedRecord: 'rec2', newSequenceNumber: '6' },
      ];
      fetchMock.mockResolvedValue(mockResponse({ results: allSuccessResults }));

      const results = await service.republish(sampleEntries);

      expect(results.filter((r) => r.success)).toHaveLength(2);
    });

    it('should handle results with epoch upgrade fields', async () => {
      const upgradeResults: RepublishResult[] = [
        {
          ipnsName: 'k51abc',
          success: true,
          signedRecord: 'rec1',
          newSequenceNumber: '11',
          upgradedEncryptedKey: 'new-encrypted-key',
          upgradedKeyEpoch: 2,
        },
      ];
      fetchMock.mockResolvedValue(mockResponse({ results: upgradeResults }));

      const results = await service.republish([sampleEntries[0]]);

      expect(results[0].upgradedEncryptedKey).toBe('new-encrypted-key');
      expect(results[0].upgradedKeyEpoch).toBe(2);
    });
  });

  // ---------------------------------------------------------------------------
  // initializeFromTee()
  // ---------------------------------------------------------------------------
  describe('initializeFromTee', () => {
    it('should initialize epoch on first boot (no existing state)', async () => {
      const healthData = { healthy: true, epoch: 1 };
      const publicKeyBytes = new Uint8Array(Buffer.from(VALID_PUBLIC_KEY_HEX, 'hex'));

      // getHealth fetch
      fetchMock.mockResolvedValueOnce(mockResponse(healthData));
      // getPublicKey fetch
      fetchMock.mockResolvedValueOnce(mockResponse({ publicKey: VALID_PUBLIC_KEY_HEX }));

      teeKeyStateService.getCurrentState!.mockResolvedValue(null);
      teeKeyStateService.initializeEpoch!.mockResolvedValue({} as TeeKeyState);

      await service.initializeFromTee();

      expect(teeKeyStateService.getCurrentState).toHaveBeenCalled();
      expect(teeKeyStateService.initializeEpoch).toHaveBeenCalledWith(1, publicKeyBytes);
    });

    it('should validate matching epoch on subsequent boot', async () => {
      const healthData = { healthy: true, epoch: 3 };
      fetchMock.mockResolvedValueOnce(mockResponse(healthData));

      const existingState = {
        currentEpoch: 3,
        currentPublicKey: Buffer.from('abc'),
      } as unknown as TeeKeyState;
      teeKeyStateService.getCurrentState!.mockResolvedValue(existingState);

      await service.initializeFromTee();

      expect(teeKeyStateService.getCurrentState).toHaveBeenCalled();
      expect(teeKeyStateService.initializeEpoch).not.toHaveBeenCalled();
    });

    it('should warn on epoch mismatch but not throw', async () => {
      const healthData = { healthy: true, epoch: 5 };
      fetchMock.mockResolvedValueOnce(mockResponse(healthData));

      const existingState = {
        currentEpoch: 3,
        currentPublicKey: Buffer.from('abc'),
      } as unknown as TeeKeyState;
      teeKeyStateService.getCurrentState!.mockResolvedValue(existingState);

      // Should not throw
      await expect(service.initializeFromTee()).resolves.toBeUndefined();

      expect(teeKeyStateService.initializeEpoch).not.toHaveBeenCalled();
    });

    it('should handle TEE worker being unavailable gracefully', async () => {
      fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));

      // Should not throw - catches and logs warning
      await expect(service.initializeFromTee()).resolves.toBeUndefined();

      expect(teeKeyStateService.getCurrentState).not.toHaveBeenCalled();
      expect(teeKeyStateService.initializeEpoch).not.toHaveBeenCalled();
    });

    it('should handle non-Error thrown values gracefully', async () => {
      fetchMock.mockRejectedValue('string error');

      // Should not throw
      await expect(service.initializeFromTee()).resolves.toBeUndefined();
    });

    it('should handle health check returning non-OK status', async () => {
      fetchMock.mockResolvedValue(mockResponse({}, 503));

      // getHealth will throw, initializeFromTee catches it
      await expect(service.initializeFromTee()).resolves.toBeUndefined();

      expect(teeKeyStateService.getCurrentState).not.toHaveBeenCalled();
    });

    it('should not call getPublicKey when state already exists', async () => {
      const healthData = { healthy: true, epoch: 2 };
      fetchMock.mockResolvedValueOnce(mockResponse(healthData));

      const existingState = {
        currentEpoch: 2,
        currentPublicKey: Buffer.from('abc'),
      } as unknown as TeeKeyState;
      teeKeyStateService.getCurrentState!.mockResolvedValue(existingState);

      await service.initializeFromTee();

      // Only one fetch call (health), not two (health + publicKey)
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  // ---------------------------------------------------------------------------
  // authHeaders() — tested indirectly
  // ---------------------------------------------------------------------------
  describe('authHeaders (indirect)', () => {
    it('should include Authorization header when secret is configured', async () => {
      fetchMock.mockResolvedValue(mockResponse({ healthy: true, epoch: 1 }));

      await service.getHealth();

      expect(fetchMock).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: { Authorization: `Bearer ${TEE_WORKER_SECRET}` },
        })
      );
    });

    it('should send empty headers when no secret is configured', async () => {
      // Rebuild the service with no secret
      const moduleNoSecret: TestingModule = await Test.createTestingModule({
        providers: [
          TeeService,
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn((key: string, defaultValue?: string) => {
                if (key === 'TEE_WORKER_URL') return TEE_WORKER_URL;
                if (key === 'TEE_WORKER_SECRET') return '';
                return defaultValue;
              }),
            },
          },
          {
            provide: TeeKeyStateService,
            useValue: { getCurrentState: jest.fn(), initializeEpoch: jest.fn() },
          },
        ],
      }).compile();

      const serviceNoSecret = moduleNoSecret.get<TeeService>(TeeService);
      fetchMock.mockResolvedValue(mockResponse({ healthy: true, epoch: 1 }));

      await serviceNoSecret.getHealth();

      expect(fetchMock).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: {},
        })
      );
    });
  });

  // ---------------------------------------------------------------------------
  // fetchWithTimeout() — tested indirectly
  // ---------------------------------------------------------------------------
  describe('fetchWithTimeout (indirect)', () => {
    it('should wrap AbortError into a descriptive timeout error', async () => {
      const abortError = new Error('The operation was aborted');
      abortError.name = 'AbortError';
      fetchMock.mockRejectedValue(abortError);

      await expect(service.getHealth()).rejects.toThrow(
        `TEE worker request timed out after 30000ms: ${TEE_WORKER_URL}/health`
      );
    });

    it('should re-throw non-abort errors as-is', async () => {
      const networkError = new Error('DNS resolution failed');
      fetchMock.mockRejectedValue(networkError);

      await expect(service.getHealth()).rejects.toThrow('DNS resolution failed');
    });

    it('should pass AbortSignal to fetch', async () => {
      fetchMock.mockResolvedValue(mockResponse({ healthy: true, epoch: 1 }));

      await service.getHealth();

      const fetchCallArgs = fetchMock.mock.calls[0][1];
      expect(fetchCallArgs.signal).toBeInstanceOf(AbortSignal);
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor / ConfigService integration
  // ---------------------------------------------------------------------------
  describe('constructor', () => {
    it('should use default TEE_WORKER_URL when not configured', async () => {
      const moduleDefaults: TestingModule = await Test.createTestingModule({
        providers: [
          TeeService,
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn((key: string, defaultValue?: string) => defaultValue),
            },
          },
          {
            provide: TeeKeyStateService,
            useValue: { getCurrentState: jest.fn(), initializeEpoch: jest.fn() },
          },
        ],
      }).compile();

      const serviceDefaults = moduleDefaults.get<TeeService>(TeeService);
      fetchMock.mockResolvedValue(mockResponse({ healthy: true, epoch: 1 }));

      await serviceDefaults.getHealth();

      // Should use default URL
      expect(fetchMock).toHaveBeenCalledWith('http://localhost:3001/health', expect.any(Object));
    });

    it('should read TEE_WORKER_URL and TEE_WORKER_SECRET from ConfigService', () => {
      expect(configService.get).toHaveBeenCalledWith('TEE_WORKER_URL', 'http://localhost:3001');
      expect(configService.get).toHaveBeenCalledWith('TEE_WORKER_SECRET', '');
    });
  });
});
