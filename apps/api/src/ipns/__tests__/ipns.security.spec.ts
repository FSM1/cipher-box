/**
 * IPNS API Security Tests
 *
 * Tests for IPNS endpoint security including authentication, validation, and error handling.
 * These tests verify the security requirements from the Phase 5 security review.
 */

// Note: ipns module is mocked via moduleNameMapper in jest.config.js

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import request from 'supertest';
import { IpnsController } from '../ipns.controller';
import { IpnsService } from '../ipns.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { MetricsService } from '../../metrics/metrics.service';

describe('IPNS API Security Tests', () => {
  let app: INestApplication;
  let ipnsService: jest.Mocked<IpnsService>;

  const validIpnsName = 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz';
  const validRecord = Buffer.from('test-record-data').toString('base64');
  const validCid = 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
  const validEncryptedKey = 'a'.repeat(200); // Valid hex, meets min length

  beforeAll(async () => {
    const mockIpnsService = {
      publishRecord: jest.fn().mockResolvedValue({
        success: true,
        ipnsName: validIpnsName,
        sequenceNumber: '1',
      }),
      resolveRecord: jest.fn().mockResolvedValue({
        cid: validCid,
        sequenceNumber: '5',
      }),
      getFolderIpns: jest.fn(),
      getAllFolderIpns: jest.fn(),
    };

    const mockMetricsService = {
      ipnsPublishes: { inc: jest.fn() },
      ipnsResolves: { inc: jest.fn() },
    };

    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ThrottlerModule.forRoot([
          {
            ttl: 60000,
            limit: 10,
          },
        ]),
      ],
      controllers: [IpnsController],
      providers: [
        {
          provide: IpnsService,
          useValue: mockIpnsService,
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
      ],
    })
      // Override the JWT guard for controlled testing
      .overrideGuard(JwtAuthGuard)
      .useValue({
        canActivate: jest.fn().mockImplementation((context) => {
          const req = context.switchToHttp().getRequest();
          // Check for Authorization header to simulate auth
          if (req.headers.authorization === 'Bearer valid-token') {
            req.user = { id: 'test-user-id' };
            return true;
          }
          return false;
        }),
      })
      // Override throttler for testing (allow more requests)
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    app = module.createNestApplication();

    // Enable ValidationPipe as in production
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      })
    );

    await app.init();

    ipnsService = module.get(IpnsService);
  });

  afterAll(async () => {
    await app.close();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Authentication', () => {
    it('should reject requests without JWT token', async () => {
      const response = await request(app.getHttpServer()).post('/ipns/publish').send({
        ipnsName: validIpnsName,
        record: validRecord,
        metadataCid: validCid,
      });

      expect(response.status).toBe(403);
      expect(ipnsService.publishRecord).not.toHaveBeenCalled();
    });

    it('should reject requests with invalid JWT token', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer invalid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
        });

      expect(response.status).toBe(403);
      expect(ipnsService.publishRecord).not.toHaveBeenCalled();
    });

    it('should accept requests with valid JWT token', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: validEncryptedKey,
          keyEpoch: 1,
        });

      expect(response.status).toBe(201);
      expect(ipnsService.publishRecord).toHaveBeenCalledTimes(1);
    });
  });

  describe('Input Validation - ipnsName', () => {
    it('should reject invalid ipnsName format (missing k51 prefix)', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: 'invalid-ipns-name',
          record: validRecord,
          metadataCid: validCid,
        });

      expect(response.status).toBe(400);
      // ValidationPipe returns array of error messages
      const messages = Array.isArray(response.body.message)
        ? response.body.message.join(' ')
        : response.body.message;
      expect(messages).toContain('ipnsName must be a valid CIDv1 libp2p-key');
    });

    it('should reject ipnsName that is too short', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: 'k51qzi5uqu5short',
          record: validRecord,
          metadataCid: validCid,
        });

      expect(response.status).toBe(400);
    });

    it('should reject ipnsName with invalid characters', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: 'k51qzi5uqu5UPPERCASE_INVALID_12345678901234567890',
          record: validRecord,
          metadataCid: validCid,
        });

      expect(response.status).toBe(400);
    });

    it('should reject empty ipnsName', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: '',
          record: validRecord,
          metadataCid: validCid,
        });

      expect(response.status).toBe(400);
    });
  });

  describe('Input Validation - record', () => {
    it('should reject non-base64 record', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: 'not-valid-base64!!!@@@',
          metadataCid: validCid,
        });

      expect(response.status).toBe(400);
    });

    it('should reject empty record', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: '',
          metadataCid: validCid,
        });

      expect(response.status).toBe(400);
    });

    it('should reject missing record field', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          metadataCid: validCid,
        });

      expect(response.status).toBe(400);
    });
  });

  describe('Input Validation - metadataCid', () => {
    it('should reject invalid CID format', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: 'invalid-cid-format',
        });

      expect(response.status).toBe(400);
      const messages = Array.isArray(response.body.message)
        ? response.body.message.join(' ')
        : response.body.message;
      expect(messages).toContain('metadataCid must be a valid CID');
    });

    it('should accept CIDv0 format (Qm...)', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG',
          encryptedIpnsPrivateKey: validEncryptedKey,
          keyEpoch: 1,
        });

      expect(response.status).toBe(201);
    });

    it('should accept CIDv1 format (bafy...)', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: validEncryptedKey,
          keyEpoch: 1,
        });

      expect(response.status).toBe(201);
    });
  });

  describe('Input Validation - encryptedIpnsPrivateKey', () => {
    it('should reject non-hex encryptedIpnsPrivateKey', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: 'not-hex-zzzz' + 'g'.repeat(100),
          keyEpoch: 1,
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('encryptedIpnsPrivateKey must be hex-encoded');
    });

    it('should reject encryptedIpnsPrivateKey that is too short', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: 'abcd1234', // Too short for ECIES
          keyEpoch: 1,
        });

      expect(response.status).toBe(400);
      const messages = Array.isArray(response.body.message)
        ? response.body.message.join(' ')
        : response.body.message;
      expect(messages).toContain('encryptedIpnsPrivateKey too short');
    });

    it('should reject encryptedIpnsPrivateKey that is too long', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: 'a'.repeat(1001), // Exceeds max length
          keyEpoch: 1,
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('encryptedIpnsPrivateKey too long');
    });
  });

  describe('Error Handling', () => {
    it('should not leak internal error details', async () => {
      // Mock service to throw internal error
      ipnsService.publishRecord.mockRejectedValueOnce(
        new Error('Database connection failed: postgres://user:password@localhost/db')
      );

      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: validEncryptedKey,
          keyEpoch: 1,
        });

      // Should return 500 but not expose internal details
      expect(response.status).toBe(500);
      // Should NOT contain sensitive information
      expect(JSON.stringify(response.body)).not.toContain('postgres://');
      expect(JSON.stringify(response.body)).not.toContain('password');
    });

    it('should return generic error for delegated routing failures', async () => {
      // Import HttpException for proper error typing
      const { HttpException, HttpStatus } = await import('@nestjs/common');
      ipnsService.publishRecord.mockRejectedValueOnce(
        new HttpException(
          'Failed to publish IPNS record to routing network',
          HttpStatus.BAD_GATEWAY
        )
      );

      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: validEncryptedKey,
          keyEpoch: 1,
        });

      expect(response.status).toBe(502);
      expect(response.body.message).toBe('Failed to publish IPNS record to routing network');
      // Should NOT expose internal routing service URLs or details
      expect(JSON.stringify(response.body)).not.toContain('delegated-ipfs.dev');
    });
  });

  describe('Resolve endpoint', () => {
    it('should return resolve result without signature fields when absent', async () => {
      ipnsService.resolveRecord.mockResolvedValueOnce({
        cid: validCid,
        sequenceNumber: '5',
      });

      const response = await request(app.getHttpServer())
        .get(`/ipns/resolve?ipnsName=${validIpnsName}`)
        .set('Authorization', 'Bearer valid-token');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        success: true,
        cid: validCid,
        sequenceNumber: '5',
      });
      expect(response.body.signatureV2).toBeUndefined();
      expect(response.body.data).toBeUndefined();
      expect(response.body.pubKey).toBeUndefined();
    });

    it('should include signature fields in response when present', async () => {
      ipnsService.resolveRecord.mockResolvedValueOnce({
        cid: validCid,
        sequenceNumber: '5',
        signatureV2: 'c2lnbmF0dXJlLWRhdGE=',
        data: 'Y2Jvci1kYXRh',
        pubKey: 'cHVibGljLWtleQ==',
      });

      const response = await request(app.getHttpServer())
        .get(`/ipns/resolve?ipnsName=${validIpnsName}`)
        .set('Authorization', 'Bearer valid-token');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        success: true,
        cid: validCid,
        sequenceNumber: '5',
        signatureV2: 'c2lnbmF0dXJlLWRhdGE=',
        data: 'Y2Jvci1kYXRh',
        pubKey: 'cHVibGljLWtleQ==',
      });
    });

    it('should return 404 when IPNS name not found', async () => {
      ipnsService.resolveRecord.mockResolvedValueOnce(null);

      const response = await request(app.getHttpServer())
        .get(`/ipns/resolve?ipnsName=${validIpnsName}`)
        .set('Authorization', 'Bearer valid-token');

      expect(response.status).toBe(404);
    });

    it('should drop partial signature fields (all-or-nothing bundle)', async () => {
      // Only signatureV2 present, data and pubKey absent — should be dropped
      ipnsService.resolveRecord.mockResolvedValueOnce({
        cid: validCid,
        sequenceNumber: '3',
        signatureV2: 'c2lnbmF0dXJl',
      });

      const response = await request(app.getHttpServer())
        .get(`/ipns/resolve?ipnsName=${validIpnsName}`)
        .set('Authorization', 'Bearer valid-token');

      expect(response.status).toBe(200);
      expect(response.body.signatureV2).toBeUndefined();
      expect(response.body.data).toBeUndefined();
      expect(response.body.pubKey).toBeUndefined();
    });
  });

  describe('Whitelist Validation (forbidNonWhitelisted)', () => {
    it('should reject requests with extra unknown fields', async () => {
      const response = await request(app.getHttpServer())
        .post('/ipns/publish')
        .set('Authorization', 'Bearer valid-token')
        .send({
          ipnsName: validIpnsName,
          record: validRecord,
          metadataCid: validCid,
          encryptedIpnsPrivateKey: validEncryptedKey,
          keyEpoch: 1,
          maliciousField: 'should-be-rejected',
          anotherBadField: { nested: 'object' },
        });

      expect(response.status).toBe(400);
      const messages = Array.isArray(response.body.message)
        ? response.body.message.join(' ')
        : response.body.message;
      expect(messages).toContain('should not exist');
    });
  });
});
