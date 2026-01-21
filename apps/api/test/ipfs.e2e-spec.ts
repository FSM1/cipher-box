import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, CanActivate, ExecutionContext } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { JwtAuthGuard } from '../src/auth/guards/jwt-auth.guard';

// Mock user returned by the guard
const mockUser = {
  id: '00000000-0000-0000-0000-000000000001',
  publicKey:
    '0x0401020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364',
};

// Mock guard that always passes and attaches mock user
const mockAuthGuard: CanActivate = {
  canActivate: (context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    request.user = mockUser;
    return true;
  },
};

describe('IPFS E2E (local node)', () => {
  let app: INestApplication;
  let ipfsAvailable = false;
  const pinnedCids: string[] = [];

  const isLocalProvider = process.env.IPFS_PROVIDER === 'local';
  const ipfsApiUrl = process.env.IPFS_LOCAL_API_URL || 'http://localhost:5001';

  // Check if local IPFS is running
  async function checkIpfsHealth(): Promise<boolean> {
    try {
      const response = await fetch(`${ipfsApiUrl}/api/v0/id`, {
        method: 'POST',
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  // Cleanup: Unpin test files and run GC
  async function cleanupIpfs(): Promise<void> {
    if (!ipfsAvailable || pinnedCids.length === 0) return;

    // Unpin all test files
    for (const cid of pinnedCids) {
      try {
        await fetch(`${ipfsApiUrl}/api/v0/pin/rm?arg=${cid}`, {
          method: 'POST',
        });
      } catch {
        // Ignore unpin errors
      }
    }

    // Run garbage collection
    try {
      await fetch(`${ipfsApiUrl}/api/v0/repo/gc`, { method: 'POST' });
    } catch {
      // Ignore GC errors
    }
  }

  beforeAll(async () => {
    if (!isLocalProvider) {
      console.log('Skipping IPFS E2E tests - IPFS_PROVIDER is not "local"');
      return;
    }

    ipfsAvailable = await checkIpfsHealth();
    if (!ipfsAvailable) {
      console.log('Skipping IPFS E2E tests - local IPFS node not available at', ipfsApiUrl);
      return;
    }

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue(mockAuthGuard)
      .compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await cleanupIpfs();
    if (app) {
      await app.close();
    }
  });

  describe('POST /ipfs/add', () => {
    it('should skip if IPFS not available', async () => {
      if (!isLocalProvider || !ipfsAvailable) {
        console.log('Test skipped - IPFS not available');
        return;
      }

      const testContent = Buffer.from(`test content for E2E - ${Date.now()}`);

      const response = await request(app.getHttpServer())
        .post('/ipfs/add')
        .attach('file', testContent, 'test.bin')
        .expect(201);

      expect(response.body).toHaveProperty('cid');
      expect(response.body).toHaveProperty('size');
      expect(response.body.cid).toMatch(/^bafy/); // CIDv1 prefix
      expect(response.body.size).toBeGreaterThan(0);

      // Track for cleanup
      pinnedCids.push(response.body.cid);

      // Verify file is actually pinned in local node
      const pinCheck = await fetch(`${ipfsApiUrl}/api/v0/pin/ls?arg=${response.body.cid}`, {
        method: 'POST',
      });
      expect(pinCheck.ok).toBe(true);
    });

    it('should pin file and return CID with correct size', async () => {
      if (!isLocalProvider || !ipfsAvailable) {
        console.log('Test skipped - IPFS not available');
        return;
      }

      const testContent = Buffer.from('Hello, IPFS E2E Test!');

      const response = await request(app.getHttpServer())
        .post('/ipfs/add')
        .attach('file', testContent, 'hello.txt')
        .expect(201);

      expect(response.body.cid).toBeDefined();
      expect(response.body.size).toBeGreaterThanOrEqual(testContent.length);

      // Track for cleanup
      pinnedCids.push(response.body.cid);
    });

    it('should reject empty file', async () => {
      if (!isLocalProvider || !ipfsAvailable) {
        console.log('Test skipped - IPFS not available');
        return;
      }

      const emptyContent = Buffer.from('');

      // The validation happens before IPFS - should fail with validation error
      const response = await request(app.getHttpServer())
        .post('/ipfs/add')
        .attach('file', emptyContent, 'empty.txt');

      // Either 400 (validation) or 422 (file processing)
      expect([400, 422]).toContain(response.status);
    });
  });

  describe('POST /ipfs/unpin', () => {
    it('should unpin previously pinned file', async () => {
      if (!isLocalProvider || !ipfsAvailable) {
        console.log('Test skipped - IPFS not available');
        return;
      }

      // First pin a file
      const testContent = Buffer.from(`content to unpin - ${Date.now()}`);
      const addResponse = await request(app.getHttpServer())
        .post('/ipfs/add')
        .attach('file', testContent, 'to-unpin.bin')
        .expect(201);

      const cid = addResponse.body.cid;
      expect(cid).toBeDefined();

      // Then unpin it
      await request(app.getHttpServer()).post('/ipfs/unpin').send({ cid }).expect(201);

      // Verify file is no longer pinned (this will fail/return error)
      const pinCheck = await fetch(`${ipfsApiUrl}/api/v0/pin/ls?arg=${cid}`, { method: 'POST' });
      // The pin check should fail because the file is no longer pinned
      expect(pinCheck.ok).toBe(false);
    });

    it('should handle unpinning already unpinned file gracefully', async () => {
      if (!isLocalProvider || !ipfsAvailable) {
        console.log('Test skipped - IPFS not available');
        return;
      }

      // First pin a file
      const testContent = Buffer.from(`content to double-unpin - ${Date.now()}`);
      const addResponse = await request(app.getHttpServer())
        .post('/ipfs/add')
        .attach('file', testContent, 'to-double-unpin.bin')
        .expect(201);

      const cid = addResponse.body.cid;

      // Unpin once
      await request(app.getHttpServer()).post('/ipfs/unpin').send({ cid }).expect(201);

      // Unpin again - should succeed (idempotent)
      await request(app.getHttpServer()).post('/ipfs/unpin').send({ cid }).expect(201);
    });
  });
});
