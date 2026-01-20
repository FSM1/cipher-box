# Testing Strategy

**Analysis Date:** 2026-01-20

## Philosophy

CipherBox employs a **Test Pyramid** approach with comprehensive coverage at all layers. Backend and TEE development follows **Test-Driven Development (TDD)**, while frontend relies on **End-to-End automation** for validation.

### Core Principles

1. **TDD for Backend & TEE**: Write tests first, then implementation
2. **Test Pyramid**: More unit tests, fewer E2E tests (fast feedback loops)
3. **Automation First**: All tests run in CI/CD pipeline
4. **Security Testing**: Cryptographic operations require exhaustive testing
5. **Frontend E2E Coverage**: UI tested through automated browser tests

---

## Test Pyramid Overview

```
                    ┌─────────────┐
                    │    E2E      │  ← Slowest, most expensive
                    │  (Cypress)  │     Frontend + API integration
                    ├─────────────┤
                    │ Integration │  ← API layer, service composition
                    │   Tests     │     Database, IPFS, external services
                    ├─────────────┤
                    │    Unit     │  ← Fastest, most numerous
                    │   Tests     │     Functions, classes, modules
                    └─────────────┘
```

**Target Ratios:**
- Unit Tests: 70%
- Integration Tests: 20%
- E2E Tests: 10%

---

## Test Frameworks & Tools

### Backend (NestJS)

| Purpose | Tool | Notes |
|---------|------|-------|
| Unit/Integration Testing | Jest | NestJS default, excellent mocking |
| Test Runner | Jest | Built-in watch mode, coverage |
| Mocking | `@nestjs/testing` + Jest mocks | Service/repository mocking |
| HTTP Testing | Supertest | E2E API testing |
| Coverage | Jest Coverage (Istanbul) | Enforce thresholds in CI |

### Frontend (React)

| Purpose | Tool | Notes |
|---------|------|-------|
| E2E Testing | **Cypress** (recommended) | Modern, reliable, great DX |
| Alternative E2E | Puppeteer | Lower-level, more control |
| Component Testing | Cypress Component Testing | Optional for complex components |
| Visual Regression | Cypress + Percy (optional) | Catch UI regressions |

### TEE (Trusted Execution Environment)

| Purpose | Tool | Notes |
|---------|------|-------|
| Unit Testing | Rust test framework | Native `#[test]` attributes |
| Integration Testing | Custom harness | Mock enclave for local testing |
| Security Testing | Manual + automated audits | Enclave attestation verification |

---

## Backend Testing Strategy

### Test-Driven Development (TDD) Workflow

**Mandatory for all backend development.** Follow the Red-Green-Refactor cycle:

```
┌─────────────────────────────────────────────────────────────┐
│  1. RED: Write a failing test for the new functionality     │
│                           ↓                                 │
│  2. GREEN: Write minimal code to make the test pass         │
│                           ↓                                 │
│  3. REFACTOR: Clean up code while keeping tests green       │
│                           ↓                                 │
│  4. REPEAT: Next requirement                                │
└─────────────────────────────────────────────────────────────┘
```

**TDD Rules:**
- No production code without a failing test first
- Tests must fail for the right reason before implementing
- Write the simplest code to pass the test
- Refactor only when tests are green
- Commit after each green phase

### Unit Tests

**Location:** Co-located with source files (`*.spec.ts`)

```
src/
├── auth/
│   ├── auth.service.ts
│   ├── auth.service.spec.ts      ← Unit tests
│   ├── auth.controller.ts
│   └── auth.controller.spec.ts   ← Unit tests
├── vault/
│   ├── vault.service.ts
│   └── vault.service.spec.ts
└── crypto/
    ├── crypto.service.ts
    └── crypto.service.spec.ts
```

**What to Unit Test:**
- Service methods in isolation
- Controller request handling and response formatting
- DTOs and validation logic
- Utility functions (crypto, data conversion)
- Guards and middleware
- Error handling and edge cases

**Unit Test Example (TDD Style):**

```typescript
// vault.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { VaultService } from './vault.service';
import { PrismaService } from '../prisma/prisma.service';
import { CryptoService } from '../crypto/crypto.service';

describe('VaultService', () => {
  let service: VaultService;
  let prisma: jest.Mocked<PrismaService>;
  let crypto: jest.Mocked<CryptoService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VaultService,
        {
          provide: PrismaService,
          useValue: {
            vault: {
              create: jest.fn(),
              findUnique: jest.fn(),
              update: jest.fn(),
            },
          },
        },
        {
          provide: CryptoService,
          useValue: {
            generateFolderKey: jest.fn(),
            encryptWithEcies: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<VaultService>(VaultService);
    prisma = module.get(PrismaService);
    crypto = module.get(CryptoService);
  });

  describe('createVault', () => {
    it('should create vault with encrypted root folder key', async () => {
      // Arrange
      const userId = 'user-123';
      const publicKey = '04abc...';
      const folderKey = new Uint8Array(32).fill(0x42);
      const encryptedKey = 'encrypted-key-hex';

      crypto.generateFolderKey.mockReturnValue(folderKey);
      crypto.encryptWithEcies.mockResolvedValue(encryptedKey);
      prisma.vault.create.mockResolvedValue({
        id: 'vault-123',
        userId,
        rootFolderKey: encryptedKey,
        rootIpnsName: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Act
      const result = await service.createVault(userId, publicKey);

      // Assert
      expect(crypto.generateFolderKey).toHaveBeenCalled();
      expect(crypto.encryptWithEcies).toHaveBeenCalledWith(folderKey, publicKey);
      expect(prisma.vault.create).toHaveBeenCalledWith({
        data: {
          userId,
          rootFolderKey: encryptedKey,
        },
      });
      expect(result.id).toBe('vault-123');
    });

    it('should throw if user already has a vault', async () => {
      // Arrange
      const userId = 'user-123';
      prisma.vault.findUnique.mockResolvedValue({ id: 'existing-vault' } as any);

      // Act & Assert
      await expect(service.createVault(userId, 'pubkey'))
        .rejects.toThrow('User already has a vault');
    });
  });
});
```

**Mocking Guidelines:**
- Mock all external dependencies (database, IPFS, Pinata)
- Never mock cryptographic functions - test real encryption/decryption
- Use factory functions for test data
- Reset mocks between tests

### Integration Tests

**Location:** `test/integration/` directory

```
test/
├── integration/
│   ├── auth.integration.spec.ts
│   ├── vault.integration.spec.ts
│   ├── ipfs.integration.spec.ts
│   └── ipns.integration.spec.ts
└── fixtures/
    ├── users.fixture.ts
    └── vaults.fixture.ts
```

**What to Integration Test:**
- Full request/response cycles through controllers
- Database operations with test database
- Service-to-service interactions
- External service integrations (mocked at network boundary)
- Authentication and authorization flows

**Integration Test Example:**

```typescript
// test/integration/vault.integration.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { PrismaService } from '../../src/prisma/prisma.service';

describe('Vault Integration (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let authToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    prisma = moduleFixture.get<PrismaService>(PrismaService);
    await app.init();

    // Setup: Create test user and get auth token
    authToken = await getTestAuthToken(app);
  });

  afterAll(async () => {
    await prisma.vault.deleteMany();
    await prisma.user.deleteMany();
    await app.close();
  });

  describe('POST /vault', () => {
    it('should create a new vault for authenticated user', async () => {
      const response = await request(app.getHttpServer())
        .post('/vault')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ publicKey: '04abc123...' })
        .expect(201);

      expect(response.body).toMatchObject({
        id: expect.any(String),
        rootFolderKey: expect.any(String),
        rootIpnsName: null,
      });

      // Verify in database
      const vault = await prisma.vault.findUnique({
        where: { id: response.body.id },
      });
      expect(vault).not.toBeNull();
    });

    it('should return 401 without auth token', async () => {
      await request(app.getHttpServer())
        .post('/vault')
        .send({ publicKey: '04abc123...' })
        .expect(401);
    });

    it('should return 409 if vault already exists', async () => {
      // First request creates vault
      await request(app.getHttpServer())
        .post('/vault')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ publicKey: '04abc123...' })
        .expect(201);

      // Second request should conflict
      await request(app.getHttpServer())
        .post('/vault')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ publicKey: '04abc123...' })
        .expect(409);
    });
  });
});
```

### API E2E Tests

**Location:** `test/e2e/` directory

**What to E2E Test:**
- Complete user journeys through the API
- Multi-step workflows (create vault → upload file → verify)
- Error recovery scenarios
- Rate limiting and security controls

**API E2E Test Example:**

```typescript
// test/e2e/file-upload-flow.e2e-spec.ts
describe('File Upload Flow (E2E)', () => {
  it('should complete full file upload and retrieval cycle', async () => {
    // 1. Authenticate
    const authResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ token: testWeb3AuthToken })
      .expect(200);

    const { accessToken } = authResponse.body;

    // 2. Create vault
    const vaultResponse = await request(app.getHttpServer())
      .post('/vault')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey: testPublicKey })
      .expect(201);

    // 3. Upload file to IPFS
    const uploadResponse = await request(app.getHttpServer())
      .post('/ipfs/add')
      .set('Authorization', `Bearer ${accessToken}`)
      .attach('file', Buffer.from('encrypted-content'), 'test.enc')
      .expect(201);

    expect(uploadResponse.body.cid).toMatch(/^Qm/);

    // 4. Publish IPNS record
    const publishResponse = await request(app.getHttpServer())
      .post('/ipns/publish')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        ipnsName: testIpnsName,
        signedRecord: testSignedRecord,
        encryptedIpnsKey: testEncryptedKey,
      })
      .expect(201);

    // 5. Retrieve file
    const fetchResponse = await request(app.getHttpServer())
      .get(`/ipfs/cat/${uploadResponse.body.cid}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(fetchResponse.body).toEqual(Buffer.from('encrypted-content'));
  });
});
```

---

## Frontend Testing Strategy

### E2E Automation with Cypress

**No TDD required for frontend.** Coverage achieved through comprehensive E2E tests.

**Location:** `apps/web/cypress/` or `frontend/cypress/`

```
cypress/
├── e2e/
│   ├── auth/
│   │   ├── login.cy.ts
│   │   ├── logout.cy.ts
│   │   └── session-expiry.cy.ts
│   ├── vault/
│   │   ├── create-vault.cy.ts
│   │   ├── file-upload.cy.ts
│   │   ├── file-download.cy.ts
│   │   ├── folder-operations.cy.ts
│   │   └── file-sharing.cy.ts
│   └── settings/
│       ├── account-settings.cy.ts
│       └── security-settings.cy.ts
├── fixtures/
│   ├── users.json
│   ├── files.json
│   └── mock-responses.json
├── support/
│   ├── commands.ts           ← Custom commands
│   ├── e2e.ts
│   └── auth.ts               ← Auth helpers
└── cypress.config.ts
```

### Cypress Configuration

```typescript
// cypress.config.ts
import { defineConfig } from 'cypress';

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    viewportWidth: 1280,
    viewportHeight: 720,
    video: true,
    screenshotOnRunFailure: true,
    retries: {
      runMode: 2,
      openMode: 0,
    },
    env: {
      apiUrl: 'http://localhost:4000',
    },
    setupNodeEvents(on, config) {
      // Task plugins for database seeding, etc.
    },
  },
  component: {
    devServer: {
      framework: 'react',
      bundler: 'vite',
    },
  },
});
```

### Custom Cypress Commands

```typescript
// cypress/support/commands.ts
declare global {
  namespace Cypress {
    interface Chainable {
      login(email?: string): Chainable<void>;
      mockWeb3Auth(): Chainable<void>;
      createVault(): Chainable<{ vaultId: string }>;
      uploadFile(fileName: string, content: string): Chainable<{ cid: string }>;
      interceptApi(method: string, path: string, response: object): Chainable<void>;
    }
  }
}

Cypress.Commands.add('login', (email = 'test@example.com') => {
  // Mock Web3Auth flow
  cy.window().then((win) => {
    win.localStorage.setItem('web3auth_token', 'mock-token');
    win.localStorage.setItem('user_email', email);
  });

  cy.intercept('POST', '/api/auth/login', {
    statusCode: 200,
    body: {
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
      user: { id: 'user-123', email },
    },
  }).as('loginRequest');

  cy.visit('/');
  cy.wait('@loginRequest');
});

Cypress.Commands.add('createVault', () => {
  cy.intercept('POST', '/api/vault', {
    statusCode: 201,
    body: {
      id: 'vault-123',
      rootFolderKey: 'encrypted-key',
      rootIpnsName: null,
    },
  }).as('createVault');

  cy.get('[data-testid="create-vault-btn"]').click();
  cy.wait('@createVault');

  return cy.wrap({ vaultId: 'vault-123' });
});

Cypress.Commands.add('uploadFile', (fileName: string, content: string) => {
  cy.intercept('POST', '/api/ipfs/add', {
    statusCode: 201,
    body: { cid: 'QmTestCid123' },
  }).as('uploadFile');

  cy.get('[data-testid="file-input"]').selectFile({
    contents: Cypress.Buffer.from(content),
    fileName,
    mimeType: 'application/octet-stream',
  });

  cy.get('[data-testid="upload-btn"]').click();
  cy.wait('@uploadFile');

  return cy.wrap({ cid: 'QmTestCid123' });
});
```

### E2E Test Examples

#### Authentication Flow

```typescript
// cypress/e2e/auth/login.cy.ts
describe('Authentication', () => {
  beforeEach(() => {
    cy.visit('/');
  });

  it('should display login options', () => {
    cy.get('[data-testid="login-google"]').should('be.visible');
    cy.get('[data-testid="login-email"]').should('be.visible');
    cy.get('[data-testid="login-wallet"]').should('be.visible');
  });

  it('should complete Google login flow', () => {
    cy.mockWeb3Auth();

    cy.get('[data-testid="login-google"]').click();

    // Verify redirect to vault
    cy.url().should('include', '/vault');
    cy.get('[data-testid="user-menu"]').should('contain', 'test@example.com');
  });

  it('should handle login failure gracefully', () => {
    cy.intercept('POST', '/api/auth/login', {
      statusCode: 401,
      body: { message: 'Invalid token' },
    });

    cy.get('[data-testid="login-google"]').click();

    cy.get('[data-testid="error-message"]')
      .should('be.visible')
      .and('contain', 'Authentication failed');
  });

  it('should redirect unauthenticated users to login', () => {
    cy.visit('/vault');
    cy.url().should('include', '/login');
  });
});
```

#### File Operations

```typescript
// cypress/e2e/vault/file-upload.cy.ts
describe('File Upload', () => {
  beforeEach(() => {
    cy.login();
    cy.createVault();
    cy.visit('/vault');
  });

  it('should upload a file successfully', () => {
    const fileName = 'test-document.txt';
    const fileContent = 'Hello, CipherBox!';

    cy.uploadFile(fileName, fileContent);

    // Verify file appears in list
    cy.get('[data-testid="file-list"]')
      .should('contain', fileName);

    // Verify success notification
    cy.get('[data-testid="notification"]')
      .should('contain', 'File uploaded successfully');
  });

  it('should show upload progress', () => {
    cy.intercept('POST', '/api/ipfs/add', (req) => {
      req.on('response', (res) => {
        res.setDelay(1000); // Simulate slow upload
      });
    });

    cy.uploadFile('large-file.bin', 'x'.repeat(10000));

    cy.get('[data-testid="upload-progress"]')
      .should('be.visible');
  });

  it('should handle upload failure', () => {
    cy.intercept('POST', '/api/ipfs/add', {
      statusCode: 500,
      body: { message: 'IPFS unavailable' },
    });

    cy.uploadFile('test.txt', 'content');

    cy.get('[data-testid="error-message"]')
      .should('contain', 'Upload failed');
  });

  it('should encrypt file before upload', () => {
    cy.intercept('POST', '/api/ipfs/add', (req) => {
      // Verify request body is encrypted (not plaintext)
      const body = req.body;
      expect(body).not.to.contain('Hello, CipherBox!');
    }).as('uploadEncrypted');

    cy.uploadFile('secret.txt', 'Hello, CipherBox!');
    cy.wait('@uploadEncrypted');
  });
});
```

#### Folder Navigation

```typescript
// cypress/e2e/vault/folder-operations.cy.ts
describe('Folder Operations', () => {
  beforeEach(() => {
    cy.login();
    cy.visit('/vault');
  });

  it('should create a new folder', () => {
    cy.get('[data-testid="new-folder-btn"]').click();
    cy.get('[data-testid="folder-name-input"]').type('Documents');
    cy.get('[data-testid="create-folder-confirm"]').click();

    cy.get('[data-testid="folder-list"]')
      .should('contain', 'Documents');
  });

  it('should navigate into folder', () => {
    // Create folder first
    cy.get('[data-testid="new-folder-btn"]').click();
    cy.get('[data-testid="folder-name-input"]').type('Documents');
    cy.get('[data-testid="create-folder-confirm"]').click();

    // Navigate into it
    cy.get('[data-testid="folder-Documents"]').dblclick();

    // Verify breadcrumb
    cy.get('[data-testid="breadcrumb"]')
      .should('contain', 'Root')
      .and('contain', 'Documents');

    // Verify empty state
    cy.get('[data-testid="empty-folder"]')
      .should('contain', 'This folder is empty');
  });

  it('should navigate using breadcrumbs', () => {
    // Setup nested folders
    cy.createNestedFolders(['Documents', 'Work', 'Projects']);

    // Navigate to deepest folder
    cy.visit('/vault/documents/work/projects');

    // Click on "Work" breadcrumb
    cy.get('[data-testid="breadcrumb-Work"]').click();

    // Verify navigation
    cy.url().should('include', '/vault/documents/work');
    cy.get('[data-testid="folder-list"]')
      .should('contain', 'Projects');
  });

  it('should delete empty folder', () => {
    cy.get('[data-testid="new-folder-btn"]').click();
    cy.get('[data-testid="folder-name-input"]').type('ToDelete');
    cy.get('[data-testid="create-folder-confirm"]').click();

    cy.get('[data-testid="folder-ToDelete"]').rightclick();
    cy.get('[data-testid="context-menu-delete"]').click();
    cy.get('[data-testid="confirm-delete"]').click();

    cy.get('[data-testid="folder-list"]')
      .should('not.contain', 'ToDelete');
  });
});
```

### Alternative: Puppeteer Setup

If Puppeteer is preferred over Cypress:

```typescript
// e2e/puppeteer/login.test.ts
import puppeteer, { Browser, Page } from 'puppeteer';

describe('Authentication', () => {
  let browser: Browser;
  let page: Page;

  beforeAll(async () => {
    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox'],
    });
  });

  afterAll(async () => {
    await browser.close();
  });

  beforeEach(async () => {
    page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 720 });
  });

  afterEach(async () => {
    await page.close();
  });

  it('should display login page', async () => {
    await page.goto('http://localhost:3000');

    const loginButton = await page.$('[data-testid="login-google"]');
    expect(loginButton).not.toBeNull();
  });

  it('should show error on failed login', async () => {
    await page.goto('http://localhost:3000');

    // Mock failed auth response
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      if (request.url().includes('/api/auth/login')) {
        request.respond({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid token' }),
        });
      } else {
        request.continue();
      }
    });

    await page.click('[data-testid="login-google"]');

    const errorMessage = await page.waitForSelector('[data-testid="error-message"]');
    const text = await errorMessage?.evaluate((el) => el.textContent);
    expect(text).toContain('Authentication failed');
  });
});
```

---

## TEE Testing Strategy

### Test-Driven Development (TDD) for TEE

**Mandatory TDD for all TEE code.** Security-critical code requires exhaustive testing.

### Unit Tests (Rust)

```rust
// src/crypto/tests.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_ipns_key_success() {
        // Arrange
        let enclave_keypair = generate_test_keypair();
        let ipns_private_key = [0x42u8; 32];
        let encrypted_key = encrypt_for_enclave(&ipns_private_key, &enclave_keypair.public);

        // Act
        let decrypted = decrypt_ipns_key(&encrypted_key, &enclave_keypair.private);

        // Assert
        assert_eq!(decrypted.unwrap(), ipns_private_key);
    }

    #[test]
    fn test_decrypt_ipns_key_wrong_epoch() {
        let current_keypair = generate_test_keypair();
        let old_keypair = generate_test_keypair();
        let ipns_private_key = [0x42u8; 32];
        let encrypted_key = encrypt_for_enclave(&ipns_private_key, &old_keypair.public);

        let result = decrypt_ipns_key(&encrypted_key, &current_keypair.private);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TeeError::DecryptionFailed);
    }

    #[test]
    fn test_sign_ipns_record() {
        let ipns_private_key = generate_ed25519_keypair();
        let record_data = b"ipns-record-content";

        let signature = sign_ipns_record(record_data, &ipns_private_key.private);

        assert!(verify_signature(record_data, &signature, &ipns_private_key.public));
    }

    #[test]
    fn test_key_cleared_after_signing() {
        // Verify key material is zeroed after use
        let ipns_private_key = [0x42u8; 32];
        let mut key_copy = ipns_private_key.clone();

        sign_and_clear(&mut key_copy, b"data");

        assert_eq!(key_copy, [0u8; 32]); // Key should be zeroed
    }
}
```

### Integration Tests (Mock Enclave)

```rust
// tests/integration/republish_flow.rs
#[test]
fn test_full_republish_flow() {
    let mock_enclave = MockEnclave::new();
    let backend_client = MockBackendClient::new();

    // Setup: encrypted IPNS key from backend
    let encrypted_key = backend_client.get_encrypted_ipns_key("user-123", "folder-abc");

    // Execute: TEE decrypts and signs
    let signed_record = mock_enclave.republish_ipns(
        encrypted_key,
        "new-cid",
        "ipns-name",
    );

    // Verify: signature is valid
    assert!(signed_record.is_valid());
    assert!(backend_client.can_publish(signed_record));
}
```

---

## Cryptographic Testing

### Critical Test Cases

All cryptographic functions require comprehensive testing regardless of layer:

```typescript
// crypto.service.spec.ts
describe('CryptoService', () => {
  describe('AES-256-GCM', () => {
    it('should encrypt and decrypt data correctly', () => {
      const key = randomBytes(32);
      const plaintext = Buffer.from('sensitive data');

      const { ciphertext, iv, tag } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, key, iv, tag);

      expect(decrypted).toEqual(plaintext);
    });

    it('should produce different ciphertext for same plaintext', () => {
      const key = randomBytes(32);
      const plaintext = Buffer.from('sensitive data');

      const result1 = encrypt(plaintext, key);
      const result2 = encrypt(plaintext, key);

      expect(result1.ciphertext).not.toEqual(result2.ciphertext);
      expect(result1.iv).not.toEqual(result2.iv);
    });

    it('should fail with wrong key', () => {
      const key1 = randomBytes(32);
      const key2 = randomBytes(32);
      const plaintext = Buffer.from('sensitive data');

      const { ciphertext, iv, tag } = encrypt(plaintext, key1);

      expect(() => decrypt(ciphertext, key2, iv, tag)).toThrow();
    });

    it('should fail with tampered ciphertext', () => {
      const key = randomBytes(32);
      const plaintext = Buffer.from('sensitive data');

      const { ciphertext, iv, tag } = encrypt(plaintext, key);
      ciphertext[0] ^= 0xff; // Tamper with first byte

      expect(() => decrypt(ciphertext, key, iv, tag)).toThrow();
    });

    it('should fail with tampered auth tag', () => {
      const key = randomBytes(32);
      const plaintext = Buffer.from('sensitive data');

      const { ciphertext, iv, tag } = encrypt(plaintext, key);
      tag[0] ^= 0xff; // Tamper with tag

      expect(() => decrypt(ciphertext, key, iv, tag)).toThrow();
    });
  });

  describe('ECIES', () => {
    it('should wrap and unwrap keys correctly', () => {
      const { publicKey, privateKey } = generateKeyPair();
      const secretKey = randomBytes(32);

      const wrapped = eciesEncrypt(secretKey, publicKey);
      const unwrapped = eciesDecrypt(wrapped, privateKey);

      expect(unwrapped).toEqual(secretKey);
    });

    it('should fail with wrong private key', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const secretKey = randomBytes(32);

      const wrapped = eciesEncrypt(secretKey, keyPair1.publicKey);

      expect(() => eciesDecrypt(wrapped, keyPair2.privateKey)).toThrow();
    });
  });

  describe('Data Conversion', () => {
    it('should convert hex to bytes and back', () => {
      const hex = 'deadbeef';
      const bytes = hexToBytes(hex);
      const backToHex = bytesToHex(bytes);

      expect(backToHex).toBe(hex);
    });

    it('should handle 0x prefix', () => {
      const hex = '0xdeadbeef';
      const bytes = hexToBytes(hex);

      expect(bytes.length).toBe(4);
      expect(bytesToHex(bytes)).toBe('deadbeef');
    });

    it('should convert UTF-8 correctly', () => {
      const text = 'Hello, 世界! 🔐';
      const bytes = utf8ToBytes(text);
      const backToText = bytesToUtf8(bytes);

      expect(backToText).toBe(text);
    });
  });
});
```

---

## Test Data & Fixtures

### Backend Fixtures

```typescript
// test/fixtures/users.fixture.ts
export const createTestUser = (overrides: Partial<User> = {}): User => ({
  id: 'user-123',
  email: 'test@example.com',
  publicKey: '04abc...',
  createdAt: new Date('2024-01-01'),
  updatedAt: new Date('2024-01-01'),
  ...overrides,
});

export const createTestVault = (overrides: Partial<Vault> = {}): Vault => ({
  id: 'vault-123',
  userId: 'user-123',
  rootFolderKey: 'encrypted-key-hex',
  rootIpnsName: 'k51qzi5uqu5...',
  createdAt: new Date('2024-01-01'),
  updatedAt: new Date('2024-01-01'),
  ...overrides,
});

// test/fixtures/crypto.fixture.ts
export const TEST_PRIVATE_KEY = new Uint8Array(32).fill(0x42);
export const TEST_PUBLIC_KEY = getPublicKey(TEST_PRIVATE_KEY, false);

export const createTestFolderMetadata = (): FolderMetadata => ({
  children: [],
  metadata: {
    created: Date.now(),
    modified: Date.now(),
  },
});
```

### Cypress Fixtures

```json
// cypress/fixtures/users.json
{
  "validUser": {
    "email": "test@example.com",
    "accessToken": "mock-access-token",
    "refreshToken": "mock-refresh-token"
  },
  "expiredTokenUser": {
    "email": "expired@example.com",
    "accessToken": "expired-token"
  }
}
```

---

## Coverage Requirements

### Backend Coverage Targets

| Area | Line Coverage | Branch Coverage |
|------|---------------|-----------------|
| Crypto Services | 100% | 100% |
| Auth Services | 90% | 85% |
| Vault Services | 90% | 85% |
| IPFS/IPNS Services | 85% | 80% |
| Controllers | 80% | 75% |
| Guards/Middleware | 90% | 85% |
| **Overall** | **85%** | **80%** |

### Frontend Coverage Targets

E2E tests don't measure code coverage. Instead, measure:

| Metric | Target |
|--------|--------|
| Critical User Journeys Covered | 100% |
| Error Scenarios Tested | 90% |
| Test Pass Rate | 100% |
| Flaky Tests | 0% |

### TEE Coverage Targets

| Area | Coverage |
|------|----------|
| Crypto Functions | 100% |
| Key Handling | 100% |
| Error Paths | 100% |

---

## CI/CD Integration

### GitHub Actions Pipeline

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  backend-unit:
    name: Backend Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci
        working-directory: ./apps/api

      - name: Run unit tests
        run: npm run test:cov
        working-directory: ./apps/api

      - name: Check coverage thresholds
        run: npm run test:cov:check
        working-directory: ./apps/api

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./apps/api/coverage/lcov.info

  backend-integration:
    name: Backend Integration Tests
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: cipherbox_test
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci
        working-directory: ./apps/api

      - name: Run migrations
        run: npm run db:migrate
        working-directory: ./apps/api
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/cipherbox_test

      - name: Run integration tests
        run: npm run test:integration
        working-directory: ./apps/api
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/cipherbox_test

  frontend-e2e:
    name: Frontend E2E Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build frontend
        run: npm run build
        working-directory: ./apps/web

      - name: Start server
        run: npm run start:ci &
        working-directory: ./apps/web

      - name: Wait for server
        run: npx wait-on http://localhost:3000

      - name: Run Cypress tests
        uses: cypress-io/github-action@v6
        with:
          working-directory: ./apps/web
          browser: chrome
          record: true
        env:
          CYPRESS_RECORD_KEY: ${{ secrets.CYPRESS_RECORD_KEY }}

      - name: Upload screenshots
        uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: cypress-screenshots
          path: apps/web/cypress/screenshots

      - name: Upload videos
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cypress-videos
          path: apps/web/cypress/videos

  tee-tests:
    name: TEE Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run tests
        run: cargo test --all-features
        working-directory: ./tee

      - name: Run with coverage
        run: cargo tarpaulin --out Xml
        working-directory: ./tee

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./tee/cobertura.xml
```

---

## Automated Linting & Pre-commit Hooks

### Overview

All code must pass automated linting and testing before commit. Pre-commit hooks **enforce** these standards automatically - commits are blocked if checks fail.

### Husky Setup

```bash
# Install husky
npm install -D husky

# Initialize husky
npx husky init

# Add pre-commit hook
echo '#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

# Run lint-staged for linting and formatting
npx lint-staged

# Run tests for changed files
npm run test:changed --if-present
' > .husky/pre-commit

# Add pre-push hook (runs full test suite)
echo '#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

# Run full test suite before push
npm run test:ci
' > .husky/pre-push

chmod +x .husky/pre-commit .husky/pre-push
```

### lint-staged Configuration

```javascript
// lint-staged.config.js
module.exports = {
  // Backend TypeScript files
  'apps/api/**/*.ts': [
    'eslint --fix --max-warnings 0',
    'prettier --write',
    'jest --bail --findRelatedTests --passWithNoTests',
  ],

  // Frontend TypeScript/React files
  'apps/web/**/*.{ts,tsx}': [
    'eslint --fix --max-warnings 0',
    'prettier --write',
  ],

  // Rust files (TEE)
  'tee/**/*.rs': [
    'cargo fmt --check',
    'cargo clippy -- -D warnings',
  ],

  // JSON, YAML, Markdown
  '**/*.{json,yaml,yml}': ['prettier --write'],
  '**/*.md': ['prettier --write --prose-wrap always'],
};
```

### ESLint Configuration (Backend)

```javascript
// apps/api/.eslintrc.js
module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint/eslint-plugin', 'jest'],
  extends: [
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'plugin:jest/recommended',
    'prettier',
  ],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  ignorePatterns: ['.eslintrc.js', 'dist/', 'coverage/'],
  rules: {
    // Enforce strict typing
    '@typescript-eslint/explicit-function-return-type': 'error',
    '@typescript-eslint/explicit-module-boundary-types': 'error',
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],

    // Security rules
    '@typescript-eslint/no-unsafe-assignment': 'error',
    '@typescript-eslint/no-unsafe-member-access': 'error',
    '@typescript-eslint/no-unsafe-call': 'error',

    // Code quality
    'no-console': ['error', { allow: ['warn', 'error'] }],
    'prefer-const': 'error',
    'no-var': 'error',

    // Jest rules
    'jest/no-disabled-tests': 'error',
    'jest/no-focused-tests': 'error',
    'jest/valid-expect': 'error',
  },
};
```

### ESLint Configuration (Frontend)

```javascript
// apps/web/.eslintrc.js
module.exports = {
  extends: [
    'react-app',
    'react-app/jest',
    'plugin:@typescript-eslint/recommended',
    'plugin:jsx-a11y/recommended',
    'prettier',
  ],
  plugins: ['@typescript-eslint', 'jsx-a11y'],
  rules: {
    // React best practices
    'react/jsx-key': 'error',
    'react/no-array-index-key': 'warn',
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',

    // Accessibility
    'jsx-a11y/alt-text': 'error',
    'jsx-a11y/click-events-have-key-events': 'error',

    // TypeScript
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  },
};
```

### Prettier Configuration

```json
// .prettierrc
{
  "semi": true,
  "singleQuote": true,
  "trailingComma": "all",
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false,
  "bracketSpacing": true,
  "arrowParens": "always",
  "endOfLine": "lf"
}
```

### Pre-commit Hook Behavior

| Check | Backend | Frontend | TEE | Blocks Commit |
|-------|---------|----------|-----|---------------|
| ESLint | Yes | Yes | N/A | **Yes** |
| Prettier | Yes | Yes | N/A | **Yes** |
| Cargo fmt | N/A | N/A | Yes | **Yes** |
| Cargo clippy | N/A | N/A | Yes | **Yes** |
| Unit tests (changed files) | Yes | No | Yes | **Yes** |
| Type checking | Yes | Yes | Yes | **Yes** |

### Pre-push Hook Behavior

| Check | Scope | Blocks Push |
|-------|-------|-------------|
| Full unit test suite | All | **Yes** |
| Integration tests | Backend | **Yes** |
| Coverage thresholds | All | **Yes** |
| Build verification | All | **Yes** |

### Enforcement Rules

1. **Zero Tolerance for Lint Errors**
   - `--max-warnings 0` ensures warnings are treated as errors
   - No `eslint-disable` comments without justification in PR

2. **No Skipped Tests in Main**
   - `jest/no-disabled-tests: error` prevents `.skip()` or `xit()`
   - `jest/no-focused-tests: error` prevents `.only()` or `fit()`

3. **Automated Fixes Applied**
   - Fixable issues (formatting, import order) are auto-corrected
   - Only unfixable issues block the commit

4. **Related Tests Must Pass**
   - `jest --findRelatedTests` runs tests affected by staged changes
   - Prevents breaking changes from being committed

### Bypassing Hooks (Emergency Only)

```bash
# Skip pre-commit hooks (use sparingly, requires justification in PR)
git commit --no-verify -m "emergency fix: <description>"

# Skip pre-push hooks
git push --no-verify
```

**Warning:** Bypassing hooks requires explicit justification in the pull request. CI will still run all checks - bypassing locally only delays failure.

### CI Verification

Pre-commit checks are duplicated in CI to catch bypassed hooks:

```yaml
# .github/workflows/lint.yml
name: Lint

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Run ESLint
        run: npm run lint -- --max-warnings 0

      - name: Check Prettier formatting
        run: npm run format:check

      - name: TypeScript type check
        run: npm run typecheck

  lint-rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Check formatting
        run: cargo fmt --check
        working-directory: ./tee

      - name: Run Clippy
        run: cargo clippy -- -D warnings
        working-directory: ./tee
```

### Package.json Scripts

```json
{
  "scripts": {
    "lint": "eslint . --ext .ts,.tsx",
    "lint:fix": "eslint . --ext .ts,.tsx --fix",
    "format": "prettier --write .",
    "format:check": "prettier --check .",
    "typecheck": "tsc --noEmit",
    "test:changed": "jest --bail --findRelatedTests --passWithNoTests",
    "test:ci": "jest --ci --coverage --runInBand",
    "prepare": "husky"
  }
}
```

---

### Jest Configuration (Backend)

```javascript
// apps/api/jest.config.js
module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: ['**/*.(t|j)s', '!**/*.module.ts', '!**/index.ts'],
  coverageDirectory: '../coverage',
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 85,
      lines: 85,
      statements: 85,
    },
    './src/crypto/': {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/../test/setup.ts'],
};
```

---

## Test Commands

### Backend

```bash
# Unit tests
npm run test              # Run all unit tests
npm run test:watch        # Watch mode
npm run test:cov          # With coverage
npm run test:debug        # Debug mode

# Integration tests
npm run test:integration  # Run integration tests
npm run test:e2e          # Run API E2E tests

# Specific tests
npm run test -- --grep "VaultService"
npm run test -- vault.service.spec.ts
```

### Frontend

```bash
# Cypress E2E
npm run cy:open           # Open Cypress UI
npm run cy:run            # Run headless
npm run cy:run:chrome     # Run in Chrome
npm run cy:run:firefox    # Run in Firefox

# Specific specs
npm run cy:run -- --spec "cypress/e2e/auth/**/*"

# Component tests (if enabled)
npm run cy:component
```

### TEE

```bash
# Rust tests
cargo test                # Run all tests
cargo test --lib          # Library tests only
cargo test -- --nocapture # Show println output
cargo tarpaulin           # Coverage report
```

---

## Best Practices

### TDD Checklist (Backend & TEE)

- [ ] Write test first, verify it fails
- [ ] Write minimum code to pass
- [ ] Refactor while green
- [ ] Commit after each green phase
- [ ] No skipped tests in main branch

### E2E Test Checklist (Frontend)

- [ ] Test happy paths completely
- [ ] Test error scenarios
- [ ] Use data-testid attributes for selectors
- [ ] Avoid flaky selectors (timing, nth-child)
- [ ] Mock external services consistently
- [ ] Clean up test data after each test

### General Testing Rules

1. **Test behavior, not implementation** - Tests should survive refactoring
2. **One assertion per test** - Makes failures clear
3. **Descriptive test names** - `should reject expired tokens` not `test1`
4. **Arrange-Act-Assert** - Clear test structure
5. **No test interdependence** - Tests run in any order
6. **Fast feedback** - Unit tests < 5ms each

---

*Testing strategy: 2026-01-20*
