/**
 * Vault Lifecycle Tests
 *
 * Tests vault initialization, duplicate init (409), get vault, export,
 * config, and quota via raw API calls (pre-SDK level).
 * Validates that the test harness creates working authenticated contexts.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { bytesToHex, deriveIpnsName } from '@cipherbox/crypto';
import { initializeVault, encryptVaultKeys } from '@cipherbox/core';
import {
  createTestContext,
  deleteTestAccount,
  type TestContext,
  API_URL,
} from '../fixtures/test-harness';

describe('Vault Lifecycle', () => {
  let ctx: TestContext;

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should create a test context with valid client', async () => {
    ctx = await createTestContext('vault-lifecycle');

    expect(ctx.client).toBeTruthy();
    expect(ctx.accessToken).toBeTruthy();
    expect(ctx.publicKey.length).toBeGreaterThan(0);
    expect(ctx.privateKey.length).toBeGreaterThan(0);
    expect(ctx.rootIpnsName).toMatch(/^k51|^bafz/);
    expect(ctx.rootFolderKey.length).toBe(32);
  });

  it('should reject duplicate vault init (409)', async () => {
    // Try to initialize vault again with same user — should get 409
    const vault = await initializeVault(ctx.privateKey);
    const encrypted = await encryptVaultKeys(vault, ctx.publicKey);
    const rootIpnsName = await deriveIpnsName(vault.rootIpnsKeypair.publicKey);

    const res = await fetch(`${API_URL}/vault/init`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${ctx.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ownerPublicKey: bytesToHex(ctx.publicKey),
        encryptedRootFolderKey: bytesToHex(encrypted.encryptedRootFolderKey),
        encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
        rootIpnsName,
      }),
    });

    expect(res.status).toBe(409);
  });

  it('should GET /vault and return vault data', async () => {
    const res = await fetch(`${API_URL}/vault`, {
      headers: { Authorization: `Bearer ${ctx.accessToken}` },
    });
    expect(res.ok).toBe(true);

    const data = await res.json();
    expect(data.rootIpnsName).toBe(ctx.rootIpnsName);
    expect(data.ownerPublicKey).toBe(bytesToHex(ctx.publicKey));
    expect(data.encryptedRootFolderKey).toBeTruthy();
    expect(data.encryptedRootIpnsPrivateKey).toBeTruthy();
  });

  it('should GET /vault/export and return export data', async () => {
    const res = await fetch(`${API_URL}/vault/export`, {
      headers: { Authorization: `Bearer ${ctx.accessToken}` },
    });
    expect(res.ok).toBe(true);

    const data = await res.json();
    expect(data.rootIpnsName).toBe(ctx.rootIpnsName);
    expect(data.encryptedRootFolderKey).toBeTruthy();
  });

  it('should GET /vault/config and return config', async () => {
    const res = await fetch(`${API_URL}/vault/config`, {
      headers: { Authorization: `Bearer ${ctx.accessToken}` },
    });
    expect(res.ok).toBe(true);

    const data = await res.json();
    expect(data.recycleBinRetentionDays).toBeTypeOf('number');
    expect(data.recycleBinRetentionDays).toBeGreaterThan(0);
  });

  it('should GET /vault/quota and return usage data', async () => {
    const res = await fetch(`${API_URL}/vault/quota`, {
      headers: { Authorization: `Bearer ${ctx.accessToken}` },
    });
    expect(res.ok).toBe(true);

    const data = await res.json();
    expect(data.usedBytes).toBeTypeOf('number');
    expect(data.limitBytes).toBeTypeOf('number');
    expect(data.limitBytes).toBeGreaterThan(0);
  });

  it('should reject requests with invalid token', async () => {
    const res = await fetch(`${API_URL}/vault`, {
      headers: { Authorization: 'Bearer invalid-token-here' },
    });
    expect(res.status).toBe(401);
  });

  it('should reject test-login with wrong secret', async () => {
    const res = await fetch(`${API_URL}/auth/test-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'bad-secret@example.com',
        secret: 'wrong-secret',
      }),
    });
    expect(res.status).toBe(401);
  });
});
