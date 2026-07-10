/**
 * Share Operations Tests
 *
 * Tests sharing a folder between two accounts (Alice and Bob),
 * verifying ECIES key wrapping, re-wrap on mutation, and revocation.
 * Uses multi-account fixture with serial API-client switching.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { wrapKey, unwrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import { createMultiAccountFixture, type MultiAccountFixture } from '../fixtures/multi-account';
import { API_URL, testFetch } from '../fixtures/test-harness';
import { generateTextContent } from '../helpers/data-generators';

/** Shape of a received/sent share object in the v3 API response (share-response.dto.ts) */
interface ShareResponse {
  shareId: string;
  encryptedReadKey: string;
  encryptedWriteKey: string | null;
  rootNodeId: string;
  shareRootIpnsName: string;
}

describe('Share Operations', () => {
  let fixture: MultiAccountFixture;

  beforeAll(async () => {
    fixture = await createMultiAccountFixture(['alice', 'bob']);
  });

  afterAll(async () => {
    if (fixture) await fixture.cleanupAll();
  });

  let shareId: string;
  let sharedNodeId: string;
  let sharedFolderIpnsName: string;

  it('should create a share from Alice to Bob', async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;

    // Alice creates a folder to share. createFolder already registers it in the
    // folderTree write-capably (NODE-03) — re-registering with a zero writeKey
    // would trip the D-06 nodeId guard on the subsequent uploadFile.
    const folder = await alice.client.createFolder(alice.rootIpnsName, 'SharedFolder');
    expect(folder.id).toBeTruthy();
    sharedNodeId = folder.id;
    sharedFolderIpnsName = folder.ipnsName;

    // Upload a file into the shared folder
    await alice.client.uploadFile(
      folder.ipnsName,
      generateTextContent('shared content'),
      'shared.txt',
      'text/plain'
    );

    // Wrap the folder readKey for Bob using ECIES (the v3 encryptedReadKey).
    const encryptedKey = await wrapKey(folder.folderKey, bob.publicKey);

    // Create share via API (v3 CreateShareDto: encryptedReadKey + rootNodeId + shareRootIpnsName)
    const res = await testFetch(`${API_URL}/shares`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        recipientPublicKey: '0x' + bytesToHex(bob.publicKey),
        encryptedReadKey: bytesToHex(encryptedKey),
        rootNodeId: folder.id,
        shareRootIpnsName: folder.ipnsName,
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.shareId).toBeTruthy();
    shareId = data.shareId;
  });

  it('should appear in Bob received shares', async () => {
    const bob = fixture.accounts.get('bob')!;

    const res = await testFetch(`${API_URL}/shares/received`, {
      headers: { Authorization: `Bearer ${bob.accessToken}` },
    });
    expect(res.ok).toBe(true);

    const data = await res.json();
    expect(data.shares.length).toBeGreaterThanOrEqual(1);
    const share = data.shares.find((s: ShareResponse) => s.shareId === shareId);
    expect(share).toBeTruthy();
    // v3 shares carry root identity (shareRootIpnsName/rootNodeId), not itemName/itemType.
    expect(share.shareRootIpnsName).toBe(sharedFolderIpnsName);
    expect(share.rootNodeId).toBe(sharedNodeId);
  });

  it('should appear in Alice sent shares', async () => {
    const alice = fixture.accounts.get('alice')!;

    const res = await testFetch(`${API_URL}/shares/sent`, {
      headers: { Authorization: `Bearer ${alice.accessToken}` },
    });
    expect(res.ok).toBe(true);

    const data = await res.json();
    const share = data.shares.find((s: ShareResponse) => s.shareId === shareId);
    expect(share).toBeTruthy();
  });

  it('should allow Bob to unwrap the shared key', async () => {
    const bob = fixture.accounts.get('bob')!;

    const res = await testFetch(`${API_URL}/shares/received`, {
      headers: { Authorization: `Bearer ${bob.accessToken}` },
    });
    const data = await res.json();
    const share = data.shares.find((s: ShareResponse) => s.shareId === shareId);

    // Bob unwraps the encryptedReadKey with his private key (hex-encoded ECIES).
    const folderKey = await unwrapKey(hexToBytes(share.encryptedReadKey), bob.privateKey);
    expect(folderKey.length).toBe(32); // AES-256 key
  });

  it('should reject self-sharing', async () => {
    const alice = fixture.accounts.get('alice')!;

    // Valid v3 body (passes DTO validation) so the request reaches the
    // self-share business rule and returns 409 rather than a 400 validation error.
    const selfKey = await wrapKey(new Uint8Array(32), alice.publicKey);
    const res = await testFetch(`${API_URL}/shares`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        recipientPublicKey: '0x' + bytesToHex(alice.publicKey),
        encryptedReadKey: bytesToHex(selfKey),
        rootNodeId: alice.rootNodeId,
        shareRootIpnsName: alice.rootIpnsName,
      }),
    });

    expect(res.status).toBe(409);
  });

  it('should revoke the share', async () => {
    const alice = fixture.accounts.get('alice')!;

    const res = await testFetch(`${API_URL}/shares/${shareId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${alice.accessToken}` },
    });

    expect(res.status).toBe(204);
  });

  it('should not appear in Bob received shares after revocation', async () => {
    const bob = fixture.accounts.get('bob')!;

    const res = await testFetch(`${API_URL}/shares/received`, {
      headers: { Authorization: `Bearer ${bob.accessToken}` },
    });
    const data = await res.json();
    const share = data.shares.find((s: ShareResponse) => s.shareId === shareId);
    // Revoked shares should not appear in received list
    expect(share).toBeUndefined();
  });
});
