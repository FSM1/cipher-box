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

/** Shape of a share object in the API response */
interface ShareResponse {
  shareId: string;
  itemName: string;
  itemType: string;
  encryptedKey: string;
}

describe.skip('Share Operations [quarantined D-01: SDK runtime stubbed mid-milestone, re-enable at phase 63-65 consumer re-wire]', () => {
  let fixture: MultiAccountFixture;

  beforeAll(async () => {
    fixture = await createMultiAccountFixture(['alice', 'bob']);
  });

  afterAll(async () => {
    if (fixture) await fixture.cleanupAll();
  });

  let shareId: string;

  it('should create a share from Alice to Bob', async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;

    // Alice creates a folder to share
    const folder = await alice.client.createFolder(alice.rootIpnsName, 'SharedFolder');
    expect(folder.id).toBeTruthy();

    // Upload a file into the shared folder
    alice.client.registerFolder(
      folder.ipnsName,
      folder.folderKey,
      { publicKey: new Uint8Array(0), privateKey: folder.ipnsPrivateKey },
      [],
      1n
    );
    await alice.client.uploadFile(
      folder.ipnsName,
      generateTextContent('shared content'),
      'shared.txt',
      'text/plain'
    );

    // Wrap the folder key for Bob using ECIES
    const encryptedKey = await wrapKey(folder.folderKey, bob.publicKey);

    // Create share via API
    const res = await testFetch(`${API_URL}/shares`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        recipientPublicKey: '0x' + bytesToHex(bob.publicKey),
        itemType: 'folder',
        ipnsName: folder.ipnsName,
        itemName: 'SharedFolder',
        encryptedKey: bytesToHex(encryptedKey),
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
    expect(share.itemName).toBe('SharedFolder');
    expect(share.itemType).toBe('folder');
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

    // Bob unwraps the key with his private key (API returns hex-encoded ciphertext)
    const folderKey = await unwrapKey(hexToBytes(share.encryptedKey), bob.privateKey);
    expect(folderKey.length).toBe(32); // AES-256 key
  });

  it('should reject self-sharing', async () => {
    const alice = fixture.accounts.get('alice')!;

    const res = await testFetch(`${API_URL}/shares`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        recipientPublicKey: '0x' + bytesToHex(alice.publicKey),
        itemType: 'folder',
        ipnsName: alice.rootIpnsName,
        itemName: 'SelfShare',
        encryptedKey: bytesToHex(new Uint8Array(64)),
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
