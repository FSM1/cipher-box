/**
 * Invite Link Tests
 *
 * Tests invite link creation, public status check, claim flow,
 * double-claim prevention, and revocation.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { wrapKey, bytesToHex } from '@cipherbox/crypto';
import { createMultiAccountFixture, type MultiAccountFixture } from '../fixtures/multi-account';
import { API_URL, testFetch } from '../fixtures/test-harness';

/** Generate a valid ECIES-wrapped key (passes DTO MinLength(258) validation) */
async function makeWrappedKey(publicKey: Uint8Array): Promise<string> {
  const fakeKey = new Uint8Array(32);
  crypto.getRandomValues(fakeKey);
  return bytesToHex(await wrapKey(fakeKey, publicKey));
}

describe('Invite Link', () => {
  let fixture: MultiAccountFixture;

  beforeAll(async () => {
    fixture = await createMultiAccountFixture(['alice', 'bob', 'charlie']);
  });

  afterAll(async () => {
    if (fixture) await fixture.cleanupAll();
  });

  let inviteToken: string;
  let folderIpnsName: string;
  let folderNodeId: string;

  it('should create an invite link', async () => {
    const alice = fixture.accounts.get('alice')!;

    // Create a folder to share via invite
    const folder = await alice.client.createFolder(alice.rootIpnsName, 'InviteFolder');
    folderIpnsName = folder.ipnsName;
    folderNodeId = folder.id;

    // Wrap with Alice's key (in real flow, this would be an ephemeral keypair)
    const encryptedKey = await makeWrappedKey(alice.publicKey);

    const res = await testFetch(`${API_URL}/shares/invites`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      // v3 CreateInviteDto: shareRootIpnsName + rootNodeId + encryptedReadKey
      body: JSON.stringify({
        shareRootIpnsName: folder.ipnsName,
        rootNodeId: folder.id,
        encryptedReadKey: encryptedKey,
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.id).toBeTruthy();
    expect(data.token).toBeTruthy();
    expect(data.status).toBe('active');
    inviteToken = data.token;
  });

  it('should show active status publicly (no auth)', async () => {
    const res = await testFetch(`${API_URL}/invites/${inviteToken}`);
    expect(res.ok).toBe(true);

    const data = await res.json();
    expect(data.status).toBe('active');
  });

  it('should return invite data for authenticated user', async () => {
    const bob = fixture.accounts.get('bob')!;

    const res = await testFetch(`${API_URL}/invites/${inviteToken}/data`, {
      headers: { Authorization: `Bearer ${bob.accessToken}` },
    });
    expect(res.ok).toBe(true);

    const data = await res.json();
    // v3 InviteDataResponseDto: status + encryptedReadKey + root identity (no itemType/itemName).
    expect(data.status).toBe('active');
    expect(data.shareRootIpnsName).toBe(folderIpnsName);
    expect(data.rootNodeId).toBe(folderNodeId);
    expect(data.encryptedReadKey).toBeTruthy();
  });

  it('should allow Bob to claim the invite', async () => {
    const bob = fixture.accounts.get('bob')!;

    // Wrap a key for Bob (API validates format, not cryptographic correctness)
    const encryptedKey = await makeWrappedKey(bob.publicKey);

    const res = await testFetch(`${API_URL}/invites/${inviteToken}/claim`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bob.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ encryptedReadKey: encryptedKey }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.shareId).toBeTruthy();
  });

  it('should reject double-claim by another user', async () => {
    const charlie = fixture.accounts.get('charlie')!;

    const encryptedKey = await makeWrappedKey(charlie.publicKey);

    const res = await testFetch(`${API_URL}/invites/${inviteToken}/claim`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${charlie.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ encryptedReadKey: encryptedKey }),
    });

    // Should be 409 (already claimed) or 404 (no longer active)
    expect([404, 409]).toContain(res.status);
  });

  it('should reject double-claim by same user', async () => {
    const bob = fixture.accounts.get('bob')!;

    const encryptedKey = await makeWrappedKey(bob.publicKey);

    const res = await testFetch(`${API_URL}/invites/${inviteToken}/claim`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bob.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ encryptedReadKey: encryptedKey }),
    });

    expect([404, 409]).toContain(res.status);
  });

  it('should allow Alice to create and revoke a new invite', async () => {
    const alice = fixture.accounts.get('alice')!;

    const encryptedKey = await makeWrappedKey(alice.publicKey);

    const createRes = await testFetch(`${API_URL}/shares/invites`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        shareRootIpnsName: folderIpnsName,
        rootNodeId: folderNodeId,
        encryptedReadKey: encryptedKey,
      }),
    });
    expect(createRes.status).toBe(201);
    const newInvite = await createRes.json();

    // Revoke it
    const revokeRes = await testFetch(`${API_URL}/shares/invites/${newInvite.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${alice.accessToken}` },
    });
    expect(revokeRes.status).toBe(204);

    // Public status should now be 404
    const statusRes = await testFetch(`${API_URL}/invites/${newInvite.token}`);
    expect(statusRes.status).toBe(404);
  });
});
