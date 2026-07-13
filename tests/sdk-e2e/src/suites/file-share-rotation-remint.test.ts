/**
 * File-Share Grant Re-Mint on Scope-Exit Rotation (recipient-pin-lifecycle §5)
 *
 * Proves the web INLINE grant-remint seam: when an owner scope-exit-rotates a
 * folder that CONTAINS a separately-shared FILE leaf, the file recipient's grant
 * must be re-minted under the file's freshly-rotated read key. The login/
 * opportunistic reconcile sweep can NEVER reach a file leaf (a file has no
 * FolderTree entry, so the sweep skips it) — only the inline seam
 * (`RotationClientCallbacks.resolveInlineGrantRemint` → `rotateReadFromNode`'s
 * per-node `reMintGrantsRootedAt`) re-wraps a file grant.
 *
 * Alice (owner) is wired WITH the inline-grant-remint seam; bob (folder
 * recipient, pinned) and carol (file recipient, pin-exempt) receive shares.
 * Rotating alice's folder D via a covered mutation (rename) must re-mint BOTH
 * grants under the rotated keys.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * STATUS: describe.skip — this suite is a live-stack REPRODUCTION, not a passing
 * gate. Run against a local stack (see repo docs) to reproduce. It surfaced
 * three genuine gaps that stop the just-committed fix (04198f81e) from re-minting
 * a file grant end-to-end. Two of them are product bugs OUTSIDE tests/sdk-e2e and
 * were therefore left unfixed here (this task is test-only). Un-skip once B and C
 * below are fixed.
 *
 *   Gap A (harness artifact, worked around):
 *     `client.getRecipientPubkeyPins(D)` slow-paths through
 *     getWriteBodyParams → re-resolve → unsealNode when the folder's in-memory
 *     `metadata.writeBody` mirror is null (a folder created THIS session via
 *     createFolder registers with metadata: null — registerFolder, client.ts).
 *     During rotation the published node is already re-sealed under the NEW read
 *     key but the in-memory folderKey is still OLD → "CryptoError: Decryption
 *     failed" (write-body-params.ts:97). Real-web navigation loads the folder via
 *     DFS with metadata populated (fast in-memory pin path), so this is a harness
 *     seeding artifact — worked around below by evicting root+D and reloading via
 *     ensureFolderLoaded (mirrors a cold navigation). It COULD still bite a
 *     same-session create+share+rotate web flow.
 *
 *   Gap C (REAL product bug — blocks ALL re-mints, folder AND file):
 *     sdk-core `reMintGrantsRootedAt` encodes the re-wrapped key as BASE64
 *     (`bytesToBase64`, packages/sdk-core/src/rotation/engine.ts:648) and hands it
 *     to the host `updateGrantFn`. But `PATCH /shares/:id/grant`
 *     (UpdateGrantDto.encryptedReadKey) — like the share-CREATE DTO and the SDK's
 *     own share-create path (share/index.ts:71 bytesToHex) — requires even-length
 *     HEX. So every re-mint PATCH is rejected:
 *       "encryptedReadKey must be an even-length hex string" (400).
 *     This affects the WEB owner-reconcile path too (owner-reconcile.service.ts
 *     updateGrant passes the base64 verbatim to sharesControllerUpdateGrant). No
 *     existing sdk-e2e exercised a real re-mint PATCH, so it was uncaught. Fix:
 *     engine.ts:648 should emit `bytesToHex`, or the API/host must agree on
 *     base64. The harness exposes an OPT-IN diagnostic (`E2E_REMINT_HEX=1`) that
 *     converts base64→hex before the PATCH so this suite can reach Gap B; it is a
 *     diagnostic, NOT a fix, and defaults OFF (faithful to web).
 *
 *   Gap B (REAL product gap — the pitfall this e2e was built to find):
 *     Re-minting carol's FILE grant requires the file node F to be rotated (its
 *     readKey changes). But `rotateReadFromNode`'s per-node key source
 *     (`nodeKeySource`, client.ts) reads ONLY the in-memory `folderTree`, which
 *     holds FOLDERS only — a file leaf is never registered there. So rotateOne
 *     fail-closes at the D-01 guard (engine.ts:1095):
 *       "rotateOne: no valid IPNS private key for k51… — provide via
 *        nodeKeySource (Phase 64) or write-body wiring (Phase 65)".
 *     The web fix wires the inline re-mint SEAM but does NOT thread a file leaf's
 *     IPNS/write key material into the rotation walk, so a file grant can never be
 *     re-minted. The web fix needs to thread file write-material (recover the
 *     file's ipnsPrivateKey/writeKey from the parent's write-body) into
 *     nodeKeySource, mirroring the desktop/Rust path.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { wrapKey, unwrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import { createMultiAccountFixture, type MultiAccountFixture } from '../fixtures/multi-account';
import { API_URL, testFetch } from '../fixtures/test-harness';
import { generateTextContent } from '../helpers/data-generators';

/** A sent-share row (SentShareResponseDto) from GET /shares/sent. */
interface SentShareRow {
  shareId: string;
  recipientPublicKey: string;
  encryptedReadKey: string;
  rootNodeId: string;
  shareRootIpnsName: string;
  rootGeneration: string;
}

/** Fetch a specific sent-share row by shareId for the given account. */
async function getSentShare(accessToken: string, shareId: string): Promise<SentShareRow> {
  const res = await testFetch(`${API_URL}/shares/sent`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  expect(res.ok).toBe(true);
  const data = (await res.json()) as { shares: SentShareRow[] };
  const share = data.shares.find((s) => s.shareId === shareId);
  if (!share) throw new Error(`sent share ${shareId} not found`);
  return share;
}

// SKIPPED: live-stack reproduction of a blocked fix — see the file header for the
// three gaps (A worked-around, B + C real product bugs outside tests/sdk-e2e).
describe.skip('File-Share Grant Re-Mint on Scope-Exit Rotation', () => {
  let fixture: MultiAccountFixture;

  beforeAll(async () => {
    // Only alice (the owner performing the rotation) needs the inline seam.
    fixture = await createMultiAccountFixture(['alice', 'bob', 'carol'], {
      alice: { withInlineGrantRemint: true },
    });
  });

  afterAll(async () => {
    if (fixture) await fixture.cleanupAll();
  });

  // Folder D and its two files, resolved in the first `it` and reused serially.
  let D: { id: string; ipnsName: string; folderKey: Uint8Array };
  let F: { readKey: Uint8Array; nodeId: string; ipnsName: string };
  let gIpnsName: string;

  let carolShareId: string;
  let carolEncBefore: string;
  let bobShareId: string;
  let bobEncBefore: string;

  it('sets up folder D with two files and resolves file F identity', async () => {
    const alice = fixture.accounts.get('alice')!;

    const folder = await alice.client.createFolder(alice.rootIpnsName, 'D');
    expect(folder.id).toBeTruthy();
    D = { id: folder.id, ipnsName: folder.ipnsName, folderKey: folder.folderKey };

    await alice.client.uploadFile(
      D.ipnsName,
      generateTextContent('secret-F'),
      'secret.txt',
      'text/plain'
    );
    await alice.client.uploadFile(
      D.ipnsName,
      generateTextContent('data-G'),
      'other.txt',
      'text/plain'
    );

    // Files are NOT in the folderTree — only their SealedChildRef pointers live in
    // the parent folder's (in-memory) children list.
    const children = alice.client.getFolderTree().get(D.ipnsName)!.children;
    const fChildRef = children.find((c) => c.name === 'secret.txt');
    const gChildRef = children.find((c) => c.name === 'other.txt');
    expect(fChildRef).toBeTruthy();
    expect(gChildRef).toBeTruthy();
    gIpnsName = gChildRef!.ipnsName;

    const fId = await alice.client.resolveChildIdentity(fChildRef!, D.folderKey);
    expect(fId.kind).toBe('file');
    F = { readKey: fId.readKey, nodeId: fId.nodeId, ipnsName: fChildRef!.ipnsName };
    expect(F.readKey.length).toBe(32);
  });

  it("creates carol's FILE share rooted at F", async () => {
    const alice = fixture.accounts.get('alice')!;
    const carol = fixture.accounts.get('carol')!;

    const res = await testFetch(`${API_URL}/shares`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        recipientPublicKey: '0x' + bytesToHex(carol.publicKey),
        encryptedReadKey: bytesToHex(await wrapKey(F.readKey, carol.publicKey)),
        rootNodeId: F.nodeId,
        shareRootIpnsName: F.ipnsName,
      }),
    });
    expect(res.status).toBe(201);
    const data = await res.json();
    carolShareId = data.shareId;
    carolEncBefore = data.encryptedReadKey;
    expect(carolShareId).toBeTruthy();
    expect(carolEncBefore).toBeTruthy();
  });

  it("creates bob's FOLDER share rooted at D (with recipient pin)", async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;

    // A folder grant root must carry the recipient's owner-sealed pin; the
    // inline re-mint fail-closes (getPinsFn) for a folder without one.
    await alice.client.addRecipientPubkeyPin(D.ipnsName, bob.publicKey);

    const res = await testFetch(`${API_URL}/shares`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        recipientPublicKey: '0x' + bytesToHex(bob.publicKey),
        encryptedReadKey: bytesToHex(await wrapKey(D.folderKey, bob.publicKey)),
        rootNodeId: D.id,
        shareRootIpnsName: D.ipnsName,
      }),
    });
    expect(res.status).toBe(201);
    const data = await res.json();
    bobShareId = data.shareId;
    bobEncBefore = data.encryptedReadKey;
    expect(bobShareId).toBeTruthy();
  });

  it('triggers scope-exit rotation on D via a covered mutation (rename)', async () => {
    const alice = fixture.accounts.get('alice')!;

    // Gap A work-around: evict root + D so ensureRootFolderState fully re-resolves
    // root (populating root.metadata) and the DFS descent then loads D with a
    // populated metadata.writeBody mirror — mirroring a real-web cold navigation.
    // Without this, D (created this session) has metadata: null and
    // getRecipientPubkeyPins re-resolves + unseals the just-rotated node with a
    // stale key mid-rotation ("Decryption failed"). See the file header, Gap A.
    const ft = alice.client.getFolderTree();
    ft.delete(D.ipnsName);
    ft.delete(alice.rootIpnsName);
    await alice.client.ensureFolderLoaded(D.ipnsName);

    // D is an active grant root → this mutation triggers scope-exit rotation,
    // which walks D's subtree and rotates D + F + G, firing the inline re-mint.
    // renameItem's `childId` param is the child's ipnsName (renameInFolder keys
    // on ipnsName, not display name).
    //
    // NOTE: with the fix wired this currently THROWS — Gap C (base64/hex) on the
    // folder re-mint PATCH, or with E2E_REMINT_HEX=1, Gap B (no file IPNS key)
    // when the walk reaches file F. See the file header.
    await alice.client.renameItem(D.ipnsName, gIpnsName, 'other2.txt');
  });

  it("re-mints carol's FILE grant under F's rotated read key", async () => {
    const alice = fixture.accounts.get('alice')!;
    const carol = fixture.accounts.get('carol')!;

    const carolShare = await getSentShare(alice.accessToken, carolShareId);
    // The grant ciphertext must have changed (re-minted, not stale).
    expect(carolShare.encryptedReadKey).not.toBe(carolEncBefore);

    // Carol unwraps the re-minted grant with her own private key.
    const newFReadKey = await unwrapKey(hexToBytes(carolShare.encryptedReadKey), carol.privateKey);
    expect(newFReadKey.length).toBe(32);
    // It must be F's NEW (rotated) key, distinct from the pre-rotation readKey.
    expect(bytesToHex(newFReadKey)).not.toBe(bytesToHex(F.readKey));

    // Prove carol's grant now wraps F's ACTUAL post-rotation readKey: re-resolve
    // F's identity via alice's refreshed folderTree (D's folderKey + F's
    // SealedChildRef are both rotated in-place after the successful rotation) and
    // deep-equal the two keys.
    const rotatedFolder = alice.client.getFolderTree().get(D.ipnsName)!;
    const fChildRefAfter = rotatedFolder.children.find((c) => c.ipnsName === F.ipnsName);
    expect(fChildRefAfter).toBeTruthy();
    const fIdAfter = await alice.client.resolveChildIdentity(
      fChildRefAfter!,
      rotatedFolder.folderKey
    );
    expect(bytesToHex(newFReadKey)).toBe(bytesToHex(fIdAfter.readKey));
  });

  it("re-mints bob's FOLDER grant under D's rotated read key", async () => {
    const alice = fixture.accounts.get('alice')!;
    const bob = fixture.accounts.get('bob')!;

    const bobShare = await getSentShare(alice.accessToken, bobShareId);
    expect(bobShare.encryptedReadKey).not.toBe(bobEncBefore);

    const newFolderKey = await unwrapKey(hexToBytes(bobShare.encryptedReadKey), bob.privateKey);
    expect(newFolderKey.length).toBe(32);
    // Equals D's rotated folderKey (refreshed in the in-memory folderTree).
    const rotatedFolderKey = alice.client.getFolderTree().get(D.ipnsName)!.folderKey;
    expect(bytesToHex(newFolderKey)).toBe(bytesToHex(rotatedFolderKey));
  });
});
