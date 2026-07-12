#!/usr/bin/env node
// bump-ipns-sequence.ts -- Advance a vault's root IPNS sequence with a REAL,
// validly-signed record, simulating another device publishing to the same vault.
//
// Why this exists: CipherBox's IPNS cache is signature-gated and keyed by
// ipnsName -- the server rejects any record whose Ed25519 SignatureV2 does not
// verify against the name's embedded public key. A sequence bump therefore can
// no longer be faked by POSTing dummy bytes to /ipns/publish (the previous
// curl/Invoke-RestMethod approach now correctly gets a 400). The only way to
// advance a name is to publish a properly-signed record -- which is exactly what
// a legitimate second device does.
//
// node/v3 model: the vault root is a Node (not legacy folder metadata). This
// script loads the two-key root read/write keys from the v3 vault key blob,
// resolves + unseals the current root Node (read + write body), and republishes
// that SAME Node UNCHANGED at sequence+1 via the node/v3 CAS publish path,
// signed with the root's own IPNS private key (recovered from the sealed
// write-body -- the authoritative vault IPNS signing key). Passing
// baseChildren === children makes the three-way merge a no-op, and preserving
// the write-body (writeKey + writeChildren) verbatim keeps the write plane
// intact. Non-destructive -- the desktop's next publish then sees a stale
// sequence, hits a 409, re-syncs, and retries, which is the conflict-resolution
// behavior test-conflict-detection exercises.
//
// Usage: tsx bump-ipns-sequence.ts --api-url <url> [--email <email>]
// Env:   TEST_SECRET (required) -- shared secret for /auth/test-login.

import {
  loadVaultKeyBlob,
  updateFolderMetadataAndPublish,
  resolveIpnsRecord,
  fetchFromIpfs,
  type SdkContext,
} from '@cipherbox/sdk-core';
import { unsealNode, type Node, type PublishedNode } from '@cipherbox/core';
import { clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../e2e-helpers/auth';

// The desktop launches with --dev-key, which maps to this fixed test identity.
const DEFAULT_EMAIL = 'dev-key@cipherbox.local';

function parseArgs(argv: string[]): { apiUrl: string; secret: string; email: string } {
  const values = parseCliArgs(argv);

  const apiUrl = values['api-url'];
  const secret = process.env.TEST_SECRET;
  const email = values['email'] || DEFAULT_EMAIL;

  if (!apiUrl || !secret) {
    throw new Error(
      'Usage: bump-ipns-sequence.ts --api-url <url> [--email <email>] (requires TEST_SECRET env var)'
    );
  }

  return { apiUrl, secret, email };
}

/**
 * Resolve an IPNS name and return the raw node/v3 PublishedNode envelope + its
 * IPNS sequence number. The envelope id/kind/generation are plaintext AAD
 * inputs (mirrors packages/sdk-core/src/share/navigate.ts).
 */
async function fetchPublishedNode(
  ipnsName: string,
  ctx: SdkContext
): Promise<{ published: PublishedNode; sequenceNumber: bigint }> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) {
    throw new Error(`IPNS record not found for ${ipnsName}`);
  }
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
  return { published, sequenceNumber: resolved.sequenceNumber };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const auth = await authenticate(args.apiUrl, args.email, args.secret);
  const accessToken = auth.accessToken;
  const userPrivateKey = Uint8Array.from(Buffer.from(auth.privateKeyHex, 'hex'));

  const ctx: SdkContext = buildSdkContext(args.apiUrl, accessToken);
  const axiosInstance = ctx.axiosInstance;
  if (!axiosInstance) {
    throw new Error('SdkContext missing axiosInstance');
  }

  // 1. Load node/v3 vault key blob → rootReadKey + rootWriteKey.
  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey, ctx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }
  const { rootReadKey, rootWriteKey } = vaultKeyBlob;

  // 2. Vault info → rootIpnsName.
  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  // 3. Resolve + unseal the current root Node (read + write body). The write
  //    body carries the root IPNS signing key and the WriteChildRef chain.
  const { published: rootPublished, sequenceNumber: rootSequenceNumber } = await fetchPublishedNode(
    rootIpnsName,
    ctx
  );
  const rootNode: Node = await unsealNode(rootPublished, rootReadKey, rootWriteKey);
  if (!rootNode.children || !rootNode.writeBody) {
    throw new Error('Root node is missing children or write-body');
  }

  // 4. Republish the SAME root Node UNCHANGED at sequence+1 with a valid
  //    signature. children === baseChildren makes the three-way merge a no-op
  //    (no resurrection); the write-body (writeKey + writeChildren) is preserved
  //    verbatim (D-03), and the root's own ipnsPrivateKey (from the sealed
  //    write-body) signs the record — the authoritative vault IPNS key.
  //    updateFolderMetadataAndPublish does NOT zero the key material it is
  //    handed (callers are terminal owners, D-09), so we zero in `finally`.
  let newSequenceNumber: bigint;
  try {
    ({ newSequenceNumber } = await updateFolderMetadataAndPublish({
      children: rootNode.children,
      baseChildren: rootNode.children,
      readKey: rootReadKey,
      writeKey: rootWriteKey,
      writeChildren: rootNode.writeBody.writeChildren,
      // D-03 (Plan 80): a write-body reseal (writeKey present) now REQUIRES a
      // recipientPins snapshot — omitting it would erase any owner-sealed pins.
      // This bump republishes the root UNCHANGED, so preserve its current pins
      // verbatim (the vault root is unpinned in practice, so this is [] — but
      // read it from the write-body rather than hardcoding, so a pinned root
      // round-trips its pins too).
      recipientPins: rootNode.writeBody.recipientPins ?? [],
      ipnsPrivateKey: rootNode.writeBody.ipnsPrivateKey,
      ipnsName: rootIpnsName,
      sequenceNumber: rootSequenceNumber,
      nodeId: rootNode.id,
      nodeGeneration: rootNode.generation,
      ctx,
    }));
  } finally {
    clearBytes(rootNode.writeBody.ipnsPrivateKey);
    clearBytes(rootReadKey);
    clearBytes(rootWriteKey);
    clearBytes(userPrivateKey);
  }

  console.log(`Server sequence bumped to ${newSequenceNumber} for ${rootIpnsName}`);
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`bump-ipns-sequence failed: ${message}`);
  process.exit(1);
});
