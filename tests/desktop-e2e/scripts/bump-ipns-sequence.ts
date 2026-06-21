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
// This re-publishes the root folder's CURRENT metadata UNCHANGED at sequence+1:
// it derives the deterministic vault IPNS keypair from the test identity's
// private key (same derivation the app uses), loads the current children, and
// republishes them via the SDK's CAS path. Non-destructive -- the desktop's next
// publish then sees a stale sequence, hits a 409, re-syncs, and retries, which is
// the conflict-resolution behavior test-conflict-detection exercises.
//
// Usage: tsx bump-ipns-sequence.ts --api-url <url> [--email <email>]
// Env:   TEST_SECRET (required) -- shared secret for /auth/test-login.

import {
  loadVaultKeyBlob,
  loadFolderMetadata,
  updateFolderMetadataAndPublish,
} from '@cipherbox/sdk-core';
import { deriveVaultIpnsKeypair, clearBytes } from '@cipherbox/crypto';
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

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const auth = await authenticate(args.apiUrl, args.email, args.secret);
  const accessToken = auth.accessToken;
  const userPrivateKey = Uint8Array.from(Buffer.from(auth.privateKeyHex, 'hex'));

  const ctx = buildSdkContext(args.apiUrl, accessToken);
  const axiosInstance = ctx.axiosInstance;
  if (!axiosInstance) {
    throw new Error('SDK context missing axios instance');
  }

  // 1. Vault key blob (rootFolderKey) + root IPNS name.
  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey, ctx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }
  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  // 2. Current root folder metadata (children + sequence).
  const folder = await loadFolderMetadata({
    ipnsName: rootIpnsName,
    folderKey: vaultKeyBlob.rootFolderKey,
    ctx,
  });
  if (!folder) {
    throw new Error(`Root folder metadata not found for ${rootIpnsName}`);
  }

  // 3. Republish the SAME children at sequence+1 with a valid signature. Passing
  //    baseChildren === children makes the 3-way merge a no-op (no resurrection).
  const rootIpnsKeypair = await deriveVaultIpnsKeypair(userPrivateKey);
  let newSequenceNumber: bigint;
  try {
    ({ newSequenceNumber } = await updateFolderMetadataAndPublish({
      children: folder.metadata.children,
      baseChildren: folder.metadata.children,
      folderKey: vaultKeyBlob.rootFolderKey,
      ipnsPrivateKey: rootIpnsKeypair.privateKey,
      ipnsName: rootIpnsName,
      sequenceNumber: folder.sequenceNumber,
      ctx,
    }));
  } finally {
    rootIpnsKeypair.privateKey.fill(0);
    clearBytes(userPrivateKey);
  }

  console.log(`Server sequence bumped to ${newSequenceNumber} for ${rootIpnsName}`);
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`bump-ipns-sequence failed: ${message}`);
  process.exit(1);
});
