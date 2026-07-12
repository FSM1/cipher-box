/**
 * rename-folder.ts -- Rename a folder in the vault via the node/v3 SDK.
 *
 * Authenticates via test-login, loads the node/v3 vault key blob
 * (rootReadKey + rootWriteKey), unseals the root Node (read + write body),
 * finds the target folder's SealedChildRef, renames it via renameInFolder
 * (a pure read-body transform — the name lives inside the sealed parent
 * read-body), and republishes the root folder metadata preserving the existing
 * write-body (D-03) so other clients (e.g. FUSE mount) detect the change.
 *
 * Usage:
 *   TEST_SECRET=<secret> tsx rename-folder.ts \
 *     --api-url http://localhost:3000 \
 *     --email dev-key@cipherbox.local \
 *     --folder-name "OldName" \
 *     --new-name "NewName"
 */

import {
  loadVaultKeyBlob,
  renameInFolder,
  updateFolderMetadataAndPublish,
  resolveIpnsRecord,
  fetchFromIpfs,
  type SdkContext,
} from '@cipherbox/sdk-core';
import { unsealNode, type Node, type PublishedNode } from '@cipherbox/core';
import { clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../../tests/e2e-helpers/auth';

interface RenameFolderArgs {
  apiUrl: string;
  secret: string;
  email: string;
  folderName: string;
  newName: string;
}

function parseArgs(argv: string[]): RenameFolderArgs {
  const values = parseCliArgs(argv);

  const apiUrl = values['api-url'];
  const secret = process.env.TEST_SECRET;
  const email = values['email'];
  const folderName = values['folder-name'];
  const newName = values['new-name'];

  if (!apiUrl || !email || !folderName || !secret || !newName) {
    throw new Error(
      'Usage: rename-folder.ts --api-url <url> --email <email> --folder-name <name> --new-name <name> (requires TEST_SECRET env var)'
    );
  }

  return { apiUrl, secret, email, folderName, newName };
}

/**
 * Resolve an IPNS name and return the raw node/v3 PublishedNode envelope + its
 * IPNS sequence number.
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

  // 1. Load node/v3 vault key blob → rootReadKey + rootWriteKey
  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey, ctx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }
  const { rootReadKey, rootWriteKey } = vaultKeyBlob;

  // 2. Get vault info for rootIpnsName
  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  // 3. Resolve + unseal the root Node (read + write body). The write body
  //    carries the root IPNS signing key and the WriteChildRef chain, both
  //    preserved verbatim on republish (D-03).
  const { published: rootPublished, sequenceNumber: rootSequenceNumber } = await fetchPublishedNode(
    rootIpnsName,
    ctx
  );
  const rootNode: Node = await unsealNode(rootPublished, rootReadKey, rootWriteKey);
  if (!rootNode.children || !rootNode.writeBody) {
    throw new Error('Root node is missing children or write-body');
  }

  // 4. Find the target folder's SealedChildRef by name, and confirm it is a
  //    folder (the child envelope kind is plaintext).
  const folderRef = rootNode.children.find((child) => child.name === args.folderName);
  if (!folderRef) {
    throw new Error(`Folder not found: ${args.folderName}`);
  }
  const { published: folderPublished } = await fetchPublishedNode(folderRef.ipnsName, ctx);
  if (folderPublished.kind !== 'folder') {
    throw new Error(`Child ${args.folderName} at root is not a folder`);
  }

  // 5. Rename in metadata — pure read-body transform. childId is the child's
  //    ipnsName (the SealedChildRef identity key in node/v3).
  const baseChildren = rootNode.children;
  const { updatedChildren } = renameInFolder({
    children: rootNode.children,
    childId: folderRef.ipnsName,
    newName: args.newName,
  });

  // 6. Republish root folder metadata with the renamed entry, preserving the
  //    existing write-body (writeKey + writeChildren + root IPNS signing key).
  let newSequenceNumber: bigint;
  try {
    ({ newSequenceNumber } = await updateFolderMetadataAndPublish({
      children: updatedChildren,
      baseChildren,
      readKey: rootReadKey,
      writeKey: rootWriteKey,
      writeChildren: rootNode.writeBody.writeChildren,
      // Preserve the root's owner-sealed recipient pins (D-03): an omitted
      // snapshot fail-closes, and sealing pin-less would erase pins on a shared root.
      recipientPins: rootNode.writeBody.recipientPins ?? [],
      ipnsPrivateKey: rootNode.writeBody.ipnsPrivateKey,
      ipnsName: rootIpnsName,
      sequenceNumber: rootSequenceNumber,
      nodeId: rootNode.id,
      nodeGeneration: rootNode.generation,
      ctx,
    }));
  } finally {
    // 7. Zero sensitive key material regardless of success/failure.
    clearBytes(rootReadKey);
    clearBytes(rootWriteKey);
    clearBytes(userPrivateKey);
  }

  console.log(
    JSON.stringify({
      folderName: args.folderName,
      oldName: args.folderName,
      newName: args.newName,
      folderSequenceNumber: newSequenceNumber.toString(),
    })
  );
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
