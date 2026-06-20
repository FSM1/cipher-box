/**
 * rename-folder.ts -- Rename a folder in the vault via the SDK.
 *
 * Authenticates via test-login, finds the target folder in the root
 * folder metadata, renames it using renameInFolder, and republishes
 * the root folder metadata so other clients (e.g. FUSE mount) detect
 * the change.
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
  loadFolderMetadata,
  renameInFolder,
  updateFolderMetadataAndPublish,
  type SdkContext,
} from '@cipherbox/sdk-core';
import { deriveVaultIpnsKeypair, clearBytes } from '@cipherbox/crypto';
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

  // 1. Load vault key blob to get rootFolderKey
  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey, ctx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }

  // 2. Get vault info for rootIpnsName
  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  // 3. Load root folder metadata
  const folder = await loadFolderMetadata({
    ipnsName: rootIpnsName,
    folderKey: vaultKeyBlob.rootFolderKey,
    ctx,
  });
  if (!folder) {
    throw new Error(`Root folder metadata not found for ${rootIpnsName}`);
  }

  // 4. Find the target folder entry by name
  const folderEntry = folder.metadata.children.find(
    (child) => child.type === 'folder' && child.name === args.folderName
  );
  if (!folderEntry) {
    throw new Error(`Folder not found: ${args.folderName}`);
  }

  // 5. Rename the folder in metadata
  const { updatedChildren } = renameInFolder({
    children: folder.metadata.children,
    childId: folderEntry.id,
    newName: args.newName,
  });

  // 6. Derive root folder IPNS keypair for republishing
  const rootIpnsKeypair = await deriveVaultIpnsKeypair(userPrivateKey);

  // 7. Republish folder metadata with the renamed entry
  let newSequenceNumber: bigint;
  try {
    ({ newSequenceNumber } = await updateFolderMetadataAndPublish({
      children: updatedChildren,
      folderKey: vaultKeyBlob.rootFolderKey,
      ipnsPrivateKey: rootIpnsKeypair.privateKey,
      ipnsName: rootIpnsName,
      sequenceNumber: folder.sequenceNumber,
      ctx,
    }));
  } finally {
    // 8. Zero sensitive key material regardless of success/failure
    rootIpnsKeypair.privateKey.fill(0);
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
