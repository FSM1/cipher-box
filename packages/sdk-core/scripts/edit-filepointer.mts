/**
 * edit-filepointer.ts -- Edit a file's content via the node/v3 SDK write chain.
 *
 * Authenticates via test-login, loads the node/v3 vault key blob
 * (rootReadKey + rootWriteKey), unseals the root Node (read + write body),
 * walks the SealedChildRef / WriteChildRef chain to recover the target file's
 * readKey, writeKey and its own IPNS signing key, encrypts the new content
 * (raw AES-256 fileKey — the v3 model stores fileKey un-wrapped inside the
 * sealed read-body, no ECIES), republishes the file's per-IPNS metadata via
 * updateFileMetadata, and republishes the root folder metadata with an updated
 * modifiedAt display mirror so other clients (e.g. FUSE mount) detect the
 * change.
 *
 * Usage:
 *   TEST_SECRET=<secret> tsx edit-filepointer.ts \
 *     --api-url http://localhost:3000 \
 *     --email dev-key@cipherbox.local \
 *     --file-name hello.txt \
 *     --new-content "Updated content from SDK"
 */

import {
  loadVaultKeyBlob,
  updateFileMetadata,
  updateFolderMetadataAndPublish,
  addToIpfs,
  resolveIpnsRecord,
  fetchFromIpfs,
  type SdkContext,
} from '@cipherbox/sdk-core';
import {
  unsealNode,
  unsealChildReadKey,
  unsealChildWriteKey,
  type Node,
  type PublishedNode,
} from '@cipherbox/core';
import { encryptAesGcm, generateFileKey, generateIv, clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../../tests/e2e-helpers/auth';

interface EditFilePointerArgs {
  apiUrl: string;
  secret: string;
  email: string;
  fileName: string;
  newContent: string;
}

function parseArgs(argv: string[]): EditFilePointerArgs {
  const values = parseCliArgs(argv);

  const apiUrl = values['api-url'];
  const secret = process.env.TEST_SECRET;
  const email = values['email'];
  const fileName = values['file-name'];
  const newContent = values['new-content'];

  if (!apiUrl || !email || !fileName || !secret || newContent === undefined) {
    throw new Error(
      'Usage: edit-filepointer.ts --api-url <url> --email <email> --file-name <name> --new-content <text> (requires TEST_SECRET env var)'
    );
  }

  return { apiUrl, secret, email, fileName, newContent };
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
  //    carries the root IPNS signing key and the WriteChildRef chain.
  const { published: rootPublished, sequenceNumber: rootSequenceNumber } = await fetchPublishedNode(
    rootIpnsName,
    ctx
  );
  const rootNode: Node = await unsealNode(rootPublished, rootReadKey, rootWriteKey);
  if (!rootNode.children || !rootNode.writeBody) {
    throw new Error('Root node is missing children or write-body');
  }

  // 4. Find the target file's SealedChildRef by name
  const fileRef = rootNode.children.find((child) => child.name === args.fileName);
  if (!fileRef) {
    throw new Error(`SealedChildRef not found for ${args.fileName}`);
  }
  const fileIpnsName = fileRef.ipnsName;

  // 5. Resolve the file node and recover its read/write keys via the
  //    parent-mirror generation (generation-source rule, navigate.ts Pitfall 1).
  const { published: filePublished, sequenceNumber: fileSequenceNumber } = await fetchPublishedNode(
    fileRef.ipnsName,
    ctx
  );
  const fileNodeId = filePublished.id;
  const fileKind = filePublished.kind;
  if (fileKind !== 'file') {
    throw new Error(`Child ${args.fileName} is not a file node`);
  }

  const fileReadKey = await unsealChildReadKey(
    fileRef.readKeySealed,
    rootReadKey,
    fileNodeId,
    fileKind,
    fileRef.generation
  );

  const writeChildRef = rootNode.writeBody.writeChildren.find((wc) => wc.childId === fileNodeId);
  if (!writeChildRef) {
    throw new Error(`File ${args.fileName} is not write-capable (no WriteChildRef)`);
  }
  const fileWriteKey = await unsealChildWriteKey(
    writeChildRef.writeKeySealed,
    rootWriteKey,
    fileNodeId,
    fileKind,
    fileRef.generation
  );

  // 6. Unseal the current file node (read + write body) to recover the current
  //    content descriptor + the file's own IPNS signing key.
  const currentFileNode = await unsealNode(filePublished, fileReadKey, fileWriteKey);
  if (currentFileNode.kind !== 'file' || !currentFileNode.content || !currentFileNode.writeBody) {
    throw new Error(`Node ${args.fileName} is not a write-capable file node`);
  }
  const currentMetadata = currentFileNode.content;
  const fileIpnsPrivateKey = currentFileNode.writeBody.ipnsPrivateKey;

  // 7. Encrypt new content with a fresh RAW fileKey (no ECIES wrap in v3).
  const plaintext = new TextEncoder().encode(args.newContent);
  const fileKey = generateFileKey();
  const iv = generateIv();
  let newCid: string;
  try {
    const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);
    const uploadResult = await addToIpfs(ctx, ciphertext);
    newCid = uploadResult.cid;

    // 8. Update file metadata — publishes the file IPNS record internally with CAS.
    //    updateFileMetadata is the terminal owner of fileIpnsPrivateKey (T-47-01)
    //    and zeroes it; fileReadKey/fileWriteKey are caller-owned (D-09).
    await updateFileMetadata({
      fileIpnsPrivateKey,
      fileReadKey,
      fileWriteKey,
      // The key below is the current node/v3 updateFileMetadata SDK parameter
      // name (packages/sdk-core/src/file/index.ts) — the file's own IPNS name,
      // NOT a retired FilePointer field read. The object-literal key is
      // dictated by the SDK signature and cannot be renamed here.
      fileMetaIpnsName: fileIpnsName,
      fileSequenceNumber,
      nodeId: fileNodeId,
      nodeGeneration: currentFileNode.generation,
      originalCreatedAt: currentFileNode.createdAt,
      currentMetadata,
      updates: {
        cid: newCid,
        fileKey,
        fileIv: iv,
        size: plaintext.length,
        mimeType: currentMetadata.mimeType,
        encryptionMode: 'GCM',
      },
      createVersion: true,
      ctx,
    });
  } finally {
    clearBytes(fileKey);
    clearBytes(iv);
  }

  // 9. Republish root folder metadata with an updated modifiedAt display mirror
  //    on the edited child so other clients (e.g. FUSE mount) detect the change.
  //    Preserve the existing write-body (writeKey + writeChildren) verbatim (D-03).
  const baseChildren = rootNode.children;
  const updatedChildren = rootNode.children.map((child) =>
    child.ipnsName === fileRef.ipnsName ? { ...child, modifiedAt: Date.now() } : child
  );

  const { newSequenceNumber } = await updateFolderMetadataAndPublish({
    children: updatedChildren,
    baseChildren,
    readKey: rootReadKey,
    writeKey: rootWriteKey,
    writeChildren: rootNode.writeBody.writeChildren,
    ipnsPrivateKey: rootNode.writeBody.ipnsPrivateKey,
    ipnsName: rootIpnsName,
    sequenceNumber: rootSequenceNumber,
    nodeId: rootNode.id,
    nodeGeneration: rootNode.generation,
    ctx,
  });

  // 10. Zero caller-owned key material.
  clearBytes(fileReadKey);
  clearBytes(fileWriteKey);
  clearBytes(rootReadKey);
  clearBytes(rootWriteKey);
  clearBytes(userPrivateKey);

  console.log(
    JSON.stringify({
      fileName: args.fileName,
      oldCid: currentMetadata.cid,
      newCid,
      newContentLength: plaintext.length,
      folderSequenceNumber: newSequenceNumber.toString(),
      fileIpnsName,
    })
  );
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
