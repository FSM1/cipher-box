/**
 * verify-filepointer.ts -- Verify a file in the vault via the node/v3 read chain.
 *
 * Authenticates via test-login, loads the node/v3 vault key blob (rootReadKey),
 * loads the root Node, traverses the SealedChildRef read chain to the target
 * file, unseals the child read key under the parent read key
 * (unsealChildReadKey, parent-mirror generation), resolves the file's
 * NodeContent, and optionally downloads + decrypts the content with the RAW
 * NodeContent.fileKey (the v3 model stores fileKey un-wrapped inside the sealed
 * read-body — no ECIES).
 *
 * Usage:
 *   TEST_SECRET=<secret> tsx verify-filepointer.ts \
 *     --api-url http://localhost:3000 \
 *     --email dev-key@cipherbox.local \
 *     --file-name hello.txt \
 *     [--folder-name Subfolder] \
 *     [--expected-content "text"]
 */

import {
  loadVaultKeyBlob,
  loadFolderMetadata,
  resolveFileMetadata,
  downloadFileContent,
  resolveIpnsRecord,
  fetchFromIpfs,
  type SdkContext,
} from '@cipherbox/sdk-core';
import { unsealChildReadKey, type PublishedNode, type SealedChildRef } from '@cipherbox/core';
import { clearBytes } from '@cipherbox/crypto';
import { authenticate, buildSdkContext, parseCliArgs } from '../../../tests/e2e-helpers/auth';

interface VerifyFilePointerArgs {
  apiUrl: string;
  secret: string;
  email: string;
  fileName: string;
  folderName?: string;
  expectedContent?: string;
}

function parseArgs(argv: string[]): VerifyFilePointerArgs {
  const values = parseCliArgs(argv);

  const apiUrl = values['api-url'];
  const secret = process.env.TEST_SECRET;
  const email = values['email'];
  const fileName = values['file-name'];

  if (!apiUrl || !email || !fileName || !secret) {
    throw new Error(
      'Usage: verify-filepointer.ts --api-url <url> --email <email> --file-name <name> [--folder-name <subfolder>] [--expected-content <text>] (requires TEST_SECRET env var)'
    );
  }

  return {
    apiUrl,
    secret,
    email,
    fileName,
    // Optional: a single subfolder (at root level) to look in instead of root.
    // Used to verify a file after it has been moved into a subfolder.
    folderName: values['folder-name'],
    expectedContent: values['expected-content'],
  };
}

/**
 * Resolve an IPNS name and return the raw node/v3 PublishedNode envelope.
 * The envelope's id/kind/generation are plaintext (AAD inputs) — mirrors the
 * canonical hop in packages/sdk-core/src/share/navigate.ts.
 */
async function fetchPublishedNode(ipnsName: string, ctx: SdkContext): Promise<PublishedNode> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) {
    throw new Error(`IPNS record not found for ${ipnsName}`);
  }
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}

/**
 * Derive a child node's read key from its SealedChildRef under the parent read
 * key. Uses childRef.generation (the PARENT MIRROR), never the child's own
 * envelope generation (navigate.ts Pitfall 1 / generation-source rule §2.6).
 */
async function deriveChildReadKey(
  childRef: SealedChildRef,
  parentReadKey: Uint8Array,
  ctx: SdkContext
): Promise<{ childReadKey: Uint8Array; childPublished: PublishedNode }> {
  const childPublished = await fetchPublishedNode(childRef.ipnsName, ctx);
  const childReadKey = await unsealChildReadKey(
    childRef.readKeySealed,
    parentReadKey,
    childPublished.id, // plaintext from child envelope
    childPublished.kind, // plaintext from child envelope
    childRef.generation // parent mirror (NOT childPublished.generation)
  );
  return { childReadKey, childPublished };
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

  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey, ctx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }

  // fileReadKey/subReadKey are minted (via deriveChildReadKey) inside the try
  // below and must be cleared in the finally alongside userPrivateKey and the
  // vault root keys — declared here so the finally can reach them regardless
  // of which branch (root-only vs --folder-name) ran.
  let fileReadKey: Uint8Array | undefined;
  let subReadKey: Uint8Array | undefined;

  try {
    const folder = await loadFolderMetadata({
      ipnsName: rootIpnsName,
      folderKey: vaultKeyBlob.rootReadKey,
      ctx,
    });
    if (!folder) {
      throw new Error(`Root folder metadata not found for ${rootIpnsName}`);
    }

    // Resolve which folder to search in, and the parent read key the file's
    // child ref is sealed under. Default: root. With --folder-name, descend
    // one level into that subfolder — the subfolder's read key is derived
    // from the root's SealedChildRef via unsealChildReadKey, so a file moved
    // into a subfolder can be verified under the destination read key (which
    // is exactly what the move/restore re-link must preserve).
    let searchChildren = folder.metadata.children ?? [];
    let parentReadKey = vaultKeyBlob.rootReadKey;

    if (args.folderName) {
      const subRef = searchChildren.find((child) => child.name === args.folderName);
      if (!subRef) {
        throw new Error(`Subfolder not found at root: ${args.folderName}`);
      }
      const { childReadKey, childPublished } = await deriveChildReadKey(subRef, parentReadKey, ctx);
      subReadKey = childReadKey;
      if (childPublished.kind !== 'folder') {
        throw new Error(`Child ${args.folderName} at root is not a folder`);
      }
      const subFolder = await loadFolderMetadata({
        ipnsName: subRef.ipnsName,
        folderKey: subReadKey,
        ctx,
      });
      if (!subFolder) {
        throw new Error(`Subfolder metadata not found for ${args.folderName}`);
      }
      searchChildren = subFolder.metadata.children ?? [];
      parentReadKey = subReadKey;
    }

    const fileRef = searchChildren.find((child) => child.name === args.fileName);
    if (!fileRef) {
      throw new Error(`SealedChildRef not found for ${args.fileName}`);
    }

    const { childReadKey, childPublished: filePublished } = await deriveChildReadKey(
      fileRef,
      parentReadKey,
      ctx
    );
    fileReadKey = childReadKey;
    if (filePublished.kind !== 'file') {
      throw new Error(`Child ${args.fileName} is not a file node`);
    }

    const { metadata, metadataCid } = await resolveFileMetadata(fileRef.ipnsName, fileReadKey, ctx);

    let contentVerified = false;
    if (args.expectedContent !== undefined) {
      const plaintext = await downloadFileContent({
        cid: metadata.cid,
        fileKey: metadata.fileKey,
        fileIv: metadata.fileIv,
        encryptionMode: metadata.encryptionMode,
        ctx,
      });

      const decoded = new TextDecoder().decode(plaintext);
      if (decoded !== args.expectedContent) {
        throw new Error(
          `Downloaded content mismatch for ${args.fileName}: expected ${JSON.stringify(args.expectedContent)}, got ${JSON.stringify(decoded)}`
        );
      }
      contentVerified = true;
    }

    console.log(
      JSON.stringify({
        rootIpnsName,
        rootMetadataCid: folder.cid,
        fileName: args.fileName,
        fileIpnsName: fileRef.ipnsName,
        fileMetadataCid: metadataCid,
        fileCid: metadata.cid,
        contentVerified,
      })
    );
  } finally {
    clearBytes(userPrivateKey);
    clearBytes(vaultKeyBlob.rootReadKey);
    clearBytes(vaultKeyBlob.rootWriteKey);
    if (fileReadKey) clearBytes(fileReadKey);
    if (subReadKey) clearBytes(subReadKey);
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
