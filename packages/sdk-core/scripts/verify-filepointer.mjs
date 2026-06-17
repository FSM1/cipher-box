import { createAxiosInstance } from '../../api-client/dist/index.mjs';
import {
  downloadAndDecrypt,
  resolveFileMetadata,
  loadFolderMetadata,
  loadVaultKeyBlob,
} from '../dist/index.mjs';
import { unwrapKey, hexToBytes } from '../../crypto/dist/index.mjs';

function parseArgs(argv) {
  const values = new Map();

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      throw new Error(`Unexpected argument: ${token}`);
    }

    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Missing value for --${key}`);
    }

    values.set(key, value);
    i += 1;
  }

  if (values.has('secret')) {
    throw new Error('Do not pass --secret on CLI. Set TEST_SECRET in environment.');
  }

  const apiUrl = values.get('api-url');
  const secret = process.env.TEST_SECRET;
  const email = values.get('email');
  const fileName = values.get('file-name');

  if (!apiUrl || !email || !fileName || !secret) {
    throw new Error(
      'Usage: verify-filepointer.mjs --api-url <url> --email <email> --file-name <name> [--folder-name <subfolder>] [--expected-content <text>] (requires TEST_SECRET env var)'
    );
  }

  return {
    apiUrl,
    secret,
    email,
    fileName,
    // Optional: a single subfolder (at root level) to look in instead of root.
    // Used to verify a file after it has been moved into a subfolder.
    folderName: values.get('folder-name'),
    expectedContent: values.get('expected-content'),
  };
}

async function authenticate(apiUrl, email, secret) {
  const response = await fetch(`${apiUrl}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, secret }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`test-login failed (${response.status}): ${body}`);
  }

  const payload = await response.json();

  if (!payload.accessToken || !payload.privateKeyHex) {
    throw new Error('test-login response missing accessToken or privateKeyHex');
  }

  return payload;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const auth = await authenticate(args.apiUrl, args.email, args.secret);
  const accessToken = auth.accessToken;
  const userPrivateKey = Uint8Array.from(Buffer.from(auth.privateKeyHex, 'hex'));

  const axiosInstance = createAxiosInstance({
    baseUrl: args.apiUrl,
    getAccessToken: async () => accessToken,
  });

  const ctx = {
    apiUrl: args.apiUrl,
    getAccessToken: async () => accessToken,
    axiosInstance,
  };

  const vaultResponse = await axiosInstance.get('/vault');
  const rootIpnsName = vaultResponse.data.rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('Vault response missing rootIpnsName');
  }

  const vaultKeyBlob = await loadVaultKeyBlob({ userPrivateKey, ctx });
  if (!vaultKeyBlob) {
    throw new Error('Vault key blob not found');
  }

  const folder = await loadFolderMetadata({
    ipnsName: rootIpnsName,
    folderKey: vaultKeyBlob.rootFolderKey,
    ctx,
  });
  if (!folder) {
    throw new Error(`Root folder metadata not found for ${rootIpnsName}`);
  }

  // Resolve which folder to search in, and the folderKey the file's metadata is
  // encrypted under. Default: root. With --folder-name, descend one level into
  // that subfolder (its folderKey is ECIES-wrapped for the vault on its
  // FolderEntry), so a file moved into a subfolder can be verified — and read
  // back under the destination folderKey, which is exactly what the
  // move/restore re-encryption must produce.
  let searchChildren = folder.metadata.children;
  let fileFolderKey = vaultKeyBlob.rootFolderKey;

  if (args.folderName) {
    const subEntry = folder.metadata.children.find(
      (child) => child.type === 'folder' && child.name === args.folderName
    );
    if (!subEntry) {
      throw new Error(`Subfolder not found at root: ${args.folderName}`);
    }
    const subFolderKey = await unwrapKey(
      hexToBytes(subEntry.folderKeyEncrypted),
      userPrivateKey
    );
    const subFolder = await loadFolderMetadata({
      ipnsName: subEntry.ipnsName,
      folderKey: subFolderKey,
      ctx,
    });
    if (!subFolder) {
      throw new Error(`Subfolder metadata not found for ${args.folderName}`);
    }
    searchChildren = subFolder.metadata.children;
    fileFolderKey = subFolderKey;
  }

  const filePointer = searchChildren.find(
    (child) => child.type === 'file' && child.name === args.fileName
  );

  if (!filePointer) {
    throw new Error(`FilePointer not found for ${args.fileName}`);
  }

  if (!filePointer.fileMetaIpnsName) {
    throw new Error(`FilePointer for ${args.fileName} is missing fileMetaIpnsName`);
  }

  const { metadata, metadataCid } = await resolveFileMetadata(
    filePointer.fileMetaIpnsName,
    fileFolderKey,
    ctx
  );

  let contentVerified = false;
  if (args.expectedContent !== undefined) {
    const plaintext = await downloadAndDecrypt({
      cid: metadata.cid,
      fileKeyEncrypted: metadata.fileKeyEncrypted,
      fileIv: metadata.fileIv,
      userPrivateKey,
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
      fileMetaIpnsName: filePointer.fileMetaIpnsName,
      fileMetadataCid: metadataCid,
      fileCid: metadata.cid,
      contentVerified,
    })
  );
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
