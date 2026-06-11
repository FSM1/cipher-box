<!-- generated-by: gsd-doc-writer -->

# @cipherbox/sdk

Stateful CipherBox client with full workflow orchestration, event emission, and internal state management.

## Install

```bash
pnpm add @cipherbox/sdk
```

## Usage

```typescript
import { CipherBoxClient } from '@cipherbox/sdk';

const client = new CipherBoxClient({
  apiUrl: 'https://api.cipherbox.cc',
  getAccessToken: async () => token,
  vaultKeypair: { publicKey, privateKey },
  rootIpnsName: 'k51qzi5uqu5dg...',
  rootFolderKey,
});

// Subscribe to typed events
const unsub = client.on((event) => {
  if (event.type === 'folder:updated') {
    store.updateFolder(event.folderId, event.children);
  }
});

// Load root folder
await client.loadFolder(rootIpnsName, rootFolderKey, rootIpnsKeypair);

await client.uploadFile(folderIpnsName, data, fileName, mimeType);
await client.deleteItem(folderIpnsName, childId);

// Cleanup
unsub();
client.destroy();
```

## API

### Client Lifecycle

- `new CipherBoxClient(config: CipherBoxClientConfig)`, `client.destroy()`

### Folder Operations

- `client.loadFolder(ipnsName, folderKey, ipnsKeypair)`
- `client.createFolder(parentIpnsName, name)`, `client.renameItem()`, `client.moveItem()`, `client.deleteItem()`

### File Operations

- `client.uploadFile(folderIpnsName, data, fileName, mimeType)`, `client.uploadFiles()` (batch)
- `client.downloadFile(cid, fileKey)`, `client.downloadFromIpns(fileMetaIpnsName)`
- `client.updateFile()`

### Recycle Bin

- `client.loadBin()`, `client.deleteToBin()`, `client.restoreFromBin()`, `client.permanentDelete()`, `client.emptyBin()`

### Share Operations

- Stateful share operations are accessed via `CipherBoxClient`
- Stateless shared-write helpers for write-share recipients: `uploadToSharedFolder()`, `createSharedSubfolder()`, `renameInSharedFolder()`, `deleteFromSharedFolder()`, `updateSharedFile()`, `updateSharePermission()`, `buildSharedWriteContext()`
- `ShareKeyCache` — caches decrypted share keys to avoid repeated ECIES operations

### Error Utilities

- `isForbiddenError(err)`, `isConflictError(err)` — error type guards
- `withRevocationGuard(fn)` — wraps an operation and handles 403 revocation
- `withConflictRetry(fn)` — retries on 409 conflict with exponential backoff

### Events

`client.on(handler)` — subscribe to all typed `SdkEvent` objects; returns an unsubscribe function.

| Event type                | Payload highlights                                   |
| ------------------------- | ---------------------------------------------------- |
| `folder:loaded`           | `folderId`, `ipnsName`, `children`, `sequenceNumber` |
| `folder:updated`          | `folderId`, `ipnsName`, `children`, `sequenceNumber` |
| `folder:deleted`          | `folderId`                                           |
| `file:uploaded`           | `folderId`, `fileName`, `cid`                        |
| `files:batchUploaded`     | `folderId`, `successes[]`, `failures[]`              |
| `file:downloaded`         | `cid`                                                |
| `bin:updated`             | `entries`                                            |
| `share:reWrapFailed`      | `folderIpnsName`, `failedRecipients`                 |
| `pin:secondaryFailed`     | `cid`, `providerName`, `error`                       |
| `ipns:batchPublishFailed` | `ipnsNames`, `error`                                 |
| `operation:start`         | `operation`                                          |
| `operation:end`           | `operation`, `durationMs`                            |
| `error`                   | `operation`, `error`                                 |

## Architecture

```text
@cipherbox/crypto
    ^
@cipherbox/core    @cipherbox/api-client
    ^                    ^
@cipherbox/sdk-core <----+
    ^
@cipherbox/sdk  <-- You are here
    |
    +-- @cipherbox/crypto (direct)
```

Part of the [CipherBox monorepo](../../README.md).

## License

ISC
