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
  onOperationStart: (op) => console.log('Starting', op),
  onOperationEnd: (op) => console.log('Done', op),
});

await client.uploadFile(folderIpnsName, data, fileName, mimeType);
await client.deleteItem(folderIpnsName, childId);
```

## API

### Client Lifecycle

- `new CipherBoxClient(config)`, `client.destroy()`

### Folder Operations

- `client.loadFolder()`, `client.createFolder()`, `client.renameItem()`, `client.moveItem()`, `client.deleteItem()`

### File Operations

- `client.uploadFile()`, `client.downloadFile()`, `client.downloadFromIpns()`

### Recycle Bin

- `client.loadBin()`, `client.deleteToBin()`, `client.restoreFromBin()`, `client.permanentDelete()`, `client.emptyBin()`

### Events

- `const unsub = client.on((event) => { ... })` — single handler receives all typed `SdkEvent` objects (`folder:loaded`, `folder:updated`, `bin:updated`, `error`, etc.)

## Architecture

```text
@cipherbox/crypto
    ^
@cipherbox/core    @cipherbox/api-client
    ^                    ^
@cipherbox/sdk-core <----+
    ^
@cipherbox/sdk  <-- You are here
```

## License

ISC
