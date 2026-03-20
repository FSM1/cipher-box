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
  getAccessToken: () => token,
  vaultKeypair,
  onOperationStart: (op) => console.log('Starting', op),
  onOperationEnd: (op) => console.log('Done', op),
});

await client.uploadFile(folderId, file);
await client.deleteFile(folderId, fileId);
```

## API

### Client Lifecycle

- `new CipherBoxClient(config)`, `client.initialize()`, `client.destroy()`

### File Operations

- `client.uploadFile()`, `client.downloadFile()`, `client.deleteFile()`, `client.moveFile()`

### Folder Operations

- `client.createFolder()`, `client.renameFolder()`, `client.deleteFolder()`

### Recycle Bin

- `client.listBin()`, `client.restoreFromBin()`, `client.emptyBin()`

### Events

- `client.on('change', callback)`, `client.on('error', callback)`

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
