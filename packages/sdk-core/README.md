# @cipherbox/sdk-core

Stateless, folder-aware vault operations for CipherBox. Designed for load testing and integration testing without browser dependencies.

## Install

```bash
pnpm add @cipherbox/sdk-core
```

## Usage

```typescript
import { uploadFileToFolder, downloadAndDecrypt, createSubfolder } from '@cipherbox/sdk-core';

const result = await uploadFileToFolder(file, metadata, folderKey, ipnsKeypair, publicKey, ctx);
```

## API

### File Operations

- `uploadFileToFolder`, `downloadAndDecrypt`

### Folder Operations

- `createSubfolder`, `renameInFolder`, `moveItem`, `deleteFromFolder`

### IPFS/IPNS

- `addToIpfs`, `fetchFromIpfs`, `unpinFromIpfs`, `createAndPublishIpnsRecord`, `batchPublishIpnsRecords`, `resolveIpnsRecord`

## Architecture

```text
@cipherbox/crypto
    ^
@cipherbox/core    @cipherbox/api-client
    ^                    ^
@cipherbox/sdk-core <----+  <-- You are here
    ^
@cipherbox/sdk
```

## License

ISC
