<!-- generated-by: gsd-doc-writer -->

# @cipherbox/sdk-core

Stateless, folder-aware vault operations for CipherBox. Designed for load testing and integration testing without browser dependencies.

Part of the [CipherBox monorepo](../../README.md).

## Usage

```typescript
import { uploadFile, downloadAndDecrypt, createSubfolder } from '@cipherbox/sdk-core';

const result = await uploadFile({ data, fileId, mimeType, folderKey, publicKey, ctx });
```

## API

### Types

- `SdkContext` — injected configuration (`apiUrl`, `getAccessToken`, optional `axiosInstance`)
- `TeeKeys` — TEE key configuration (`currentPublicKey`, `currentEpoch`, optional previous key/epoch)
- `IpfsAddResult`, `ProgressCallback`, `DownloadProgressCallback`

### File Operations

- `uploadFile`, `downloadAndDecrypt`
- `createFileMetadata`, `resolveFileMetadata`, `updateFileMetadata`

### Folder Operations

- `fetchAndDecryptMetadata`, `loadFolderMetadata`, `updateFolderMetadataAndPublish`
- `createSubfolder`, `renameInFolder`, `moveItem`, `deleteFromFolder`
- `addFilePointerToFolder`, `addFileToFolder`, `addFilesToFolder`, `replaceFileInFolder`

### Tree Utilities

- `getDepth`, `calculateSubtreeDepth`, `isDescendantOf`

### IPFS/IPNS

- `addToIpfs`, `fetchFromIpfs`, `unpinFromIpfs`, `registerCid`
- `createAndPublishIpnsRecord`, `batchPublishIpnsRecords`, `resolveIpnsRecord`, `verifyIpnsSignature`

### Vault

- `publishVaultKeyBlob`, `loadVaultKeyBlob`

### Pinning Providers (BYO-IPFS)

- `KuboProvider`, `PsaProvider`, `PinataProvider`, `DualPinProvider`, `testConnection`
- Types: `PinningProvider`, `PinResult`, `PinStatus`, `PinningMode`, `ExternalProviderConfig`, `ConnectionTestResult`, `ProviderOptions`, `DualPinResult`

### Encryption Mode

- `selectEncryptionMode`, `normalizeEncryptionMode`
- Type: `EncryptionMode`

## Testing

```bash
pnpm test
```

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
