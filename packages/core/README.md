<!-- generated-by: gsd-doc-writer -->

# @cipherbox/core

CipherBox domain types, metadata schemas, validators, and metadata encryption.

Part of the [CipherBox monorepo](../../README.md).

## Usage

```typescript
import {
  type FolderMetadata,
  encryptFolderMetadata,
  decryptFolderMetadata,
  validateFolderMetadata,
} from '@cipherbox/core';
```

## API

### Folder Metadata

- Types: `FolderMetadata`, `FolderChild`, `FolderEntry`, `EncryptedFolderMetadata`
- Functions: `encryptFolderMetadata`, `decryptFolderMetadata`, `validateFolderMetadata`

### File Metadata

- Types: `FileMetadata`, `FilePointer`, `VersionEntry`, `EncryptedFileMetadata`
- Functions: `encryptFileMetadata`, `decryptFileMetadata`, `validateFileMetadata`, `deriveFileIpnsKeypair`, `generateFileIpnsKeypair`

### Device Registry

- Types: `DeviceEntry`, `DeviceRegistry`, `DeviceRegistryVersion`, `DeviceAuthStatus`, `DevicePlatform`
- Functions: `encryptRegistry`, `decryptRegistry`, `deriveRegistryIpnsKeypair`, `validateDeviceRegistry`

### Recycle Bin

- Types: `BinEntry`, `RecycleBinMetadata`
- Functions: `encryptBinMetadata`, `decryptBinMetadata`, `deriveBinIpnsKeypair`, `validateBinMetadata`

### Vault

- Types: `VaultInit`, `EncryptedVaultKeys`, `ByoIpfsConfig`, `VaultSettings`
- Functions: `initializeVault`, `encryptVaultKeys`, `decryptVaultKeys`, `serializeVaultBlobV2`, `deserializeVaultBlobV2`, `detectBlobVersion`, `validateVaultSettings`
- Constants: `BLOB_V2_VERSION`, `DEFAULT_VAULT_SETTINGS`

### IPNS Records

- Types: `IPNSRecord`
- Functions: `createIpnsRecord`, `deriveIpnsName`, `marshalIpnsRecord`, `unmarshalIpnsRecord`, `signIpnsData`
- Constants: `IPNS_SIGNATURE_PREFIX`

## Architecture

```text
@cipherbox/crypto
    ^
@cipherbox/core  <-- You are here
    ^
@cipherbox/sdk-core
    ^
@cipherbox/sdk
```

## Testing

```bash
pnpm test
```

## License

ISC
