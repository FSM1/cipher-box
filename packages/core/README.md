# @cipherbox/core

CipherBox domain types, metadata schemas, validators, and metadata encryption.

## Install

```bash
pnpm add @cipherbox/core
```

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
- Functions: `encryptFileMetadata`, `decryptFileMetadata`, `validateFileMetadata`, `deriveFileIpnsKeypair`

### Device Registry

- Types: `DeviceEntry`, `DeviceRegistry`, `DeviceAuthStatus`, `DevicePlatform`
- Functions: `encryptRegistry`, `decryptRegistry`, `deriveRegistryIpnsKeypair`, `validateDeviceRegistry`

### Recycle Bin

- Types: `BinEntry`, `RecycleBinMetadata`
- Functions: `encryptBinMetadata`, `decryptBinMetadata`, `deriveBinIpnsKeypair`, `validateBinMetadata`

### Vault Initialization

- Types: `VaultInit`, `EncryptedVaultKeys`
- Functions: `initializeVault`, `encryptVaultKeys`, `decryptVaultKeys`

### IPNS Records

- Types: `IPNSRecord`
- Functions: `createIpnsRecord`, `deriveIpnsName`, `marshalIpnsRecord`, `unmarshalIpnsRecord`

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

## License

ISC
