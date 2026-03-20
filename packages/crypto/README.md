# @cipherbox/crypto

Pure cryptographic primitives and key derivation for the CipherBox ecosystem.

## Install

```bash
pnpm add @cipherbox/crypto
```

## Usage

```typescript
import {
  encryptAesGcm,
  decryptAesGcm,
  generateFileKey,
  wrapKey,
  unwrapKey,
} from '@cipherbox/crypto';
```

## API

### AES-GCM / AES-CTR

- `encryptAesGcm`, `decryptAesGcm`, `sealAesGcm`, `unsealAesGcm`
- `encryptAesCtr`, `decryptAesCtr`, `decryptAesCtrRange`

### ECIES Key Wrapping

- `wrapKey`, `unwrapKey`, `reWrapKey`

### Ed25519

- `generateEd25519Keypair`, `signEd25519`, `verifyEd25519`

### Key Derivation

- `deriveKey`, `deriveContextKey`, `generateFolderKey`, `generateFileKey`
- `deriveVaultIpnsKeypair`

### Device Keys

- `generateDeviceKeypair`, `deriveDeviceId`

### Utilities

- `hexToBytes`, `bytesToHex`, `concatBytes`, `clearBytes`, `generateRandomBytes`

## Architecture

```text
@cipherbox/crypto  <-- You are here
    ^
@cipherbox/core
    ^
@cipherbox/sdk-core
    ^
@cipherbox/sdk
```

## License

ISC
