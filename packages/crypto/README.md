<!-- generated-by: gsd-doc-writer -->

# @cipherbox/crypto

Pure cryptographic primitives and key derivation for the CipherBox ecosystem.

Part of the [CipherBox monorepo](../../README.md).

## Usage

```typescript
import {
  encryptAesGcm,
  decryptAesGcm,
  generateFileKey,
  generateIv,
  wrapKey,
  unwrapKey,
} from '@cipherbox/crypto';

// Encrypt file content
const fileKey = generateFileKey();
const iv = generateIv();
const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);

// Wrap file key with user's public key (ECIES secp256k1)
const wrappedKey = await wrapKey(fileKey, vaultKey.publicKey);

// Unwrap and decrypt
const unwrappedKey = await unwrapKey(wrappedKey, vaultKey.privateKey);
const decrypted = await decryptAesGcm(ciphertext, unwrappedKey, iv);
```

## API

### AES-256-GCM

- `encryptAesGcm`, `decryptAesGcm` — encrypt/decrypt with explicit IV
- `sealAesGcm`, `unsealAesGcm` — prepend IV to ciphertext for self-contained blobs

### AES-256-CTR (streaming / random-access)

- `encryptAesCtr`, `decryptAesCtr` — full-stream CTR encryption
- `decryptAesCtrRange` — random-access decryption for media byte-range requests

### ECIES secp256k1 Key Wrapping

- `wrapKey`, `unwrapKey`, `reWrapKey`

### Ed25519

- `generateEd25519Keypair`, `deriveEd25519PublicKey`, `signEd25519`, `verifyEd25519`

### Key Derivation

- `deriveKey`, `deriveContextKey`, `generateFolderKey`

### Vault IPNS Key Derivation

- `deriveVaultIpnsKeypair`, `deriveVaultKeyIpnsKeypair`
- `deriveByoConfigIpnsKeypair`, `deriveVaultSettingsIpnsKeypair`

### IPNS

- `deriveIpnsName`

### Device Keys

- `generateDeviceKeypair`, `deriveDeviceId`

### Utilities

- `generateFileKey`, `generateIv`, `generateCtrIv`, `generateRandomBytes`
- `hexToBytes`, `bytesToHex`, `concatBytes`, `clearBytes`, `clearAll`

### Types and Constants

- `CryptoError`, `CryptoErrorCode`, `VaultKey`, `EncryptedData`
- `AES_KEY_SIZE`, `AES_IV_SIZE`, `AES_TAG_SIZE`, `SECP256K1_PUBLIC_KEY_SIZE`, and related constants

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

## Testing

```bash
pnpm test
pnpm test:watch
pnpm test:coverage
```

## License

ISC
