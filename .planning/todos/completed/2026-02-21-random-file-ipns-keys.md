---
created: 2026-02-21T04:10
title: Switch file IPNS keys from deterministic (HKDF) to random, matching folder pattern
area: crypto
files:
  - packages/crypto/src/file-ipns/derive.ts
  - packages/crypto/src/file-ipns/types.ts
  - packages/crypto/src/folder/metadata.ts
  - packages/crypto/src/folder/types.ts
  - apps/web/src/services/file-metadata.service.ts
  - apps/web/src/services/folder.service.ts
  - apps/desktop/src-tauri/src/fuse/operations.rs
  - apps/desktop/src-tauri/src/crypto/ipns.rs
  - docs/METADATA_SCHEMAS.md
  - docs/METADATA_EVOLUTION_PROTOCOL.md
---

## Summary

File IPNS keys are currently derived deterministically via HKDF(privateKey, "cipherbox-file-ipns-v1-{fileId}"), while folder IPNS keys are randomly generated Ed25519 keypairs stored encrypted in parent metadata. This asymmetry has no valid justification and should be corrected.

## Problem

The original justification for deterministic file IPNS keys was self-sovereign recovery (derive all keys from recovery phrase without tree traversal). This is incorrect because:

1. Recovery already traverses the folder tree to discover files — file IPNS names are found in parent folder metadata (`FilePointer.fileMetaIpnsName`), not derived independently
2. You can't resolve a file's IPNS without first knowing the `fileId`, which is only available by decrypting the parent folder
3. TEE republishing receives the IPNS private key encrypted at publish time — it doesn't re-derive anything
4. The deterministic design prevents future write-sharing on individual files (giving another user publish authority over a single file's IPNS record)

## Solution

Switch file IPNS keys to randomly generated Ed25519 keypairs, matching the folder IPNS pattern:

1. **FilePointer type**: Add `ipnsPrivateKeyEncrypted` field (ECIES-wrapped with owner's publicKey), same pattern as `FolderEntry.ipnsPrivateKeyEncrypted`
2. **File creation**: Generate random Ed25519 keypair instead of HKDF derivation; store encrypted private key in parent folder's FilePointer
3. **File IPNS publish**: Decrypt the IPNS private key from FilePointer instead of re-deriving via HKDF
4. **TEE republishing**: No change needed — already receives encrypted key at publish time
5. **Recovery tool**: Update to read IPNS private key from FilePointer (already traverses tree)
6. **Desktop FUSE**: Update create()/release() to generate random keypair and store in metadata
7. **Remove**: `deriveFileIpnsKeypair()` HKDF function and related derivation code
8. **Schema**: Breaking change to FilePointer — exercise METADATA_EVOLUTION_PROTOCOL.md with dual-read migration (not clean-break)

### Schema change (FilePointer)

```diff
 interface FilePointer {
   type: 'file';
   nameEncrypted: string;
   nameIv: string;
   fileMetaIpnsName: string;
+  ipnsPrivateKeyEncrypted?: string;  // ECIES(ipnsPrivateKey, ownerPublicKey) — optional for backward compat
   fileId: string;
   created: number;
   modified: number;
 }
```

Field is **optional** in the type to support dual-read migration. When absent, clients fall back to HKDF derivation. All new writes include the field. After a sufficient migration window, the field can be made required and HKDF code removed.

### Post-completion checklist

- [ ] Update STATE.md: remove/update the "Read-only sharing only (no multi-writer IPNS)" decision note — file IPNS keys are now sharing-ready (though multi-writer IPNS sequence number conflicts remain an open problem for v3)
- [ ] Update METADATA_SCHEMAS.md Section 14 (IPNS Key Derivation Summary) — remove file IPNS from the HKDF table, add to the "random" category alongside subfolder keys
- [ ] Follow METADATA_EVOLUTION_PROTOCOL.md Section 4 checklist for the FilePointer schema change

## Migration Strategy

This is a **breaking schema change** to FilePointer (adding required `ipnsPrivateKeyEncrypted` field). Rather than relying on the clean-break window philosophy from Phase 12.3.1 (wipe DB, no migration), this task should exercise the **METADATA_EVOLUTION_PROTOCOL.md** properly:

1. **Dual-read support**: New clients read both old FilePointers (no `ipnsPrivateKeyEncrypted`) and new ones. Old FilePointers fall back to HKDF derivation for the IPNS key.
2. **Write-new-only**: All new/updated FilePointers include `ipnsPrivateKeyEncrypted` with a randomly generated keypair.
3. **Lazy migration**: When an old FilePointer is encountered, the HKDF-derived key is re-wrapped and written back as `ipnsPrivateKeyEncrypted` on next folder metadata publish.
4. **Recovery tool**: Must handle both formats (HKDF fallback when field is absent).
5. **Desktop FUSE**: Same dual-read, write-new pattern as web.

This approach validates that the evolution protocol works in practice for a real breaking change, building confidence before Phase 14 (sharing) introduces more complex schema extensions.

### Why not clean-break again

- Production data may exist by the time this runs — can't assume DB wipe
- The evolution protocol was created specifically for this class of change
- Exercising the protocol now (with a relatively simple migration) proves the process before harder migrations arrive

## Notes

- Multi-writer IPNS (two users publishing to same IPNS name) still has the sequence number conflict problem — this todo doesn't solve that, but removes the key-distribution blocker
- Consider doing this before Phase 14 (User-to-User Sharing) since sharing will benefit from file-level IPNS key handoff
