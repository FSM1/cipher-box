---
created: 2026-02-21T00:00
title: Move rootFolderKey to IPFS vault record, eliminate server-side key storage
area: crypto
files:
  - packages/crypto/src/vault/types.ts
  - packages/crypto/src/vault/init.ts
  - apps/api/src/users/users.service.ts
  - apps/web/src/services/folder.service.ts
  - apps/web/public/recovery.html
---

## Summary

## Context

`EncryptedVaultKeys` stores two ECIES-wrapped keys on the server:

- `encryptedRootFolderKey` — randomly generated AES-256 key (cannot be derived)
- `encryptedIpnsPrivateKey` — deterministically derivable via HKDF (redundant)

Since the root IPNS private key is derivable from the user's secp256k1 key, the only reason EncryptedVaultKeys exists is to store the root folder key.

## Proposal

Move `encryptedRootFolderKey` into the IPFS blob pointed at by the root vault IPNS record. The blob would contain both the ECIES-wrapped folder key and the AES-GCM encrypted FolderMetadata. This eliminates all server-side crypto material storage.

New flow: login → derive IPNS key via HKDF → resolve IPNS → unwrap folder key from blob → decrypt metadata.

## Considerations

- **IPNS reliability:** Adds IPNS resolution to the critical login path. If resolution fails, user can't get their root folder key. Server-cached CID fallback mitigates this but doesn't eliminate the risk.
- **Breaking change:** New wire format for root IPFS blob. Requires version bump or migration strategy per `docs/METADATA_EVOLUTION_PROTOCOL.md`.
- **Recovery tool:** Must be updated to handle the new blob format.
- **TEE republishing:** Unaffected — TEE uses separately wrapped IPNS keys from `folder_ipns` table.
- **Zero-knowledge improvement:** Server stores zero crypto material, becoming a pure relay.

## References

- `docs/METADATA_SCHEMAS.md` Section 10 (EncryptedVaultKeys)
- `docs/METADATA_EVOLUTION_PROTOCOL.md` Section 3.2 (Breaking Changes)
