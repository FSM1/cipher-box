# Phase 14: User-to-User Sharing - Context

**Gathered:** 2026-02-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Users can share encrypted folders and individual files with other CipherBox users while maintaining zero-knowledge guarantees. The server never sees plaintext folderKey/fileKey at any point. This phase covers read-only sharing only — read-write sharing and re-sharing are out of scope. User discovery/lookup (by email, username, etc.) is a separate future phase; this phase uses direct public key exchange.

</domain>

<decisions>
## Implementation Decisions

### Invitation flow

- Share by pasting recipient's secp256k1 public key (uncompressed, 0x04... format)
- No email/username lookup — recipient's pubkey obtained out-of-band (copy from Settings, send via chat, etc.)
- Backend verifies the pasted pubkey belongs to a registered CipherBox user before allowing the share
- Instant share — no accept/decline flow. Folder/file immediately appears in recipient's "Shared with me"
- Recipient can hide/remove unwanted shares from their view (mechanism left to implementation)

### Sharing UI & interactions

- Share action accessible from **context menu** (quick share) AND **details dialog** (manage existing shares)
- Context menu adds "Share" item with `@` icon, between "Move to..." and "Details"
- "Shared with me" is a **separate top-level section**, navigated via breadcrumb path `~/shared` (not a sidebar — stays consistent with existing breadcrumb-based navigation)
- Sharer sees list of recipients as truncated pubkeys (e.g., `0x1a2b...9f0e`)
- Share dialog is a modal following existing modal pattern (500px, #003322 border, backdrop)
- Share dialog title includes item name: `SHARE: documents/` or `SHARE: report.pdf`
- Recipients shown as flat list with per-recipient revoke action
- No upload/new-folder/refresh buttons when browsing shared content (read-only)

### Revocation & key rotation

- **Lazy key rotation**: revoking a share removes the recipient's access record but does NOT immediately rotate the folderKey. Key rotation happens on next folder modification
- Per-recipient revoke — remove individual recipients while others keep access
- Revoke action styled as danger (`--revoke` in `#EF4444`)
- Recipient's experience on revoke: folder silently disappears from "Shared with me" on next poll (Claude's discretion on exact behavior)

### Permissions model

- **Read-only only** for this phase — recipients can view and download but not modify
- Both **folder-level and file-level sharing** supported (per-file IPNS from Phase 12.6 makes this architecturally possible)
- **No re-sharing** — readers receive folderKey/fileKey for decryption only, NOT the IPNS private key. Without the IPNS private key, they cannot modify metadata or re-share
- Shared items display `[RO]` badge inline in the file list (read-only indicator)
- Organization of shared files vs folders in "Shared with me": Claude's discretion

### Settings - Public Key

- User's public key displayed in Settings page with copy-to-clipboard button
- Section header: `// your public key` in terminal comment style
- Full key displayed in bordered box, monospace, with word-wrap
- Help text: `// share this key with others to receive shared files`
- Copy button: `--copy` label, secondary outline style

### Claude's Discretion

- Exact read-only enforcement UX (hide vs disable upload/modify actions)
- How shared items are organized in "Shared with me" (flat list vs grouped)
- How recipient removal/hiding works (client-side vs server-side record)
- Exact revoke experience for the recipient (silent disappear vs brief "access revoked" state)
- Share record storage architecture (server DB vs client-side)
- ECIES re-wrapping implementation details
- "Shared by me" view (whether sharer can see all their outgoing shares in one place)

</decisions>

<specifics>
## Specific Ideas

- Terminal command style for all sharing UI — `--share`, `--revoke`, `//` comments, `~/shared` path
- Share dialog mimics running a command: `SHARE: filename` as title
- Truncated pubkeys shown as `0x1a2b...9f0e` (first 4 + last 4 hex chars)
- Access model mirrors a file permission system: readers get decryption keys only, writers (future) would get IPNS signing keys
- "Shared with me" column shows `SHARED BY` with truncated pubkey of the sharer

</specifics>

<trade-offs>
## Architecture Trade-Off: Server-Side vs Metadata-Embedded Sharing

### Current Approach: Server-Side Share Records

Phase 14 stores sharing state in PostgreSQL (`shares` and `share_keys` tables). The server holds ECIES-wrapped keys per recipient. IPFS metadata schemas (FolderMetadata, FileMetadata) are unchanged.

**Consequence:** The server knows the sharing graph — who shared what with whom — but never sees plaintext keys or content.

### Alternative: Metadata-Embedded ACLs

The original design consideration was embedding `readers`/`writers` arrays directly in IPFS metadata:

```
readers?: Array<{ pubKey: string; encryptedFolderKey: string }>
```

This would be pervasive across the entire IPNS/IPFS tree. From a schema evolution perspective, this is a clean additive change (optional field, defaults to `undefined`, no version bump needed per the Evolution Protocol).

**Advantages:**

- Server has zero knowledge of the sharing graph — not just content, but relationships
- Sharing metadata is self-contained and travels with the encrypted data
- No server dependency for access control verification

**Disadvantages:**

- Sharing a folder requires re-publishing metadata for every node in the subtree (N IPNS publishes for N items)
- Concurrent shares from multiple devices create metadata write conflicts
- Metadata size grows ~130 bytes per reader per node (65-byte pubkey + ~65-byte ECIES ciphertext)
- Revocation requires tree-wide re-keying to achieve cryptographic revocation

### Revocation Risk Assessment

Cryptographic revocation (re-keying on revoke) is not implemented in either approach. Both rely on access-control revocation only — removing the ability to fetch new keys, not invalidating already-obtained keys.

The practical risk of this is low because:

1. Recipients receive file keys as non-extractable Web Crypto `CryptoKey` objects in-browser — not raw bytes
2. Deliberate key extraction would require intercepting the ECIES-wrapped key from the API response AND retaining the recipient's private key AND the content CID
3. After any content update, old CIDs point to stale content and old keys no longer decrypt the current version
4. Old CIDs are unpinned on Pinata when content updates, so they are eventually garbage collected

This risk profile is identical in both approaches — during the authorized access window, the recipient's browser holds plaintext keys in memory regardless of where the ACL lives.

### Third Option: CRDT-Based IPNS Inbox (Post-Phase 14 Research)

A third approach emerged from post-Phase 14 discussion: derive a deterministic IPNS "inbox" per recipient (via HKDF of their public key) and use CRDTs as the content model to handle concurrent writes from multiple sharers without conflict.

This reframes the problem: instead of working around IPNS write conflicts per-feature (folder sync, sharing, device registry), solve conflict-free state as a horizontal concern using CRDTs (G-Set/OR-Set). The same pattern would benefit folder metadata sync, not just sharing.

Key insight: every centralized workaround we add (DB-cached CIDs, shares table, pinned_cids) individually makes sense but collectively erodes the serverless premise. Fixing IPNS conflict resolution once — via CRDTs — would unblock all features simultaneously.

Open challenges: write-access control on publicly-derivable IPNS addresses, revocation semantics, and IPNS reliability (a prerequisite regardless of approach).

**See:** `.planning/todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md` for full research scope.

### Decision

Server-side approach chosen for Phase 14 (read-only sharing). The metadata-embedded approach remains viable for a future "fully decentralized sharing" phase if hiding the social graph from the server becomes a requirement. The CRDT-based IPNS inbox is a promising third option pending research into IPNS reliability and CRDT feasibility.

</trade-offs>

<deferred>
## Deferred Ideas

- **User discovery/lookup service** — Find users by email, username, or wallet address to get their pubkey automatically. Requires privacy controls (what data your pubkey can be looked up via). Separate phase.
- **Read-write sharing** — Requires giving recipients the IPNS private key, which enables modification and re-sharing. Multi-writer IPNS is an unsolved problem (noted in research decisions). Future phase.
- **Display names for recipients** — Show human-readable names instead of truncated pubkeys. Depends on user discovery/profile phase.
- **Immediate key rotation on revoke** — Upgrade from lazy to immediate rotation if security review warrants it. Easy to change later.
- **Share notifications** — Notify recipients when new items are shared with them. Currently relies on polling discovery.

</deferred>

---

_Phase: 14-user-to-user-sharing_
_Context gathered: 2026-02-21_
