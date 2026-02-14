# Session Context

**Session ID:** 24c1ea04-c260-46f6-bc55-26dd7ed202af

**Commit Message:** <objective>
Capture an idea, task, or issue that surfaces during a GSD s

## Prompt



---

<objective>
Capture an idea, task, or issue that surfaces during a GSD session as a structured todo for later work.

Enables "thought → capture → continue" flow without losing context or derailing current work.
</objective>

<context>
@.planning/STATE.md
</context>

<process>

<step name="ensure_directory">
```bash
mkdir -p .planning/todos/pending .planning/todos/done
```
</step>

<step name="check_existing_areas">
```bash
ls .planning/todos/pending/*.md 2>/dev/null | xargs -I {} grep "^area:" {} 2>/dev/null | cut -d' ' -f2 | sort -u
```

Note existing areas for consistency in infer_area step.
</step>

<step name="extract_content">
**With arguments:** Use as the title/focus.
- `/gsd:add-todo Add auth token refresh` → title = "Add auth token refresh"

**Without arguments:** Analyze recent conversation to extract:
- The specific problem, idea, or task discussed
- Relevant file paths mentioned
- Technical details (error messages, line numbers, constraints)

Formulate:
- `title`: 3-10 word descriptive title (action verb preferred)
- `problem`: What's wrong or why this is needed
- `solution`: Approach hints or "TBD" if just an idea
- `files`: Relevant paths with line numbers from conversation
</step>

<step name="infer_area">
Infer area from file paths:

| Path pattern | Area |
|--------------|------|
| `src/api/*`, `api/*` | `api` |
| `src/components/*`, `src/ui/*` | `ui` |
| `src/auth/*`, `auth/*` | `auth` |
| `src/db/*`, `database/*` | `database` |
| `tests/*`, `__tests__/*` | `testing` |
| `docs/*` | `docs` |
| `.planning/*` | `planning` |
| `scripts/*`, `bin/*` | `tooling` |
| No files or unclear | `general` |

Use existing area from step 2 if similar match exists.
</step>

<step name="check_duplicates">
```bash
grep -l -i "[key words from title]" .planning/todos/pending/*.md 2>/dev/null
```

If potential duplicate found:
1. Read the existing todo
2. Compare scope

If overlapping, use AskUserQuestion:
- header: "Duplicate?"
- question: "Similar todo exists: [title]. What would you like to do?"
- options:
  - "Skip" — keep existing todo
  - "Replace" — update existing with new context
  - "Add anyway" — create as separate todo
</step>

<step name="create_file">
```bash
timestamp=$(date "+%Y-%m-%dT%H:%M")
date_prefix=$(date "+%Y-%m-%d")
```

Generate slug from title (lowercase, hyphens, no special chars).

Write to `.planning/todos/pending/${date_prefix}-${slug}.md`:

```markdown
---
created: [timestamp]
title: [title]
area: [area]
files:
  - [file:lines]
---

## Problem

[problem description - enough context for future Claude to understand weeks later]

## Solution

[approach hints or "TBD"]
```
</step>

<step name="update_state">
If `.planning/STATE.md` exists:

1. Count todos: `ls .planning/todos/pending/*.md 2>/dev/null | wc -l`
2. Update "### Pending Todos" under "## Accumulated Context"
</step>

<step name="git_commit">
Commit the todo and any updated state:

```bash
git add .planning/todos/pending/[filename]
[ -f .planning/STATE.md ] && git add .planning/STATE.md
git commit -m "$(cat <<'EOF'
docs: capture todo - [title]

Area: [area]
EOF
)"
```

Confirm: "Committed: docs: capture todo - [title]"
</step>

<step name="confirm">
```
Todo saved: .planning/todos/pending/[filename]

  [title]
  Area: [area]
  Files: [count] referenced

---

Would you like to:

1. Continue with current work
2. Add another todo
3. View all todos (/gsd:check-todos)
```
</step>

</process>

<output>
- `.planning/todos/pending/[date]-[slug].md`
- Updated `.planning/STATE.md` (if exists)
</output>

<anti_patterns>
- Don't create todos for work in current plan (that's deviation rule territory)
- Don't create elaborate solution sections — captures ideas, not plans
- Don't block on missing information — "TBD" is fine
</anti_patterns>

<success_criteria>
- [ ] Directory structure exists
- [ ] Todo file created with valid frontmatter
- [ ] Problem section has enough context for future Claude
- [ ] No duplicates (checked and resolved)
- [ ] Area consistent with existing todos
- [ ] STATE.md updated if exists
- [ ] Todo and state committed to git
</success_criteria>


ARGUMENTS: <img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# CipherBox File Metadata Evolution v2

**Status:** Specification for implementation
**Version:** 1.0
**Date:** February 14, 2026
**Applies to:** Core CipherBox IPFS/IPNS architecture (DATA_FLOWS.md, TECHNICAL_ARCHITECTURE.md)

## Goal

Split heavy file metadata (`cid`, `fileKeyEncrypted`, size, timestamps) into separate per-file metadata objects while preserving:

- Instant folder listing (UnixFS-style).
- Per-file sharing.
- Minimal folder metadata churn.
- Backward compatibility with v1 vault exports.[^1][^2]


## Data Model

### Folder Metadata (unchanged size, lighter content)

**Decrypted JSON structure:**

```json
{
  "children": [
    {
      "type": "folder",
      "nameEncrypted": "0x...",
      "nameIv": "0x...",
      "ipnsName": "k51qzi5uqu5dlvj55...",
      "folderKeyEncrypted": "0x...",  // ECIES(folderKey, publicKey)
      "ipnsPrivateKeyEncrypted": "0x...",  // ECIES(ipnsPrivateKey, publicKey)
      "created": 1705268100,
      "modified": 1705268100
    },
    {
      "type": "file", 
      "nameEncrypted": "0x...",     // ← Essential for listing
      "nameIv": "0x...",
      "fileMetaIpnsName": "k51qzy5uqu5dlvj66...",  // ← New: points to file metadata
      "created": 1705268100,
      "modified": 1705268100
    }
  ],
  "metadata": {
    "created": 1705268100,
    "modified": 1705268100
  }
}
```


### New: File Metadata Object

**IPNS record → CID → decrypted JSON:**

```json
{
  "cid": "QmXxxx...",                    // Encrypted file content
  "fileKeyEncrypted": "0x...",           // ECIES(fileKey, publicKey)
  "fileIv": "0x...",                     // AES-GCM IV
  "size": 2048576,
  "mimeType": "application/pdf",         // Optional
  "created": 1705268100,
  "modified": 1705268100,
  "versionHistory": [                    // Optional: for future
    "QmOldCID...", "QmNewerCID..."
  ]
}
```

**Key invariants:**

- Folder holds: `nameEncrypted` (listing) + `fileMetaIpnsName` (pointer).
- File-meta holds: access details (`cid`, `fileKeyEncrypted`, etc.).
- Rename = folder update only.
- Content update = file-meta IPNS update only.[^3]


## Operations

### 1. File Upload (v1 → v2)

**Current v1:**

```
1. Encrypt content → cid
2. Update folder.children[type=file entry] → re-encrypt folder → ipns publish
```

**v2 Flow:**

```
1. Encrypt content → fileContentCid
2. Generate fileKey, iv → encryptFileKey = ECIES(fileKey, publicKey)
3. Create file metadata JSON → encrypt with fileKey → ipfs add → fileMetaCid  
4. Generate file IPNS keypair → publish fileMetaCid → get fileMetaIpnsName
5. Add to folder.children: {type: "file", nameEncrypted, fileMetaIpnsName}
6. Re-encrypt folder → ipns publish folder
```

**Result:** Two IPNS publishes (folder + new file).

### 2. File Rename

```
1. Decrypt folder metadata
2. Update target entry.nameEncrypted + nameIv  
3. Re-encrypt folder → ipfs add → ipns publish folder
```

**Result:** Folder IPNS only (file-meta untouched).

### 3. File Content Update

```
1. New content → encrypt → newFileContentCid  
2. Update file metadata: new cid, new fileKeyEncrypted, fileIv, modified
3. Re-encrypt file metadata → ipfs add → ipns publish fileMetaIpnsName
4. vaultunpin oldFileContentCid (quota)
```

**Result:** File IPNS only (folder untouched!).

### 4. Folder Listing

```
1. Resolve folder IPNS → folderMetaCid
2. ipfs cat folderMetaCid → decrypt with folderKey
3. Decrypt each child.nameEncrypted → instant list
```

**Unchanged UX:** Names appear without resolving children.

### 5. File Download

```
1. From folder listing → get fileMetaIpnsName
2. Resolve fileMetaIpns → fileMetaCid  
3. ipfs cat fileMetaCid → decrypt with folderKey? No:
   - Decrypt fileKeyEncrypted with privateKey
   - ipfs cat fileContentCid → AES-GCM decrypt with fileKey
```


### 6. Per-File Sharing (New!)

```
Share bundle:
{
  "fileMetaIpnsName": "k51qzy...",
  "recipientFileKeyEncrypted": "0x..."  // ECIES(fileKey, recipientPublicKey)
}

Recipient:
1. Resolve fileMetaIpns → get cid
2. Decrypt recipientFileKeyEncrypted → get fileKey  
3. Download + AES-GCM decrypt
```

No folder access needed.

## Backward Compatibility

### Vault Export

**v1 vaults:** Walk existing folder tree → for each file entry:

```
- Extract cid, fileKeyEncrypted, fileIv → create synthetic file-meta
- Generate temp fileMetaIpnsName (or use CID directly for recovery)
```

**Export format extension:**

```json
{
  "v1Migration": {
    "legacyFileEntries": [...]  // Original embedded entries
  }
}
```


### Recovery Tool

```
if legacyFileEntries:
  Use v1 entry directly (cid + fileKeyEncrypted)
else:
  Resolve fileMetaIpnsName → normal v2 flow
```


## Key Derivation \& Storage

### File IPNS Keys

**Derive per-file IPNS keypair:**

```typescript
// packages/crypto/src/ipns.ts (extend existing)
export function deriveFileIpnsKeypair(
  userSecp256k1PrivateKey: Uint8Array,
  fileId: string,  // random 128-bit UUID
  environment: Environment
): { publicKey: Uint8Array, privateKey: Uint8Array } {
  // HKDF with fileId context (like folder derivation)
  const info = `${ENVIRONMENTCONTEXT[environment]}file${fileId}`;
  // ... existing HKDF logic
}
```

**Storage:** `ipnsPrivateKeyEncrypted` *not* needed in file-meta (vault-held keys only).

### Vault Storage Changes

**DB Schema:**

```
folder_ipns table unchanged

New: file_metadata_pins? (optional, for quota tracking)
- fileMetaIpnsName
- ownerUserId  
- latestContentCid
- size
```


## Implementation Checklist

### Phase 1: Data Structures (1 week)

- [ ] Extend folder.children with `fileMetaIpnsName?: string`
- [ ] Create FileMetadata type + serialization
- [ ] Unit tests: encrypt/decrypt roundtrip


### Phase 2: Upload Flow (1 week)

- [ ] Generate file IPNS keypair from fileId
- [ ] File upload → create file-meta → publish file IPNS → add pointer to folder
- [ ] Integration test: upload → list → download


### Phase 3: Update Operations (1 week)

- [ ] Rename: folder-only
- [ ] Content replace: file-meta-only + unpin old
- [ ] E2E: multi-device sync detects both


### Phase 4: Sharing \& Migration (1 week)

- [ ] Export v1 → synthetic file-meta
- [ ] Recovery handles both formats
- [ ] Share endpoint: generate recipientFileKeyEncrypted


### Phase 5: Polish (2 days)

- [ ] UI: file listing unchanged
- [ ] Metrics: folder publish frequency drop
- [ ] Docs: update DATA_FLOWS.md sequences


## Success Criteria

| Metric | v1 Baseline | v2 Target |
| :-- | :-- | :-- |
| Folder publishes per content update | 1 | 0 |
| List 100-file folder latency | 200ms | 200ms |
| File rename publishes | 1 folder | 1 folder |
| Share single file (no folder leak) | ❌ | ✅ |
| Vault export compatibility | ✅ | ✅ |

## Rollout Plan

1. **Feature flag:** `USE_FILE_METADATA_V2=false` (default)
2. **New vaults:** Opt-in via client setting
3. **Existing vaults:** Manual migration (re-upload files → new structure)
4. **Flag flip:** After 90 days, default=true

***

This spec preserves your v1 UX/performance while unlocking per-file isolation. Ready for implementation—ping for code snippets or flow diagrams.[^2][^1][^3]

<div align="center">⁂</div>

[^1]: DATA_FLOWS.md

[^2]: TECHNICAL_ARCHITECTURE.md

[^3]: https://specs.ipfs.tech/unixfs/

## Summary

Todo saved: `.planning/todos/pending/2026-02-14-file-metadata-evolution-v2.md`

```
  Split file metadata into per-file IPNS objects (v2)
  Area: crypto
  Files: 5 referenced
```

---

Would you like to:

1. Continue with current work (switch back to main)
2. Add another todo
3. View all todos (`/gsd:check-todos`)

## Key Actions

- - **Bash**: Ensure todo directories exist
- - **Bash**: Check existing todo areas
- - **Grep**: file.?meta|per.?file|metadata.?evolution
- - **Bash**: Create feature branch for todo commit
- - **Write**: /Users/michael/Code/cipher-box/.planning/todos/pending/2026-02-14-file-metadata-evolution-v2.md
- - **Bash**: Count pending todos
- - **Read**: /Users/michael/Code/cipher-box/.planning/STATE.md
- - **Bash**: List all pending todos
- - **Grep**: ^title:
- - **Edit**: /Users/michael/Code/cipher-box/.planning/STATE.md
