# CipherBox Filesystem Specification

This document defines the rules, constraints, and rationale governing the CipherBox virtual filesystem. These rules apply across all platforms (web, desktop macOS, desktop Linux, desktop Windows) and are enforced at different layers depending on the operation.

## Design Principles

CipherBox must present a consistent filesystem experience across three very different access surfaces:

1. **Web browser** — drag-and-drop uploads, folder tree UI
2. **macOS desktop** — FUSE-T virtual mount via SMB backend, accessed through Finder and Terminal
3. **Linux desktop** — kernel FUSE (libfuse3) virtual mount, accessed through file manager and terminal
4. **Windows desktop** — WinFsp virtual mount, accessed through Explorer, PowerShell, and Git Bash

The strictest platform constraint wins. Windows is case-insensitive and has the most restricted filename rules, so CipherBox defaults to rules compatible with Windows even when accessed from other platforms. This ensures files created on any platform are accessible on every other platform.

## Naming Rules

### Case Handling

| Platform | Storage    | Lookup                           | Implementation                                                |
| -------- | ---------- | -------------------------------- | ------------------------------------------------------------- |
| Web      | As-entered | Case-sensitive (`===`)           | `folder.service.ts`, `sdk-core/folder`                        |
| macOS    | As-entered | NFC-normalized                   | `inode.rs:normalize_name()` via `unicode-normalization` crate |
| Linux    | As-entered | NFC-normalized                   | Same `fuse` feature as macOS; case-sensitive                  |
| Windows  | As-entered | Case-insensitive (lowercase key) | `inode.rs:normalize_name()` via `.to_lowercase()`             |

**Rationale:** Original casing is always preserved in the encrypted metadata (`InodeData.name` / `FolderChild.name`). The normalization only affects HashMap key lookups in the FUSE layer. On macOS, NFC normalization prevents mismatches between composed and decomposed Unicode forms (e.g., `e` + combining acute vs. precomposed `e`). On Windows, lowercase folding implements the case-insensitive semantics that Explorer and all Windows applications expect.

**Current gap:** The web UI uses strict case-sensitive matching for duplicate detection. A user could create `Report.pdf` and `report.pdf` in the same folder on the web, but these would collide when the vault is mounted on Windows. This is a known limitation — the web layer does not currently enforce Windows-compatible case-insensitive uniqueness.

### Character Restrictions

| Character                  | Status        | Rationale                                                                      |
| -------------------------- | ------------- | ------------------------------------------------------------------------------ |
| Null byte (`\0`)           | Forbidden     | Invalid in all filesystem APIs; rejected by UTF-8 validation in FUSE callbacks |
| Full UTF-8 range           | Allowed       | Stored encrypted in metadata; no server-side interpretation                    |
| Emoji and CJK              | Allowed       | Full Unicode support across all platforms                                      |
| Path separators (`/`, `\`) | Not validated | Names are stored in flat per-folder child arrays, not as paths                 |

**Note:** Windows reserves additional characters (`<`, `>`, `:`, `"`, `|`, `?`, `*`) in filenames. CipherBox does not currently validate against these at the web or SDK layer. Files created with these characters on the web would fail to materialize on a Windows FUSE mount. This is a known gap.

### Reserved Names

CipherBox filters platform-specific system files that should never be created, synced, or displayed. These are silently rejected during file creation (EACCES) and hidden from directory listings in the FUSE layer.

**Cross-platform filter** (`helpers.rs:is_platform_special()`):

| Pattern                  | Platform | Purpose                       |
| ------------------------ | -------- | ----------------------------- |
| `._*` (prefix)           | macOS    | Resource fork files           |
| `.DS_Store`              | macOS    | Finder metadata               |
| `.Trashes`               | macOS    | Trash directory               |
| `.fseventsd`             | macOS    | File system events            |
| `.Spotlight-V100`        | macOS    | Spotlight index               |
| `.hidden`, `.localized`  | macOS    | Finder display hints          |
| `.metadata_never_index*` | macOS    | Spotlight indexing hints      |
| `.ql_disablecache`       | macOS    | Quick Look cache control      |
| `.ql_disablethumbnails`  | macOS    | Quick Look thumbnail control  |
| `DCIM`                   | macOS    | Digital camera images dir     |
| `Thumbs.db`              | Windows  | Explorer thumbnail cache      |
| `desktop.ini`            | Windows  | Explorer folder customization |
| `.directory`             | Linux    | KDE directory metadata        |
| `.Trash-*` (prefix)      | Linux    | Per-user trash directories    |
| `.gvfs`                  | Linux    | GNOME virtual filesystem      |
| `.xdg-volume-info`       | Linux    | XDG volume information        |

**Windows-specific filter** (`helpers.rs:is_windows_special()`):

| Pattern                        | Purpose                              |
| ------------------------------ | ------------------------------------ |
| `$recycle.bin`                 | Recycle bin directory                |
| `System Volume Information`    | NTFS system metadata                 |
| `Recycler`                     | Legacy recycle bin                   |
| `pagefile.sys`, `swapfile.sys` | Virtual memory files                 |
| `hiberfil.sys`                 | Hibernation file                     |
| `$*` (prefix)                  | NTFS alternate data streams          |
| `*:Zone.Identifier*`           | Downloaded file security zone marker |

**Rationale:** These files are created automatically by operating systems and file managers. Syncing them wastes storage quota, creates noise in the file browser, and can cause errors when the vault is accessed from a different platform. Filtering at the FUSE layer (not the web layer) means the web UI has no awareness of these restrictions — files with these names can be uploaded via the web. They simply won't appear when the vault is mounted on desktop.

**Not currently filtered:** Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`). These would cause issues on Windows FUSE mounts but are unlikely to be created intentionally.

## Size Limits

### File Size

| Limit         | Value  | Enforcement                                 | Constant                                                                              |
| ------------- | ------ | ------------------------------------------- | ------------------------------------------------------------------------------------- |
| Max file size | 100 MB | Client-side (web upload), server-side (API) | `MAX_FILE_SIZE` in `useDropUpload.ts`, `MaxFileSizeValidator` in `ipfs.controller.ts` |

**Rationale:** 100 MB balances usability with memory constraints. The entire file must fit in memory for AES-256-GCM encryption (authenticated encryption requires the full plaintext). AES-256-CTR streaming mode could support larger files but is currently only used for decryption/playback, not upload. The Web Worker encryption offload helps with CPU blocking but does not change the memory requirement.

### Storage Quota

| Limit       | Value   | Enforcement                                        | Constant                            |
| ----------- | ------- | -------------------------------------------------- | ----------------------------------- |
| Total quota | 500 MiB | Server-side (`vault.service.ts`), client pre-check | `QUOTA_LIMIT_BYTES` / `QUOTA_BYTES` |

**Rationale:** Technology demonstrator limit. Quota tracks encrypted blob sizes (not plaintext sizes). BYO-IPFS users bypass this limit (advisory only) since they manage their own storage.

## Folder Structure

### Depth Limit

| Limit            | Value     | Enforcement                              | Constant           |
| ---------------- | --------- | ---------------------------------------- | ------------------ |
| Max folder depth | 20 levels | Client-side (create folder, move folder) | `MAX_FOLDER_DEPTH` |

**Rationale:** Each folder level requires a separate IPNS resolve + AES-256-GCM decrypt to traverse. Deep nesting creates latency during navigation and increases the number of IPNS records the TEE must republish. 20 levels is generous for practical use while bounding operational costs.

**Enforcement points:**

- `folder.service.ts:170` — `createFolder` checks `parentDepth >= MAX_FOLDER_DEPTH`
- `folder.service.ts:759` — `moveFolder` checks `destDepth + 1 + subtreeDepth > MAX_FOLDER_DEPTH`
- `useFolderMutations.ts:73` — duplicate check in React hooks layer

### Duplicate Names

Files and folders within the same parent must have unique names. Duplicate detection is case-sensitive at the web/SDK layer.

**Enforcement:** Before any create, rename, or move operation, the target folder's children are scanned:

```typescript
const nameExists = children.some((c) => c.name === newName && c.id !== childId);
if (nameExists) throw new Error('An item with this name already exists');
```

**Cross-type collision:** A file cannot have the same name as a folder in the same parent. The web upload layer explicitly checks for file-to-folder name collisions before starting uploads.

**Batch upload deduplication:** Within a single batch upload, duplicate filenames are rejected before any files are read into memory.

## File Versioning

| Limit             | Value      | Enforcement        | Constant                |
| ----------------- | ---------- | ------------------ | ----------------------- |
| Max versions/file | 10         | SDK and FUSE layer | `MAX_VERSIONS_PER_FILE` |
| Version cooldown  | 15 minutes | Desktop FUSE only  | `VERSION_COOLDOWN_MS`   |

**Rationale:** Version history is stored inside the file's IPNS metadata. Each version entry contains a CID, key, IV, and timestamp. Capping at 10 prevents metadata bloat. The 15-minute cooldown on desktop prevents rapid saves (e.g., auto-save in text editors) from consuming all version slots.

**Web behavior:** The web UI creates a new version on every file replace operation. There is no cooldown — the user explicitly triggers each replace via the upload dialog.

## FUSE Mount Specifics

### Content Download

| Parameter        | Value  | Constant                   |
| ---------------- | ------ | -------------------------- |
| Download timeout | 120s   | `CONTENT_DOWNLOAD_TIMEOUT` |
| Block size       | 4096 B | `BLOCK_SIZE`               |

**Rationale:** File content is fetched from IPFS on `open()` and cached in memory. Large files (up to 100 MB) can take 30-60 seconds from the staging IPFS gateway. The 120-second timeout accommodates slow networks while preventing indefinite hangs. After the initial fetch, all `read()` calls are served from cache.

### Mount Backend

| Platform | Backend | Notes                                                                                                     |
| -------- | ------- | --------------------------------------------------------------------------------------------------------- |
| macOS    | SMB     | FUSE-T's SMB backend. NFS backend has unfixable kernel bug (WRITE RPCs never reach FUSE-T for new files). |
| Linux    | libfuse | Kernel FUSE via libfuse3. Standard FUSE semantics, no translation layer.                                  |
| Windows  | WinFsp  | Native user-mode filesystem driver.                                                                       |

### Inode Management

- **Root inode:** Always `1` (standard FUSE convention)
- **Inode stability:** `populate_folder` reuses existing inode numbers for same-name children. Allocating new inodes for unchanged files causes NFS "stale file handle" disconnects on macOS.
- **Lazy loading:** Folder children are populated on first `readdir`/`lookup`, not on mount. This avoids loading the entire vault tree upfront.

## Encryption Modes

| Mode        | Usage                              | File size threshold    | Notes                                           |
| ----------- | ---------------------------------- | ---------------------- | ----------------------------------------------- |
| AES-256-GCM | Default for all files              | Any                    | Authenticated encryption; full file in memory   |
| AES-256-CTR | Large media streaming (decryption) | > 256 KB (video/audio) | Enables streaming playback without full decrypt |

**Rationale:** GCM provides authentication (tamper detection) but requires the entire plaintext in memory. CTR mode is used only for decryption/playback of large media files where streaming is essential for UX. Uploads always use GCM. The mode is recorded in file metadata so the correct decryption path is selected on download.

## Metadata Storage

File and folder names, timestamps, and structural information are stored as encrypted JSON in IPNS records. The server never sees plaintext names or folder structure. See [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md) for the full schema reference and [METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md) for change management rules.

## Known Gaps

These are documented limitations where cross-platform consistency is not yet enforced:

1. **Web case-sensitivity vs. Windows case-insensitivity** — Files created via the web with names differing only by case will collide on Windows desktop mount.
2. **Windows reserved characters** — Characters like `<`, `>`, `:`, `"`, `|`, `?`, `*` are not validated at the web/SDK layer. Files with these characters will fail on Windows FUSE mounts.
3. **Windows reserved device names** — `CON`, `PRN`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` are not validated.
4. **Path length** — No total path length validation. Windows has a 260-character path limit (unless long path support is enabled). Deep nesting + long names could exceed this on Windows.
5. **Leading/trailing spaces and dots** — Windows silently strips these from filenames. Files with trailing dots/spaces created on the web would appear with different names on Windows.

<!-- Filesystem specification: 2026-03-30 -->
