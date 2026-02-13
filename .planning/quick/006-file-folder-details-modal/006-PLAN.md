# Quick Task 006: File/Folder Details Modal

## Description

Implement a details modal accessible from the context menu that displays technical metadata about files and folders. For files: content CID, file metadata CID (parent folder's IPNS-resolved CID), encryption IV, encryption mode, file size, timestamps. For folders: IPNS name, folder metadata CID (resolved from IPNS), IPNS sequence number, folder encryption key (redacted), child count, timestamps.

## Tasks

### Task 1: Create DetailsDialog component + CSS

**Files:**
- CREATE `apps/web/src/components/file-browser/DetailsDialog.tsx`
- CREATE `apps/web/src/styles/details-dialog.css`

**Implementation:**
- New `DetailsDialog` component using existing `Modal` base
- Props: `open`, `onClose`, `item: FolderChild | null`, `parentFolderId: string`
- Reads from `useFolderStore` to get parent folder's IPNS name and resolve metadata CID
- Resolves IPNS record on open to get live metadata CID
- Displays fields in labeled rows with monospace CID values
- File fields: Name, Type, Content CID, Metadata CID, Encryption Mode, File IV, Size, Created, Modified
- Folder fields: Name, Type, IPNS Name, Metadata CID, Sequence Number, Encryption Key (redacted), Child Count, Created, Modified
- CID values are truncatable with copy-to-clipboard button
- Terminal aesthetic: green-on-black, uppercase labels, monospace values

### Task 2: Add "Details" to ContextMenu + integrate into FileBrowser

**Files:**
- EDIT `apps/web/src/components/file-browser/ContextMenu.tsx`
- EDIT `apps/web/src/components/file-browser/FileBrowser.tsx`

**Implementation:**
- Add `onDetails` prop to ContextMenu
- Add "Details" button between "Move to..." and the divider (before delete)
- Add `detailsDialog` state to FileBrowser (same DialogState pattern)
- Add `handleDetailsClick` callback
- Wire DetailsDialog into FileBrowser render

## Acceptance Criteria

- [ ] Details modal opens from context menu for both files and folders
- [ ] File details show: name, type, content CID, metadata CID, encryption mode, file IV, size, created/modified dates
- [ ] Folder details show: name, type, IPNS name, metadata CID, sequence number, encryption key (redacted), child count, created/modified dates
- [ ] CIDs can be copied to clipboard
- [ ] Terminal aesthetic matches existing UI
- [ ] Modal closes with X button, Escape key, or backdrop click
