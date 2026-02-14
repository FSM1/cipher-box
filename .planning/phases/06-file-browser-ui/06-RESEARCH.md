# Phase 6: File Browser UI - Research

**Researched:** 2026-01-21
**Domain:** React file browser interface with drag-drop, tree views, context menus
**Confidence:** HIGH

## Summary

Phase 6 implements the web interface for file management in CipherBox. The codebase already has substantial infrastructure: Zustand stores for folders/uploads/downloads, service layer for file operations, hooks for upload/download/delete/folder operations, and a basic dashboard layout. The task is to build UI components on top of this existing architecture.

The research identified that the project uses plain CSS (no UI library), React 18.3.1, and Zustand for state management. The CLIENT_SPECIFICATION.md defines the target UI mockups. Key decisions from CONTEXT.md include: list view only, single selection, drag-drop for move operations, no keyboard shortcuts, and mobile-responsive sidebar overlay.

**Primary recommendation:** Build custom components leveraging native HTML5 drag-drop API via react-dropzone for file uploads, a simple recursive tree component for the folder sidebar, and a custom context menu using React portals. Avoid introducing heavy UI libraries - the existing plain CSS approach is intentional and sufficient.

## Standard Stack

The established libraries/tools for this domain:

### Core (Already in Project)
| Library | Version | Purpose | Status |
|---------|---------|---------|--------|
| react | 18.3.1 | UI framework | Installed |
| zustand | 5.0.10 | State management | Installed, stores exist |
| react-router-dom | 7.12.0 | Routing | Installed, routes exist |
| @tanstack/react-query | 5.62.0 | Server state | Installed |

### New Dependencies Needed
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| react-dropzone | 14.x | File upload drag-drop zone | Most popular, headless, well-maintained |
| @floating-ui/react | 0.26.x | Context menu positioning | Replaces Popper.js, handles edge cases |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| react-dropzone | Native drag events | More boilerplate, need to handle edge cases |
| @floating-ui/react | CSS positioning | Edge detection, viewport clipping handled automatically |
| Custom tree | react-arborist | Overkill for simple folder tree, large bundle |
| Custom context menu | react-contexify | Adds styling opinions, less control |

**Installation:**
```bash
pnpm add react-dropzone @floating-ui/react
```

**Note on UI Libraries:** The project explicitly uses plain CSS without a component library. This is intentional - the CLIENT_SPECIFICATION shows specific UI mockups, and Tailwind CSS is listed as the tech stack but not yet installed. For Phase 6, continue with plain CSS to match existing patterns. Tailwind can be added in a future phase if desired.

## Architecture Patterns

### Recommended Project Structure
```
apps/web/src/
  components/
    file-browser/
      FileBrowser.tsx           # Main container component
      FileList.tsx              # File/folder list display
      FileListItem.tsx          # Individual file/folder row
      FolderTree.tsx            # Sidebar folder tree
      FolderTreeNode.tsx        # Recursive tree node
      Breadcrumbs.tsx           # Navigation breadcrumbs
      ContextMenu.tsx           # Right-click menu
      UploadZone.tsx            # Drag-drop upload area
      UploadModal.tsx           # Upload progress modal
      ConfirmDialog.tsx         # Delete confirmation modal
      RenameDialog.tsx          # Rename input dialog
      EmptyState.tsx            # Empty folder display
    ui/
      Modal.tsx                 # Generic modal component
      Portal.tsx                # React portal wrapper
  hooks/
    useFolderNavigation.ts      # Navigation state management
    useContextMenu.ts           # Context menu show/hide logic
  styles/
    file-browser.css            # File browser styles
```

### Pattern 1: Controlled Selection with Single Item
**What:** Single selection model per CONTEXT.md decisions.
**When to use:** All file/folder interactions.
**Example:**
```typescript
// In FileBrowser component
const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

// Clear selection on folder navigation
const handleNavigate = (folderId: string) => {
  setSelectedItemId(null);
  setCurrentFolder(folderId);
};

// Select on click
const handleItemClick = (itemId: string) => {
  setSelectedItemId(itemId);
};
```

### Pattern 2: Context Menu via Portal
**What:** Right-click menu rendered outside component tree for proper z-index.
**When to use:** File/folder context actions.
**Example:**
```typescript
// useContextMenu.ts
function useContextMenu() {
  const [state, setState] = useState<{
    visible: boolean;
    x: number;
    y: number;
    item: FolderChild | null;
  }>({ visible: false, x: 0, y: 0, item: null });

  const show = useCallback((e: React.MouseEvent, item: FolderChild) => {
    e.preventDefault();
    setState({ visible: true, x: e.clientX, y: e.clientY, item });
  }, []);

  const hide = useCallback(() => {
    setState(prev => ({ ...prev, visible: false, item: null }));
  }, []);

  return { ...state, show, hide };
}
```

### Pattern 3: Drag-Drop for Move Operations
**What:** Move files/folders by dragging to folder tree sidebar per CONTEXT.md.
**When to use:** Move operations only (no menu-based move).
**Example:**
```typescript
// FileListItem.tsx - draggable
const handleDragStart = (e: React.DragEvent) => {
  e.dataTransfer.setData('application/json', JSON.stringify({
    id: item.id,
    type: item.type,
    parentId: currentFolderId,
  }));
  e.dataTransfer.effectAllowed = 'move';
};

// FolderTreeNode.tsx - drop target
const handleDrop = (e: React.DragEvent) => {
  e.preventDefault();
  const data = JSON.parse(e.dataTransfer.getData('application/json'));
  if (data.parentId !== folderId) {
    onMove(data.id, data.type, data.parentId, folderId);
  }
};
```

### Pattern 4: Upload Queue Modal
**What:** Modal dialog showing all queued uploads with per-file progress.
**When to use:** During file uploads per CONTEXT.md decisions.
**Example:**
```typescript
// UploadModal shows when upload store has active uploads
const { status, totalFiles, completedFiles, currentFile, progress, error } = useUploadStore();

return (
  <Modal open={status !== 'idle' && status !== 'success'} onClose={canClose ? onClose : undefined}>
    <div className="upload-modal">
      <h3>Uploading Files</h3>
      <div className="upload-list">
        {files.map(file => (
          <UploadItem
            key={file.id}
            file={file}
            onCancel={() => cancel(file.id)}
            onRetry={() => retry(file.id)}
          />
        ))}
      </div>
    </div>
  </Modal>
);
```

### Anti-Patterns to Avoid
- **Global CSS without namespacing:** Use component-specific class prefixes (e.g., `.file-browser-*`)
- **Nested ternaries in JSX:** Extract to helper functions or separate components
- **Direct Zustand store calls in components:** Use existing hooks (useFolder, useFileUpload, etc.)
- **Inline event handlers for complex logic:** Extract to named functions or custom hooks
- **Storing selected file in URL:** Single selection is ephemeral, don't persist to URL

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| File drop zone | Native drag events | react-dropzone | Handles file selection dialog, multiple files, browser quirks |
| Menu positioning | CSS calc() | @floating-ui/react | Edge detection, flip behavior, scroll containers |
| Modal accessibility | Custom focus trap | Existing patterns or Headless UI | Focus management, escape key, aria attributes |
| File size formatting | Manual calculation | Existing formatBytes util | Consistent formatting |
| Date formatting | Manual string building | Intl.DateTimeFormat | Locale-aware, consistent |

**Key insight:** The codebase already has services and hooks for all business logic. Phase 6 is purely UI components that compose these existing pieces.

## Common Pitfalls

### Pitfall 1: Stale Closure in Event Handlers
**What goes wrong:** Drag handlers capture old state values.
**Why it happens:** Event handlers created during render close over current state.
**How to avoid:** Use refs for values needed in event handlers, or use useCallback with correct dependencies.
**Warning signs:** Dragging drops to wrong folder, incorrect parent ID.

### Pitfall 2: Context Menu Doesn't Close
**What goes wrong:** Menu stays open after action or clicking elsewhere.
**Why it happens:** Missing document click handler or not cleaning up listeners.
**How to avoid:** Add document click listener in useEffect, clean up on unmount.
**Warning signs:** Multiple context menus appearing, menu never closes.

```typescript
useEffect(() => {
  if (!contextMenu.visible) return;

  const handleClick = () => contextMenu.hide();
  document.addEventListener('click', handleClick);
  return () => document.removeEventListener('click', handleClick);
}, [contextMenu.visible]);
```

### Pitfall 3: Upload Progress Not Updating
**What goes wrong:** Progress bar shows 0% or jumps directly to 100%.
**Why it happens:** Upload store updates aren't triggering re-renders.
**How to avoid:** Ensure useUploadStore is subscribed correctly, check shallow comparison.
**Warning signs:** UI feels frozen during uploads.

### Pitfall 4: Mobile Sidebar Z-Index Issues
**What goes wrong:** Sidebar overlay appears behind file list or doesn't cover content.
**Why it happens:** Complex stacking contexts with multiple positioned elements.
**How to avoid:** Use fixed positioning with high z-index for mobile overlay, ensure backdrop covers entire viewport.
**Warning signs:** Content visible through overlay, clicks pass through to file list.

### Pitfall 5: Breadcrumb Navigation Loses Folder State
**What goes wrong:** Navigating via breadcrumbs loses loaded folder children.
**Why it happens:** Only loading folder on initial navigation, not on breadcrumb click.
**How to avoid:** Folder store already caches loaded folders; navigate function should use cached state.
**Warning signs:** Going "back" shows empty folder briefly.

## Code Examples

Verified patterns aligned with existing codebase:

### FileList Component
```typescript
// Source: CLIENT_SPECIFICATION.md + existing store patterns
import { useFolderStore } from '../../stores/folder.store';
import { formatBytes, formatDate } from '../../utils/format';
import type { FolderChild, FileEntry, FolderEntry } from '@cipherbox/crypto';

interface FileListProps {
  items: FolderChild[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onNavigate: (folderId: string) => void;
  onContextMenu: (e: React.MouseEvent, item: FolderChild) => void;
  onDragStart: (e: React.DragEvent, item: FolderChild) => void;
}

export function FileList({ items, selectedId, onSelect, onNavigate, onContextMenu, onDragStart }: FileListProps) {
  // Sort: folders first, then alphabetical by name
  const sorted = [...items].sort((a, b) => {
    if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return (
    <div className="file-list">
      <div className="file-list-header">
        <span className="file-list-col-name">Name</span>
        <span className="file-list-col-size">Size</span>
        <span className="file-list-col-date">Modified</span>
      </div>
      {sorted.map(item => (
        <FileListItem
          key={item.id}
          item={item}
          isSelected={item.id === selectedId}
          onSelect={onSelect}
          onNavigate={onNavigate}
          onContextMenu={onContextMenu}
          onDragStart={onDragStart}
        />
      ))}
    </div>
  );
}
```

### Upload Zone with react-dropzone
```typescript
// Source: react-dropzone documentation + existing upload hook
import { useDropzone } from 'react-dropzone';
import { useFileUpload } from '../../hooks/useFileUpload';
import { useFolderStore } from '../../stores/folder.store';

export function UploadZone({ folderId }: { folderId: string }) {
  const { upload, canUpload } = useFileUpload();
  const { folders, updateFolderChildren } = useFolderStore();

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const totalSize = acceptedFiles.reduce((sum, f) => sum + f.size, 0);

    if (!canUpload(totalSize)) {
      // Show quota error
      return;
    }

    try {
      const results = await upload(acceptedFiles);
      // Add uploaded files to folder metadata
      // (This would call folder service to update IPNS)
    } catch (error) {
      // Error handled by upload store
    }
  }, [upload, canUpload]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    noClick: false, // Allow click to open file dialog
  });

  return (
    <div
      {...getRootProps()}
      className={`upload-zone ${isDragActive ? 'upload-zone-active' : ''}`}
    >
      <input {...getInputProps()} />
      <div className="upload-zone-content">
        <span className="upload-zone-icon">+</span>
        <span className="upload-zone-text">
          Drag files here or click to upload
        </span>
      </div>
    </div>
  );
}
```

### FolderTree Component
```typescript
// Source: Recursive tree pattern + existing folder store
import { useFolderStore } from '../../stores/folder.store';
import type { FolderChild, FolderEntry } from '@cipherbox/crypto';

interface FolderTreeProps {
  onNavigate: (folderId: string) => void;
  onDrop: (itemId: string, itemType: 'file' | 'folder', sourceId: string, destId: string) => void;
  currentFolderId: string | null;
}

export function FolderTree({ onNavigate, onDrop, currentFolderId }: FolderTreeProps) {
  const { folders } = useFolderStore();
  const rootFolder = folders['root'];

  if (!rootFolder) return <div className="folder-tree-loading">Loading...</div>;

  return (
    <nav className="folder-tree" aria-label="Folder navigation">
      <FolderTreeNode
        folder={rootFolder}
        level={0}
        currentFolderId={currentFolderId}
        onNavigate={onNavigate}
        onDrop={onDrop}
      />
    </nav>
  );
}

function FolderTreeNode({ folder, level, currentFolderId, onNavigate, onDrop }) {
  const [expanded, setExpanded] = useState(level === 0); // Root expanded by default
  const { folders } = useFolderStore();

  const subfolders = folder.children.filter(c => c.type === 'folder') as FolderEntry[];
  const isActive = folder.id === currentFolderId;

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    try {
      const data = JSON.parse(e.dataTransfer.getData('application/json'));
      if (data.parentId !== folder.id) {
        onDrop(data.id, data.type, data.parentId, folder.id);
      }
    } catch {}
  };

  return (
    <div className="folder-tree-node" style={{ paddingLeft: level * 16 }}>
      <div
        className={`folder-tree-item ${isActive ? 'folder-tree-item-active' : ''}`}
        onClick={() => onNavigate(folder.id)}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
      >
        {subfolders.length > 0 && (
          <button
            className="folder-tree-toggle"
            onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}
          >
            {expanded ? '-' : '+'}
          </button>
        )}
        <span className="folder-tree-icon">folder</span>
        <span className="folder-tree-name">{folder.name}</span>
      </div>
      {expanded && subfolders.map(sub => {
        const subNode = folders[sub.id];
        if (!subNode) return null;
        return (
          <FolderTreeNode
            key={sub.id}
            folder={subNode}
            level={level + 1}
            currentFolderId={currentFolderId}
            onNavigate={onNavigate}
            onDrop={onDrop}
          />
        );
      })}
    </div>
  );
}
```

### Context Menu Component
```typescript
// Source: Custom implementation with @floating-ui/react
import { useFloating, offset, flip, shift } from '@floating-ui/react';
import { createPortal } from 'react-dom';
import type { FolderChild } from '@cipherbox/crypto';

interface ContextMenuProps {
  x: number;
  y: number;
  item: FolderChild;
  onClose: () => void;
  onDownload?: () => void;  // Only for files
  onRename: () => void;
  onDelete: () => void;
}

export function ContextMenu({ x, y, item, onClose, onDownload, onRename, onDelete }: ContextMenuProps) {
  const { refs, floatingStyles } = useFloating({
    placement: 'bottom-start',
    middleware: [offset(4), flip(), shift({ padding: 8 })],
  });

  // Position reference at click location
  useEffect(() => {
    refs.setReference({
      getBoundingClientRect: () => ({
        x, y, top: y, left: x, bottom: y, right: x, width: 0, height: 0,
      }),
    });
  }, [x, y, refs]);

  const actions = [
    ...(item.type === 'file' ? [{ label: 'Download', onClick: onDownload }] : []),
    { label: 'Rename', onClick: () => { onClose(); onRename(); } },
    { label: 'Delete', onClick: () => { onClose(); onDelete(); } },
  ];

  return createPortal(
    <div className="context-menu-backdrop" onClick={onClose}>
      <div
        ref={refs.setFloating}
        style={floatingStyles}
        className="context-menu"
        onClick={e => e.stopPropagation()}
      >
        {actions.map(action => (
          <button
            key={action.label}
            className="context-menu-item"
            onClick={action.onClick}
          >
            {action.label}
          </button>
        ))}
      </div>
    </div>,
    document.body
  );
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Heavy UI libraries (Bootstrap, Ant Design) | Headless components + custom CSS | 2024+ | Better bundle size, more control |
| jQuery file upload plugins | react-dropzone + native APIs | Long ago | React ecosystem standard |
| Popper.js for positioning | @floating-ui/react | 2022+ | Smaller, more features |
| Complex DnD libraries for simple cases | Native HTML5 drag-drop | Always | Native API sufficient for move operations |

**Deprecated/outdated:**
- `react-dnd`: Overkill for simple file browser, introduces provider complexity
- `@popperjs/core`: Replaced by @floating-ui ecosystem
- `react-modal`: Consider Headless UI Dialog for better accessibility
- Heavy file manager libraries: Custom components give better integration with CipherBox architecture

## Open Questions

Things that couldn't be fully resolved:

1. **Folder Loading Strategy**
   - What we know: Folders have isLoaded flag, children need to be fetched on expand
   - What's unclear: Should folder contents be lazy-loaded on tree expand or pre-fetched?
   - Recommendation: Lazy-load on expand, show loading indicator in tree node

2. **Mobile Touch Gestures**
   - What we know: CONTEXT.md leaves mobile gesture handling to Claude's discretion
   - What's unclear: Long-press for context menu, swipe actions?
   - Recommendation: Start with long-press for context menu only, no swipe actions for v1

3. **Error Boundaries**
   - What we know: Need to handle rendering errors gracefully
   - What's unclear: Error boundary placement, fallback UI design
   - Recommendation: Wrap FileBrowser component in error boundary with "Something went wrong" fallback

## Integration with Existing Services

### Existing Hooks to Use
| Hook | Purpose | Used For |
|------|---------|----------|
| `useFileUpload` | Upload files with progress | UploadZone, UploadModal |
| `useFileDownload` | Download with progress | Context menu download action |
| `useFileDelete` | Delete files | Context menu delete action |
| `useFolder` | Create, rename, move, delete folders | All folder operations |
| `useAuth` | Authentication state | Protected routes |

### Existing Stores to Subscribe
| Store | State Used | Components |
|-------|------------|------------|
| `useFolderStore` | folders, currentFolderId, breadcrumbs | FolderTree, Breadcrumbs, FileList |
| `useUploadStore` | status, progress, currentFile | UploadModal, UploadZone |
| `useDownloadStore` | status, progress | Download indicator |
| `useVaultStore` | isInitialized | Root folder access |
| `useAuthStore` | isAuthenticated | Route protection |

### API Integration
All API calls are already abstracted through services and hooks. UI components should NOT import API functions directly - use the hooks layer.

## Sources

### Primary (HIGH confidence)
- Existing codebase files: stores, services, hooks
- CLIENT_SPECIFICATION.md - UI mockups and requirements
- 06-CONTEXT.md - User decisions for this phase
- [react-dropzone documentation](https://react-dropzone.js.org/) - File drop zone API
- [Floating UI documentation](https://floating-ui.com/docs/react) - Positioning library

### Secondary (MEDIUM confidence)
- [React Complex Tree](https://github.com/lukasbach/react-complex-tree) - Tree view patterns (not using library, but patterns useful)
- [Base UI Context Menu](https://base-ui.com/react/components/context-menu) - Accessibility patterns
- [MDN Drag and Drop API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Drag_and_Drop_API) - Native API reference

### Tertiary (LOW confidence)
- WebSearch results for React file browser patterns - General patterns, verify against codebase

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Based on existing project dependencies
- Architecture: HIGH - Aligns with existing codebase patterns
- Integration: HIGH - Direct analysis of existing services/stores/hooks
- UI patterns: MEDIUM - Standard React patterns, verify during implementation

**Research date:** 2026-01-21
**Valid until:** 2026-02-21 (30 days - UI patterns are stable)
