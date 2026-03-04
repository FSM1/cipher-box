import { useCallback, type MouseEvent } from 'react';
import type { BinEntry } from '@cipherbox/crypto';
import { formatBytes } from '../../utils/format';

type BinListItemProps = {
  /** The bin entry to display */
  entry: BinEntry;
  /** Whether this item is currently selected */
  isSelected: boolean;
  /** Days remaining before auto-purge */
  daysLeft: number;
  /** Callback when item is clicked (with modifier key info) */
  onSelect: (
    entryId: string,
    event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }
  ) => void;
  /** Callback when right-click context menu is requested */
  onContextMenu: (event: MouseEvent, entry: BinEntry) => void;
};

/**
 * Format a deletion timestamp as a relative time string.
 */
function formatRelativeTime(timestamp: number): string {
  const diff = Date.now() - timestamp;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days === 1) return '1 day ago';
  return `${days} days ago`;
}

/**
 * Get a terminal-style type indicator based on item type and MIME.
 */
function getItemIcon(entry: BinEntry): string {
  if (entry.itemType === 'folder') return '[DIR]';
  if (!entry.mimeType) return '[FILE]';
  if (entry.mimeType.startsWith('image/')) return '[IMG]';
  if (entry.mimeType.startsWith('video/')) return '[VID]';
  if (entry.mimeType.startsWith('audio/')) return '[AUD]';
  if (entry.mimeType.startsWith('text/')) return '[TXT]';
  if (entry.mimeType === 'application/pdf') return '[PDF]';
  return '[FILE]';
}

/**
 * Single row in the bin list.
 *
 * Displays deleted item with name, original location, deletion date,
 * file size, and days remaining before auto-purge.
 */
export function BinListItem({
  entry,
  isSelected,
  daysLeft,
  onSelect,
  onContextMenu,
}: BinListItemProps) {
  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      onSelect(entry.id, { ctrlKey: e.ctrlKey, shiftKey: e.shiftKey, metaKey: e.metaKey });
    },
    [entry.id, onSelect]
  );

  const handleCheckboxClick = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      onSelect(entry.id, { ctrlKey: true, shiftKey: false, metaKey: false });
    },
    [entry.id, onSelect]
  );

  const handleContextMenu = useCallback(
    (e: MouseEvent) => {
      e.preventDefault();
      onContextMenu(e, entry);
    },
    [entry, onContextMenu]
  );

  const sizeDisplay =
    entry.itemType === 'folder' && entry.size === 0 ? 'Folder' : formatBytes(entry.size);

  const remainingText = daysLeft <= 0 ? 'expired' : daysLeft === 1 ? '< 1 day' : `${daysLeft}d`;

  const isWarning = daysLeft <= 3;

  const className = [
    'bin-list-item',
    isSelected ? 'bin-list-item--selected' : '',
    isWarning ? 'bin-list-item--warning' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={className}
      data-testid={`bin-item-${entry.id}`}
      onClick={handleClick}
      onContextMenu={handleContextMenu}
      role="row"
      aria-selected={isSelected}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const rect = e.currentTarget.getBoundingClientRect();
          const syntheticEvent = {
            preventDefault: () => {},
            clientX: rect.left + rect.width / 2,
            clientY: rect.top + rect.height / 2,
          } as MouseEvent;
          onContextMenu(syntheticEvent, entry);
        }
      }}
    >
      <div className="bin-list-item-name" role="gridcell">
        <span
          className="bin-list-item-checkbox"
          onClick={handleCheckboxClick}
          role="checkbox"
          aria-checked={isSelected}
          aria-label={`Select ${entry.name}`}
          tabIndex={-1}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              e.stopPropagation();
              onSelect(entry.id, { ctrlKey: true, shiftKey: false, metaKey: false });
            }
          }}
        >
          {isSelected ? '[x]' : '[ ]'}
        </span>
        <span className="bin-list-item-icon" aria-hidden="true">
          {getItemIcon(entry)}
        </span>
        <span className="bin-list-item-label">{entry.name}</span>
      </div>
      <div className="bin-list-item-path" role="gridcell" title={entry.originalPath}>
        {entry.originalPath}
      </div>
      <div className="bin-list-item-deleted" role="gridcell">
        {formatRelativeTime(entry.deletedAt)}
      </div>
      <div className="bin-list-item-size" role="gridcell">
        {sizeDisplay}
      </div>
      <div
        className={`bin-list-item-remaining ${isWarning ? 'bin-list-item-remaining--warning' : ''}`}
        role="gridcell"
      >
        {remainingText}
      </div>
    </div>
  );
}
