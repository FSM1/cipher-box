/**
 * SharedFolderRow -- Row component for items within a shared folder.
 *
 * Shows [RW] or [RO] badge based on the share's permission level.
 * Supports inline renaming when isRenaming is true.
 */

import type React from 'react';
import type { MouseEvent } from 'react';
import type { FolderChild } from '@cipherbox/core';

export type SharedFolderRowProps = {
  item: FolderChild;
  permission: 'read' | 'write' | null;
  isRenaming: boolean;
  renameValue: string;
  renameInputRef: React.RefObject<HTMLInputElement>;
  onRenameChange: (value: string) => void;
  onRenameKeyDown: (e: React.KeyboardEvent) => void;
  onRenameSubmit: () => void;
  onContextMenu: (e: MouseEvent) => void;
  onDoubleClick: () => void;
};

export function SharedFolderRow({
  item,
  permission,
  isRenaming,
  renameValue,
  renameInputRef,
  onRenameChange,
  onRenameKeyDown,
  onRenameSubmit,
  onContextMenu,
  onDoubleClick,
}: SharedFolderRowProps) {
  const isFolder = item.type === 'folder';
  const icon = isFolder ? '\uD83D\uDCC1' : '\uD83D\uDCC4';
  const date = item.modifiedAt ? new Date(item.modifiedAt).toLocaleDateString() : '--';
  const isWrite = permission === 'write';

  return (
    <div
      className="file-list-row"
      role="row"
      tabIndex={0}
      onDoubleClick={isRenaming ? undefined : onDoubleClick}
      onContextMenu={(e) => {
        e.preventDefault();
        onContextMenu(e);
      }}
      onKeyDown={(e) => {
        if (isRenaming) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onDoubleClick();
        }
      }}
    >
      <div className="file-list-cell file-list-cell-name" role="gridcell">
        <span className="file-icon">{icon}</span>
        {isRenaming ? (
          <input
            ref={renameInputRef}
            type="text"
            className="shared-inline-rename-field"
            value={renameValue}
            onChange={(e) => onRenameChange(e.target.value)}
            onKeyDown={onRenameKeyDown}
            onBlur={onRenameSubmit}
            aria-label="Rename item"
          />
        ) : (
          <>
            <span className="file-name">
              {item.name}
              {isFolder ? '/' : ''}
            </span>
            {isWrite ? (
              <span className="shared-rw-badge">{'[RW]'}</span>
            ) : (
              <span className="shared-ro-badge">{'[RO]'}</span>
            )}
          </>
        )}
      </div>
      <div className="file-list-cell file-list-cell-size" role="gridcell">
        --
      </div>
      <div className="file-list-cell file-list-cell-date" role="gridcell">
        {date}
      </div>
    </div>
  );
}
