/** SharedListRow -- Row component for the top-level shared items list. */

import type { MouseEvent } from 'react';
import type { SharedListItem } from '../../hooks/useSharedNavigation';

/**
 * Truncate a public key for display: 0x{first4}...{last4}
 */
function truncatePubkey(pubkey: string): string {
  if (pubkey.length <= 12) return pubkey;
  const hex = pubkey.startsWith('0x') ? pubkey.slice(2) : pubkey;
  return `0x${hex.slice(0, 4)}...${hex.slice(-4)}`;
}

export type SharedListRowProps = {
  sharedItem: SharedListItem;
  onOpen: () => void;
  onContextMenu: (e: MouseEvent) => void;
};

export function SharedListRow({ sharedItem, onOpen, onContextMenu }: SharedListRowProps) {
  const { share } = sharedItem;
  const isFolder = share.itemType === 'folder';
  const icon = isFolder ? '\uD83D\uDCC1' : '\uD83D\uDCC4';
  const date = new Date(share.createdAt).toLocaleDateString();
  const isWrite = share.permission === 'write';

  return (
    <div
      className="file-list-row shared-list-row"
      role="row"
      tabIndex={0}
      onDoubleClick={onOpen}
      onContextMenu={(e) => {
        e.preventDefault();
        onContextMenu(e);
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <div className="file-list-cell file-list-cell-name" role="gridcell">
        <span className="file-icon">{icon}</span>
        <span className="file-name">
          {share.itemName}
          {isFolder ? '/' : ''}
        </span>
        {isWrite ? (
          <span className="shared-rw-badge">{'[RW]'}</span>
        ) : (
          <span className="shared-ro-badge">{'[RO]'}</span>
        )}
      </div>
      <div className="file-list-cell shared-by-cell" role="gridcell">
        {truncatePubkey(share.sharerPublicKey)}
      </div>
      <div className="file-list-cell file-list-cell-date" role="gridcell">
        {date}
      </div>
    </div>
  );
}
