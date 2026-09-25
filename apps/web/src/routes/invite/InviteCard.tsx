import { useState } from 'react';
import type { InvitePreviewDescriptor } from '@cipherbox/client';
import { displayName } from '../../vault/displayName';
import { entryKindLabel, permissionLabel, previewHeadline } from './invitePreview';

interface InviteCardProps {
  preview: InvitePreviewDescriptor;
  joining: boolean;
  /** A sign-in on the page unmounts the focused control; "join" is next. */
  focusJoin: boolean;
  onJoin(name: string): void;
}

/**
 * The live, unjoined preview (ADR 0028 D2, variant A): the lead line, the
 * permission, the one-level listing, the grantee's own name and "join".
 */
export function InviteCard({ preview, joining, focusJoin, onJoin }: InviteCardProps) {
  const [name, setName] = useState('');

  return (
    <>
      <div className="invite-header">
        <p className="invite-headline" data-testid="invite-headline">
          {previewHeadline(preview.names)}
        </p>
        {preview.permission !== null && (
          <span
            className={`invite-badge invite-badge--${preview.permission}`}
            data-testid="invite-permission"
          >
            {permissionLabel(preview.permission)}
          </span>
        )}
      </div>
      {preview.listing.length === 0 ? (
        <p className="invite-dim" data-testid="invite-listing-empty">
          this folder is empty.
        </p>
      ) : (
        <ul className="invite-listing" data-testid="invite-listing">
          {preview.listing.map((entry, index) => (
            <li key={index} data-testid="invite-entry" data-kind={entry.kind}>
              <span className="invite-kind">{entryKindLabel(entry)}</span>
              <span className="invite-entry-name">{displayName(entry.name)}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="invite-join">
        <label className="invite-name">
          <span>your name</span>
          <input
            className="email-login-input"
            value={name}
            onChange={(event) => setName(event.target.value)}
            disabled={joining}
            data-testid="invite-name"
          />
        </label>
        <button
          autoFocus={focusJoin}
          type="button"
          className="terminal-btn terminal-btn--filled"
          onClick={() => onJoin(name)}
          disabled={joining}
          data-testid="invite-join"
        >
          {joining ? 'joining...' : 'join'}
        </button>
      </div>
    </>
  );
}
