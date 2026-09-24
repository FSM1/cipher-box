/** PROTOTYPE — throwaway. Pieces the three invite-page variants share. */
import { useState, type ReactNode } from 'react';
import {
  INVITE_PROTO_FOLDER,
  protoCounts,
  protoPermissionLabel,
  protoSize,
  type InviteProtoDispatch,
  type InviteProtoPermission,
  type InviteProtoState,
} from './InvitePrototypeStore';

const FOLDER = INVITE_PROTO_FOLDER;

/** The app's invite-page frame: the same panel the real page renders in. */
export function InviteProtoPanel({ children, testId }: { children: ReactNode; testId: string }) {
  return (
    <div className="login-panel proto-inv-panel" data-testid={testId}>
      <h1>CipherBox</h1>
      <p className="tagline">invite link</p>
      {children}
    </div>
  );
}

/** Identical in every variant: fixed text, then the sign-in methods, all stubs. */
export function InviteProtoSignedOut({ dispatch }: { dispatch: InviteProtoDispatch }) {
  const [email, setEmail] = useState('');
  return (
    <InviteProtoPanel testId="proto-invite-signed-out">
      <p className="login-description" role="status">
        this link shares a folder with you. sign in to see what is inside.
      </p>
      <div className="login-methods">
        <button
          type="button"
          className="terminal-btn"
          onClick={() => dispatch({ type: 'sign-in', method: 'google' })}
        >
          sign in with google
        </button>
        <div className="login-divider">
          <span>// or</span>
        </div>
        <form
          className="email-login-form"
          onSubmit={(event) => {
            event.preventDefault();
            dispatch({ type: 'sign-in', method: 'email', email: email.trim() });
          }}
        >
          <input
            className="email-login-input"
            type="email"
            placeholder="email address"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <button type="submit" className="terminal-btn terminal-btn--filled">
            send code
          </button>
        </form>
        <div className="login-divider">
          <span>// or</span>
        </div>
        <button
          type="button"
          className="terminal-btn"
          onClick={() => dispatch({ type: 'sign-in', method: 'wallet' })}
        >
          connect wallet
        </button>
      </div>
      <p className="proto-inv-stub-note">stub: every method signs in at once</p>
    </InviteProtoPanel>
  );
}

export function InviteProtoPermissionBadge({ permission }: { permission: InviteProtoPermission }) {
  return (
    <span className={`proto-inv-badge proto-inv-badge--${permission}`} data-testid="proto-perm">
      {protoPermissionLabel(permission)}
    </span>
  );
}

/** Folder name, "from <owner>", and the permission the link gives. */
export function InviteProtoHeader({
  permission,
  size = 'lg',
}: {
  permission: InviteProtoPermission;
  size?: 'lg' | 'sm';
}) {
  return (
    <div className={`proto-inv-header proto-inv-header--${size}`}>
      <div className="proto-inv-folder-name">[DIR] {FOLDER.name}</div>
      <div className="proto-inv-header-meta">
        <span className="proto-inv-dim">from {FOLDER.owner}</span>
        <InviteProtoPermissionBadge permission={permission} />
      </div>
    </div>
  );
}

export function InviteProtoSignedInAs({ identifier }: { identifier: string | null }) {
  return <p className="proto-inv-dim proto-inv-small">signed in as {identifier ?? '-'}</p>;
}

export function InviteProtoCounts() {
  return <p className="proto-inv-dim proto-inv-small">{protoCounts(FOLDER.entries)}</p>;
}

/** The one-level listing as a plain list: kind, name, size. */
export function InviteProtoPlainList() {
  return (
    <ul className="proto-inv-plain" data-testid="proto-listing">
      {FOLDER.entries.map((entry) => (
        <li key={entry.name}>
          <span className="proto-inv-kind">{entry.kind === 'folder' ? '[DIR]' : '[FILE]'}</span>
          <span className="proto-inv-plain-name">{entry.name}</span>
          <span className="proto-inv-dim">{protoSize(entry.bytes)}</span>
        </li>
      ))}
    </ul>
  );
}

/** The one-level listing in the app's file-list look, read-only: no select, no menu. */
export function InviteProtoBrowserList({ locked }: { locked: boolean }) {
  return (
    <div className="file-list proto-inv-browser" role="grid" data-testid="proto-listing">
      <div className="file-list-header" role="row">
        <div className="file-list-header-name" role="columnheader">
          [NAME]
        </div>
        <div className="file-list-header-size" role="columnheader">
          [SIZE]
        </div>
        <div className="file-list-header-date" role="columnheader">
          [MODIFIED]
        </div>
      </div>
      <div className="file-list-body" role="rowgroup">
        {FOLDER.entries.map((entry) => (
          <div
            key={entry.name}
            className="file-list-item"
            role="row"
            title={locked && entry.kind === 'folder' ? 'opens after you join' : undefined}
          >
            <div className="file-list-item-row-top" role="gridcell">
              <span className="file-list-item-icon" aria-hidden="true">
                {entry.kind === 'folder' ? '[DIR]' : '[FILE]'}
              </span>
              <span className="file-list-item-name">{entry.name}</span>
            </div>
            <div className="file-list-item-row-bottom">
              <span className="file-list-item-size" role="gridcell">
                {protoSize(entry.bytes)}
              </span>
              <span className="file-list-item-date" role="gridcell">
                {entry.modified}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/** The claimant's own label: pre-filled with the sign-in identifier, editable. */
export function InviteProtoNameField({
  state,
  dispatch,
}: {
  state: InviteProtoState;
  dispatch: InviteProtoDispatch;
}) {
  return (
    <label className="proto-inv-name">
      <span className="proto-inv-small">your name for {FOLDER.owner}</span>
      <input
        className="email-login-input"
        value={state.name}
        onChange={(event) => dispatch({ type: 'set-name', name: event.target.value })}
        data-testid="proto-name"
      />
      <span className="proto-inv-dim proto-inv-xsmall">
        {FOLDER.owner} sees this name in the people list and can change it.
      </span>
    </label>
  );
}

export function InviteProtoJoinButton({ dispatch }: { dispatch: InviteProtoDispatch }) {
  return (
    <button
      type="button"
      className="terminal-btn terminal-btn--filled"
      onClick={() => dispatch({ type: 'join' })}
      data-testid="proto-join"
    >
      join
    </button>
  );
}

/**
 * Expired, revoked, or already joined: known only after sign-in, because the
 * link read that finds out needs a session. `null` when the preview can show.
 */
export function inviteProtoStatusScreen(
  state: InviteProtoState,
  dispatch: InviteProtoDispatch
): ReactNode {
  if (state.alreadyJoined) {
    return (
      <InviteProtoPanel testId="proto-invite-already">
        <p className="login-description" role="status">
          you already have this folder. {FOLDER.name} from {FOLDER.owner} is in your shared folders.
        </p>
        <button
          type="button"
          className="terminal-btn terminal-btn--filled"
          onClick={() => dispatch({ type: 'open-folder' })}
        >
          open folder
        </button>
      </InviteProtoPanel>
    );
  }
  if (state.link === 'live') return null;
  return (
    <InviteProtoPanel testId={`proto-invite-${state.link}`}>
      <p className="login-description" role="status">
        {state.link === 'expired'
          ? 'this link has expired.'
          : `${FOLDER.owner} turned this link off.`}{' '}
        ask {FOLDER.owner} for a new link.
      </p>
      <InviteProtoSignedInAs identifier={state.identifier} />
    </InviteProtoPanel>
  );
}

/** After "join": a short confirmation, then the folder. */
export function InviteProtoJoined({
  state,
  dispatch,
}: {
  state: InviteProtoState;
  dispatch: InviteProtoDispatch;
}) {
  return (
    <InviteProtoPanel testId="proto-invite-joined">
      <p className="login-description" role="status">
        you are in. {FOLDER.name} from {FOLDER.owner} is now in your shared folders.
      </p>
      {state.permission === 'write' && (
        <p className="login-description proto-inv-warn">
          you can view the files now. editing starts when {FOLDER.owner}&apos;s app adds you. this
          happens in the background.
        </p>
      )}
      <button
        type="button"
        className="terminal-btn terminal-btn--filled"
        onClick={() => dispatch({ type: 'open-folder' })}
        data-testid="proto-open-folder"
      >
        open folder
      </button>
    </InviteProtoPanel>
  );
}

/** Where "open folder" lands: the shared folder in the app's browser look. */
export function InviteProtoFolderView({ state }: { state: InviteProtoState }) {
  return (
    <div className="proto-inv-folder" data-testid="proto-invite-folder">
      <nav className="breadcrumb-nav" aria-label="Current location">
        <span className="breadcrumb-prefix">~</span>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-item">shared</span>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-item breadcrumb-item--current">{FOLDER.name}</span>
      </nav>
      <div className="proto-inv-header-meta">
        <span className="proto-inv-dim">from {FOLDER.owner}</span>
        <InviteProtoPermissionBadge permission={state.permission} />
        {state.permission === 'write' && (
          <span className="proto-inv-warn proto-inv-small">
            edit starts when {FOLDER.owner} adds you
          </span>
        )}
      </div>
      <InviteProtoBrowserList locked={false} />
    </div>
  );
}
