/**
 * PROTOTYPE — throwaway, for the invite-flow UI question. An in-memory stand-in
 * for one invite link seen by one person: sign-in first, then a read-only
 * preview, then "join" as its own action. No engine, no facade, no auth.
 */
import { useReducer } from 'react';

export type InviteProtoPermission = 'read' | 'write';
export type InviteProtoLink = 'live' | 'expired' | 'revoked';
export type InviteProtoMethod = 'google' | 'email' | 'wallet';

/** Where the person is in the flow. The link status is separate, see `link`. */
export type InviteProtoPhase = 'signed-out' | 'preview' | 'joined' | 'in-folder';

export interface InviteProtoEntry {
  name: string;
  kind: 'folder' | 'file';
  /** Bytes for a file; `null` for a folder. */
  bytes: number | null;
  modified: string;
}

/** Courtesy text from the link fragment plus the one-level listing the preview reads. */
export const INVITE_PROTO_FOLDER: { name: string; owner: string; entries: InviteProtoEntry[] } = {
  name: 'berlin trip 2026',
  owner: 'alex',
  entries: [
    { name: 'photos', kind: 'folder', bytes: null, modified: '2026-09-18' },
    { name: 'receipts', kind: 'folder', bytes: null, modified: '2026-09-12' },
    { name: 'itinerary.pdf', kind: 'file', bytes: 1_240_000, modified: '2026-09-02' },
    { name: 'budget.xlsx', kind: 'file', bytes: 88_300, modified: '2026-09-20' },
    { name: 'packing-list.md', kind: 'file', bytes: 3_400, modified: '2026-09-21' },
  ],
};

export interface InviteProtoState {
  phase: InviteProtoPhase;
  link: InviteProtoLink;
  permission: InviteProtoPermission;
  /** This account already holds the folder (joined earlier, on any device). */
  alreadyJoined: boolean;
  /** The sign-in identifier: an email, or the short wallet form. */
  identifier: string | null;
  /** The name field; pre-filled from `identifier`, editable. Rides the sealed claim. */
  name: string;
  /** Variant C only: which step the signed-in person is on. */
  step: 'look' | 'join';
  /** The last action, surfaced by the state panel. */
  last: string;
}

export type InviteProtoPreset =
  | 'arrival'
  | 'signed-in'
  | 'joined'
  | 'expired'
  | 'revoked'
  | 'already-joined'
  | 'write-link';

export const INVITE_PROTO_PRESETS: { key: InviteProtoPreset; label: string }[] = [
  { key: 'arrival', label: 'arrival signed out' },
  { key: 'signed-in', label: 'signed in (preview)' },
  { key: 'joined', label: 'join pressed' },
  { key: 'expired', label: 'expired link' },
  { key: 'revoked', label: 'revoked link' },
  { key: 'already-joined', label: 'already joined' },
  { key: 'write-link', label: 'write link (can edit)' },
];

export type InviteProtoAction =
  | { type: 'preset'; key: InviteProtoPreset }
  | { type: 'sign-in'; method: InviteProtoMethod; email?: string }
  | { type: 'set-name'; name: string }
  | { type: 'next' }
  | { type: 'back' }
  | { type: 'join' }
  | { type: 'open-folder' }
  | { type: 'expire' }
  | { type: 'revoke' }
  | { type: 'mark-already-joined' }
  | { type: 'toggle-permission' };

export type InviteProtoDispatch = (action: InviteProtoAction) => void;

const IDENTIFIERS: Record<InviteProtoMethod, string> = {
  google: 'dana.k@gmail.com',
  email: 'dana@example.com',
  wallet: '0x71c7…976f',
};

const INITIAL: InviteProtoState = {
  phase: 'signed-out',
  link: 'live',
  permission: 'read',
  alreadyJoined: false,
  identifier: null,
  name: '',
  step: 'look',
  last: 'arrived with a link, signed out',
};

function signedIn(
  state: InviteProtoState,
  method: InviteProtoMethod,
  email?: string
): InviteProtoState {
  const identifier = email !== undefined && email !== '' ? email : IDENTIFIERS[method];
  return { ...state, phase: 'preview', identifier, name: identifier, step: 'look' };
}

function preset(key: InviteProtoPreset): InviteProtoState {
  const base = signedIn(INITIAL, 'google');
  switch (key) {
    case 'arrival':
      return INITIAL;
    case 'signed-in':
      return { ...base, last: 'preset: signed in, preview shown' };
    case 'joined':
      return { ...base, phase: 'joined', last: 'preset: join pressed' };
    case 'expired':
      return { ...base, link: 'expired', last: 'preset: signed in on an expired link' };
    case 'revoked':
      return { ...base, link: 'revoked', last: 'preset: signed in on a revoked link' };
    case 'already-joined':
      return { ...base, alreadyJoined: true, last: 'preset: link already joined on this account' };
    case 'write-link':
      return { ...base, permission: 'write', last: 'preset: signed in, write link' };
  }
}

function reduce(state: InviteProtoState, action: InviteProtoAction): InviteProtoState {
  switch (action.type) {
    case 'preset':
      return preset(action.key);
    case 'sign-in':
      if (state.phase !== 'signed-out') return { ...state, last: 'sign in: already signed in' };
      return {
        ...signedIn(state, action.method, action.email),
        last: `signed in with ${action.method}; the preview read ran, nothing saved`,
      };
    case 'set-name':
      return { ...state, name: action.name, last: 'edited the name field' };
    case 'next':
      return { ...state, step: 'join', last: 'step 2 -> step 3' };
    case 'back':
      return { ...state, step: 'look', last: 'step 3 -> step 2' };
    case 'join':
      if (state.phase !== 'preview' || state.link !== 'live' || state.alreadyJoined)
        return { ...state, last: 'join: not available in this state' };
      return {
        ...state,
        phase: 'joined',
        last: `joined as "${state.name.trim() || '(no name)'}"; claim sealed and posted`,
      };
    case 'open-folder':
      return { ...state, phase: 'in-folder', last: 'opened the shared folder' };
    case 'expire':
      return { ...state, link: 'expired', last: 'the link expired' };
    case 'revoke':
      return { ...state, link: 'revoked', last: 'the owner revoked the link' };
    case 'mark-already-joined':
      return { ...state, alreadyJoined: true, last: 'marked: this account already has the folder' };
    case 'toggle-permission': {
      const permission = state.permission === 'read' ? 'write' : 'read';
      return { ...state, permission, last: `link permission now ${permission}` };
    }
  }
}

export function useInvitePrototypeStore() {
  return useReducer(reduce, INITIAL);
}

export const protoPermissionLabel = (permission: InviteProtoPermission) =>
  permission === 'write' ? 'can edit' : 'can view';

export function protoSize(bytes: number | null): string {
  if (bytes === null) return '-';
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

/** "2 folders, 3 files, 1.3 MB" — the counts line for the one-level listing. */
export function protoCounts(entries: InviteProtoEntry[]): string {
  const folders = entries.filter((entry) => entry.kind === 'folder').length;
  const files = entries.length - folders;
  const bytes = entries.reduce((sum, entry) => sum + (entry.bytes ?? 0), 0);
  const noun = (count: number, one: string) => `${count} ${one}${count === 1 ? '' : 's'}`;
  return `${noun(folders, 'folder')}, ${noun(files, 'file')}, ${protoSize(bytes)}`;
}
