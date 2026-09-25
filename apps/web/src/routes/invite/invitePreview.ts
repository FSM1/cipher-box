import {
  EngineRequestError,
  type InvitePreviewDescriptor,
  type InvitePreviewEntryDescriptor,
  type Permission,
} from '@cipherbox/client';
import { displayName } from '../../vault/displayName';

/** A preview read that did not answer. */
export type PreviewFailure = 'untrusted' | 'unreadable';

/** What the page shows once the preview read settles (ADR 0028 D5). */
export type PreviewOutcome =
  | 'joinable'
  | 'joined'
  | 'expired'
  | 'revoked'
  | 'unresolvable'
  | PreviewFailure;

/**
 * A bookmark wins over the link state: the folder reads through its own
 * standing once joined, so a dead link still offers "open folder".
 */
export function previewOutcome(preview: InvitePreviewDescriptor): PreviewOutcome {
  if (preview.joined) return 'joined';
  return preview.state === 'live' ? 'joinable' : preview.state;
}

/**
 * A gate refusal is a trust violation, never an outage (AGENTS.md rule 6), so
 * it reads apart from a read that did not complete.
 */
export function failedPreviewOutcome(failure: unknown): PreviewFailure {
  return failure instanceof EngineRequestError && failure.code === 'trustViolation'
    ? 'untrusted'
    : 'unreadable';
}

/**
 * The card's lead line. Names show only under a verified owner signature, and
 * a verified name may still be empty.
 */
export function previewHeadline(names: InvitePreviewDescriptor['names']): string {
  const folder = names?.folderName ? displayName(names.folderName) : 'a folder';
  return names?.ownerName
    ? `${displayName(names.ownerName)} shared ${folder} with you`
    : `${folder} was shared with you`;
}

export function permissionLabel(permission: Permission): string {
  return permission === 'write' ? 'can edit' : 'can view';
}

export function entryKindLabel(entry: InvitePreviewEntryDescriptor): string {
  return entry.kind === 'folder' ? '[DIR]' : '[FILE]';
}
