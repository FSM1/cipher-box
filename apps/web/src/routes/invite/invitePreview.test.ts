import { EngineRequestError, type InvitePreviewDescriptor } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import {
  entryKindLabel,
  failedPreviewOutcome,
  permissionLabel,
  previewHeadline,
  previewOutcome,
} from './invitePreview';

function preview(overrides: Partial<InvitePreviewDescriptor>): InvitePreviewDescriptor {
  return {
    scope: new Uint8Array(16),
    names: null,
    permission: 'read',
    state: 'live',
    joined: false,
    listing: [],
    ...overrides,
  };
}

describe('previewOutcome', () => {
  it('offers the join only on a live link this account has not joined', () => {
    expect(previewOutcome(preview({}))).toBe('joinable');
  });

  it('reads a joined link as joined, whatever the link state', () => {
    expect(previewOutcome(preview({ joined: true }))).toBe('joined');
    expect(previewOutcome(preview({ joined: true, state: 'revoked' }))).toBe('joined');
  });

  it.each(['expired', 'revoked', 'unresolvable'] as const)('reads a %s link as itself', (state) => {
    expect(previewOutcome(preview({ state }))).toBe(state);
  });
});

describe('failedPreviewOutcome', () => {
  it('reads a trust violation as untrusted', () => {
    expect(failedPreviewOutcome(new EngineRequestError('refused', 'trustViolation'))).toBe(
      'untrusted'
    );
  });

  it('reads every other failure as unreadable', () => {
    expect(failedPreviewOutcome(new EngineRequestError('down', 'contentUnavailable'))).toBe(
      'unreadable'
    );
    expect(failedPreviewOutcome(new Error('that is not an invite link'))).toBe('unreadable');
  });
});

describe('previewHeadline', () => {
  it('names the owner and the folder under a verified signature', () => {
    expect(previewHeadline({ ownerName: 'Ada', folderName: 'trips' })).toBe(
      'Ada shared trips with you'
    );
  });

  it('names nobody when the signature does not verify', () => {
    expect(previewHeadline(null)).toBe('a folder was shared with you');
  });

  it('leads with the folder alone when the verified owner name is empty', () => {
    expect(previewHeadline({ ownerName: '', folderName: 'trips' })).toBe(
      'trips was shared with you'
    );
    expect(previewHeadline({ ownerName: '', folderName: '' })).toBe('a folder was shared with you');
  });

  it('clamps a long name', () => {
    const headline = previewHeadline({ ownerName: 'a'.repeat(500), folderName: 'trips' });
    expect(headline.length).toBeLessThan(200);
  });
});

describe('labels', () => {
  it('names each permission and each kind', () => {
    expect(permissionLabel('read')).toBe('can view');
    expect(permissionLabel('write')).toBe('can edit');
    expect(entryKindLabel({ name: 'a', kind: 'folder' })).toBe('[DIR]');
    expect(entryKindLabel({ name: 'a', kind: 'file' })).toBe('[FILE]');
  });
});
