import { describe, expect, it } from 'vitest';
import type { ShellModel } from './frontDoor';
import type { VaultStatus } from './vault';
import { windowIntent } from './window';

function model(over: Partial<ShellModel> = {}): ShellModel {
  return {
    phase: 'signedOut',
    busy: false,
    step: null,
    methods: [],
    email: null,
    error: null,
    vault: null,
    vaultError: null,
    ...over,
  };
}

function vaultStatus(over: Partial<VaultStatus> = {}): VaultStatus {
  return {
    items: 0,
    staleness: 'fresh',
    deadLetters: 0,
    provisioned: true,
    warnings: [],
    mount: { state: 'mounted', path: '/home/member/CipherBox' },
    ...over,
  };
}

describe('the window the session asks for', () => {
  it('asks for nothing while the session is being restored', () => {
    expect(windowIntent(model({ phase: 'starting' }))).toBeNull();
  });

  it('shows the window when there is no session to resume', () => {
    expect(windowIntent(model({ phase: 'signedOut' }))).toBe('show');
  });

  // The restore passes through the front door on its way to a resumed session,
  // so a rule that read that phase would paint a window nobody asked for.
  it('asks for nothing while the restore is still in flight', () => {
    expect(windowIntent(model({ phase: 'signedOut', busy: true, step: 'restore' }))).toBeNull();
    expect(windowIntent(model({ phase: 'starting', busy: true, step: 'restore' }))).toBeNull();
  });

  it('shows the window when a sign-in waits on the recovery phrase', () => {
    expect(windowIntent(model({ phase: 'recovery' }))).toBe('show');
  });

  it('hides the window once a sign-in completed and the vault mounted', () => {
    expect(windowIntent(model({ phase: 'signedIn', vault: vaultStatus() }))).toBe('hide');
  });

  it('shows the window when the mount was refused', () => {
    const refused = vaultStatus({ mount: { state: 'refused', reason: 'FUSE-T is not installed' } });
    expect(windowIntent(model({ phase: 'signedIn', vault: refused }))).toBe('show');
  });

  it('asks for nothing while the mount is still opening', () => {
    const opening = vaultStatus({ mount: { state: 'opening' } });
    expect(windowIntent(model({ phase: 'signedIn', vault: opening }))).toBeNull();
    expect(windowIntent(model({ phase: 'signedIn' }))).toBeNull();
  });
});
