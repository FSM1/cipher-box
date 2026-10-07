import { describe, expect, it } from 'vitest';

import {
  readAuthMethods,
  readBin,
  readEvent,
  readInvitePreview,
  readReceivedShares,
  readSharing,
  readSnapshot,
  readVaultStorage,
} from './commandCodec.js';
import type {
  AuthMethodDescriptor,
  BinDescriptor,
  EventDescriptor,
  InvitePreviewDescriptor,
  ReceivedShareDescriptor,
  SharingDescriptor,
  SharingInviteLinkDescriptor,
  VaultStorageDescriptor,
} from './protocol.js';
import type { SnapshotView } from '../../wasm/cipherbox_wasm.js';

describe('readEvent', () => {
  /** An event as a version-skewed engine could send it: off the typed union. */
  const skewed = (event: Record<string, unknown>) => event as unknown as EventDescriptor;

  it('passes a known event through as the engine sent it', () => {
    const event: EventDescriptor = {
      kind: 'opProgress',
      opId: 9n,
      node: new Uint8Array(16).fill(4),
      phase: 'uploadProgress',
      progress: { confirmed: 3, total: 8 },
      error: null,
    };
    expect(readEvent(event)).toBe(event);
  });

  it('fails closed on an event kind this build does not know', () => {
    expect(() => readEvent(skewed({ kind: 'somethingNew' }))).toThrow(
      'unknown WASM event kind: somethingNew'
    );
    expect(() => readEvent(skewed({ kind: 'toString' }))).toThrow('unknown WASM event kind');
  });

  it('fails closed on an owed work class this build does not know', () => {
    const owed = { kind: 'rotationWorkOwed', scopeRoot: new Uint8Array(16), detail: 'x' };
    expect(() => readEvent(skewed({ ...owed, retryable: false, class: 'somethingNew' }))).toThrow(
      'unknown WASM owed work class: somethingNew'
    );
    const known: EventDescriptor = {
      ...owed,
      kind: 'rotationWorkOwed',
      retryable: false,
      class: 'trust',
    };
    expect(readEvent(known)).toBe(known);
  });

  it('fails closed on a drop cause this build does not know', () => {
    const dropped = { scopeRoot: new Uint8Array(16), nodeId: new Uint8Array(16) };
    expect(() =>
      readEvent(skewed({ kind: 'nodeDropped', ...dropped, cause: 'second-ref' }))
    ).toThrow('unknown WASM drop cause: second-ref');
    const known: EventDescriptor = { kind: 'nodeDropped', ...dropped, cause: 'no-head-block' };
    expect(readEvent(known)).toBe(known);
  });

  it('passes the name wave and the sweep convergence events through', () => {
    const scopeRoot = new Uint8Array(16).fill(5);
    const events: EventDescriptor[] = [
      { kind: 'nameWaveStarted', scopeRoot, at: 1n },
      { kind: 'nameWaveProgress', scopeRoot, moved: 1, total: 3, at: 2n },
      { kind: 'nameWaveEnded', scopeRoot, interiorNodes: 2, dropped: 0, at: 3n },
      {
        kind: 'sweepConvergence',
        scopeRoot,
        readEpoch: 2n,
        oldEpochNodes: 0,
        cutAt: 1n,
        lastResealAt: null,
        at: 4n,
      },
    ];
    for (const event of events) expect(readEvent(event)).toBe(event);
  });

  it('passes the restored-from-server-copy event through', () => {
    const event: EventDescriptor = { kind: 'restoredFromServerCopy', routingKey: 'k51abc' };
    expect(readEvent(event)).toBe(event);
  });

  it('fails closed on a staleness level this build does not know', () => {
    expect(() => readEvent(skewed({ kind: 'stalenessChanged', staleness: 'frozen' }))).toThrow(
      'unknown WASM staleness: frozen'
    );
  });

  it('fails closed on an unknown or absent dead letter reason', () => {
    expect(() =>
      readEvent(skewed({ kind: 'deadLetter', opId: 7n, target: null, reason: 'lost' }))
    ).toThrow('unknown WASM dead letter reason: lost');
    expect(() => readEvent(skewed({ kind: 'deadLetter', opId: 7n }))).toThrow(
      'unknown WASM dead letter reason: undefined'
    );
  });

  it('preserves the target and reason of a refused scope-root delete', () => {
    const event: EventDescriptor = {
      kind: 'deadLetter',
      opId: 7n,
      target: new Uint8Array(16).fill(9),
      reason: 'targetIsScopeRoot',
    };
    expect(readEvent(event)).toBe(event);
  });

  it('fails closed on an unknown opProgress phase', () => {
    const node = new Uint8Array(16);
    expect(() => readEvent(skewed({ kind: 'opProgress', node, phase: 'uploadPaused' }))).toThrow(
      'unknown WASM op phase: uploadPaused'
    );
    expect(() => readEvent(skewed({ kind: 'opProgress', node, phase: 2 }))).toThrow(
      'unknown WASM op phase: 2'
    );
  });
});

/**
 * A view as a version-skewed engine could send it: off the generated type. The
 * reads below are the one place an unknown enum value is refused.
 */
function skewed<T>(view: unknown): T {
  return view as T;
}

/** An empty snapshot: nothing pending, nothing dead-lettered, nothing held. */
function baseView(): SnapshotView {
  return {
    root: new Uint8Array(16),
    folder: new Uint8Array(16),
    folderName: '',
    permission: 'write',
    receivedShare: false,
    children: [],
    ancestors: [],
    deadLetters: [],
    queueHold: null,
    retainedRecords: 0n,
    staleness: 'fresh',
  };
}

function child(overrides: Partial<SnapshotView['children'][number]> = {}) {
  return {
    id: new Uint8Array(16),
    name: 'x',
    kind: 'file' as const,
    size: null,
    mtime: null,
    pending: 'none' as const,
    deadLetter: false,
    contentVersion: null,
    contentCid: null,
    pendingInviteClaims: 0,
    ipnsName: null,
    ...overrides,
  };
}

describe('readSnapshot', () => {
  it('passes a known snapshot through as the engine sent it', () => {
    const view: SnapshotView = {
      ...baseView(),
      children: [child({ kind: 'folder', pending: 'content' })],
      deadLetters: [{ opId: 9_007_199_254_740_993n, reason: 'attemptsExhausted' }],
      queueHold: {
        reason: 'quota',
        opId: 12n,
        node: new Uint8Array(16).fill(6),
        neededBytes: 9_007_199_254_740_993n,
      },
      staleness: 'reconciling',
    };
    expect(readSnapshot(view)).toEqual(view);
  });

  it('reads a held head by its reason', () => {
    for (const check of [
      'byo-provider-missing',
      'stranded-mint',
      'revision-rolled-back',
      'expired',
      'unreadable',
    ]) {
      const view = skewed<SnapshotView>({
        ...baseView(),
        queueHold: { reason: 'settings', opId: 13n, node: new Uint8Array(16), check },
      });
      expect(readSnapshot(view).queueHold).toEqual(view.queueHold);
    }
  });

  it('reads a held delete with its target', () => {
    const view = skewed<SnapshotView>({
      ...baseView(),
      queueHold: { reason: 'delete-plane', opId: 14n, node: new Uint8Array(16).fill(7) },
    });
    expect(readSnapshot(view).queueHold).toEqual(view.queueHold);
  });

  it('reads a head held over a newer release with its target', () => {
    const view = skewed<SnapshotView>({
      ...baseView(),
      queueHold: { reason: 'newer-release', opId: 15n, node: new Uint8Array(16).fill(8) },
    });
    expect(readSnapshot(view).queueHold).toEqual(view.queueHold);
  });

  it('fails closed on a hold reason this build cannot name', () => {
    const view = skewed<SnapshotView>({
      ...baseView(),
      queueHold: { reason: 'weather', opId: 1n, node: new Uint8Array(16) },
    });
    expect(() => readSnapshot(view)).toThrow('unknown WASM queue hold reason: weather');
  });

  it('fails closed on a hold check this build cannot name', () => {
    const hold = (reason: string, check: string) =>
      skewed<SnapshotView>({
        ...baseView(),
        queueHold: { reason, opId: 1n, node: new Uint8Array(16), check },
      });
    expect(() => readSnapshot(hold('settings', 'byo-unreachable'))).toThrow(
      'unknown WASM settings hold check: byo-unreachable'
    );
    expect(() => readSnapshot(hold('bin-index', 'stranded-mint'))).toThrow(
      'unknown WASM bin-index hold check: stranded-mint'
    );
    // Each check vocabulary is held apart.
    expect(() => readSnapshot(hold('settings', 'suppressed'))).toThrow(
      'unknown WASM settings hold check'
    );
  });

  it.each([
    ['permission', { permission: 'admin' }, 'unknown WASM permission: admin'],
    ['staleness', { staleness: 'frozen' }, 'unknown WASM staleness: frozen'],
    [
      'dead letter reason',
      { deadLetters: [{ opId: 1n, reason: 'lost' }] },
      'unknown WASM dead letter reason: lost',
    ],
    ['node kind', { children: [child({ kind: skewed('link') })] }, 'unknown WASM node kind: link'],
    [
      'pending class',
      { children: [child({ pending: skewed(2) })] },
      'unknown WASM pending class: 2',
    ],
  ])('fails closed on a %s this build does not know', (_name, override, message) => {
    expect(() => readSnapshot(skewed<SnapshotView>({ ...baseView(), ...override }))).toThrow(
      message
    );
  });
});

describe('readSharing', () => {
  const link: SharingInviteLinkDescriptor = {
    tag: new Uint8Array(32).fill(0x7a),
    permission: 'write',
    expiresAt: 1_700_000_000_000n,
    expired: false,
    admissionCap: 5n,
    pendingClaims: 1,
    contactBudgetFull: true,
    refusedClaims: 2,
  };
  const view: SharingDescriptor = {
    scope: new Uint8Array(16).fill(3),
    contacts: [{ identityPublicKey: new Uint8Array([1]), cachedName: 'Ada' }],
    ownContactCode: new Uint8Array([4, 5, 6]),
    state: {
      grants: [
        {
          recipientIdentityPublicKey: new Uint8Array([2]),
          permission: 'read',
          granteeName: { name: 'Ada', source: 'claimant' },
          viaLink: new Uint8Array(32).fill(0x7a),
        },
      ],
      grantRefusal: null,
      inviteLinkRefusal: null,
      inviteLinks: [link],
      epochs: { readEpoch: 9_007_199_254_740_993n, writeEpoch: 1n },
    },
  };
  const grant = view.state!.grants[0]!;

  it('passes a known sharing view through, and an unreachable scope too', () => {
    expect(readSharing(view)).toEqual(view);
    expect(readSharing({ ...view, state: null }).state).toBeNull();
  });

  it.each([
    [
      'grantee name source',
      { grants: [{ ...grant, granteeName: { name: 'Ada', source: 'admin' } }] },
      'unknown WASM grantee name source: admin',
    ],
    [
      'grant permission',
      { grants: [{ ...grant, permission: 'admin' }] },
      'unknown WASM permission: admin',
    ],
    [
      'link permission',
      { inviteLinks: [{ ...link, permission: 'admin' }] },
      'unknown WASM permission: admin',
    ],
  ])('fails closed on a %s this build does not know', (_name, override, message) => {
    const drifted = skewed<SharingDescriptor>({ ...view, state: { ...view.state, ...override } });
    expect(() => readSharing(drifted)).toThrow(message);
  });
});

describe('readReceivedShares', () => {
  const row: ReceivedShareDescriptor = {
    scope: new Uint8Array(16).fill(7),
    sharerIdentityPublicKey: new Uint8Array([9]),
    displayName: 'shared-folder',
    permission: 'read',
    resolution: 'revocation-signal',
    viaLink: true,
  };

  it('passes known rows through, an unresolved one included', () => {
    const rows = [row, { ...row, resolution: null }];
    expect(readReceivedShares(rows)).toEqual(rows);
  });

  it('fails closed on a verdict or a permission this build does not know', () => {
    // A guessed verdict would paint a revoked share as still granted.
    expect(() => readReceivedShares([skewed({ ...row, resolution: 'granted-ish' })])).toThrow(
      'unknown WASM resolution class: granted-ish'
    );
    expect(() => readReceivedShares([skewed({ ...row, permission: 'admin' })])).toThrow(
      'unknown WASM permission: admin'
    );
  });
});

describe('readInvitePreview', () => {
  const preview: InvitePreviewDescriptor = {
    scope: new Uint8Array(16).fill(4),
    names: { ownerName: 'Ada', folderName: 'trips' },
    permission: 'write',
    state: 'live',
    joined: false,
    listing: [
      { name: 'drafts', kind: 'folder' },
      { name: 'notes.txt', kind: 'file' },
    ],
  };

  it('passes a known preview through, an unverified one included', () => {
    expect(readInvitePreview(preview)).toEqual(preview);
    const unverified = {
      ...preview,
      names: null,
      permission: null,
      state: 'unresolvable' as const,
    };
    expect(readInvitePreview(unverified)).toEqual(unverified);
  });

  it.each([
    ['state', { state: 'joinable' }, 'unknown WASM invite preview state: joinable'],
    ['permission', { permission: 'admin' }, 'unknown WASM permission: admin'],
    ['listing kind', { listing: [{ name: 'x', kind: 'link' }] }, 'unknown WASM node kind: link'],
  ])('fails closed on a %s this build does not know', (_name, override, message) => {
    expect(() =>
      readInvitePreview(skewed<InvitePreviewDescriptor>({ ...preview, ...override }))
    ).toThrow(message);
  });
});

describe('readBin', () => {
  const row: BinDescriptor['entries'][number] = {
    node: new Uint8Array(16).fill(4),
    kind: 'folder',
    originParent: new Uint8Array(16).fill(1),
    originName: 'holiday',
    originFolder: { kind: 'folder', name: 'trips' },
    deletedAt: 1_800_000_000_000n,
    scope: new Uint8Array(16).fill(2),
  };

  it('passes a known bin through, the defaults rung included', () => {
    const view: BinDescriptor = {
      entries: [
        row,
        { ...row, originFolder: { kind: 'root' } },
        { ...row, originFolder: { kind: 'gone' } },
      ],
      origin: 'resolved',
    };
    expect(readBin(view)).toEqual(view);
    expect(readBin({ entries: [], origin: 'defaults' })).toEqual({
      entries: [],
      origin: 'defaults',
    });
  });

  it.each([
    ['origin', { origin: 'cached' }, 'unknown WASM settings origin: cached'],
    ['row kind', { entries: [{ ...row, kind: 'link' }] }, 'unknown WASM node kind: link'],
    [
      'origin folder kind',
      { entries: [{ ...row, originFolder: { kind: 'moved' } }] },
      'unknown WASM bin origin kind: moved',
    ],
  ])('fails closed on a %s this build does not know', (_name, override, message) => {
    expect(() =>
      readBin(skewed<BinDescriptor>({ entries: [row], origin: 'resolved', ...override }))
    ).toThrow(message);
  });
});

describe('readVaultStorage', () => {
  const view: VaultStorageDescriptor = {
    settings: {
      pinMode: 'dual',
      byoEndpoint: 'https://kubo.example',
      byoKind: 'psa',
      byoCredentialStored: true,
      keepLatestVersions: 5,
      binRetentionDays: 30,
      origin: 'stale',
    },
    quota: { usedBytes: 512n, limitBytes: 2048n, advisory: true },
    pendingReclaimBytes: 0n,
    pendingReclaimIsPartial: true,
    reclaimStalls: [
      { node: new Uint8Array(16).fill(3), target: 'bafyDoomedRoot', reason: 'targetStillLive' },
    ],
  };

  it('passes a known storage view through, one with no provider included', () => {
    expect(readVaultStorage(view)).toEqual(view);
    const bare = { ...view, settings: { ...view.settings, byoKind: null }, quota: null };
    expect(readVaultStorage(bare)).toEqual(bare);
  });

  it.each([
    ['pin mode', { pinMode: 'cloud' }, 'unknown WASM pin mode: cloud'],
    ['provider kind', { byoKind: 'ftp' }, 'unknown WASM provider kind: ftp'],
    ['settings origin', { origin: 'cached' }, 'unknown WASM settings origin: cached'],
  ])('fails closed on a %s this build does not know', (_name, override, message) => {
    expect(() =>
      readVaultStorage(
        skewed<VaultStorageDescriptor>({ ...view, settings: { ...view.settings, ...override } })
      )
    ).toThrow(message);
  });

  it('fails closed on a stall reason this build does not know', () => {
    // A guessed reason would tell a member the wrong thing about a debt that
    // never drains.
    const drifted = skewed<VaultStorageDescriptor>({
      ...view,
      reclaimStalls: [{ ...view.reclaimStalls[0], reason: 'lost' }],
    });
    expect(() => readVaultStorage(drifted)).toThrow('unknown WASM reclaim stall reason: lost');
  });
});

describe('readAuthMethods', () => {
  const row: AuthMethodDescriptor = {
    id: '3f2a-uuid',
    kind: 'wallet',
    identifierDisplay: '0x1234…abcd',
    createdAt: '2026-08-27T10:00:00.000Z',
    lastUsedAt: null,
  };

  it('passes known rows through, the engine-spelled unknown kind included', () => {
    const rows = [
      row,
      { ...row, kind: 'email' as const, identifierDisplay: 'm***@example.test' },
      { ...row, kind: 'unknown' as const },
    ];
    expect(readAuthMethods(rows)).toEqual(rows);
  });

  it('fails closed on a kind this build does not know', () => {
    expect(() => readAuthMethods([skewed({ ...row, kind: 'passkey' })])).toThrow(
      'unknown WASM auth method kind: passkey'
    );
  });
});
