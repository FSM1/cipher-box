import { describe, expect, it } from 'vitest';

import { fakeWasmEnums } from '../testkit.js';
import {
  readAuthMethods,
  readBin,
  readDevices,
  readFileVersions,
  readPendingApprovals,
  readEvent,
  readInvitePreview,
  readReceivedShare,
  readSharing,
  readSnapshot,
  readVaultStorage,
} from './commandCodec.js';
import type {
  EngineWasm,
  WasmBinView,
  WasmEvent,
  WasmSnapshotView,
  WasmVaultStorageView,
  WasmVersionEntry,
} from './engineWasm.js';

/**
 * A structural stand-in for the wasm-bindgen namespace: only the mirror-enum
 * value tables the codec's read paths consult.
 */
const fakeWasm = fakeWasmEnums as unknown as EngineWasm;

describe('readDevices', () => {
  const row = {
    id: '7c1e-uuid',
    publicKey: 'ed25519hex',
    label: 'Work laptop',
    createdAt: '2026-08-27T10:00:00.000Z',
    lastSeenAt: '2026-08-27T11:00:00.000Z',
  };

  it('reads a registry row through, and an absent label as null', () => {
    expect(readDevices([row, { ...row, id: '9a2b-uuid', label: undefined }])).toEqual([
      {
        id: '7c1e-uuid',
        publicKey: 'ed25519hex',
        label: 'Work laptop',
        createdAt: '2026-08-27T10:00:00.000Z',
        lastSeenAt: '2026-08-27T11:00:00.000Z',
      },
      {
        id: '9a2b-uuid',
        publicKey: 'ed25519hex',
        label: null,
        createdAt: '2026-08-27T10:00:00.000Z',
        lastSeenAt: '2026-08-27T11:00:00.000Z',
      },
    ]);
  });
});

describe('readFileVersions', () => {
  const versionRow = (
    contentCid: Uint8Array,
    free: () => void,
    getter?: () => bigint
  ): WasmVersionEntry => ({
    contentCid,
    get size() {
      return getter ? getter() : 12n;
    },
    modifiedAt: 1756_000_000_000n,
    free,
  });

  it('reads a version row through and releases it', () => {
    const freed: number[] = [];
    const rows = [
      versionRow(Uint8Array.of(1, 2), () => freed.push(0)),
      versionRow(Uint8Array.of(3, 4), () => freed.push(1)),
    ];

    expect(readFileVersions(rows)).toEqual([
      { contentCid: Uint8Array.of(1, 2), size: 12n, modifiedAt: 1756_000_000_000n },
      { contentCid: Uint8Array.of(3, 4), size: 12n, modifiedAt: 1756_000_000_000n },
    ]);
    expect(freed).toEqual([0, 1]);
  });

  it('releases every row when one row throws, not only the rows it reached', () => {
    const freed: number[] = [];
    const rows = [
      versionRow(
        Uint8Array.of(1, 2),
        () => freed.push(0),
        () => {
          throw new Error('boundary read failed');
        }
      ),
      versionRow(Uint8Array.of(3, 4), () => freed.push(1)),
    ];

    expect(() => readFileVersions(rows)).toThrow('boundary read failed');
    expect(freed).toEqual([0, 1]);
  });
});

describe('readPendingApprovals', () => {
  it('reads a pending row through with the digits its screen must show', () => {
    expect(
      readPendingApprovals([
        {
          requestId: 'req-1',
          requesterDevicePublicKey: 'ed25519hex',
          ephemeralPublicKey: '02beef',
          comparisonValue: '482913',
          createdAt: '2026-08-27T10:00:00.000Z',
          expiresAt: '2026-08-27T10:05:00.000Z',
        },
      ])
    ).toEqual([
      {
        requestId: 'req-1',
        requesterDevicePublicKey: 'ed25519hex',
        ephemeralPublicKey: '02beef',
        comparisonValue: '482913',
        createdAt: '2026-08-27T10:00:00.000Z',
        expiresAt: '2026-08-27T10:05:00.000Z',
      },
    ]);
  });
});

describe('readEvent', () => {
  it('maps renewalFailed instead of throwing (the transport-bricking bug)', () => {
    const event: WasmEvent = {
      kind: 'renewalFailed',
      routingKey: 'k51qzi5uqu5dr',
      detail: 'record rejected',
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'renewalFailed',
      routingKey: 'k51qzi5uqu5dr',
      detail: 'record rejected',
    });
  });

  it('maps scopeExitCutOwed so an uncut scope reaches the host', () => {
    const scopeRoot = new Uint8Array(16).fill(0x9e);
    const event: WasmEvent = {
      kind: 'scopeExitCutOwed',
      scopeRoot,
      detail: 'publish-failed',
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'scopeExitCutOwed',
      scopeRoot,
      detail: 'publish-failed',
    });
  });

  it('maps the payload-free unjournaled registry debt', () => {
    expect(readEvent(fakeWasm, { kind: 'registryDebtUnjournaled' })).toEqual({
      kind: 'registryDebtUnjournaled',
    });
  });

  it('maps the payload-free grantee-name cache reset', () => {
    expect(readEvent(fakeWasm, { kind: 'granteeNamesCleared' })).toEqual({
      kind: 'granteeNamesCleared',
    });
  });

  it('maps granteeJoined so the owner sees who joined which scope', () => {
    const scopeRoot = new Uint8Array(16).fill(0x5a);
    const event: WasmEvent = {
      kind: 'granteeJoined',
      scopeRoot,
      name: 'Grace',
      fingerprint: 'ab12-cd34',
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'granteeJoined',
      scopeRoot,
      name: 'Grace',
      fingerprint: 'ab12-cd34',
    });
  });

  it.each(['conversionRecordUnreadable', 'refusedClaimDropped'] as const)(
    'maps the payload-free %s notice',
    (kind) => {
      expect(readEvent(fakeWasm, { kind })).toEqual({ kind });
    }
  );

  it('maps the payload-free parked-writes refusal', () => {
    expect(readEvent(fakeWasm, { kind: 'parkedWritesUnreadable' })).toEqual({
      kind: 'parkedWritesUnreadable',
    });
  });

  it('maps the payload-free settings change', () => {
    expect(readEvent(fakeWasm, { kind: 'vaultSettingsChanged' })).toEqual({
      kind: 'vaultSettingsChanged',
    });
  });

  it('maps a full opProgress payload to string-literal phase', () => {
    const node = new Uint8Array(16).fill(3);
    const event: WasmEvent = {
      kind: 'opProgress',
      opId: 7n,
      node,
      phase: 2,
      error: 'unavailable',
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'opProgress',
      opId: 7n,
      node,
      phase: 'downloadFailed',
      blocksConfirmed: null,
      blocksTotal: null,
      error: 'unavailable',
    });
  });

  it('maps an op-less, error-less opProgress to nulls', () => {
    const event: WasmEvent = { kind: 'opProgress', node: new Uint8Array(16), phase: 0 };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'opProgress',
      opId: null,
      node: new Uint8Array(16),
      phase: 'downloadStarted',
      blocksConfirmed: null,
      blocksTotal: null,
      error: null,
    });
  });

  it('carries an upload phase and its block counters through to the descriptor', () => {
    const node = new Uint8Array(16).fill(4);
    const event: WasmEvent = {
      kind: 'opProgress',
      opId: 9n,
      node,
      phase: fakeWasm.OpPhase.UploadProgress,
      blocksConfirmed: 3,
      blocksTotal: 8,
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'opProgress',
      opId: 9n,
      node,
      phase: 'uploadProgress',
      blocksConfirmed: 3,
      blocksTotal: 8,
      error: null,
    });
  });

  it('carries a dead letter reason through to the descriptor', () => {
    const event: WasmEvent = { kind: 'deadLetter', opId: 7n, deadLetterReason: 2 };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'deadLetter',
      opId: 7n,
      reason: 'destinationInsideTarget',
    });
  });

  it('maps the unrecoverable-content dead letter reason', () => {
    const event: WasmEvent = { kind: 'deadLetter', opId: 4n, deadLetterReason: 7 };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'deadLetter',
      opId: 4n,
      reason: 'contentUnrecoverable',
    });
  });

  it('maps the two reasons an abandonment reports about the record plane', () => {
    expect(readEvent(fakeWasm, { kind: 'deadLetter', opId: 1n, deadLetterReason: 10 })).toEqual({
      kind: 'deadLetter',
      opId: 1n,
      reason: 'preservationRefused',
    });
    expect(readEvent(fakeWasm, { kind: 'deadLetter', opId: 2n, deadLetterReason: 11 })).toEqual({
      kind: 'deadLetter',
      opId: 2n,
      reason: 'alreadyPublished',
    });
  });

  it('fails closed on an unknown or absent dead letter reason', () => {
    expect(() =>
      readEvent(fakeWasm, { kind: 'deadLetter', opId: 7n, deadLetterReason: 42 })
    ).toThrow('unknown WASM dead letter reason value: 42');
    expect(() => readEvent(fakeWasm, { kind: 'deadLetter', opId: 7n })).toThrow(
      'unknown WASM dead letter reason value: undefined'
    );
  });

  it('fails closed on an unknown opProgress phase', () => {
    const event: WasmEvent = { kind: 'opProgress', node: new Uint8Array(16), phase: 99 };
    expect(() => readEvent(fakeWasm, event)).toThrow('unknown WASM op phase value: 99');
    expect(() => readEvent(fakeWasm, { kind: 'opProgress', node: new Uint8Array(16) })).toThrow(
      'unknown WASM op phase value'
    );
  });
});

/** An empty view: nothing pending, nothing dead-lettered, nothing held. */
function baseView(): WasmSnapshotView {
  return {
    root: new Uint8Array(16),
    folder: new Uint8Array(16),
    folderName: '',
    permission: fakeWasmEnums.ViewPermission.Write,
    receivedShare: false,
    children: [],
    ancestors: [],
    deadLetters: [],
    retainedRecords: 0,
    staleness: 0,
  };
}

describe('readSnapshot', () => {
  it('maps every field, including bigint dead letters and null size/mtime', () => {
    const view: WasmSnapshotView = {
      root: new Uint8Array(16).fill(1),
      folder: new Uint8Array(16).fill(2),
      folderName: 'holiday',
      permission: fakeWasmEnums.ViewPermission.Read,
      receivedShare: true,
      children: [
        {
          id: new Uint8Array(16).fill(3),
          name: 'photo.jpg',
          kind: 0,
          size: 1024n,
          mtime: 1_700_000_000_000n,
          pending: 2,
          deadLetter: false,
          pendingInviteClaims: 0,
          contentVersion: 2n,
          contentCid: new Uint8Array([0xc1, 0xd0]),
          ipnsName: 'k51qzi5uqu5djmw2yvf8kk5cdjc1ddc00o4d5sjwi6f79xzcay9j3gkddw5uu4',
        },
        {
          id: new Uint8Array(16).fill(4),
          name: 'docs',
          kind: 1,
          pending: 0,
          deadLetter: true,
          pendingInviteClaims: 3,
        },
        {
          id: new Uint8Array(16).fill(5),
          name: 'renamed.txt',
          kind: 0,
          pending: 1,
          deadLetter: false,
          pendingInviteClaims: 0,
        },
      ],
      ancestors: [{ id: new Uint8Array(16).fill(1), name: '' }],
      deadLetters: [
        { opId: 9n, reason: 4 },
        { opId: 9_007_199_254_740_993n, reason: 6 },
      ],
      queueHold: {
        opId: 12n,
        node: new Uint8Array(16).fill(6),
        reason: 'quota',
        neededBytes: 9_007_199_254_740_993n,
      },
      retainedRecords: 2,
      staleness: 1,
    };

    expect(readSnapshot(fakeWasm, view)).toEqual({
      root: new Uint8Array(16).fill(1),
      folder: new Uint8Array(16).fill(2),
      folderName: 'holiday',
      permission: 'read',
      receivedShare: true,
      children: [
        {
          id: new Uint8Array(16).fill(3),
          name: 'photo.jpg',
          kind: 'file',
          size: 1024n,
          mtime: 1_700_000_000_000n,
          pending: 'content',
          deadLetter: false,
          pendingInviteClaims: 0,
          contentVersion: 2n,
          contentCid: new Uint8Array([0xc1, 0xd0]),
          ipnsName: 'k51qzi5uqu5djmw2yvf8kk5cdjc1ddc00o4d5sjwi6f79xzcay9j3gkddw5uu4',
        },
        {
          id: new Uint8Array(16).fill(4),
          name: 'docs',
          kind: 'folder',
          size: null,
          mtime: null,
          pending: 'none',
          deadLetter: true,
          pendingInviteClaims: 3,
          contentVersion: null,
          contentCid: null,
          ipnsName: null,
        },
        {
          id: new Uint8Array(16).fill(5),
          name: 'renamed.txt',
          kind: 'file',
          size: null,
          mtime: null,
          pending: 'metadata',
          deadLetter: false,
          pendingInviteClaims: 0,
          contentVersion: null,
          contentCid: null,
          ipnsName: null,
        },
      ],
      ancestors: [{ id: new Uint8Array(16).fill(1), name: '' }],
      deadLetters: [
        { opId: 9n, reason: 'undecodable' },
        { opId: 9_007_199_254_740_993n, reason: 'attemptsExhausted' },
      ],
      queueHold: {
        opId: 12n,
        node: new Uint8Array(16).fill(6),
        reason: 'quota',
        neededBytes: 9_007_199_254_740_993n,
      },
      retainedRecords: 2,
      staleness: 'reconciling',
    });
  });

  it('maps an absent hold to null', () => {
    expect(readSnapshot(fakeWasm, baseView()).queueHold).toBeNull();
  });

  it('reads a held head by its reason', () => {
    const view = {
      ...baseView(),
      queueHold: {
        opId: 13n,
        node: new Uint8Array(16).fill(7),
        reason: 'settings',
        check: 'byo-provider-missing',
      },
    };
    expect(readSnapshot(fakeWasm, view).queueHold).toEqual({
      opId: 13n,
      node: new Uint8Array(16).fill(7),
      reason: 'settings',
      check: 'byo-provider-missing',
    });
  });

  it('reads a stranded settings mint as a settings hold', () => {
    const view = {
      ...baseView(),
      queueHold: {
        opId: 14n,
        node: new Uint8Array(16).fill(7),
        reason: 'settings',
        check: 'settings-unavailable',
      },
    };
    expect(readSnapshot(fakeWasm, view).queueHold).toEqual({
      opId: 14n,
      node: new Uint8Array(16).fill(7),
      reason: 'settings',
      check: 'settings-unavailable',
    });
  });

  it('fails closed on a hold reason this build cannot name', () => {
    const view = {
      ...baseView(),
      queueHold: { opId: 1n, node: new Uint8Array(16), reason: 'weather' },
    };
    expect(() => readSnapshot(fakeWasm, view)).toThrow('unknown WASM queue hold reason: weather');
  });

  it('fails closed on a quota hold that carries no byte count', () => {
    const view = {
      ...baseView(),
      queueHold: { opId: 1n, node: new Uint8Array(16), reason: 'quota' },
    };
    expect(() => readSnapshot(fakeWasm, view)).toThrow('WASM quota hold carries no byte count');
  });

  it('fails closed on a hold check this build cannot name', () => {
    const settings = {
      ...baseView(),
      queueHold: {
        opId: 1n,
        node: new Uint8Array(16),
        reason: 'settings',
        check: 'byo-unreachable',
      },
    };
    expect(() => readSnapshot(fakeWasm, settings)).toThrow(
      'unknown WASM settings hold check: byo-unreachable'
    );

    const bin = {
      ...baseView(),
      queueHold: {
        opId: 1n,
        node: new Uint8Array(16),
        reason: 'bin-index',
        check: 'stranded-mint',
      },
    };
    expect(() => readSnapshot(fakeWasm, bin)).toThrow(
      'unknown WASM bin-index hold check: stranded-mint'
    );
  });

  it('holds each check vocabulary apart', () => {
    const crossed = {
      ...baseView(),
      queueHold: { opId: 1n, node: new Uint8Array(16), reason: 'settings', check: 'suppressed' },
    };
    expect(() => readSnapshot(fakeWasm, crossed)).toThrow('unknown WASM settings hold check');
  });

  it('fails closed on an unknown dead letter reason', () => {
    expect(() =>
      readSnapshot(fakeWasm, { ...baseView(), deadLetters: [{ opId: 1n, reason: 42 }] })
    ).toThrow('unknown WASM dead letter reason value: 42');
  });

  it('fails closed on an unknown child kind, pending class or staleness value', () => {
    const base = baseView();
    expect(() => readSnapshot(fakeWasm, { ...base, staleness: 42 })).toThrow(
      'unknown WASM staleness value: 42'
    );
    expect(() =>
      readSnapshot(fakeWasm, {
        ...base,
        children: [
          {
            id: new Uint8Array(16),
            name: 'x',
            kind: 42,
            pending: 0,
            deadLetter: false,
            pendingInviteClaims: 0,
          },
        ],
      })
    ).toThrow('unknown WASM node kind value: 42');
    expect(() =>
      readSnapshot(fakeWasm, {
        ...base,
        children: [
          {
            id: new Uint8Array(16),
            name: 'x',
            kind: 0,
            pending: 42,
            deadLetter: false,
            pendingInviteClaims: 0,
          },
        ],
      })
    ).toThrow('unknown WASM pending class value: 42');
  });
});

describe('readSharing', () => {
  const link = {
    tag: new Uint8Array(32).fill(0x7a),
    permission: fakeWasmEnums.ViewPermission.Write,
    expiresAt: 1_700_000_000_000n,
    expired: false,
    admissionCap: 5n,
    pendingClaims: 1,
    contactBudgetFull: true,
    refusedClaims: 2,
  };
  const view = {
    scope: new Uint8Array(16).fill(3),
    contacts: [{ identityPublicKey: new Uint8Array([1]), cachedName: 'Ada' }],
    ownContactCode: new Uint8Array([4, 5, 6]),
    state: {
      grants: [
        {
          recipientIdentityPublicKey: new Uint8Array([2]),
          permission: fakeWasmEnums.ViewPermission.Read,
          granteeName: { name: 'Ada', source: 'claimant' },
          viaLink: new Uint8Array(32).fill(0x7a),
        },
      ],
      grantRefusal: 'grant-parent-envelope-version-unsupported',
      inviteLinkRefusal: 'invite-parent-envelope-version-unsupported',
      inviteLinks: [link],
      readEpoch: 9_007_199_254_740_993n,
      writeEpoch: 1n,
    },
  };

  it('carries the scope, its grants and its link standing through unchanged', () => {
    expect(readSharing(fakeWasm, view)).toEqual({
      scope: view.scope,
      contacts: [{ identityPublicKey: view.contacts[0].identityPublicKey, cachedName: 'Ada' }],
      ownContactCode: view.ownContactCode,
      state: {
        grants: [
          {
            recipientIdentityPublicKey: new Uint8Array([2]),
            permission: 'read',
            granteeName: { name: 'Ada', source: 'claimant' },
            viaLink: new Uint8Array(32).fill(0x7a),
          },
        ],
        grantRefusal: 'grant-parent-envelope-version-unsupported',
        inviteLinkRefusal: 'invite-parent-envelope-version-unsupported',
        inviteLinks: [
          {
            tag: link.tag,
            permission: 'write',
            expiresAt: 1_700_000_000_000n,
            expired: false,
            admissionCap: 5,
            pendingClaims: 1,
            contactBudgetFull: true,
            refusedClaims: 2,
          },
        ],
        epochs: { readEpoch: 9_007_199_254_740_993n, writeEpoch: 1n },
      },
    });
  });

  it('reads a node that is no scope root as carrying no epochs', () => {
    const plain = {
      ...view,
      state: { ...view.state, readEpoch: undefined, writeEpoch: undefined },
    };

    expect(readSharing(fakeWasm, plain).state?.epochs).toBeNull();
  });

  it('reads an unnamed direct row and an uncached contact as null', () => {
    const unnamed = {
      ...view,
      contacts: [{ identityPublicKey: new Uint8Array([1]), cachedName: undefined }],
      state: {
        ...view.state,
        grants: [{ ...view.state.grants[0], granteeName: undefined, viaLink: undefined }],
      },
    };

    const read = readSharing(fakeWasm, unnamed);
    expect(read.contacts[0].cachedName).toBeNull();
    expect(read.state?.grants[0].granteeName).toBeNull();
    expect(read.state?.grants[0].viaLink).toBeNull();
  });

  it('refuses a grantee name whose source this build does not know', () => {
    const drifted = {
      ...view,
      state: {
        ...view.state,
        grants: [{ ...view.state.grants[0], granteeName: { name: 'Ada', source: 'admin' } }],
      },
    };

    expect(() => readSharing(fakeWasm, drifted)).toThrow('unknown WASM grantee name source: admin');
  });

  it('reads every link the commitment carries, an expired one included', () => {
    const expired = { ...link, tag: new Uint8Array(32).fill(0x7b), expired: true };
    const both = { ...view, state: { ...view.state, inviteLinks: [link, expired] } };

    const read = readSharing(fakeWasm, both).state?.inviteLinks;
    expect(read?.map((each) => each.tag)).toEqual([link.tag, expired.tag]);
    expect(read?.map((each) => each.expired)).toEqual([false, true]);
  });

  it('refuses a link permission this build does not know', () => {
    const drifted = {
      ...view,
      state: { ...view.state, inviteLinks: [{ ...link, permission: 42 }] },
    };

    expect(() => readSharing(fakeWasm, drifted)).toThrow('unknown WASM permission value: 42');
  });

  it('reads an unreachable scope as absent, never as one granting nothing', () => {
    expect(readSharing(fakeWasm, { ...view, state: undefined }).state).toBeNull();
  });

  it("hands out this member's own contact code even when the scope is unreachable", () => {
    // The exchange's outbound half does not depend on any scope read.
    expect(readSharing(fakeWasm, { ...view, state: undefined }).ownContactCode).toEqual(
      view.ownContactCode
    );
  });
});

describe('readReceivedShare', () => {
  const row = {
    scope: new Uint8Array(16).fill(7),
    sharerIdentityPublicKey: new Uint8Array([9]),
    displayName: 'shared-folder',
    permission: fakeWasmEnums.ViewPermission.Read,
    resolution: 'revocation-signal',
    viaLink: true,
  };

  it('carries the row, the engine verdict and the link it reads through unchanged', () => {
    expect(readReceivedShare(fakeWasm, row)).toEqual({
      scope: row.scope,
      sharerIdentityPublicKey: row.sharerIdentityPublicKey,
      displayName: 'shared-folder',
      permission: 'read',
      resolution: 'revocation-signal',
      viaLink: true,
    });
    expect(readReceivedShare(fakeWasm, { ...row, viaLink: false }).viaLink).toBe(false);
  });

  it('carries an expired link through as the expired verdict', () => {
    expect(readReceivedShare(fakeWasm, { ...row, resolution: 'expired' }).resolution).toBe(
      'expired'
    );
  });

  it('reads an absent verdict as null, never as a verdict', () => {
    expect(readReceivedShare(fakeWasm, { ...row, resolution: undefined }).resolution).toBeNull();
  });

  it('fails closed on a class it cannot map', () => {
    // A guessed class would paint a revoked share as still granted.
    expect(() => readReceivedShare(fakeWasm, { ...row, resolution: 'granted-ish' })).toThrow(
      'unknown WASM resolution class: granted-ish'
    );
  });
});

describe('readInvitePreview', () => {
  const preview = {
    scope: new Uint8Array(16).fill(4),
    ownerName: 'Ada',
    folderName: 'trips',
    permission: fakeWasmEnums.ViewPermission.Write,
    state: 'live',
    joined: false,
    listing: [
      { name: 'drafts', kind: fakeWasmEnums.NodeKind.Folder },
      { name: 'notes.txt', kind: fakeWasmEnums.NodeKind.File },
    ],
  };

  it('carries the scope, the verified names, the permission, the state and the listing', () => {
    expect(readInvitePreview(fakeWasm, preview)).toEqual({
      scope: new Uint8Array(16).fill(4),
      names: { ownerName: 'Ada', folderName: 'trips' },
      permission: 'write',
      state: 'live',
      joined: false,
      listing: [
        { name: 'drafts', kind: 'folder' },
        { name: 'notes.txt', kind: 'file' },
      ],
    });
  });

  it('reads absent names and an absent permission as null', () => {
    const unverified = readInvitePreview(fakeWasm, {
      ...preview,
      ownerName: undefined,
      folderName: undefined,
      permission: undefined,
      state: 'unresolvable',
      listing: [],
    });
    expect(unverified.names).toBeNull();
    expect(unverified.permission).toBeNull();
    expect(unverified.state).toBe('unresolvable');
  });

  it('fails closed on one name without the other', () => {
    expect(() => readInvitePreview(fakeWasm, { ...preview, folderName: undefined })).toThrow(
      'WASM invite preview carries one name without the other'
    );
  });

  it('fails closed on a state it cannot map', () => {
    expect(() => readInvitePreview(fakeWasm, { ...preview, state: 'joinable' })).toThrow(
      'unknown WASM invite preview state: joinable'
    );
  });
});

describe('readBin', () => {
  const view = (): WasmBinView => ({
    entries: [
      {
        node: new Uint8Array(16).fill(4),
        kind: fakeWasmEnums.NodeKind.Folder,
        originParent: new Uint8Array(16).fill(1),
        originName: 'holiday',
        originFolderKind: fakeWasmEnums.BinOriginKind.Folder,
        originFolderName: 'trips',
        deletedAt: 1_800_000_000_000n,
        scope: new Uint8Array(16).fill(2),
      },
    ],
    origin: fakeWasmEnums.SettingsOrigin.Resolved,
  });

  it('reads the rows and the rung the index load reached through', () => {
    expect(readBin(fakeWasm, view())).toEqual({
      entries: [
        {
          node: new Uint8Array(16).fill(4),
          kind: 'folder',
          originParent: new Uint8Array(16).fill(1),
          originName: 'holiday',
          originFolder: { kind: 'folder', name: 'trips' },
          deletedAt: 1_800_000_000_000n,
          scope: new Uint8Array(16).fill(2),
        },
      ],
      origin: 'resolved',
    });
  });

  it('reads a bin no index backed as the defaults rung', () => {
    // The empty entries are the fallback, which a surface renders apart from a
    // bin it read.
    expect(
      readBin(fakeWasm, { entries: [], origin: fakeWasmEnums.SettingsOrigin.Defaults })
    ).toEqual({ entries: [], origin: 'defaults' });
  });

  it('fails closed on a row kind it cannot map', () => {
    const base = view();
    expect(() =>
      readBin(fakeWasm, { ...base, entries: [{ ...base.entries[0]!, kind: 42 }] })
    ).toThrow('unknown WASM node kind value: 42');
  });

  it('fails closed on an origin it cannot map', () => {
    // A guessed origin would present the fallback as a bin this device read.
    expect(() => readBin(fakeWasm, { ...view(), origin: 42 })).toThrow(
      'unknown WASM settings origin value: 42'
    );
  });

  it('reads the root and a gone origin folder apart, and neither as a name', () => {
    const base = view();
    const rowFor = (originFolderKind: number, originFolderName: string) =>
      readBin(fakeWasm, {
        ...base,
        entries: [{ ...base.entries[0]!, originFolderKind, originFolderName }],
      }).entries[0]!.originFolder;

    expect(rowFor(fakeWasmEnums.BinOriginKind.Root, '')).toEqual({ kind: 'root' });
    expect(rowFor(fakeWasmEnums.BinOriginKind.Gone, '')).toEqual({ kind: 'gone' });
  });

  it('fails closed on an origin folder kind it cannot map', () => {
    // A guessed kind would name a folder the engine did not.
    const base = view();
    expect(() =>
      readBin(fakeWasm, { ...base, entries: [{ ...base.entries[0]!, originFolderKind: 42 }] })
    ).toThrow('unknown WASM bin origin kind value: 42');
  });
});

describe('readVaultStorage', () => {
  const view = (): WasmVaultStorageView => ({
    settings: {
      pinMode: fakeWasmEnums.ViewPinMode.Dual,
      byoEndpoint: 'https://kubo.example',
      byoKind: fakeWasmEnums.ViewByoKind.Psa,
      byoCredentialStored: true,
      keepLatestVersions: 5,
      binRetentionDays: 30,
      origin: fakeWasmEnums.SettingsOrigin.Stale,
    },
    quota: { usedBytes: 512n, limitBytes: 2048n, advisory: true },
    pendingReclaimBytes: 0n,
    pendingReclaimIsPartial: true,
    reclaimStalls: [
      {
        node: new Uint8Array(16).fill(3),
        target: 'bafyDoomedRoot',
        reason: fakeWasmEnums.ReclaimStallReason.TargetStillLive,
      },
    ],
  });

  it('reads the settings, the quota and the stalled debts through', () => {
    expect(readVaultStorage(fakeWasm, view())).toEqual({
      settings: {
        pinMode: 'dual',
        byoEndpoint: 'https://kubo.example',
        byoKind: 'psa',
        byoCredentialStored: true,
        keepLatestVersions: 5,
        binRetentionDays: 30,
        origin: 'stale',
      },
      quota: { usedBytes: 512, limitBytes: 2048, advisory: true },
      pendingReclaimBytes: 0,
      pendingReclaimIsPartial: true,
      reclaimStalls: [
        { node: new Uint8Array(16).fill(3), target: 'bafyDoomedRoot', reason: 'targetStillLive' },
      ],
    });
  });

  it('reads a vault with no provider and an unanswered probe as null, never as blank', () => {
    const bare = readVaultStorage(fakeWasm, {
      ...view(),
      settings: {
        pinMode: fakeWasmEnums.ViewPinMode.Hosted,
        byoEndpoint: undefined,
        byoKind: undefined,
        byoCredentialStored: false,
        keepLatestVersions: undefined,
        binRetentionDays: 0,
        origin: fakeWasmEnums.SettingsOrigin.Defaults,
      },
      quota: undefined,
    });

    expect(bare.settings.byoEndpoint).toBeNull();
    expect(bare.settings.byoKind).toBeNull();
    expect(bare.settings.keepLatestVersions).toBeNull();
    expect(bare.quota).toBeNull();
  });

  it.each([
    ['pin mode', { pinMode: 42 }, 'unknown WASM pin mode value: 42'],
    ['provider kind', { byoKind: 42 }, 'unknown WASM provider kind value: 42'],
    ['settings origin', { origin: 42 }, 'unknown WASM settings origin value: 42'],
  ])('fails closed on a %s it cannot map', (_name, override, message) => {
    const base = view();
    expect(() =>
      readVaultStorage(fakeWasm, { ...base, settings: { ...base.settings, ...override } })
    ).toThrow(message);
  });

  it('fails closed on a stall reason it cannot map', () => {
    // A guessed reason would tell a member the wrong thing about a debt that
    // never drains.
    const base = view();
    expect(() =>
      readVaultStorage(fakeWasm, {
        ...base,
        reclaimStalls: [{ ...base.reclaimStalls[0]!, reason: 42 }],
      })
    ).toThrow('unknown WASM reclaim stall reason value: 42');
  });
});

describe('readAuthMethods', () => {
  const row = {
    id: '3f2a-uuid',
    kind: fakeWasmEnums.AuthMethodKind.Wallet,
    identifierDisplay: '0x1234…abcd',
    createdAt: '2026-08-27T10:00:00.000Z',
    lastUsedAt: '2026-08-27T11:00:00.000Z',
  };

  it('reads the display form through, and an absent one as null', () => {
    // The second row is the kind this build does not know: the engine already
    // spells it `Unknown`, and a row is a display fact, not a trust decision.
    expect(
      readAuthMethods(fakeWasm, [
        row,
        {
          ...row,
          kind: fakeWasmEnums.AuthMethodKind.Unknown,
          identifierDisplay: undefined,
          lastUsedAt: undefined,
        },
      ])
    ).toEqual([
      {
        id: '3f2a-uuid',
        kind: 'wallet',
        identifierDisplay: '0x1234…abcd',
        createdAt: '2026-08-27T10:00:00.000Z',
        lastUsedAt: '2026-08-27T11:00:00.000Z',
      },
      {
        id: '3f2a-uuid',
        kind: 'unknown',
        identifierDisplay: null,
        createdAt: '2026-08-27T10:00:00.000Z',
        lastUsedAt: null,
      },
    ]);
  });

  it('fails closed on a kind value it cannot map', () => {
    expect(() => readAuthMethods(fakeWasm, [{ ...row, kind: 42 }])).toThrow(
      'unknown WASM auth method kind value: 42'
    );
  });
});
