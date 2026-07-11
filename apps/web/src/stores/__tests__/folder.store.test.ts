/**
 * Folder Store Projection Tests
 *
 * The folder store's `children` + `sequenceNumber` are PROJECTION-ONLY state:
 * the ONLY path that writes them from SDK-routed mutations is the
 * `subscribeToSdk` handler reacting to `folder:loaded` / `folder:updated`
 * events. These tests prove that the handler projects children + sequenceNumber
 * into Zustand, keyed by a reverse `ipnsName` lookup, INCLUDING the root folder,
 * and that an unknown ipnsName is a safe no-op.
 *
 * Plan 09 (68.2-09) collapsed the handler to a PURE synchronous projection:
 * `event.children` arrives as `ResolvedChild[]`, fully resolved (kind/size/
 * modifiedAt pre-resolved by the SDK, 68.2-02) — there is no web-side
 * resolveKinds/kind-cache side-channel anymore (SC#3, D-01). Only the
 * load-bearing 68.1 staleness guards remain: the empty-over-populated guard
 * (T-68.1-26-01) and the stale-event sequence guard (T-68.1-33-01).
 *
 * See: phase 47 (sdk-folder-state-publish-consolidation), REQ-1, Assumption A2;
 * phase 68.1-26 (empty-over-non-empty guard); phase 68.2-09 (ResolvedChild
 * projection collapse).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { ResolvedChild } from '@cipherbox/sdk';
import type { CipherBoxClient } from '@cipherbox/sdk';
import type { SdkEvent, SdkEventHandler } from '@cipherbox/sdk';
import { useFolderStore, type FolderNode } from '../folder.store';

/**
 * Build a minimal fake CipherBoxClient that captures the handler passed to
 * `on()`. `subscribeToSdk` only uses `client.on(handler)`, so we can return a
 * tiny fake and drive the captured handler directly with typed events.
 */
function makeFakeClient(): {
  client: CipherBoxClient;
  emit: (event: SdkEvent) => void;
} {
  let captured: SdkEventHandler | null = null;
  const client = {
    on(handler: SdkEventHandler): () => void {
      captured = handler;
      return () => {
        captured = null;
      };
    },
  } as unknown as CipherBoxClient;

  return {
    client,
    emit: (event) => {
      if (!captured) throw new Error('handler not subscribed');
      captured(event);
    },
  };
}

/** Helper: build a ResolvedChild fixture with a recognizable name. */
function makeChild(name: string, modifiedAt = 1000): ResolvedChild {
  return {
    ipnsName: `k51file-${name}`,
    name,
    kind: 'file',
    createdAt: 0,
    modifiedAt,
    sequence: 0,
  };
}

/** Helper: build a FolderNode fixture for seeding the store. */
function makeFolderNode(overrides: Partial<FolderNode>): FolderNode {
  return {
    id: 'f1',
    name: 'Folder',
    ipnsName: 'k51child',
    parentId: 'root',
    children: [makeChild('old')],
    isLoaded: false,
    isLoading: false,
    sequenceNumber: 1n,
    folderKey: new Uint8Array(32).fill(1),
    ipnsPrivateKey: new Uint8Array(32).fill(2),
    ...overrides,
  };
}

describe('useFolderStore — subscribeToSdk projection', () => {
  beforeEach(() => {
    // Reset store + module-level subscription before each test.
    useFolderStore.getState().clearFolders();
    useFolderStore.setState({
      folders: {},
      currentFolderId: null,
      breadcrumbs: [],
      pendingPublishes: new Set<string>(),
    });
  });

  it('projects children + sequenceNumber on folder:updated (reverse ipnsName lookup)', () => {
    const node = makeFolderNode({ id: 'f1', ipnsName: 'k51child' });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    const newChildren = [makeChild('new', 5000)];
    emit({
      type: 'folder:updated',
      // SDK uses ipnsName as folderId
      folderId: 'k51child',
      ipnsName: 'k51child',
      children: newChildren,
      sequenceNumber: 3n,
    });

    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual(newChildren);
    expect(folder.children[0].name).toBe('new');
    expect(folder.sequenceNumber).toBe(3n);
    // updateFolderChildren also flips isLoaded true (projection marks loaded).
    expect(folder.isLoaded).toBe(true);
    expect(folder.isLoading).toBe(false);
  });

  it('projects onto the ROOT folder via reverse ipnsName lookup (Assumption A2)', () => {
    // Root is a normal entry keyed id:'root' — matching is by ipnsName, not id.
    const rootNode = makeFolderNode({
      id: 'root',
      name: 'Root',
      ipnsName: 'k51root',
      parentId: null,
      children: [makeChild('rootOld')],
      sequenceNumber: 7n,
    });
    useFolderStore.getState().setFolder(rootNode);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    const rootChildren = [makeChild('rootNew', 9000)];
    emit({
      type: 'folder:updated',
      folderId: 'k51root',
      ipnsName: 'k51root',
      children: rootChildren,
      sequenceNumber: 12n,
    });

    const root = useFolderStore.getState().folders['root'];
    expect(root.children).toEqual(rootChildren);
    expect(root.children[0].name).toBe('rootNew');
    expect(root.sequenceNumber).toBe(12n);
  });

  it('also projects on folder:loaded', () => {
    const node = makeFolderNode({ id: 'f1', ipnsName: 'k51child', sequenceNumber: 1n });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    const loadedChildren = [makeChild('loaded', 2222)];
    emit({
      type: 'folder:loaded',
      folderId: 'k51child',
      ipnsName: 'k51child',
      children: loadedChildren,
      sequenceNumber: 4n,
    });

    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual(loadedChildren);
    expect(folder.sequenceNumber).toBe(4n);
    expect(folder.isLoaded).toBe(true);
  });

  it('is a no-op for an unknown ipnsName (no throw, no state change)', () => {
    const node = makeFolderNode({ id: 'f1', ipnsName: 'k51child', sequenceNumber: 1n });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    const before = useFolderStore.getState().folders['f1'];

    expect(() =>
      emit({
        type: 'folder:updated',
        folderId: 'k51unknown',
        ipnsName: 'k51unknown',
        children: [makeChild('ignored')],
        sequenceNumber: 99n,
      })
    ).not.toThrow();

    const after = useFolderStore.getState().folders['f1'];
    // Unchanged: same children reference + same sequence.
    expect(after.children).toBe(before.children);
    expect(after.sequenceNumber).toBe(1n);
    expect(after.isLoaded).toBe(false);
  });

  it('keeps updateFolderChildren / updateFolderSequence actions available (resync paths)', () => {
    const node = makeFolderNode({ id: 'f1', ipnsName: 'k51child', sequenceNumber: 1n });
    useFolderStore.getState().setFolder(node);

    const actions = useFolderStore.getState();
    expect(typeof actions.updateFolderChildren).toBe('function');
    expect(typeof actions.updateFolderSequence).toBe('function');
    expect(typeof actions.updateFolderRawChildren).toBe('function');

    const resyncChildren = [makeChild('resync')];
    actions.updateFolderChildren('f1', resyncChildren);
    actions.updateFolderSequence('f1', 8n);

    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual(resyncChildren);
    expect(folder.sequenceNumber).toBe(8n);
  });

  // -------------------------------------------------------------------------
  // Pure synchronous projection (Plan 09 collapse) — every event applies
  // immediately, no resolveKinds/cache-miss branch exists anymore.
  // -------------------------------------------------------------------------

  it('projects children synchronously (no independent resolve, ResolvedChild arrives pre-resolved)', () => {
    const node = makeFolderNode({ id: 'f1', ipnsName: 'k51child', sequenceNumber: 1n });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    const newChildren = [makeChild('a'), makeChild('b')];

    emit({
      type: 'folder:updated',
      folderId: 'k51child',
      ipnsName: 'k51child',
      children: newChildren,
      sequenceNumber: 3n,
    });

    // Asserted IMMEDIATELY after emit — no awaited tick, no async branch.
    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual(newChildren);
    expect(folder.sequenceNumber).toBe(3n);
  });

  it('projects an empty children array synchronously (68.1-29 delete-last-item parity)', () => {
    const node = makeFolderNode({
      id: 'f1',
      ipnsName: 'k51child',
      isLoaded: true,
      children: [makeChild('last')],
      sequenceNumber: 5n,
    });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    // A newer sequence number passes the 68.1-26 guard (a genuine deletion),
    // so the empty array should project instantly.
    emit({
      type: 'folder:updated',
      folderId: 'k51child',
      ipnsName: 'k51child',
      children: [],
      sequenceNumber: 6n,
    });

    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual([]);
    expect(folder.sequenceNumber).toBe(6n);
  });

  it('still refuses an empty-over-non-empty event at or below the stored sequence (68.1-26 guard preserved)', () => {
    const node = makeFolderNode({
      id: 'f1',
      ipnsName: 'k51child',
      isLoaded: true,
      children: [makeChild('kept')],
      sequenceNumber: 5n,
    });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    // Stale/mismatched empty event at the SAME sequence — guard must reject.
    emit({
      type: 'folder:updated',
      folderId: 'k51child',
      ipnsName: 'k51child',
      children: [],
      sequenceNumber: 5n,
    });

    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual([makeChild('kept')]);
    expect(folder.sequenceNumber).toBe(5n);
  });

  it('refuses a stale event at a LOWER sequence than the store already holds (T-68.1-33-01 guard preserved)', () => {
    const node = makeFolderNode({
      id: 'f1',
      ipnsName: 'k51child',
      isLoaded: true,
      children: [makeChild('current')],
      sequenceNumber: 5n,
    });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    // Stale non-empty event at a lower sequence — must be rejected outright,
    // never clobbering the newer store state.
    emit({
      type: 'folder:updated',
      folderId: 'k51child',
      ipnsName: 'k51child',
      children: [makeChild('stale')],
      sequenceNumber: 2n,
    });

    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual([makeChild('current')]);
    expect(folder.sequenceNumber).toBe(5n);
  });

  it('adopts an event at an EQUAL-OR-NEWER sequence (strict `>` staleness guard)', () => {
    const node = makeFolderNode({
      id: 'f1',
      ipnsName: 'k51child',
      isLoaded: true,
      children: [makeChild('current')],
      sequenceNumber: 5n,
    });
    useFolderStore.getState().setFolder(node);

    const { client, emit } = makeFakeClient();
    useFolderStore.getState().subscribeToSdk(client);

    const equalSeqChildren = [makeChild('equal')];
    emit({
      type: 'folder:updated',
      folderId: 'k51child',
      ipnsName: 'k51child',
      children: equalSeqChildren,
      sequenceNumber: 5n,
    });

    const folder = useFolderStore.getState().folders['f1'];
    expect(folder.children).toEqual(equalSeqChildren);
    expect(folder.sequenceNumber).toBe(5n);
  });
});
