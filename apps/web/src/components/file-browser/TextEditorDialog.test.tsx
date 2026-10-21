import type { EngineClient } from '@cipherbox/client';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
import { fakeRead } from '../../test/readFakes';
import type { ListingRow } from '../../vault/listing';
import { TextEditorDialog } from './TextEditorDialog';

const NODE = new Uint8Array(16).fill(0xab);
const READ_AT = new Uint8Array([0xc1, 0xd0, 0x01]);
const LOADED = 'the text the editor read';

function row(overrides: Partial<ListingRow> = {}): ListingRow {
  return {
    id: NODE,
    key: 'abababab',
    name: 'notes.txt',
    storedName: 'notes.txt',
    kind: 'file',
    icon: '[FILE]',
    size: '24 B',
    bytes: BigInt(LOADED.length),
    contentVersion: 3n,
    contentCid: READ_AT,
    modified: '14 Nov 2023',
    pending: 'none',
    deadLetter: false,
    pendingInviteClaims: 0,
    ipnsName: null,
    ...overrides,
  };
}

/**
 * An engine that holds one newest version per file and refuses a save against
 * any other, as the handle does. A commit stages the next version; the row's
 * CID, the published head, does not move until a drain.
 */
function fakeClient(newest: Uint8Array = READ_AT) {
  const opened: { node: Uint8Array; expectedVersion?: Uint8Array }[] = [];
  const committed: Uint8Array[] = [];
  let current = newest;
  const bytes = () => new TextEncoder().encode(LOADED).buffer;
  const client = {
    facade: {
      subscribe: () => () => undefined,
      read: fakeRead({
        snapshot: () => new Promise(() => undefined),
        download: () => Promise.resolve(bytes()),
        servedContent: () => Promise.resolve({ bytes: bytes(), version: current }),
      }),
      setFocus: () => Promise.resolve(),
      beginWrite: (target: { node: Uint8Array; expectedVersion?: Uint8Array }) => {
        opened.push(target);
        const anchor = target.expectedVersion;
        if (anchor !== undefined && anchor.join() !== current.join()) {
          return Promise.reject(new Error('expected-version-is-not-the-newest'));
        }
        return Promise.resolve(1n);
      },
      pushChunk: () => Promise.resolve(),
      commitWrite: () => {
        current = Uint8Array.of(0xc2, committed.length);
        committed.push(current);
        return Promise.resolve(7n);
      },
      abortWrite: () => Promise.resolve(),
    },
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;
  return { client, opened, committed };
}

async function edited(listing: ListingRow, client: EngineClient) {
  const view = render(
    <EngineProvider createClient={() => client}>
      <TextEditorDialog row={listing} present onClose={() => undefined} />
    </EngineProvider>
  );
  const field = await screen.findByTestId('text-editor-field');
  fireEvent.change(field, { target: { value: 'edited text' } });
  fireEvent.click(screen.getByTestId('text-editor-save'));
  return view;
}

describe('the text editor', () => {
  it('anchors the save on the version the editor loaded', async () => {
    const { client, opened } = fakeClient();

    await edited(row(), client);

    await waitFor(() => expect(opened).toHaveLength(1));
    expect(opened[0]).toEqual({ node: NODE, expectedVersion: READ_AT });
  });

  it('saves a queued file against the version the read served', async () => {
    const queued = Uint8Array.of(0xb0, 0x0b);
    const { client, opened, committed } = fakeClient(queued);

    await edited(row({ contentCid: null }), client);

    await waitFor(() => expect(committed).toHaveLength(1));
    expect(opened[0]).toEqual({ node: NODE, expectedVersion: queued });
  });

  it('applies a second edit made before the drain publishes the first', async () => {
    const { client, opened, committed } = fakeClient();

    const first = await edited(row(), client);
    await waitFor(() => expect(committed).toHaveLength(1));
    first.unmount();

    await edited(row(), client);

    await waitFor(() => expect(committed).toHaveLength(2));
    expect(opened[1]).toEqual({ node: NODE, expectedVersion: committed[0] });
  });
});
