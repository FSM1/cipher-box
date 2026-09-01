import type { EngineClient } from '@cipherbox/client';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
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
    kind: 'file',
    icon: '[FILE]',
    size: '24 B',
    bytes: BigInt(LOADED.length),
    contentVersion: 3n,
    contentCid: READ_AT,
    modified: '14 Nov 2023',
    pending: 'none',
    deadLetter: false,
    ...overrides,
  };
}

function fakeClient() {
  const opened: { node: Uint8Array; expectedVersion?: Uint8Array }[] = [];
  const client = {
    facade: {
      subscribe: () => () => undefined,
      snapshot: () => new Promise(() => undefined),
      setFocus: () => Promise.resolve(),
      download: () => Promise.resolve(new TextEncoder().encode(LOADED)),
      beginWrite: (target: { node: Uint8Array; expectedVersion?: Uint8Array }) => {
        opened.push(target);
        return Promise.resolve(1n);
      },
      pushChunk: () => Promise.resolve(),
      commitWrite: () => Promise.resolve(7n),
      abortWrite: () => Promise.resolve(),
    },
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;
  return { client, opened };
}

async function edited(listing: ListingRow, client: EngineClient) {
  render(
    <EngineProvider createClient={() => client}>
      <TextEditorDialog row={listing} onClose={() => undefined} />
    </EngineProvider>
  );
  const field = await screen.findByTestId('text-editor-field');
  fireEvent.change(field, { target: { value: 'edited text' } });
  fireEvent.click(screen.getByTestId('text-editor-save'));
}

describe('the text editor', () => {
  it('anchors the save on the version the editor loaded', async () => {
    const { client, opened } = fakeClient();

    await edited(row(), client);

    await waitFor(() => expect(opened).toHaveLength(1));
    expect(opened[0]).toEqual({ node: NODE, expectedVersion: READ_AT });
  });

  it('leaves the anchor to the engine when the row has no projected version', async () => {
    const { client, opened } = fakeClient();

    await edited(row({ contentCid: null }), client);

    await waitFor(() => expect(opened).toHaveLength(1));
    expect(opened[0]).toEqual({ node: NODE, expectedVersion: undefined });
  });
});
