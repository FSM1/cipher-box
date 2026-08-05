import type { EngineClient, EventDescriptor } from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
import { UploadPanel } from './UploadPanel';

const FOLDER = new Uint8Array(16).fill(7);

/** The write-handle surface `useDropUpload` drives, held open at the commit. */
function uploadEngine() {
  let settle = () => undefined as void;
  const facade = {
    subscribe: (_listener: (event: EventDescriptor) => void) => () => undefined,
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    beginWrite: vi.fn(() => Promise.resolve(1n)),
    pushChunk: vi.fn(() => Promise.resolve()),
    commitWrite: vi.fn(
      () =>
        new Promise<bigint>((resolve) => {
          settle = () => resolve(1n);
        })
    ),
    abortWrite: vi.fn(() => Promise.resolve()),
    cancelUpload: vi.fn(() => Promise.resolve()),
  };
  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;
  return { client, facade, settle: () => settle() };
}

function draw(client: EngineClient, folder: Uint8Array | null) {
  return render(
    <EngineProvider createClient={() => client}>
      <UploadPanel folder={folder} />
    </EngineProvider>
  );
}

describe('the upload panel', () => {
  it('offers no drop target when no folder can take one', () => {
    draw(uploadEngine().client, null);
    expect(screen.queryByTestId('upload-zone')).toBeNull();
  });

  it('keeps a running upload on screen across a folder change', async () => {
    const engine = uploadEngine();
    const { rerender } = draw(engine.client, FOLDER);

    fireEvent.change(screen.getByLabelText('Choose files to upload'), {
      target: { files: [new File(['x'], 'notes.txt')] },
    });
    await waitFor(() => expect(screen.getByTestId('upload-row')).toBeTruthy());

    // The next folder's snapshot has not landed, so there is nowhere to drop.
    rerender(
      <EngineProvider createClient={() => engine.client}>
        <UploadPanel folder={null} />
      </EngineProvider>
    );

    expect(screen.queryByTestId('upload-zone')).toBeNull();
    expect(screen.getByTestId('upload-row')).toBeTruthy();
    expect(screen.getByLabelText('Cancel upload of notes.txt')).toBeTruthy();
    // The write kept its handle rather than being torn down with the zone.
    expect(engine.facade.abortWrite).not.toHaveBeenCalled();
    await act(async () => {
      engine.settle();
    });
  });

  it('drops files into the folder on screen', async () => {
    const engine = uploadEngine();
    draw(engine.client, FOLDER);

    fireEvent.drop(screen.getByTestId('upload-zone'), {
      dataTransfer: { files: [new File(['x'], 'notes.txt')], types: ['Files'], dropEffect: 'none' },
    });

    await waitFor(() =>
      expect(engine.facade.beginWrite).toHaveBeenCalledWith(
        { parent: FOLDER, name: 'notes.txt' },
        1
      )
    );
    await act(async () => {
      engine.settle();
    });
  });
});
