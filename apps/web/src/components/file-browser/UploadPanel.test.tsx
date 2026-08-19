import type { EngineClient, EventDescriptor, SnapshotDescriptor } from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ROOT_ID, view } from '../../engine/testFakes';
import { EngineProvider } from '../../providers/EngineProvider';
import { UploadPanel } from './UploadPanel';

const FOLDER = new Uint8Array(16).fill(7);

/** The write-handle surface `useDropUpload` drives, held open at the commit. */
function uploadEngine() {
  let settle = () => undefined as void;
  const listeners = new Set<(event: EventDescriptor) => void>();
  let snapshot: SnapshotDescriptor = view();
  const facade = {
    subscribe: (listener: (event: EventDescriptor) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    snapshot: () => Promise.resolve(snapshot),
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
  return {
    client,
    facade,
    settle: () => settle(),
    /** Lands a new engine snapshot, as an op stage does. */
    publish: (next: SnapshotDescriptor) => {
      snapshot = next;
      for (const listener of listeners) listener({ kind: 'snapshotUpdated' });
    },
  };
}

/** Drops one file and settles its commit, leaving the row queued on op 1. */
async function queueOne(engine: ReturnType<typeof uploadEngine>) {
  fireEvent.change(screen.getByLabelText('Choose files to upload'), {
    target: { files: [new File(['x'], 'notes.txt')] },
  });
  await waitFor(() => expect(engine.facade.commitWrite).toHaveBeenCalled());
  await act(async () => {
    engine.settle();
  });
  await waitFor(() => expect(screen.getByTestId('upload-row-status').textContent).toBe('queued'));
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

  it("names the drain's hold on the row holding the held op, until it clears", async () => {
    const engine = uploadEngine();
    draw(engine.client, FOLDER);
    await queueOne(engine);

    await act(async () => {
      engine.publish({
        ...view(),
        blocked: { opId: 1n, node: ROOT_ID, neededBytes: 900n },
      });
    });
    await waitFor(() =>
      expect(screen.getByTestId('upload-row-hold').textContent).toContain('900 B')
    );

    // The drain freed room: the hold is snapshot state, so it leaves with it.
    await act(async () => {
      engine.publish(view());
    });
    await waitFor(() => expect(screen.queryByTestId('upload-row-hold')).toBeNull());
    expect(screen.getByTestId('upload-row-status').textContent).toBe('queued');
  });

  it('leaves a row alone while the drain holds some other op', async () => {
    const engine = uploadEngine();
    draw(engine.client, FOLDER);
    await queueOne(engine);
    await act(async () => {
      engine.publish({ ...view(), blocked: { opId: 1n, node: ROOT_ID, neededBytes: 900n } });
    });
    await waitFor(() => expect(screen.getByTestId('upload-row-hold')).toBeTruthy());

    // A hold on another session's op charges the same budget but is not this
    // row's business.
    await act(async () => {
      engine.publish({ ...view(), blocked: { opId: 99n, node: ROOT_ID, neededBytes: 900n } });
    });

    await waitFor(() => expect(screen.queryByTestId('upload-row-hold')).toBeNull());
    expect(screen.getByTestId('upload-row-status').textContent).toBe('queued');
  });

  it('accounts for staged bytes this session cannot read', async () => {
    const engine = uploadEngine();
    draw(engine.client, FOLDER);
    expect(screen.queryByTestId('upload-retained')).toBeNull();

    await act(async () => {
      engine.publish({ ...view(), retainedRecords: 2 });
    });

    await waitFor(() =>
      expect(screen.getByTestId('upload-retained').textContent).toContain('2 queued uploads')
    );
  });
});
