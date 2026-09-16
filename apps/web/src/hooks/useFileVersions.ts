/**
 * One file's prior versions and the three commands that act on one. Versions are
 * not a snapshot field: the dialog reads them when it opens, and reads them again
 * after a restore or a delete, because either one rewrites the list.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { VersionEntryDescriptor } from '@cipherbox/client';
import { OPAQUE, REVOKE_AFTER_MS, saveBlobToDisk } from '../lib/saveBlob';
import { useCommandRunner } from './useCommandRunner';

/** Which version command is in flight, or `null` when the dialog is idle. */
export type VersionCommand = 'versions' | 'download' | 'restore' | 'delete';

/** The two commands that rewrite the list, so each one re-reads it. */
export type VersionWrite = 'restore' | 'delete';

export interface FileVersions {
  /** `null` until a read lands; never an empty list a render would read as one. */
  entries: readonly VersionEntryDescriptor[] | null;
  busy: VersionCommand | null;
  /** The last dispatch's failure, cleared by the next dispatch. */
  error: string | null;
  /** Saves one prior version's plaintext under the file's own name. */
  download(contentCid: Uint8Array): Promise<boolean>;
  /** Dispatches one write against the named version, then re-reads the list. */
  write(command: VersionWrite, contentCid: Uint8Array): Promise<boolean>;
}

/**
 * Reads `node`'s prior versions. A `null` node is a kind that holds no versions,
 * and reads nothing.
 */
export function useFileVersions(node: Uint8Array | null, name: string): FileVersions {
  const { busy, error, run } = useCommandRunner<VersionCommand>();
  const [entries, setEntries] = useState<readonly VersionEntryDescriptor[] | null>(null);
  // Two reads can land out of order; only the newest may write the state.
  const generation = useRef(0);
  const blobUrls = useRef(new Map<ReturnType<typeof setTimeout>, string>());

  // A deferred revoke left behind outlives the dialog that owns it: it holds the
  // plaintext blob alive past the close.
  useEffect(
    () => () => {
      for (const [timer, url] of blobUrls.current) {
        clearTimeout(timer);
        URL.revokeObjectURL(url);
      }
      blobUrls.current.clear();
    },
    []
  );

  const reload = useCallback(
    (target: Uint8Array) => {
      const mine = ++generation.current;
      return run('versions', async (facade) => {
        const read = await facade.fileVersions(target);
        if (mine === generation.current) setEntries(read);
      });
    },
    [run]
  );

  useEffect(() => {
    // Entries name one node. A list the previous node answered with must not
    // stay on screen, and an in-flight read of it must not land on the new one.
    setEntries(null);
    if (node === null) {
      generation.current += 1;
      return;
    }
    void reload(node);
  }, [node, reload]);

  const download = useCallback(
    (contentCid: Uint8Array): Promise<boolean> => {
      if (node === null) return Promise.resolve(false);
      return run('download', async (facade) => {
        const bytes = await facade.downloadVersion(node, contentCid);
        const url = URL.createObjectURL(new Blob([bytes], { type: OPAQUE }));
        saveBlobToDisk(url, name);
        const timer = setTimeout(() => {
          blobUrls.current.delete(timer);
          URL.revokeObjectURL(url);
        }, REVOKE_AFTER_MS);
        blobUrls.current.set(timer, url);
      });
    },
    [name, node, run]
  );

  const write = useCallback(
    async (command: VersionWrite, contentCid: Uint8Array): Promise<boolean> => {
      if (node === null) return false;
      const accepted = await run(command, (facade) =>
        command === 'restore'
          ? facade.restoreVersion(node, contentCid)
          : facade.deleteVersion(node, contentCid)
      );
      if (accepted) await reload(node);
      return accepted;
    },
    [node, reload, run]
  );

  return { entries, busy, error, download, write };
}
