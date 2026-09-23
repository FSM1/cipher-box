/**
 * The `/shared` route's one read. The rows are the durable accept bookmarks and
 * the verdict on each is the focus tick's last resolve, so a re-read is what
 * moves a standing.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReceivedShareDescriptor } from '@cipherbox/client';
import { useEngine } from '../providers/EngineProvider';
import { useCommandRunner } from './useCommandRunner';

export interface ReceivedSharesRead {
  /** `null` until a read lands; never an empty list a render would read as one. */
  shares: readonly ReceivedShareDescriptor[] | null;
  busy: boolean;
  error: string | null;
  reload(): Promise<boolean>;
}

export function useReceivedShares(): ReceivedSharesRead {
  const client = useEngine();
  const { busy, error, run } = useCommandRunner<'receivedShares'>();
  const [shares, setShares] = useState<readonly ReceivedShareDescriptor[] | null>(null);
  // One read at a time, and a request during it costs one trailing read: the
  // engine emits a snapshot update per op stage, and two reads in flight could
  // land out of order in both the list and the runner's error.
  const queue = useRef<{ current: Promise<boolean> | null; again: boolean }>({
    current: null,
    again: false,
  });
  const alive = useRef(true);
  // A trailing read dispatches through the runner of the client it runs under.
  const runner = useRef(run);

  useEffect(() => {
    runner.current = run;
  }, [run]);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const reload = useCallback((): Promise<boolean> => {
    const reads = queue.current;
    if (reads.current !== null) {
      reads.again = true;
      return reads.current;
    }
    const drain = async (): Promise<boolean> => {
      let landed: boolean;
      do {
        reads.again = false;
        landed = await runner.current('receivedShares', async (facade) =>
          setShares(await facade.receivedShares())
        );
      } while (reads.again && alive.current);
      reads.current = null;
      return landed;
    };
    reads.current = drain();
    return reads.current;
  }, []);

  // The provider builds its client in an effect, so a direct load renders once
  // without one. Dispatching there would paint a not-ready refusal every time.
  useEffect(() => {
    if (client !== null) void reload();
  }, [client, reload]);

  // The tick grafts a share it accepts and announces the graft as a snapshot
  // update, so a new share appears here without a timer or a press.
  useEffect(() => {
    if (client === null) return;
    return client.facade.subscribe((event) => {
      if (event.kind === 'snapshotUpdated') void reload();
    });
  }, [client, reload]);

  return { shares, busy: busy !== null, error, reload };
}
