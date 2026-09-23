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
  // An event and a press can each start a read. Only the newest may write, so
  // a slow older read never paints over the list a newer one returned.
  const latest = useRef(0);

  const reload = useCallback(() => {
    const ticket = (latest.current += 1);
    return run('receivedShares', async (facade) => {
      const read = await facade.receivedShares();
      if (ticket === latest.current) setShares(read);
    });
  }, [run]);

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
