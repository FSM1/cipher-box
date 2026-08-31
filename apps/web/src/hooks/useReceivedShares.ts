/**
 * The `/shared` route's one read. The rows are the durable accept bookmarks and
 * the verdict on each is the focus tick's last resolve, so a re-read is what
 * moves a standing.
 */

import { useCallback, useEffect, useState } from 'react';
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

  const reload = useCallback(
    () => run('receivedShares', async (facade) => setShares(await facade.receivedShares())),
    [run]
  );

  // The provider builds its client in an effect, so a direct load renders once
  // without one. Dispatching there would paint a not-ready refusal every time.
  useEffect(() => {
    if (client !== null) void reload();
  }, [client, reload]);

  return { shares, busy: busy !== null, error, reload };
}
