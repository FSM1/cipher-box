/**
 * The Service Worker end of the port relay (`portRelay`). It names a client back
 * to itself and forwards the far end of a channel to the client a tab addressed;
 * it reads neither side and keeps nothing.
 */

import { RELAY_PORT, type MessagePortLike } from '../portRelay.js';
import type { ClientsLike, WindowClientLike } from './clients.js';

/** Hands `port` to the window client named `to`, or closes it if that tab is gone. */
export async function deliverPort(
  clients: ClientsLike,
  to: string,
  port: MessagePortLike
): Promise<void> {
  // A tab the worker has not claimed yet is still a legitimate target.
  const windows = await clients.matchAll({ type: 'window', includeUncontrolled: true });
  const target: WindowClientLike | undefined = windows.find((client) => client.id === to);
  if (!target) {
    port.close();
    return;
  }
  target.postMessage({ type: RELAY_PORT }, [port]);
}
