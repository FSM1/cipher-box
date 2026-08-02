/** The `Clients` surface the Service Worker's two message consumers drive. */

import type { MediaPortRequest } from '../media/protocol.js';
import type { MessagePortLike, RelayMessage } from '../portRelay.js';

/** The subset of a window client the worker drives (injectable). */
export interface WindowClientLike {
  /** Matches `FetchEventLike.clientId`, so a request can be aimed at one tab. */
  readonly id?: string;
  postMessage(message: MediaPortRequest | RelayMessage, transfer?: MessagePortLike[]): void;
}

/** The subset of `ServiceWorkerGlobalScope.clients` the worker drives. */
export interface ClientsLike {
  matchAll(options: {
    type: 'window';
    includeUncontrolled?: boolean;
  }): Promise<readonly WindowClientLike[]>;
}
