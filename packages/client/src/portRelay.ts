/**
 * The cross-context port wire. A `BroadcastChannel` carries no transferables and
 * delivers to every context that opened it, so the origin's Service Worker is
 * the only route by which one tab can hand another a private `MessagePort`. It
 * forwards the port untouched and keeps no state of its own: a killed worker
 * costs a re-broker, never a channel already open.
 */

/** The subset of `MessagePort` the pipe, the relay, and the broker drive. */
export interface MessagePortLike {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  start?(): void;
  close(): void;
}

/** Tab → Service Worker: name the sending client back to itself. */
export const RELAY_WHOAMI = 'cb:relay:whoami';
/** Service Worker → the asking tab: that tab's own client id. */
export const RELAY_SELF = 'cb:relay:self';
/** Tab → Service Worker, carrying the far end of a fresh `MessageChannel`. */
export const RELAY_DELIVER = 'cb:relay:deliver';
/** Service Worker → the addressed tab, carrying that far end. */
export const RELAY_PORT = 'cb:relay:port';

export type RelayMessage =
  | { type: typeof RELAY_WHOAMI }
  | { type: typeof RELAY_SELF; id: string }
  | { type: typeof RELAY_DELIVER; to: string }
  | { type: typeof RELAY_PORT };

/** Opens private point-to-point channels between same-origin contexts. */
export interface PortCourier {
  /** This context's address, for another context to `connect` to. */
  address(): Promise<string>;
  /** Opens a channel to `to`, returning this side's end. */
  connect(to: string): Promise<MessagePortLike>;
  /** Registers for channels opened to this context; the return unsubscribes. */
  onPort(handler: (port: MessagePortLike) => void): () => void;
}
