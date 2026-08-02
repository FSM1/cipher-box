/**
 * Cross-context `MessagePort` brokerage. A `BroadcastChannel` carries no
 * transferables and delivers to every context that opened it, so the origin's
 * Service Worker is the only route by which one tab can hand another a private
 * port. It forwards the port untouched and keeps no state of its own: a killed
 * worker costs a re-broker, never a channel already open.
 */

import type { MessagePortLike } from './media/protocol.js';

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

/** The `ServiceWorker` surface a brokerage step drives. */
export interface CourierWorkerLike {
  postMessage(message: unknown, transfer?: MessagePortLike[]): void;
}

/** The `navigator.serviceWorker` surface the courier drives (injectable). */
export interface CourierContainerLike {
  readonly controller: CourierWorkerLike | null;
  readonly ready: Promise<{ readonly active: CourierWorkerLike | null }>;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
}

export interface CourierOptions {
  /** How long the worker has to answer one brokerage step. */
  timeoutMs?: number;
  createChannel?: () => { port1: MessagePortLike; port2: MessagePortLike };
}

const DEFAULT_TIMEOUT_MS = 5000;

const NO_WORKER = 'no Service Worker to broker a private engine port';

export class ServiceWorkerCourier implements PortCourier {
  private self: Promise<string> | null = null;
  private readonly handlers = new Set<(port: MessagePortLike) => void>();
  private readonly timeoutMs: number;
  private readonly createChannel: () => { port1: MessagePortLike; port2: MessagePortLike };
  private listening = false;

  private readonly onMessage = (event: MessageEvent): void => {
    if ((event.data as { type?: unknown } | null)?.type !== RELAY_PORT) return;
    const port = event.ports?.[0] as MessagePortLike | undefined;
    if (!port) return;
    for (const handler of [...this.handlers]) handler(port);
  };

  constructor(
    private readonly container: CourierContainerLike,
    options: CourierOptions = {}
  ) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.createChannel = options.createChannel ?? ((): MessageChannel => new MessageChannel());
  }

  address(): Promise<string> {
    if (this.self) return this.self;
    const asking = this.ask();
    this.self = asking;
    // A worker that never answered must not pin this context to a dead address.
    asking.catch(() => {
      if (this.self === asking) this.self = null;
    });
    return asking;
  }

  async connect(to: string): Promise<MessagePortLike> {
    const worker = await this.worker();
    const channel = this.createChannel();
    const deliver: RelayMessage = { type: RELAY_DELIVER, to };
    worker.postMessage(deliver, [channel.port2]);
    channel.port1.start?.();
    return channel.port1;
  }

  onPort(handler: (port: MessagePortLike) => void): () => void {
    if (!this.listening) {
      this.container.addEventListener('message', this.onMessage);
      this.listening = true;
    }
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
      if (this.handlers.size > 0) return;
      this.container.removeEventListener('message', this.onMessage);
      this.listening = false;
    };
  }

  private async ask(): Promise<string> {
    const worker = await this.worker();
    return new Promise<string>((resolve, reject) => {
      const listener = (event: MessageEvent): void => {
        const data = event.data as { type?: unknown; id?: unknown } | null;
        if (data?.type !== RELAY_SELF || typeof data.id !== 'string') return;
        finish();
        resolve(data.id);
      };
      const finish = (): void => {
        clearTimeout(timer);
        this.container.removeEventListener('message', listener);
      };
      const timer = setTimeout(() => {
        finish();
        reject(new Error('the Service Worker did not name this client'));
      }, this.timeoutMs);
      this.container.addEventListener('message', listener);
      const whoami: RelayMessage = { type: RELAY_WHOAMI };
      worker.postMessage(whoami);
    });
  }

  private async worker(): Promise<CourierWorkerLike> {
    const controller = this.container.controller;
    if (controller) return controller;
    const registration = await withTimeout(this.container.ready, this.timeoutMs, NO_WORKER);
    if (!registration.active) throw new Error(NO_WORKER);
    return registration.active;
  }
}

/**
 * Follower reads travel over a brokered port and never fall back onto the shared
 * bus, so a browser without a Service Worker mirrors nothing.
 */
class UnavailableCourier implements PortCourier {
  address(): Promise<string> {
    return Promise.reject(new Error(NO_WORKER));
  }

  connect(): Promise<MessagePortLike> {
    return Promise.reject(new Error(NO_WORKER));
  }

  onPort(): () => void {
    return () => undefined;
  }
}

/** This tab's courier, or a refusing one where the browser offers no Service Worker. */
export function defaultCourier(): PortCourier {
  const container = (globalThis as { navigator?: { serviceWorker?: CourierContainerLike } })
    .navigator?.serviceWorker;
  return container ? new ServiceWorkerCourier(container) : new UnavailableCourier();
}

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    );
  });
}
