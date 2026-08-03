/**
 * The tab side of the port relay ([`portRelay`](./portRelay.ts)): it drives the
 * Service Worker that forwards ports between same-origin contexts. The tab must
 * already have that worker registered — `MediaService` does it — and a tab that
 * has none gets [`unavailableCourier`](unavailableCourier), which refuses.
 */

import {
  RELAY_DELIVER,
  RELAY_PORT,
  RELAY_SELF,
  RELAY_WHOAMI,
  type MessagePortLike,
  type PortCourier,
  type RelayMessage,
} from './portRelay.js';

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
    worker.postMessage({ type: RELAY_DELIVER, to } satisfies RelayMessage, [channel.port2]);
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
      worker.postMessage({ type: RELAY_WHOAMI } satisfies RelayMessage);
    });
  }

  private async worker(): Promise<CourierWorkerLike> {
    const controller = this.container.controller;
    if (controller) return controller;
    let timer: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(NO_WORKER)), this.timeoutMs);
    });
    try {
      const registration = await Promise.race([this.container.ready, deadline]);
      if (!registration.active) throw new Error(NO_WORKER);
      return registration.active;
    } finally {
      clearTimeout(timer!);
    }
  }
}

/**
 * The courier a context with no Service Worker gets. Follower reads travel over
 * a brokered port and never fall back onto the shared channel, so such a tab
 * mirrors nothing.
 */
export const unavailableCourier: PortCourier = {
  address: () => Promise.reject(new Error(NO_WORKER)),
  connect: () => Promise.reject(new Error(NO_WORKER)),
  onPort: () => () => undefined,
};

/** This tab's courier, or the refusing one where the browser offers no Service Worker. */
export function defaultCourier(): PortCourier {
  const container = (globalThis as { navigator?: { serviceWorker?: CourierContainerLike } })
    .navigator?.serviceWorker;
  return container ? new ServiceWorkerCourier(container) : unavailableCourier;
}
