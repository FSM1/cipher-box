/**
 * The tab-side entry point for streaming media: registers the Service Worker,
 * keeps exactly one brokered port alive across worker restarts, and mints the
 * ticket URLs the UI hands to a media element.
 */

import { MediaBroker, type MediaReader } from './broker.js';
import {
  MEDIA_PORT_OFFER,
  MEDIA_PORT_REQUEST,
  ticketFromUrl,
  type MediaPortOffer,
} from './protocol.js';
import { StreamRegistry, type MediaSource } from './registry.js';

/** The `ServiceWorker` surface the offer needs. */
export interface ServiceWorkerLike {
  postMessage(message: unknown, transfer: Transferable[]): void;
}

export interface ServiceWorkerRegistrationLike {
  readonly active: ServiceWorkerLike | null;
}

/** The `navigator.serviceWorker` surface this service drives. */
export interface ServiceWorkerContainerLike {
  register(
    scriptUrl: string | URL,
    options?: { scope?: string; type?: 'classic' | 'module' }
  ): Promise<ServiceWorkerRegistrationLike>;
  readonly ready: Promise<ServiceWorkerRegistrationLike>;
  readonly controller: ServiceWorkerLike | null;
  addEventListener(
    type: 'message' | 'controllerchange',
    listener: (event: MessageEvent) => void
  ): void;
  removeEventListener(
    type: 'message' | 'controllerchange',
    listener: (event: MessageEvent) => void
  ): void;
}

export interface MediaServiceConfig {
  container: ServiceWorkerContainerLike;
  scriptUrl: string | URL;
  scriptType?: 'classic' | 'module';
  reader: MediaReader;
  createChannel?: () => MessageChannel;
  /** The origin a revoked stream URL must resolve to; defaults to the tab's. */
  origin?: string;
}

export class MediaService {
  private readonly registry: StreamRegistry;
  private readonly broker: MediaBroker;
  private readonly origin: string;
  private readonly createChannel: () => MessageChannel;
  private registration: ServiceWorkerRegistrationLike | null = null;
  private channel: MessageChannel | null = null;
  private startup: Promise<void> | null = null;
  private disposed = false;

  constructor(private readonly config: MediaServiceConfig) {
    this.origin = config.origin ?? globalThis.location.origin;
    this.registry = new StreamRegistry(this.origin);
    this.broker = new MediaBroker(this.registry, config.reader);
    this.createChannel = config.createChannel ?? ((): MessageChannel => new MessageChannel());
  }

  /**
   * True only when this tab's own fetches are intercepted: a live brokered
   * channel is not enough, the worker must also control the tab.
   */
  get streaming(): boolean {
    return this.channel !== null && this.config.container.controller !== null;
  }

  /** Streaming is an enhancement: a failure degrades the tab, never its boot. */
  start(): Promise<void> {
    this.startup ??= this.begin();
    return this.startup;
  }

  /** A ticket is a bearer capability to plaintext; an unintercepted fetch would send it to the origin server. */
  createStreamUrl(source: MediaSource): string {
    if (!this.streaming) {
      throw new Error(
        'a stream ticket must not leave the device without a controlling Service Worker'
      );
    }
    return this.registry.register(source);
  }

  /**
   * Resolves once nothing is reading `url` — its transfer ended, or `stallMs`
   * passed with no window delivered. A holder that revokes on this drops a
   * ticket as soon as its bytes stop rather than holding plaintext addressable
   * for the life of the tab.
   */
  whenStreamIdle(url: string, stallMs: number): Promise<void> {
    const ticket = ticketFromUrl(url, this.origin);
    if (ticket === null || this.registry.lookup(ticket) === undefined) return Promise.resolve();
    return this.broker.whenIdle(ticket, stallMs);
  }

  /** False when the URL named no live ticket of this tab's. */
  revokeStreamUrl(url: string): boolean {
    const ticket = ticketFromUrl(url, this.origin);
    if (ticket === null || !this.registry.revoke(url)) return false;
    this.broker.revoke(ticket);
    return true;
  }

  /** Leaves the worker registered — the app-shell precache must outlive the tab. */
  async dispose(): Promise<void> {
    this.disposed = true;
    if (this.startup !== null) await this.startup;
    const container = this.config.container;
    container.removeEventListener('controllerchange', this.onControllerChange);
    container.removeEventListener('message', this.onMessage);
    this.registry.clear();
    this.broker.close();
    this.brokerTo(null);
  }

  private async begin(): Promise<void> {
    const container = this.config.container;
    // The `/` scope is load-bearing — the pipe intercepts `/stream/` and the
    // precache serves the app shell from the root.
    try {
      this.registration = await container.register(this.config.scriptUrl, {
        scope: '/',
        type: this.config.scriptType ?? 'classic',
      });
      await container.ready;
    } catch {
      return;
    }
    if (this.disposed) return;

    container.addEventListener('controllerchange', this.onControllerChange);
    container.addEventListener('message', this.onMessage);
    this.rebroker();
  }

  private readonly onControllerChange = (): void => {
    this.rebroker();
  };

  /** The worker asks for a port when it was killed and lost the one it had. */
  private readonly onMessage = (event: MessageEvent): void => {
    const data: unknown = event.data;
    if (typeof data !== 'object' || data === null) return;
    if ((data as { type?: unknown }).type === MEDIA_PORT_REQUEST) this.rebroker();
  };

  private rebroker(): void {
    // A first load has no controller until the worker claims the tab, but its
    // active worker can already take the offer.
    this.brokerTo(this.config.container.controller ?? this.registration?.active ?? null);
  }

  private brokerTo(target: ServiceWorkerLike | null): void {
    const previous = this.channel;
    this.channel = null;

    if (target !== null) {
      const channel = this.createChannel();
      this.broker.serve(channel.port1);
      const offer: MediaPortOffer = { type: MEDIA_PORT_OFFER };
      target.postMessage(offer, [channel.port2]);
      this.channel = channel;
    }

    previous?.port1.close();
    previous?.port2.close();
  }
}
