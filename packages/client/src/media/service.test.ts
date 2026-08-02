import { describe, expect, it } from 'vitest';

import { FakePort } from '../sw/testDoubles.js';
import type { MediaReader } from './broker.js';
import { MEDIA_PORT_OFFER, MEDIA_PORT_REQUEST, type MediaResponse } from './protocol.js';
import {
  MediaService,
  type ServiceWorkerContainerLike,
  type ServiceWorkerLike,
  type ServiceWorkerRegistrationLike,
} from './service.js';

class FakeChannel {
  readonly port1 = new FakePort();
  readonly port2 = new FakePort();

  constructor() {
    this.port1.peer = this.port2;
    this.port2.peer = this.port1;
  }
}

class FakeWorker implements ServiceWorkerLike {
  readonly offers: Array<{ message: unknown; transfer: Transferable[] }> = [];

  postMessage(message: unknown, transfer: Transferable[]): void {
    this.offers.push({ message, transfer });
  }
}

class FakeContainer implements ServiceWorkerContainerLike {
  controller: ServiceWorkerLike | null = null;
  readonly registration: { active: ServiceWorkerLike | null } = { active: null };
  readonly registered: Array<{ scriptUrl: string | URL; scope?: string }> = [];
  readonly ready: Promise<ServiceWorkerRegistrationLike>;
  failRegister = false;
  private readonly listeners = new Map<string, Set<(event: MessageEvent) => void>>();

  constructor() {
    this.ready = Promise.resolve(this.registration);
  }

  register(
    scriptUrl: string | URL,
    options?: { scope?: string }
  ): Promise<ServiceWorkerRegistrationLike> {
    if (this.failRegister) return Promise.reject(new Error('no service workers here'));
    this.registered.push({ scriptUrl, scope: options?.scope });
    return Promise.resolve(this.registration);
  }

  addEventListener(type: string, listener: (event: MessageEvent) => void): void {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: (event: MessageEvent) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  emit(type: 'message' | 'controllerchange', data?: unknown): void {
    for (const listener of this.listeners.get(type) ?? []) listener({ data } as MessageEvent);
  }

  listenerCount(type: string): number {
    return this.listeners.get(type)?.size ?? 0;
  }
}

const ORIGIN = 'https://vault.example';

const reader: MediaReader = {
  downloadRange: (_node, _offset, length) => Promise.resolve(new ArrayBuffer(length)),
};

interface Setup {
  container: FakeContainer;
  worker: FakeWorker;
  service: MediaService;
  channels: FakeChannel[];
}

function setup(): Setup {
  const container = new FakeContainer();
  const worker = new FakeWorker();
  const channels: FakeChannel[] = [];
  const service = new MediaService({
    container,
    scriptUrl: '/sw.js',
    reader,
    origin: ORIGIN,
    createChannel: () => {
      const channel = new FakeChannel();
      channels.push(channel);
      return channel as unknown as MessageChannel;
    },
  });
  return { container, worker, service, channels };
}

const brokeredPort = (channels: FakeChannel[]): FakePort => channels[channels.length - 1].port1;

describe('MediaService', () => {
  it('registers the worker at the root scope and offers a port to the controller', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;

    await service.start();

    expect(container.registered).toEqual([{ scriptUrl: '/sw.js', scope: '/' }]);
    expect(channels).toHaveLength(1);
    expect(worker.offers).toHaveLength(1);
    expect(worker.offers[0].message).toEqual({ type: MEDIA_PORT_OFFER });
    expect(worker.offers[0].transfer).toEqual([channels[0].port2]);
    expect(channels[0].port1.started).toBe(true);
    expect(service.streaming).toBe(true);
  });

  it('offers to the registration active worker when no controller has claimed the tab', async () => {
    const { container, worker, service, channels } = setup();
    container.registration.active = worker;

    await service.start();

    expect(worker.offers).toHaveLength(1);
    expect(worker.offers[0].transfer).toEqual([channels[0].port2]);
    // The offer primes a worker that has not claimed yet; until it does, this
    // tab's fetches still go to the network.
    expect(service.streaming).toBe(false);
  });

  it('refuses to mint a ticket while no worker controls the tab', async () => {
    const { container, worker, service } = setup();
    container.registration.active = worker;
    await service.start();

    expect(() =>
      service.createStreamUrl({ node: new Uint8Array(1), size: 1, mimeType: 'video/mp4' })
    ).toThrow(/controlling Service Worker/);
  });

  it('serves media requests over the brokered port', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;
    await service.start();

    const url = service.createStreamUrl({
      node: new Uint8Array([9]),
      size: 8,
      mimeType: 'audio/o',
    });
    const ticket = url.slice('/stream/'.length);
    const answers: MediaResponse[] = [];
    channels[0].port2.addEventListener('message', (event) =>
      answers.push(event.data as MediaResponse)
    );
    channels[0].port2.postMessage({ type: 'cb:media:open', requestId: 1, ticket, range: null });

    expect(answers[0]).toMatchObject({ type: 'cb:media:head', status: 200 });

    expect(service.revokeStreamUrl(url)).toBe(true);
    channels[0].port2.postMessage({ type: 'cb:media:open', requestId: 2, ticket, range: null });
    expect(answers[1]).toMatchObject({ type: 'cb:media:head', status: 404 });
  });

  it('revokes the absolute form of a minted url and reports an unknown one', async () => {
    const { container, worker, service } = setup();
    container.controller = worker;
    await service.start();
    const url = service.createStreamUrl({
      node: new Uint8Array([9]),
      size: 8,
      mimeType: 'audio/o',
    });

    // What a caller reads back off `videoEl.src` — the ticket must still die.
    expect(service.revokeStreamUrl(`${ORIGIN}${url}`)).toBe(true);
    expect(service.revokeStreamUrl(`${ORIGIN}${url}`)).toBe(false);
  });

  it('re-brokers a fresh channel and closes the old one when the worker asks for a port', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;
    await service.start();

    container.emit('message', { type: MEDIA_PORT_REQUEST });

    expect(channels).toHaveLength(2);
    expect(channels[0].port1.closed).toBe(true);
    expect(channels[0].port2.closed).toBe(true);
    expect(channels[1].port1.closed).toBe(false);
    expect(worker.offers).toHaveLength(2);
    expect(worker.offers[1].transfer).toEqual([channels[1].port2]);
    expect(brokeredPort(channels).started).toBe(true);
  });

  it('ignores an unrelated message from the worker', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;
    await service.start();

    container.emit('message', { type: 'something-else' });
    container.emit('message', null);

    expect(channels).toHaveLength(1);
  });

  it('re-brokers to the new controller on controllerchange', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;
    await service.start();

    const next = new FakeWorker();
    container.controller = next;
    container.emit('controllerchange');

    expect(next.offers).toHaveLength(1);
    expect(next.offers[0].transfer).toEqual([channels[1].port2]);
    expect(channels[0].port1.closed).toBe(true);
  });

  it('starts once and reuses the same brokered port', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;

    await Promise.all([service.start(), service.start()]);
    await service.start();

    expect(container.registered).toHaveLength(1);
    expect(channels).toHaveLength(1);
    expect(worker.offers).toHaveLength(1);
  });

  it('degrades instead of rejecting when registration fails', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;
    container.failRegister = true;

    await expect(service.start()).resolves.toBeUndefined();

    expect(channels).toEqual([]);
    expect(worker.offers).toEqual([]);
    expect(service.streaming).toBe(false);
    expect(() =>
      service.createStreamUrl({ node: new Uint8Array(1), size: 1, mimeType: 'video/mp4' })
    ).toThrow(/controlling Service Worker/);
  });

  it('detaches, closes the channel, and stops serving on dispose', async () => {
    const { container, worker, service, channels } = setup();
    container.controller = worker;
    await service.start();
    const port = channels[0].port1;
    expect(port.listenerCount).toBe(1);

    await service.dispose();

    expect(port.closed).toBe(true);
    expect(channels[0].port2.closed).toBe(true);
    expect(port.listenerCount).toBe(0);
    expect(container.listenerCount('message')).toBe(0);
    expect(container.listenerCount('controllerchange')).toBe(0);
    expect(service.streaming).toBe(false);
  });
});
