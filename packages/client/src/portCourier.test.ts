import { describe, expect, it } from 'vitest';

import type { MessagePortLike } from './portRelay.js';
import {
  ServiceWorkerCourier,
  type CourierContainerLike,
  type CourierWorkerLike,
} from './portCourier.js';
import { RELAY_DELIVER, RELAY_PORT, RELAY_SELF, RELAY_WHOAMI } from './portRelay.js';
import { FakeChannelPort } from './testkit.js';

/** The worker the tab posts brokerage steps to, plus what it received. */
class FakeWorker implements CourierWorkerLike {
  readonly posts: Array<{ message: unknown; transfer: MessagePortLike[] }> = [];

  postMessage(message: unknown, transfer?: MessagePortLike[]): void {
    this.posts.push({ message, transfer: transfer ? [...transfer] : [] });
  }
}

class FakeContainer implements CourierContainerLike {
  controller: CourierWorkerLike | null;
  readonly ready: Promise<{ readonly active: CourierWorkerLike | null }>;
  private readonly listeners = new Set<(event: MessageEvent) => void>();

  constructor(worker: FakeWorker | null, options: { controlled?: boolean } = {}) {
    this.controller = options.controlled === false ? null : worker;
    this.ready = Promise.resolve({ active: worker });
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners.add(listener);
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners.delete(listener);
  }

  get listenerCount(): number {
    return this.listeners.size;
  }

  emit(data: unknown, ports: MessagePortLike[] = []): void {
    for (const listener of [...this.listeners]) {
      listener({ data, ports } as unknown as MessageEvent);
    }
  }
}

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

function channel(): { port1: MessagePortLike; port2: MessagePortLike } {
  const port1 = new FakeChannelPort();
  const port2 = new FakeChannelPort();
  port1.peer = port2;
  port2.peer = port1;
  return { port1, port2 };
}

describe('service worker port courier', () => {
  it('asks the worker for this context address and answers later calls from cache', async () => {
    const worker = new FakeWorker();
    const container = new FakeContainer(worker);
    const courier = new ServiceWorkerCourier(container);

    const asking = courier.address();
    await tick();
    container.emit({ type: RELAY_SELF, id: 'window-4' });

    await expect(asking).resolves.toBe('window-4');
    await expect(courier.address()).resolves.toBe('window-4');
    expect(worker.posts.map((post) => post.message)).toEqual([{ type: RELAY_WHOAMI }]);
    // The one-shot reply listener is not left behind on the container.
    expect(container.listenerCount).toBe(0);
  });

  it('rejects an unanswered address and asks again on the next call', async () => {
    const worker = new FakeWorker();
    const container = new FakeContainer(worker);
    const courier = new ServiceWorkerCourier(container, { timeoutMs: 5 });

    await expect(courier.address()).rejects.toThrow(/did not name this client/);

    const retried = courier.address();
    await tick();
    container.emit({ type: RELAY_SELF, id: 'window-9' });
    await expect(retried).resolves.toBe('window-9');
    expect(worker.posts).toHaveLength(2);
  });

  it('refuses to broker where no worker is active', async () => {
    const courier = new ServiceWorkerCourier(new FakeContainer(null, { controlled: false }));

    await expect(courier.address()).rejects.toThrow(/no Service Worker/);
    await expect(courier.connect('window-1')).rejects.toThrow(/no Service Worker/);
  });

  it('transfers the far end of a fresh channel to the addressed context', async () => {
    const worker = new FakeWorker();
    const courier = new ServiceWorkerCourier(new FakeContainer(worker), {
      createChannel: channel,
    });

    const near = (await courier.connect('window-7')) as FakeChannelPort;
    const [post] = worker.posts;

    expect(post.message).toEqual({ type: RELAY_DELIVER, to: 'window-7' });
    // The far end is transferred, so the worker forwards it without ever holding
    // a second reference to this side of the channel.
    expect(post.transfer).toEqual([near.peer]);
    expect(near.started).toBe(true);
  });

  it('hands ports the worker forwards to every subscriber until it unsubscribes', async () => {
    const worker = new FakeWorker();
    const container = new FakeContainer(worker);
    const courier = new ServiceWorkerCourier(container);
    const taken: MessagePortLike[] = [];
    const stop = courier.onPort((port) => taken.push(port));

    const first = new FakeChannelPort();
    container.emit({ type: RELAY_PORT }, [first]);
    // Traffic that names no port, and traffic that is not a forwarded port.
    container.emit({ type: RELAY_PORT }, []);
    container.emit({ type: 'cb:media:needPort' }, [new FakeChannelPort()]);
    expect(taken).toEqual([first]);

    stop();
    container.emit({ type: RELAY_PORT }, [new FakeChannelPort()]);
    expect(taken).toEqual([first]);
    expect(container.listenerCount).toBe(0);
  });
});
