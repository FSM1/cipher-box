/**
 * The transport-swapping engine client (blueprint/web-client.md "The facade is
 * transport-agnostic"). One typed async facade over the origin's single engine,
 * regardless of whether *this* tab is the leader hosting the worker or a
 * follower mirroring it. Leadership changes swap the transport underneath the
 * facade without the UI noticing.
 *
 * - **Leader**: holds the `cipherbox-engine` Web Lock, spawns the engine worker,
 *   drives it over `LocalTransport`, and relays for followers.
 * - **Follower**: holds no worker and no keys; drives the leader over
 *   `BroadcastTransport`.
 * - **Failover**: the lock releases → this tab may win it, spawn a fresh worker,
 *   re-derive its keys from the `SecretSource`, and rehydrate from the durable
 *   origin-shared seams. Commands in flight at the swap reject (never hang), so
 *   the UI retries them — and because the engine journals an op before acking
 *   it, an accepted op survives the handoff.
 */

import { BROADCAST_CHANNEL_NAME, newClientId, type BroadcastChannelLike } from './broadcast.js';
import { BroadcastTransport } from './broadcastTransport.js';
import { fanOut, unknownHandle } from './correlatedTransport.js';
import { EngineFacade } from './facade.js';
import { LeaderRelay } from './leaderRelay.js';
import { LeaderElection, type LockManagerLike } from './leadership.js';
import { defaultCourier } from './portCourier.js';
import type { PortCourier } from './portRelay.js';
import { requestStoragePersistence } from './storagePersistence.js';
import type { EngineEventListener, EngineTransport, EngineWorkerLike } from './transport.js';
import { LocalTransport } from './transport.js';
import type {
  CommandDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/**
 * Re-derives the login secret when this tab is promoted to leader mid-session
 * (failover). Keys never persist in JS (security rule 1); the UI re-exports the
 * secret from its auth session (Web3Auth Core Kit restore) on demand. The
 * returned buffer is transferred into the worker and zeroed — never retained.
 */
export interface SecretSource {
  provideSecret(): Promise<ArrayBuffer>;
}

export interface EngineClientConfig {
  /** `navigator.locks` (or a test double). */
  locks: LockManagerLike;
  /** Builds the broadcast channel; each tab keeps one for its lifetime. */
  createChannel?: () => BroadcastChannelLike;
  /** Brokers the private port a follower reads over; defaults to the tab's Service Worker. */
  courier?: PortCourier;
  /** Spawns and bootstraps the engine worker (leader only). */
  spawnWorker: () => EngineWorkerLike;
  /** Re-derives the secret for a failover cold-start. */
  secretSource?: SecretSource;
  /** This tab's correlation id; defaults to a random UUID. */
  clientId?: string;
  /** Overrides the lock name (tests isolate origins by name). */
  lockName?: string;
  /** Surfaces election/failover faults (best-effort; the facade still works). */
  onError?: (error: Error) => void;
  /** Reports the origin's storage-persistence grant (`storagePersistence`). */
  onStoragePersistence?: (persisted: boolean) => void;
}

export type EngineClientRole = 'follower' | 'leader' | 'closed';

/**
 * One engine plane's open handles, as this client's own id → the live engine's.
 *
 * An engine's handle counters restart at 1, so a handle from a departed leader
 * names a live handle on the next one: a stale stream reads a *different* node's
 * plaintext, and a stale `pushChunk` pushes one file's bytes into another file's
 * staging, sealing correctly under the entry it lands in. Ids that are monotonic
 * for this client's whole life, dropped on every swap, make a stale handle
 * unmatchable rather than ambiguous.
 */
class HandleTable {
  private readonly inner = new Map<bigint, bigint>();
  private next = 0n;

  /** Adopts a freshly minted engine handle, naming it for this client. */
  open(inner: bigint): bigint {
    this.next += 1n;
    this.inner.set(this.next, inner);
    return this.next;
  }

  /** The engine handle behind `handle`, or `undefined` once its engine is gone. */
  resolve(handle: bigint): bigint | undefined {
    return this.inner.get(handle);
  }

  release(handle: bigint): void {
    this.inner.delete(handle);
  }

  clear(): void {
    this.inner.clear();
  }
}

/**
 * The object handed to `EngineFacade`: it *is* the transport, delegating to the
 * live inner transport and re-homing the UI's event subscription across swaps.
 */
export class EngineClient implements EngineTransport {
  readonly facade: EngineFacade;

  private readonly channel: BroadcastChannelLike;
  private readonly clientId: string;
  private readonly courier: PortCourier;
  private readonly election: LeaderElection;

  private role: EngineClientRole = 'follower';
  private current!: EngineTransport;
  private readonly streams = new HandleTable();
  private readonly writes = new HandleTable();
  private generation = 0;
  private relay: LeaderRelay | null = null;
  private innerUnsub!: () => void;
  private readonly listeners = new Set<EngineEventListener>();

  // The vault is active (user logged in). A follower promoted while active must
  // re-derive keys; a never-active tab elected first just awaits `start`.
  private started = false;
  private ownFocus: Uint8Array | null = null;

  constructor(private readonly config: EngineClientConfig) {
    this.clientId = config.clientId ?? newClientId();
    this.channel = (config.createChannel ?? defaultChannel)();
    this.courier = config.courier ?? defaultCourier();

    this.installFollower();

    // Requested before any tab can enqueue: an evicted origin loses the durable
    // op queue and every staged byte, not just cache.
    void requestStoragePersistence()
      .then((persisted) => config.onStoragePersistence?.(persisted))
      .catch((error: unknown) =>
        config.onError?.(error instanceof Error ? error : new Error(String(error)))
      );

    this.election = new LeaderElection(
      config.locks,
      config.lockName ?? BROADCAST_CHANNEL_NAME,
      () => this.becomeLeader(),
      config.onError
    );

    this.facade = new EngineFacade(this);
  }

  currentRole(): EngineClientRole {
    return this.role;
  }

  // --- EngineTransport ---

  start(secret: ArrayBuffer): Promise<void> {
    if (this.role === 'closed') return Promise.reject(new Error('engine client closed'));
    // This seam is the secret's terminal owner (security rule 7). On the leader
    // path the worker becomes the terminal owner — `LocalTransport.start`
    // transfers the buffer in (neutered), never copied. On the follower path the
    // keyless transport gets no secret: we scrub the buffer we decided not to use
    // right here, rather than in a callee that would be zeroing someone else's.
    if (this.role !== 'leader') new Uint8Array(secret).fill(0);
    return this.current.start(secret).then(() => {
      this.started = true;
    });
  }

  command(command: CommandDescriptor, transfer: Transferable[]): Promise<void> {
    return this.current.command(command, transfer);
  }

  async beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    const generation = this.generation;
    const inner = await this.current.beginWrite(target, size);
    // The engine that minted this went away mid-open; its staging went with it.
    if (generation !== this.generation) throw unknownHandle('write');
    return this.writes.open(inner);
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    const inner = this.writes.resolve(handle);
    if (inner === undefined) return Promise.reject(unknownHandle('write'));
    return this.current.pushChunk(inner, chunk);
  }

  async commitWrite(handle: WriteHandle): Promise<bigint> {
    const inner = this.writes.resolve(handle);
    if (inner === undefined) throw unknownHandle('write');
    const opId = await this.current.commitWrite(inner);
    // Dropped only once the commit resolves: a rejected one leaves the handle
    // open for its owner to abort.
    this.writes.release(handle);
    return opId;
  }

  async abortWrite(handle: WriteHandle): Promise<void> {
    const inner = this.writes.resolve(handle);
    // An abort on a handle whose engine is gone has nothing left to release.
    if (inner === undefined) return;
    await this.current.abortWrite(inner);
    this.writes.release(handle);
  }

  snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    return this.current.snapshot(folder);
  }

  siweChallenge(): Promise<string> {
    return this.current.siweChallenge();
  }

  download(node: Uint8Array): Promise<ArrayBuffer> {
    return this.current.download(node);
  }

  async openContentStream(node: Uint8Array): Promise<StreamHandle> {
    const generation = this.generation;
    const inner = await this.current.openContentStream(node);
    // The engine that minted this went away mid-open; its stream went with it.
    if (generation !== this.generation) throw unknownHandle('stream');
    return this.streams.open(inner);
  }

  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    const inner = this.streams.resolve(handle);
    if (inner === undefined) return Promise.reject(unknownHandle('stream'));
    return this.current.readStream(inner, offset, length);
  }

  closeStream(handle: StreamHandle): Promise<void> {
    const inner = this.streams.resolve(handle);
    if (inner === undefined) return Promise.resolve();
    this.streams.release(handle);
    return this.current.closeStream(inner);
  }

  subscribe(listener: EngineEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  close(): void {
    void this.dispose();
  }

  // --- leadership + swaps ---

  /** Reports this tab's open folder into the origin-wide focus-window union. */
  reportFocus(node: Uint8Array | null): void {
    this.ownFocus = node;
    if (this.role === 'leader') this.relay?.reportLocalFocus(this.clientId, node);
    else if (this.role === 'follower') (this.current as BroadcastTransport).reportFocus(node);
  }

  /** Tears this tab out of the engine: closes the transport and releases the lock. */
  async dispose(): Promise<void> {
    if (this.role === 'closed') return;
    this.role = 'closed';
    this.innerUnsub();
    this.relay?.close();
    this.current.close();
    await this.election.close();
    this.channel.close();
  }

  /** Installs the live transport, retiring the handles the previous one held. */
  private swapCurrent(transport: EngineTransport): void {
    this.current = transport;
    this.retireHandles();
  }

  /** Retires every open handle: the engine that minted them is gone. */
  private retireHandles(): void {
    this.generation += 1;
    this.streams.clear();
    this.writes.clear();
  }

  private installFollower(): BroadcastTransport {
    // Leadership moving between two *other* tabs replaces the engine without
    // replacing this transport, so the handle fence rides the same signal as the
    // transport's own port fence.
    const follower = new BroadcastTransport(
      this.channel,
      this.clientId,
      this.courier,
      this.config.locks,
      {
        onLeadershipChange: () => this.retireHandles(),
      }
    );
    this.swapCurrent(follower);
    this.innerUnsub = follower.subscribe((event) => this.fanOut(event));
    return follower;
  }

  private becomeLeader(): void {
    if (this.role === 'closed') return;
    // Defer off the election callback so `this.election` is fully assigned before
    // promotion runs: a synchronous worker-spawn throw then reaches `abortPromotion`
    // with a live election to release, never a half-constructed one.
    queueMicrotask(() => void this.promote());
  }

  /**
   * Win the lock → become the engine host. The worker is spawned and (on
   * failover) cold-started with a re-derived secret **before** we advertise
   * leadership: we do not install the local transport, route commands, or
   * register the relay until the worker start resolves, so a command in the
   * promotion window never reaches an uninitialized worker. If startup fails we
   * release the lock (a healthy tab takes over) and surface via `onError` rather
   * than holding a dead-leader lock.
   */
  private async promote(): Promise<void> {
    if (this.role === 'closed') return;
    const wasActiveFollower = this.started;

    // Drop the follower transport now: a command in flight rejects so the UI
    // retries it against the new leader, and a command issued during the
    // promotion window hits this closed transport and rejects (never hangs).
    this.innerUnsub();
    this.current.close();

    // Worker creation and cold start run inside the guard: a synchronous throw
    // from `spawnWorker()` or the `LocalTransport` constructor must release the
    // Web Lock exactly like an async startup failure, never leave it held with
    // no live leader (a dead-leader lock).
    let local: LocalTransport | null = null;
    try {
      const worker = this.config.spawnWorker();
      local = new LocalTransport(worker);

      if (wasActiveFollower) {
        const secret = await this.provideFailoverSecret();
        try {
          await local.start(secret);
        } finally {
          // This frame owns the re-derived buffer until a transfer detaches it
          // (`SecretSource`); a start that failed before the post did not.
          if (secret.byteLength > 0) new Uint8Array(secret).fill(0);
        }
      }
      // `dispose()` may have latched `closed` during the awaited startup.
      if ((this.role as EngineClientRole) === 'closed') {
        local.close();
        return;
      }

      // Startup resolved: only now install the transport as active, wire events,
      // and announce the relay so followers route commands to a live worker.
      this.role = 'leader';
      this.swapCurrent(local);
      this.innerUnsub = local.subscribe((event) => this.fanOut(event));
      this.relay = new LeaderRelay(this.channel, local, this.courier, this.config.locks);
      if (this.ownFocus) this.relay.reportLocalFocus(this.clientId, this.ownFocus);
    } catch (error) {
      this.abortPromotion(local, error);
    }
  }

  private async provideFailoverSecret(): Promise<ArrayBuffer> {
    const source = this.config.secretSource;
    if (!source) throw new Error('failover leader has no SecretSource; engine cannot start');
    return source.provideSecret();
  }

  private abortPromotion(local: LocalTransport | null, error: unknown): void {
    // Never advertise a dead leader: tear down any half-built worker, release
    // the lock so a healthy tab is elected, and fall back to a follower that
    // mirrors the next leader. `local` is null when the throw beat transport
    // construction — there is nothing to tear down, only the lock to release.
    local?.close();
    if (this.role !== 'closed') {
      this.role = 'follower';
      this.installFollower();
      void this.election.close();
    }
    this.config.onError?.(error instanceof Error ? error : new Error(String(error)));
  }

  private fanOut(event: Parameters<EngineEventListener>[0]): void {
    fanOut(this.listeners, event);
  }
}

function defaultChannel(): BroadcastChannelLike {
  return new BroadcastChannel(BROADCAST_CHANNEL_NAME);
}
