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
import { BroadcastTransport, EngineHeldElsewhereError } from './broadcastTransport.js';
import { fanOut, unknownHandle } from './correlatedTransport.js';
import { asError } from './errorMessage.js';
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
  CommandOutcomeDescriptor,
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
  provideSecret(): Promise<LoginSecret>;
}

/**
 * The two travel together because a failover cold start must not open one
 * account's durable stores under another account's secret.
 */
export interface LoginSecret {
  secret: ArrayBuffer;
  /** Names the account whose durable stores the engine opens (`makeBrowserSeams`). */
  accountId: string;
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
 * How long a sign-in refused by an engine-less leader waits for that leader to
 * give the lock up. Bounded so a peer that will not step aside surfaces as the
 * refusal it made rather than as a hang; each step is a lock release, so a
 * handful of engine-less tabs still clear well inside it.
 */
const YIELD_TIMEOUT_MS = 5000;

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
  // Replaced, not reused, when this tab steps aside (`yieldLeadership`): a
  // request is one-shot, so re-queueing means a fresh one.
  private election: LeaderElection;

  private role: EngineClientRole = 'follower';
  private current!: EngineTransport;
  private readonly streams = new HandleTable();
  private readonly writes = new HandleTable();
  private generation = 0;
  private relay: LeaderRelay | null = null;
  private innerUnsub!: () => void;
  private readonly listeners = new Set<EngineEventListener>();

  // The account the engine this tab reaches holds; `null` until a start resolves
  // against it. This is the tab's session, published to `subscribeSession`.
  private accountId: string | null = null;
  // The account this tab hosts an engine for: named the moment `start` is
  // called, then tracked to whatever an engine actually holds. A tab can have a
  // session before any engine holds it — that gap is what a promotion
  // cold-starts through, and what stops a signed-in tab yielding.
  private loginAccount: string | null = null;
  private readonly sessionListeners = new Set<() => void>();
  // Starts parked on this tab cold-starting its own engine (`awaitOwnEngine`).
  private readonly promotions = new Set<(failure: Error | null) => void>();
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

    this.election = this.newElection();

    this.facade = new EngineFacade(this);
  }

  currentRole(): EngineClientRole {
    return this.role;
  }

  /**
   * Subscribes to this tab's session state; `useSyncExternalStore`-shaped, so a
   * host reads sign-in from the engine rather than from a store of its own
   * (blueprint/web-client.md "UI state law"). Returns an unsubscribe.
   */
  readonly subscribeSession = (listener: () => void): (() => void) => {
    this.sessionListeners.add(listener);
    return () => this.sessionListeners.delete(listener);
  };

  /**
   * The account the origin's engine holds for this tab, or `null` when it holds
   * none — a tab that never signed in, one whose session was torn down, and one
   * whose promotion could not cold-start an engine all read the same.
   */
  readonly signedInAccount = (): string | null => this.accountId;

  // --- EngineTransport ---

  start(secret: ArrayBuffer, accountId: string): Promise<void> {
    // This seam is the secret's terminal owner (security rule 7). On the leader
    // path the worker becomes the terminal owner — `LocalTransport.start`
    // transfers the buffer in (neutered), never copied. On the follower path the
    // keyless transport gets no secret, and a closed client no transport at all:
    // we scrub the buffer we decided not to use right here, rather than in a
    // callee that would be zeroing someone else's.
    const asFollower = this.role !== 'leader';
    if (asFollower) new Uint8Array(secret).fill(0);
    if (this.role === 'closed') return Promise.reject(new Error('engine client closed'));
    // Named before the send: a promotion landing mid-start must cold-start for
    // this account rather than take the lock as an engine-less leader.
    this.loginAccount = accountId;
    return this.current.start(secret, accountId).then(
      () => {
        this.holdsAccount(accountId);
        this.relay?.serves(accountId);
      },
      (error: unknown) => this.startOnOwnEngine(error, accountId, asFollower)
    );
  }

  /**
   * A follower start that reached no engine falls back to this tab's own
   * promotion: an engine-less leader steps aside for a tab that has a session,
   * because only the lock holder can cold-start one. Leadership moving at all
   * mid-start replaces the transport this call was delegated to, so the answer
   * is whether this tab's engine comes up — not what the leadership it asked
   * had to say on its way out.
   *
   * A refusal naming another account is final: the origin's one engine is not
   * this tab's to take, whatever the lock does next. So is a leader-path
   * failure, where the engine itself refused the secret.
   */
  private async startOnOwnEngine(
    error: unknown,
    accountId: string,
    asFollower: boolean
  ): Promise<void> {
    try {
      const heldByOther = error instanceof EngineHeldElsewhereError && error.heldBy !== null;
      if (!asFollower || heldByOther) throw error;
      await this.awaitOwnEngine(accountId, asError(error));
    } catch (failure) {
      // Back to whatever an engine really holds: nothing, unless an earlier
      // start already landed one. Otherwise every engine-less leader after this
      // would be asked to step aside for a session that never was.
      this.holdsAccount(this.accountId);
      throw failure;
    }
  }

  /**
   * Waits for this tab's own promotion to cold-start `accountId`, settling with
   * `refusal` when it runs out or resolves against some other account — a wait
   * that ended without an engine is the refusal it started from.
   */
  private awaitOwnEngine(accountId: string, refusal: Error): Promise<void> {
    if (this.accountId === accountId) return Promise.resolve();
    return new Promise<void>((resolve, reject) => {
      const settle = (failure: Error | null): void => {
        clearTimeout(timer);
        this.promotions.delete(settle);
        if (failure === null && this.accountId === accountId) resolve();
        else reject(failure ?? refusal);
      };
      const timer = setTimeout(() => settle(refusal), YIELD_TIMEOUT_MS);
      this.promotions.add(settle);
    });
  }

  /** Settles every start parked on this tab cold-starting its own engine. */
  private settlePromotions(failure: Error | null): void {
    for (const settle of [...this.promotions]) settle(failure);
  }

  /**
   * Records what the engine this tab reaches holds, publishing the change. The
   * account this tab hosts for follows it: an engine holding one is a session
   * the next promotion must cold-start again, and an engine holding none leaves
   * this tab nothing to host.
   */
  private holdsAccount(accountId: string | null): void {
    this.loginAccount = accountId;
    if (this.accountId === accountId) return;
    this.accountId = accountId;
    fanOut(this.sessionListeners, undefined);
  }

  command(command: CommandDescriptor, transfer: Transferable[]): Promise<CommandOutcomeDescriptor> {
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
    if (inner === undefined) {
      // Refused before any transfer: this seam is the chunk's terminal owner.
      new Uint8Array(chunk).fill(0);
      return Promise.reject(unknownHandle('write'));
    }
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
    this.holdsAccount(null);
    this.settlePromotions(new Error('engine client closed'));
    await this.election.close();
    this.channel.close();
  }

  /**
   * An engine-less leader steps aside for a tab that has a session: only the
   * lock holder can cold-start an engine, and this one holds no keys to do it
   * with, so every other tab on the origin is blocked until it gives the lock
   * up. It re-queues behind the tabs already waiting, so a later sign-in here
   * can still host — and since only a leader with no session ever yields, two
   * of them cannot pass the lock between themselves.
   */
  private yieldLeadership(): void {
    if (this.role !== 'leader' || this.loginAccount !== null) return;
    this.innerUnsub();
    this.relay?.close();
    this.relay = null;
    this.current.close();
    this.role = 'follower';
    this.installFollower();
    // Queued before the release, so the request lands behind every tab already
    // waiting rather than ahead of the one this step aside is for.
    const steppingDown = this.election;
    this.election = this.newElection();
    void steppingDown.close();
  }

  private newElection(): LeaderElection {
    return new LeaderElection(
      this.config.locks,
      this.config.lockName ?? BROADCAST_CHANNEL_NAME,
      () => this.becomeLeader(),
      this.config.onError
    );
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
        // A tab that is already signed in keeps its account across a rebuilt
        // transport: a promotion that aborts must not leave it greeting for none.
        // The login, not the engine's answer — a tab refused by an engine-less
        // leader has to greet the next one under its account to be served.
        accountId: this.loginAccount ?? undefined,
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
    const hasSession = this.loginAccount !== null;

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

      if (hasSession) {
        const { secret, accountId } = await this.provideFailoverSecret();
        try {
          await local.start(secret, accountId);
          this.holdsAccount(accountId);
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
      this.relay = new LeaderRelay(this.channel, local, this.courier, this.config.locks, {
        onEngineWanted: () => this.yieldLeadership(),
      });
      this.relay.serves(this.accountId);
      if (this.ownFocus) this.relay.reportLocalFocus(this.clientId, this.ownFocus);
      // Only once the transport is live: a start this releases must find a
      // leader that can already serve it.
      this.settlePromotions(null);
    } catch (error) {
      this.abortPromotion(local, error);
    }
  }

  private async provideFailoverSecret(): Promise<LoginSecret> {
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
    const failure = asError(error);
    // Cleared before the follower is rebuilt, which greets under it: the engine
    // this tab was to host does not exist, so neither does its session, and a
    // UI rendering signed in over it would be rendering a dead one.
    this.holdsAccount(null);
    if (this.role !== 'closed') {
      this.role = 'follower';
      this.installFollower();
      void this.election.close();
    }
    this.settlePromotions(failure);
    this.config.onError?.(failure);
  }

  private fanOut(event: Parameters<EngineEventListener>[0]): void {
    fanOut(this.listeners, event);
  }
}

function defaultChannel(): BroadcastChannelLike {
  return new BroadcastChannel(BROADCAST_CHANNEL_NAME);
}
