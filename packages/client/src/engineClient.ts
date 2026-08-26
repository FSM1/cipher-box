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

import {
  BROADCAST_CHANNEL_NAME,
  isSessionEnded,
  newClientId,
  SESSION_ENDED,
  type BroadcastChannelLike,
} from './broadcast.js';
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
  ReceivedShareDescriptor,
  SharingDescriptor,
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

/** A `start` waiting for an engine it can use, and the deadline bounding it. */
interface ParkedStart {
  /** Drops the deadline; this tab is opening the engine the start waits for. */
  hold(): void;
  settle(failure: Error | null): void;
}

/**
 * How long a start that reached no engine waits for one to arrive. Bounded so a
 * peer that will not step aside surfaces as the refusal it made rather than as
 * a hang; each step is a lock hand-off, so a handful of engine-less tabs still
 * clear well inside it.
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
  private readonly election: LeaderElection;

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
  // The account a `start` in flight named. `accountId` carries it once an engine
  // answers; together they are this tab's claim on one, which is what a
  // promotion cold-starts for and what stops a signed-in tab yielding.
  private pendingLogin: string | null = null;
  private readonly sessionListeners = new Set<() => void>();
  private readonly sessionEndListeners = new Set<() => void>();
  // Held here rather than read off `config`, because a session end drops it: the
  // capability to re-export the login secret must not outlive the session.
  private secretSource: SecretSource | null;
  // Starts parked on an engine for this tab becoming reachable (`awaitEngine`).
  private readonly parkedStarts = new Set<ParkedStart>();
  private ownFocus: Uint8Array | null = null;

  constructor(private readonly config: EngineClientConfig) {
    this.clientId = config.clientId ?? newClientId();
    this.channel = (config.createChannel ?? defaultChannel)();
    this.courier = config.courier ?? defaultCourier();
    this.secretSource = config.secretSource ?? null;

    this.channel.addEventListener('message', this.onChannelMessage);
    this.installFollower();

    // Requested before any tab can enqueue: an evicted origin loses the durable
    // op queue and every staged byte, not just cache.
    void requestStoragePersistence()
      .then((persisted) => config.onStoragePersistence?.(persisted))
      .catch((error: unknown) => config.onError?.(asError(error)));

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
   * none — never signed in, torn down, and could not be cold-started all read
   * the same, because none of them backs a vault.
   */
  readonly signedInAccount = (): string | null => this.accountId;

  /**
   * Subscribes to the origin-wide session end another tab announced. This client
   * has already dropped its claim and torn itself down by the time a listener
   * runs; what is left is the host's own half — its login provider's session and
   * whatever it renders over one. Returns an unsubscribe.
   */
  readonly subscribeSessionEnd = (listener: () => void): (() => void) => {
    this.sessionEndListeners.add(listener);
    return () => this.sessionEndListeners.delete(listener);
  };

  private readonly onChannelMessage = (event: MessageEvent): void => {
    if (!isSessionEnded(event.data)) return;
    this.endSession();
    fanOut(this.sessionEndListeners, undefined);
  };

  /**
   * Ends this tab's session: drops the re-export capability, then tears the tab
   * out of the engine. Both halves land before this returns, so a promotion the
   * released lock triggers finds no claim to cold-start for and no exporter to
   * cold-start it with.
   */
  private endSession(): void {
    this.secretSource = null;
    void this.dispose();
  }

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
    this.pendingLogin = accountId;
    return this.current.start(secret, accountId).then(
      () => {
        this.holdsAccount(accountId);
        this.relay?.serves(accountId);
      },
      (error: unknown) => this.startOnNextEngine(error, accountId, asFollower)
    );
  }

  /**
   * A follower start that reached no engine waits for the next one instead of
   * reporting a refusal the member cannot act on: an engine-less leader steps
   * aside for a tab that has a session, and whichever tab then wins the lock
   * either cold-starts here or adopts this tab's port.
   *
   * A refusal naming another account is final — the origin's one engine is not
   * this tab's to take, whatever the lock does next — as is a leader-path
   * failure, where the engine itself refused the secret, and a closed election,
   * which no promotion can ever settle.
   */
  private startOnNextEngine(error: unknown, accountId: string, asFollower: boolean): Promise<void> {
    const refusal = asError(error);
    const heldByOther = error instanceof EngineHeldElsewhereError && error.heldBy !== null;
    const settled =
      !asFollower || heldByOther || this.election.role === 'closed'
        ? Promise.reject(refusal)
        : this.awaitEngine(accountId, refusal);
    return settled.catch((failure: unknown) => {
      // The claim ends with the start that made it. A tab still holding one asks
      // every engine-less leader after it to step aside — and each stands down,
      // re-queues and is elected again, churning leadership for a session that
      // never was — and cold-starts for it on its own promotion.
      this.pendingLogin = null;
      if (this.accountId === null && this.role === 'follower') {
        (this.current as BroadcastTransport).forgetAccount();
      }
      throw failure;
    });
  }

  /**
   * Waits for an engine holding `accountId` to become reachable, settling with
   * `refusal` when the wait runs out or ends on some other account: a wait that
   * ended without an engine is the refusal it started from.
   */
  private awaitEngine(accountId: string, refusal: Error): Promise<void> {
    if (this.accountId === accountId) return Promise.resolve();
    return new Promise<void>((resolve, reject) => {
      let deadline: ReturnType<typeof setTimeout> | null = null;
      const parked: ParkedStart = {
        hold: () => {
          if (deadline !== null) clearTimeout(deadline);
          deadline = null;
        },
        settle: (failure) => {
          parked.hold();
          this.parkedStarts.delete(parked);
          if (failure === null && this.accountId === accountId) resolve();
          else reject(failure ?? refusal);
        },
      };
      deadline = setTimeout(() => parked.settle(refusal), YIELD_TIMEOUT_MS);
      this.parkedStarts.add(parked);
    });
  }

  /**
   * This tab reached an engine holding `accountId` — its own, or a leader's that
   * adopted its port. Either answers a start parked on the origin finding one,
   * so a tab served by whoever won the lock is not left rendering signed out.
   */
  private reachedEngine(accountId: string): void {
    this.holdsAccount(accountId);
    this.settleParkedStarts(null);
  }

  /** Settles every start parked on an engine becoming reachable. */
  private settleParkedStarts(failure: Error | null): void {
    fanOut(
      [...this.parkedStarts].map((parked) => parked.settle),
      failure
    );
  }

  /**
   * Stops the parked deadlines: this tab is starting the engine they wait for,
   * and a cold start is network-bound work rather than the lock hand-off the
   * deadline bounds. `abortPromotion` still settles them if it never opens.
   */
  private holdParkedStarts(): void {
    for (const parked of this.parkedStarts) parked.hold();
  }

  /**
   * Records what the engine this tab reaches holds, publishing the change. An
   * engine's answer supersedes the claim a start made, whether it granted one or
   * took the last one away.
   */
  private holdsAccount(accountId: string | null): void {
    this.pendingLogin = null;
    if (this.accountId === accountId) return;
    this.accountId = accountId;
    fanOut(this.sessionListeners, undefined);
  }

  /** Whether this tab has a login an engine should be hosting. */
  private get hasLogin(): boolean {
    return this.pendingLogin !== null || this.accountId !== null;
  }

  command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    return this.current.command(command);
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

  sharing(scope: Uint8Array | null): Promise<SharingDescriptor> {
    return this.current.sharing(scope);
  }

  receivedShares(): Promise<ReceivedShareDescriptor[]> {
    return this.current.receivedShares();
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

  /**
   * The teardown a facade logout runs, which on this client ends the session for
   * the whole origin rather than only this tab: the engine it tears down is the
   * origin's only one, and a sibling that kept its claim would win the released
   * lock and cold-start a replacement — re-seeding the durable seams a forget
   * just erased and minting a login for the session it just revoked.
   *
   * The provider's own lifecycle teardown goes to {@link dispose}, which ends no
   * session and announces nothing.
   */
  close(): void {
    if (this.role === 'closed') return;
    this.channel.postMessage(SESSION_ENDED);
    this.endSession();
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
    this.settleParkedStarts(new Error('engine client closed'));
    await this.election.close();
    this.channel.removeEventListener('message', this.onChannelMessage);
    this.channel.close();
  }

  /**
   * An engine-less leader steps aside for a tab that has a session: only the
   * lock holder can cold-start an engine, and this one holds no keys to do it
   * with, so every other tab on the origin is blocked until it gives the lock
   * up. Only a leader with no login of its own ever yields, so two engine-less
   * tabs cannot pass the lock between themselves.
   */
  private yieldLeadership(): void {
    if (this.role !== 'leader' || this.hasLogin) return;
    this.innerUnsub();
    this.relay?.close();
    this.relay = null;
    this.current.close();
    this.role = 'follower';
    this.installFollower();
    this.election.requeue();
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
        // The claim, not just the engine's answer — a tab refused by an
        // engine-less leader has to greet the next one under its account.
        accountId: this.accountId ?? this.pendingLogin ?? undefined,
        onLeadershipChange: () => this.retireHandles(),
        onAdopted: (accountId) => this.reachedEngine(accountId),
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
    const hasSession = this.hasLogin;

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
        this.holdParkedStarts();
        const { secret, accountId } = await this.provideFailoverSecret();
        try {
          // The session can end origin-wide while the export runs. Cold-starting
          // past that re-seeds the seams the end erased, so the latch is read
          // again here rather than only at entry.
          if ((this.role as EngineClientRole) === 'closed') {
            local.close();
            return;
          }
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
      // Only once the transport is live: a start this releases must find an
      // engine it can already use.
      this.settleParkedStarts(null);
    } catch (error) {
      this.abortPromotion(local, error);
    }
  }

  private async provideFailoverSecret(): Promise<LoginSecret> {
    const source = this.secretSource;
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
    this.settleParkedStarts(failure);
    this.config.onError?.(failure);
  }

  private fanOut(event: Parameters<EngineEventListener>[0]): void {
    fanOut(this.listeners, event);
  }
}

function defaultChannel(): BroadcastChannelLike {
  return new BroadcastChannel(BROADCAST_CHANNEL_NAME);
}
