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
import { fanOut } from './correlatedTransport.js';
import { EngineFacade } from './facade.js';
import { LeaderRelay } from './leaderRelay.js';
import { LeaderElection, type LockManagerLike } from './leadership.js';
import type { EngineEventListener, EngineTransport, EngineWorkerLike } from './transport.js';
import { LocalTransport } from './transport.js';
import type { CommandDescriptor } from './worker/protocol.js';

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
}

export type EngineClientRole = 'follower' | 'leader' | 'closed';

/**
 * The object handed to `EngineFacade`: it *is* the transport, delegating to the
 * live inner transport and re-homing the UI's event subscription across swaps.
 */
export class EngineClient implements EngineTransport {
  readonly facade: EngineFacade;

  private readonly channel: BroadcastChannelLike;
  private readonly clientId: string;
  private readonly election: LeaderElection;

  private role: EngineClientRole = 'follower';
  private current: EngineTransport;
  private relay: LeaderRelay | null = null;
  private innerUnsub: () => void;
  private readonly listeners = new Set<EngineEventListener>();

  // The vault is active (user logged in). A follower promoted while active must
  // re-derive keys; a never-active tab elected first just awaits `start`.
  private started = false;
  private ownFocus: Uint8Array | null = null;

  constructor(private readonly config: EngineClientConfig) {
    this.clientId = config.clientId ?? newClientId();
    this.channel = (config.createChannel ?? defaultChannel)();

    const follower = new BroadcastTransport(this.channel, this.clientId);
    this.current = follower;
    this.innerUnsub = follower.subscribe((event) => this.fanOut(event));

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
    return this.current.start(secret).then(() => {
      this.started = true;
    });
  }

  command(command: CommandDescriptor, transfer: Transferable[]): Promise<void> {
    return this.current.command(command, transfer);
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

  private becomeLeader(): void {
    if (this.role === 'closed') return;
    const wasActiveFollower = this.started;
    this.role = 'leader';

    // Drop the follower transport: any command in flight rejects so the UI
    // retries it against the new leader rather than losing it silently.
    this.innerUnsub();
    this.current.close();

    const worker = this.config.spawnWorker();
    const local = new LocalTransport(worker);
    this.current = local;
    this.innerUnsub = local.subscribe((event) => this.fanOut(event));
    this.relay = new LeaderRelay(this.channel, local);
    if (this.ownFocus) this.relay.reportLocalFocus(this.clientId, this.ownFocus);

    // A promoted active follower must cold-start the fresh worker with a
    // re-derived secret; a first-ever leader waits for the UI's explicit start.
    if (wasActiveFollower) this.coldStartOnFailover(local);
  }

  private coldStartOnFailover(local: LocalTransport): void {
    const source = this.config.secretSource;
    if (!source) {
      this.config.onError?.(new Error('failover leader has no SecretSource; engine cannot start'));
      return;
    }
    void source
      .provideSecret()
      .then((secret) => local.start(secret))
      .catch((error: unknown) => {
        this.config.onError?.(error instanceof Error ? error : new Error(String(error)));
      });
  }

  private fanOut(event: Parameters<EngineEventListener>[0]): void {
    fanOut(this.listeners, event);
  }
}

function defaultChannel(): BroadcastChannelLike {
  return new BroadcastChannel(BROADCAST_CHANNEL_NAME);
}
