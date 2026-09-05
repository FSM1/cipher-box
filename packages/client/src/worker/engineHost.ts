/**
 * The engine host: wraps the wasm-bindgen `EngineHandle` in the wire-protocol
 * shape the worker serves. Runs inside the engine worker realm; key material
 * never leaves it.
 */

import { wipeTransfer } from '../buffers.js';
import { commandTransfer } from './protocol.js';
import type {
  AuthMethodDescriptor,
  BinDescriptor,
  CommandDescriptor,
  CommandOutcomeDescriptor,
  DeviceRendezvousResult,
  DeviceRendezvousStep,
  EventDescriptor,
  OpenedStream,
  PendingApprovalDescriptor,
  ReceivedShareDescriptor,
  RegisteredDeviceDescriptor,
  SharingDescriptor,
  SiweIntent,
  SnapshotDescriptor,
  StreamHandle,
  VaultStorageDescriptor,
  WriteHandle,
  WriteTarget,
} from './protocol.js';
import type {
  EngineWasm,
  WasmCommandOutcome,
  WasmDeviceApprovalResponse,
  WasmEngineHandle,
} from './engineWasm.js';
import type { EngineHostConfig } from '../spawnEngineWorker.js';
import {
  buffer,
  buildCommand,
  bytes,
  count,
  minted,
  nodeId,
  readAuthMethods,
  readBin,
  readDevices,
  readEvent,
  readPendingApprovals,
  readReceivedShare,
  readSharing,
  readSnapshot,
  readVaultStorage,
  record,
  text,
} from './commandCodec.js';

/**
 * The engine-facing surface the protocol server ([`serveEngine`]) drives. The
 * real [`EngineHost`] wraps WASM; the browser suite substitutes a fake to
 * exercise transport ordering and out-of-order correlation deterministically.
 */
export interface EngineHostLike {
  /** Cold-starts the engine for `accountId`, whose durable state it opens. */
  start(secret: ArrayBuffer, accountId: string): Promise<void>;
  /** Runs one command; resolves with what it produced. */
  command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor>;
  /** Opens a write handle for `size` plaintext bytes; the engine reserves them. */
  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle>;
  /** Takes ownership of `chunk`: the host is its terminal owner, so it scrubs the
   * plaintext to bound the lifetime of a copy no caller can reach. */
  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void>;
  /** Closes the handle and journals its op; resolves with the durable op id. */
  commitWrite(handle: WriteHandle): Promise<bigint>;
  abortWrite(handle: WriteHandle): Promise<void>;
  snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor>;
  /** Reads the contact book and `scope`'s committed grants, or the root's. */
  sharing(scope: Uint8Array | null): Promise<SharingDescriptor>;
  /** Reads this vault's accepted shares and the engine's verdict on each. */
  receivedShares(): Promise<ReceivedShareDescriptor[]>;
  /** Reads the owner's bin: one key-free row per soft-deleted node. */
  bin(): Promise<BinDescriptor>;
  vaultStorage(): Promise<VaultStorageDescriptor>;
  authMethods(): Promise<AuthMethodDescriptor[]>;
  /** Reads the device identity keys registered to this account. */
  devices(): Promise<RegisteredDeviceDescriptor[]>;
  /** The bytes this device signs to join the account registry. */
  deviceRegistrationChallenge(devicePublicKey: string): Promise<Uint8Array>;
  /** Reads the rendezvous rows this account is asked to approve. */
  pendingApprovals(): Promise<PendingApprovalDescriptor[]>;
  /** Runs one pure rendezvous step (ADR 0009); the engine holds no state for it. */
  deviceRendezvous(step: DeviceRendezvousStep): Promise<DeviceRendezvousResult>;
  siweChallenge(intent: SiweIntent): Promise<string>;
  download(node: Uint8Array): Promise<ArrayBuffer>;
  /**
   * Opens a read stream pinned to the node's current head content version,
   * reporting that version's plaintext size with the handle.
   */
  openContentStream(node: Uint8Array): Promise<OpenedStream>;
  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer>;
  closeStream(handle: StreamHandle): Promise<void>;
  nextEvent(): Promise<EventDescriptor | null>;
}

/**
 * The handle returns a JS-owned copy (never a WASM-memory view); reuse its exact
 * backing buffer for the transfer, re-slicing only a partial view.
 */
function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? (bytes.buffer as ArrayBuffer)
    : (bytes.slice().buffer as ArrayBuffer);
}

/** A getter the outcome's own `kind` promises, refused when it answers nothing. */
function present<T>(value: T | undefined, kind: string, field: string): T {
  if (value === undefined) throw new Error(`command outcome ${kind} carries no ${field}`);
  return value;
}

/** Reads a wasm-bindgen `CommandOutcome`'s getters into a descriptor. */
function readOutcome(outcome: WasmCommandOutcome): CommandOutcomeDescriptor {
  const kind = outcome.kind;
  switch (kind) {
    case 'done':
      return { kind: 'done' };
    case 'queued':
      return { kind: 'queued', opId: present(outcome.opId, kind, 'opId') };
    case 'contactImported':
      return {
        kind: 'contactImported',
        identityPublicKey: present(outcome.identityPublicKey, kind, 'identityPublicKey'),
        encPublicKey: present(outcome.encPublicKey, kind, 'encPublicKey'),
      };
    case 'inviteLinkMinted':
      return { kind: 'inviteLinkMinted', fragment: present(outcome.fragment, kind, 'fragment') };
    case 'forgotten':
      return {
        kind: 'forgotten',
        unsettledBytes:
          outcome.unsettledBytes === undefined ? null : Number(outcome.unsettledBytes),
        stalls: present(outcome.unsettledStalls, kind, 'unsettledStalls'),
      };
  }
  throw new Error(`unknown command outcome ${kind}`);
}

/** Reads an approver's answer into a descriptor, releasing the boundary object. */
function readApproval(answer: WasmDeviceApprovalResponse): DeviceRendezvousResult {
  try {
    return { kind: 'response', sealedFactor: answer.sealedFactor ?? null, payload: answer.payload };
  } finally {
    answer.free();
  }
}

/**
 * Exhaustiveness bound: adding a step kind without a wasm call fails the build,
 * and a sender off the union gets a refusal rather than an unhandled
 * fall-through.
 */
function unknownStep(step: never): Error {
  return new Error(`unknown rendezvous step kind: ${String((step as DeviceRendezvousStep).kind)}`);
}

/**
 * Runs one rendezvous step against the pure wasm functions. A step arrives as
 * plain data across a realm boundary, so every field passes a checker before
 * wasm-bindgen can coerce a wrong-typed one.
 */
function runRendezvous(wasm: EngineWasm, step: DeviceRendezvousStep): DeviceRendezvousResult {
  try {
    return dispatchRendezvous(wasm, step);
  } finally {
    // This realm's copies are its own to erase (security rule 7). The caller
    // keeps and erases its own, and a transferred buffer is already detached.
    scrubStep(step);
  }
}

/** Erases every secret a step carried into this realm. */
function scrubStep(step: DeviceRendezvousStep): void {
  if (typeof step !== 'object' || step === null) return;
  for (const held of [
    (step as { scalar?: unknown }).scalar,
    (step as { sealScalar?: unknown }).sealScalar,
    (step as { factorKey?: unknown }).factorKey,
  ]) {
    if (held instanceof Uint8Array) held.fill(0);
  }
}

function dispatchRendezvous(wasm: EngineWasm, step: DeviceRendezvousStep): DeviceRendezvousResult {
  text(record(step, 'step').kind, 'step.kind');
  switch (step.kind) {
    case 'open': {
      const opened = wasm.openDeviceRendezvous(
        text(step.devicePublicKey, 'devicePublicKey'),
        bytes(step.scalar, 'scalar')
      );
      try {
        return {
          kind: 'opened',
          ephemeralPublicKey: opened.ephemeralPublicKey,
          requestPayload: opened.requestPayload,
          comparisonValue: opened.comparisonValue,
        };
      } finally {
        opened.free();
      }
    }
    case 'approve':
      return readApproval(
        wasm.approveDeviceRendezvous(
          text(step.devicePublicKey, 'devicePublicKey'),
          text(step.requestId, 'requestId'),
          text(step.requesterDevicePublicKey, 'requesterDevicePublicKey'),
          text(step.ephemeralPublicKey, 'ephemeralPublicKey'),
          bytes(step.sealScalar, 'sealScalar'),
          bytes(step.factorKey, 'factorKey')
        )
      );
    case 'deny':
      return readApproval(
        wasm.denyDeviceRendezvous(
          text(step.devicePublicKey, 'devicePublicKey'),
          text(step.requestId, 'requestId'),
          text(step.ephemeralPublicKey, 'ephemeralPublicKey')
        )
      );
    case 'openFactor':
      return {
        kind: 'factor',
        factorKey: wasm.openDeviceFactor(
          text(step.sealedFactor, 'sealedFactor'),
          text(step.requestId, 'requestId'),
          text(step.requesterDevicePublicKey, 'requesterDevicePublicKey'),
          text(step.responderDevicePublicKey, 'responderDevicePublicKey'),
          text(step.responseSignature, 'responseSignature'),
          bytes(step.scalar, 'scalar')
        ),
      };
    default:
      throw unknownStep(step);
  }
}

/** A refusal carrying one of the engine's own stable codes, as the engine does. */
function refuse(code: 'notStarted' | 'alreadyStarted', message: string): Error {
  return Object.assign(new Error(message), { code });
}

/** What the engine instance itself is configured with, beyond its seams. */
export type EngineHostOptions = Pick<
  EngineHostConfig,
  'apiBaseUrl' | 'acceleratorBaseUrl' | 'publicGateways' | 'profile'
> & {
  /** Origin headroom the engine splits into its staging budget. */
  storageHeadroomBytes?: number;
};

export class EngineHost implements EngineHostLike {
  private engine: { handle: WasmEngineHandle; accountId: string } | null = null;
  private live!: (handle: WasmEngineHandle) => void;
  /** Resolves with the engine once one exists, so the event pump can wait. */
  private readonly running = new Promise<WasmEngineHandle>((resolve) => {
    this.live = resolve;
  });

  constructor(
    private readonly wasm: EngineWasm,
    private readonly seams: (accountId: string) => unknown,
    private readonly options: EngineHostOptions
  ) {}

  /**
   * The engine for `accountId`, built by the first `start`. Construction waits
   * for that call because the seams are namespaced per account, and no account
   * is known until the login secret arrives.
   */
  private engineFor(accountId: string): WasmEngineHandle {
    const id = text(accountId, 'accountId');
    const current = this.engine;
    if (current) {
      if (current.accountId !== id)
        throw refuse('alreadyStarted', 'another account holds this engine');
      return current.handle;
    }
    const handle = new this.wasm.EngineHandle(
      this.seams(id),
      this.options.profile,
      this.options.apiBaseUrl,
      this.options.acceleratorBaseUrl,
      this.options.publicGateways,
      this.options.storageHeadroomBytes
    );
    this.engine = { handle, accountId: id };
    this.live(handle);
    return handle;
  }

  /** The running engine; refused before `start`, as the engine itself refuses. */
  private get handle(): WasmEngineHandle {
    if (!this.engine) throw refuse('notStarted', 'engine not started');
    return this.engine.handle;
  }

  /**
   * Runs `use` over `buffer`, scrubbing it once the call settles — including
   * when it rejects. Buffers reaching the host arrive by transfer, making the
   * worker their terminal owner, and the engine below copies what it keeps.
   */
  private async scrubbing(
    buffer: ArrayBuffer,
    use: (view: Uint8Array) => Promise<unknown>
  ): Promise<void> {
    const view = new Uint8Array(buffer);
    try {
      await use(view);
    } finally {
      view.fill(0);
    }
  }

  async start(secret: ArrayBuffer, accountId: string): Promise<void> {
    // Inside `scrubbing`: a refused account still leaves this frame the
    // secret's terminal owner (security rule 7).
    return this.scrubbing(buffer(secret, 'secret'), (view) =>
      this.engineFor(accountId).start(view)
    );
  }

  async command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    // A buffer the descriptor carries arrived transferred, so this realm holds
    // the only copy — including on the routes that refuse before the codec is
    // reached, which is where the codec's own scrub cannot run.
    try {
      const outcome = await this.handle.command(buildCommand(this.wasm, command));
      try {
        return readOutcome(outcome);
      } finally {
        outcome.free();
      }
    } finally {
      wipeTransfer(commandTransfer(command));
    }
  }

  async beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    const reserved = count(size, 'size');
    const fields = record(target, 'target');
    if ('node' in fields) {
      return this.handle.beginWrite(
        undefined,
        undefined,
        nodeId(this.wasm, fields.node, 'node'),
        reserved,
        fields.expectedVersion === undefined
          ? undefined
          : bytes(fields.expectedVersion, 'expectedVersion')
      );
    }
    return this.handle.beginWrite(
      nodeId(this.wasm, fields.parent, 'parent'),
      text(fields.name, 'name'),
      undefined,
      reserved,
      undefined
    );
  }

  async pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    const write = minted(handle, 'handle');
    return this.scrubbing(buffer(chunk, 'chunk'), (view) => this.handle.pushChunk(write, view));
  }

  async commitWrite(handle: WriteHandle): Promise<bigint> {
    return this.handle.commitWrite(minted(handle, 'handle'));
  }

  async abortWrite(handle: WriteHandle): Promise<void> {
    await this.handle.abortWrite(minted(handle, 'handle'));
  }

  async snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    const view = await this.handle.snapshot(
      folder === null ? undefined : nodeId(this.wasm, folder, 'folder')
    );
    return readSnapshot(this.wasm, view);
  }

  async sharing(scope: Uint8Array | null): Promise<SharingDescriptor> {
    const view = await this.handle.sharing(
      scope === null ? undefined : nodeId(this.wasm, scope, 'scope')
    );
    return readSharing(this.wasm, view);
  }

  async receivedShares(): Promise<ReceivedShareDescriptor[]> {
    const rows = await this.handle.receivedShares();
    return rows.map((row) => readReceivedShare(this.wasm, row));
  }

  async bin(): Promise<BinDescriptor> {
    return readBin(this.wasm, await this.handle.bin());
  }

  async vaultStorage(): Promise<VaultStorageDescriptor> {
    return readVaultStorage(this.wasm, await this.handle.vaultStorage());
  }

  async authMethods(): Promise<AuthMethodDescriptor[]> {
    return readAuthMethods(this.wasm, await this.handle.authMethods());
  }

  async devices(): Promise<RegisteredDeviceDescriptor[]> {
    return readDevices(await this.handle.devices());
  }

  async deviceRegistrationChallenge(devicePublicKey: string): Promise<Uint8Array> {
    return this.handle.deviceRegistrationChallenge(text(devicePublicKey, 'devicePublicKey'));
  }

  async pendingApprovals(): Promise<PendingApprovalDescriptor[]> {
    return readPendingApprovals(await this.handle.pendingApprovals());
  }

  async deviceRendezvous(step: DeviceRendezvousStep): Promise<DeviceRendezvousResult> {
    return runRendezvous(this.wasm, step);
  }

  siweChallenge(intent: SiweIntent): Promise<string> {
    return this.handle.siweChallenge(intent);
  }

  async download(node: Uint8Array): Promise<ArrayBuffer> {
    return ownedBuffer(await this.handle.download(nodeId(this.wasm, node, 'node')));
  }

  async openContentStream(node: Uint8Array): Promise<OpenedStream> {
    const opened = await this.handle.openContentStream(nodeId(this.wasm, node, 'node'));
    try {
      return { handle: opened.handle, size: opened.size };
    } finally {
      opened.free();
    }
  }

  async readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    return ownedBuffer(
      await this.handle.readStream(
        minted(handle, 'handle'),
        count(offset, 'offset'),
        count(length, 'length')
      )
    );
  }

  async closeStream(handle: StreamHandle): Promise<void> {
    await this.handle.closeStream(minted(handle, 'handle'));
  }

  async nextEvent(): Promise<EventDescriptor | null> {
    const handle = await this.running;
    const event = await handle.nextEvent();
    return event ? readEvent(this.wasm, event) : null;
  }
}
