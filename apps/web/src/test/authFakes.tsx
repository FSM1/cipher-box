/**
 * The engine and Core Kit as the login flow sees them: both seams recorded, so a
 * test asserts what the flow dispatched rather than how it got there.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type {
  ApprovalDecision,
  AuthMethodDescriptor,
  BinDescriptor,
  BinRowDescriptor,
  CommandOutcomeDescriptor,
  DeviceRendezvousResult,
  DeviceRendezvousStep,
  EngineClient,
  ReceivedShareDescriptor,
  PendingApprovalDescriptor,
  RegisteredDeviceDescriptor,
  SiweIntent,
  SnapshotDescriptor,
  VaultSettingsDescriptor,
  VaultStorageDescriptor,
} from '@cipherbox/client';
import { rendezvousTransfer } from '@cipherbox/client';
import type { ReactNode } from 'react';
import { WagmiProvider } from 'wagmi';
import { CoreKitProvider } from '../auth/CoreKitProvider';
import type { WebCoreKitSession } from '../auth/coreKit';
import { DeviceIdentity } from '../auth/deviceIdentity';
import { MemoryDeviceKeys, SerialLocks } from './storeFakes';

import { IdentityProvider } from '../auth/IdentityProvider';
import {
  RecoveryRequiredError,
  type IdentityCredential,
  type IdentityExchange,
  type IdentityMethod,
} from '@cipherbox/login';
import { wagmiConfig } from '../lib/wagmi';
import { EngineProvider } from '../providers/EngineProvider';
import { VaultStorageProvider } from '../providers/VaultStorageProvider';

/** A 32-byte scalar in the hex shape Core Kit exports. */
export const SECRET_HEX = '0f'.repeat(32);

/** The nonce the fake exchange issues for a SIWE challenge. */
export const FAKE_NONCE = 'nonce123456789ab';

/** The identity token the fake exchange mints, whichever method asked. */
export const FAKE_IDENTITY_TOKEN = 'header.payload.signature';

/** The one phrase the fake session enrolls and accepts; 24 words, as a real one is. */
export const FAKE_PHRASE = `${'word '.repeat(23)}last`;

/** This browser's own device identity key, in the hex the registry takes. */
export const FAKE_DEVICE_PUBLIC_KEY = 'aa'.repeat(32);

/** This browser as the account's device registry carries it. */
export const FAKE_REGISTERED_DEVICE: RegisteredDeviceDescriptor = {
  id: 'device-01',
  publicKey: FAKE_DEVICE_PUBLIC_KEY,
  label: 'this browser',
  createdAt: '2026-08-31T09:00:00.000Z',
  lastSeenAt: '2026-08-31T09:00:00.000Z',
};

/**
 * The secp256k1 key the engine cuts for one rendezvous, in the compressed SEC1
 * hex the field takes: a `02`/`03` prefix and 32 bytes of x, so 66 characters.
 */
export const FAKE_EPHEMERAL_PUBLIC_KEY = `02${'bb'.repeat(32)}`;

/**
 * Detach exactly what the real transport transfers, so a component that then
 * touches one of those buffers fails here rather than only in a browser. The
 * rule comes from `@cipherbox/client` itself, so this double cannot drift.
 */
function detachTransferred(step: DeviceRendezvousStep): void {
  for (const buffer of rendezvousTransfer(step)) {
    structuredClone(buffer, { transfer: [buffer] });
  }
}

/** Copies a step's byte fields, so a later detach cannot rewrite the evidence. */
function snapshotStep(step: DeviceRendezvousStep): DeviceRendezvousStep {
  return Object.fromEntries(
    Object.entries(step).map(([field, value]) => [
      field,
      value instanceof Uint8Array ? value.slice() : value,
    ])
  ) as DeviceRendezvousStep;
}

/**
 * Whether a buffer holds no secret in this realm: either it was transferred
 * away, which detaches the view and leaves it no bytes, or it was erased in
 * place.
 */
export function holdsNoSecret(bytes: Uint8Array): boolean {
  return bytes.byteLength === 0 || bytes.every((byte) => byte === 0);
}

/**
 * The digits both screens show, which the member matches by eye (ADR 0009 D1).
 * A function of the two fields the requester itself fixed, as the engine's own
 * is: two screens shown different fields read out different digits.
 */
export function fakeComparisonValue(
  requesterDevicePublicKey: string,
  ephemeralPublicKey: string
): string {
  const transcript = `${requesterDevicePublicKey}/${ephemeralPublicKey}`;
  let folded = 0;
  for (const character of transcript) {
    folded = (folded * 31 + character.charCodeAt(0)) % 100_000_000;
  }
  const digits = String(folded).padStart(8, '0');
  return `${digits.slice(0, 4)} ${digits.slice(4)}`;
}

/** The factor an approver sealed back, as the relay carries it. */
export const FAKE_SEALED_FACTOR = 'c2VhbGVkLWZhY3Rvcg';

/** What each rendezvous step hands back for the caller to sign. */
export const FAKE_REQUEST_PAYLOAD = new Uint8Array([1, 2, 3, 4]);
export const FAKE_APPROVE_PAYLOAD = new Uint8Array([5, 6, 7, 8]);
export const FAKE_DENY_PAYLOAD = new Uint8Array([9, 10, 11, 12]);

/**
 * A stand-in signature that is a function of the message, so a test can bind a
 * dispatched signature to the payload it was taken over. Nothing verifies it.
 */
export function fakeSignatureOver(message: Uint8Array): string {
  const hex = Array.from(message, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex}${'0'.repeat(128)}`.slice(0, 128);
}

export interface EngineCalls {
  /** The buffers `start` was handed, still live so a test can check zeroization. */
  started: ArrayBuffer[];
  /** What each buffer held on arrival, before the handoff scrubbed it. */
  secrets: Uint8Array[];
  /** The wallet links, kept apart from `siwe`: a link is not a login. */
  siweLinks: { message: string; signature: Uint8Array }[];
  siweChallenges: number;
  /** The intent each nonce mint named; a link must never mint from the sign-in pool. */
  siweChallengeIntents: SiweIntent[];
  logouts: number;
  /** How many times this tab announced the session end to the origin. */
  originSessionEnds: number;
  /** The settings each accepted or refused save carried. */
  vaultSettings: VaultSettingsDescriptor[];
  /** The method id each unlink named. */
  unlinked: string[];
  /** Each restore, as the page dispatched it. */
  restores: { node: Uint8Array; into: Uint8Array | null }[];
  /** Each purge, by the node it named. */
  purges: Uint8Array[];
  /** The public key each registration challenge was asked for. */
  registrationChallenges: string[];
  registered: {
    publicKey: string;
    signature: string;
    identityToken: string;
    label: string | null;
  }[];
  /** The device id each revoke named. */
  revoked: string[];
  /**
   * Every rendezvous step, in the order a screen ran them, holding the caller's
   * own buffers. A step's transferred fields are detached by the time a test
   * reads them, so this answers what the caller was left holding, never what it
   * sent. Read [`rendezvousSent`] for the bytes.
   */
  rendezvous: DeviceRendezvousStep[];
  /** What each step carried, copied before the transfer detached it. */
  rendezvousSent: DeviceRendezvousStep[];
  answered: {
    requestId: string;
    decision: ApprovalDecision;
    devicePublicKey: string;
    ephemeralPublicKey: string;
    signature: string;
    sealedFactor: string | null;
  }[];
}

/** A hosted vault whose ledger has drained, as the storage pane first reads it. */
export const FAKE_VAULT_STORAGE: VaultStorageDescriptor = {
  settings: {
    pinMode: 'hosted',
    byoEndpoint: null,
    byoKind: null,
    byoCredentialStored: false,
    keepLatestVersions: null,
    binRetentionDays: 30,
    origin: 'resolved',
  },
  quota: { usedBytes: 1024, limitBytes: 4096, advisory: false },
  pendingReclaimBytes: 0,
  reclaimStalls: [],
};

/** A bin index the vault published and this device read, holding nothing. */
export const FAKE_EMPTY_BIN: BinDescriptor = { entries: [], origin: 'resolved' };

/** One soft-deleted node, as the bin index names it. 2026-01-01T00:00:00Z. */
export function binEntry(overrides: Partial<BinRowDescriptor> = {}): BinRowDescriptor {
  return {
    node: new Uint8Array(16).fill(7),
    kind: 'file',
    originParent: new Uint8Array(16).fill(2),
    originName: 'notes.txt',
    originFolder: { kind: 'folder', name: 'docs' },
    deletedAt: 1_767_225_600_000n,
    scope: new Uint8Array(16).fill(3),
    ...overrides,
  };
}

/**
 * The engine as a host reads it: a `start` the engine resolved *is* the session,
 * and tearing the client down ends it — so a test drives sign-in through the
 * engine, exactly as `EngineClient` publishes it.
 */
export function fakeEngineClient(
  overrides: Partial<{
    start: () => Promise<void>;
    logout: () => Promise<void>;
    saveVaultSettings: () => Promise<void>;
    unlinkAuthMethod: () => Promise<void>;
    /** What the storage pane reads back; `null` stands for a probe that failed. */
    vaultStorage: () => Promise<VaultStorageDescriptor>;
    authMethods: () => Promise<AuthMethodDescriptor[]>;
    receivedShares: () => Promise<ReceivedShareDescriptor[]>;
    /** The bin the `/bin` route reads back. */
    bin: () => Promise<BinDescriptor>;
    /** The listing the destination picker walks; it never lands by default. */
    snapshot: () => Promise<SnapshotDescriptor>;
    restore: () => Promise<CommandOutcomeDescriptor>;
    purge: () => Promise<CommandOutcomeDescriptor>;
    devices: () => Promise<RegisteredDeviceDescriptor[]>;
    pendingApprovals: () => Promise<PendingApprovalDescriptor[]>;
    registerDevice: () => Promise<void>;
    revokeDevice: () => Promise<void>;
    respondToApproval: () => Promise<void>;
  }> = {}
) {
  const calls: EngineCalls = {
    started: [],
    secrets: [],
    logouts: 0,
    siweLinks: [],
    siweChallenges: 0,
    siweChallengeIntents: [],
    originSessionEnds: 0,
    vaultSettings: [],
    unlinked: [],
    restores: [],
    purges: [],
    registrationChallenges: [],
    registered: [],
    revoked: [],
    rendezvous: [],
    rendezvousSent: [],
    answered: [],
  };
  const sessionListeners = new Set<() => void>();
  const sessionEndListeners = new Set<() => void>();
  let account: string | null = null;
  const holds = (next: string | null): void => {
    if (account === next) return;
    account = next;
    for (const listener of [...sessionListeners]) listener();
  };
  const client = {
    subscribeSession(listener: () => void) {
      sessionListeners.add(listener);
      return () => sessionListeners.delete(listener);
    },
    signedInAccount: () => account,
    // Announce-only, as the real client is: a tab is not its own sibling.
    endOriginSession() {
      calls.originSessionEnds += 1;
    },
    subscribeSessionEnd(listener: () => void) {
      sessionEndListeners.add(listener);
      return () => sessionEndListeners.delete(listener);
    },
    facade: {
      async start(secret: ArrayBuffer, accountId: string) {
        calls.started.push(secret);
        calls.secrets.push(new Uint8Array(secret).slice());
        await (overrides.start?.() ?? Promise.resolve());
        holds(accountId);
      },
      siweChallenge(intent: SiweIntent) {
        calls.siweChallenges += 1;
        calls.siweChallengeIntents.push(intent);
        return Promise.resolve(FAKE_NONCE);
      },
      siweLink(message: string, signature: Uint8Array) {
        calls.siweLinks.push({ message, signature });
        return Promise.resolve();
      },
      unlinkAuthMethod(methodId: string) {
        calls.unlinked.push(methodId);
        return overrides.unlinkAuthMethod?.() ?? Promise.resolve();
      },
      vaultStorage: () => overrides.vaultStorage?.() ?? Promise.resolve(FAKE_VAULT_STORAGE),
      authMethods: () => overrides.authMethods?.() ?? Promise.resolve([]),
      receivedShares: () => overrides.receivedShares?.() ?? Promise.resolve([]),
      bin: () => overrides.bin?.() ?? Promise.resolve(FAKE_EMPTY_BIN),
      restore(node: Uint8Array, into: Uint8Array | null) {
        calls.restores.push({ node, into });
        return overrides.restore?.() ?? Promise.resolve({ kind: 'done' as const });
      },
      purge(node: Uint8Array) {
        calls.purges.push(node);
        return overrides.purge?.() ?? Promise.resolve({ kind: 'done' as const });
      },
      devices: () => overrides.devices?.() ?? Promise.resolve([]),
      pendingApprovals: () => overrides.pendingApprovals?.() ?? Promise.resolve([]),
      deviceRegistrationChallenge(devicePublicKey: string) {
        calls.registrationChallenges.push(devicePublicKey);
        return Promise.resolve(Uint8Array.from([0xc0, 0xde]));
      },
      deviceRendezvous(step: DeviceRendezvousStep): Promise<DeviceRendezvousResult> {
        calls.rendezvous.push(step);
        calls.rendezvousSent.push(snapshotStep(step));
        detachTransferred(step);
        switch (step.kind) {
          case 'open':
            return Promise.resolve({
              kind: 'opened',
              ephemeralPublicKey: FAKE_EPHEMERAL_PUBLIC_KEY,
              requestPayload: FAKE_REQUEST_PAYLOAD,
              comparisonValue: fakeComparisonValue(step.devicePublicKey, FAKE_EPHEMERAL_PUBLIC_KEY),
            });
          case 'approve':
            return Promise.resolve({
              kind: 'response',
              sealedFactor: FAKE_SEALED_FACTOR,
              payload: FAKE_APPROVE_PAYLOAD,
            });
          case 'deny':
            return Promise.resolve({
              kind: 'response',
              sealedFactor: null,
              payload: FAKE_DENY_PAYLOAD,
            });
          case 'openFactor':
            return Promise.resolve({ kind: 'factor', factorKey: new Uint8Array(32).fill(0x7c) });
        }
      },
      registerDevice(
        publicKey: string,
        signature: string,
        identityToken: string,
        label: string | null
      ) {
        calls.registered.push({ publicKey, signature, identityToken, label });
        return overrides.registerDevice?.() ?? Promise.resolve();
      },
      revokeDevice(deviceId: string) {
        calls.revoked.push(deviceId);
        return overrides.revokeDevice?.() ?? Promise.resolve();
      },
      respondToApproval(
        requestId: string,
        decision: ApprovalDecision,
        devicePublicKey: string,
        ephemeralPublicKey: string,
        signature: string,
        sealedFactor: string | null
      ) {
        calls.answered.push({
          requestId,
          decision,
          devicePublicKey,
          ephemeralPublicKey,
          signature,
          sealedFactor,
        });
        return overrides.respondToApproval?.() ?? Promise.resolve();
      },
      async logout() {
        calls.logouts += 1;
        // The engine is zeroized either way: `EngineFacade.logout` tears the
        // transport down whatever the command answers.
        try {
          await (overrides.logout?.() ?? Promise.resolve());
        } finally {
          holds(null);
        }
      },
      forgetDevice: () => Promise.resolve(),
      saveVaultSettings(settings: VaultSettingsDescriptor) {
        calls.vaultSettings.push(settings);
        return overrides.saveVaultSettings?.() ?? Promise.resolve();
      },
      subscribe: () => () => undefined,
      snapshot: () => overrides.snapshot?.() ?? new Promise(() => undefined),
      setFocus: () => Promise.resolve(),
    },
    reportFocus: () => undefined,
    dispose() {
      holds(null);
      return Promise.resolve();
    },
  } as unknown as EngineClient;
  /** Replays the origin-wide session end a sibling tab would have announced. */
  const endSessionElsewhere = (): void => {
    holds(null);
    for (const listener of [...sessionEndListeners]) listener();
  };
  return { client, calls, endSessionElsewhere };
}

export interface CoreKitCalls {
  logins: IdentityCredential[];
  exports: number;
  logouts: number;
  phrases: string[];
  enrollments: number;
  /** The messages this device's identity key was asked to sign, as they arrived. */
  signed: Uint8Array[];
  /** Each fresh approval factor, still the caller's buffer, so a zeroization check reads it. */
  mintedFactors: Uint8Array[];
  /** Each adopted factor's live buffer, and what it held on arrival. */
  adopted: Uint8Array[];
  adoptedBytes: Uint8Array[];
}

/**
 * This device's identity key as the device surfaces drive it. Its signatures are
 * a function of the message rather than real Ed25519: nothing under test
 * verifies one, and a test binds a dispatched signature to what was signed.
 */
class FakeDeviceIdentity extends DeviceIdentity {
  constructor(private readonly calls: CoreKitCalls) {
    super(new MemoryDeviceKeys(), new SerialLocks(), 'fake-device-identity');
  }

  override publicKeyHex(): Promise<string> {
    return Promise.resolve(FAKE_DEVICE_PUBLIC_KEY);
  }

  override sign(message: Uint8Array<ArrayBuffer>): Promise<string> {
    this.calls.signed.push(message.slice());
    return Promise.resolve(fakeSignatureOver(message));
  }

  override forget(): Promise<void> {
    return Promise.resolve();
  }
}

export function fakeCoreKitSession(
  options: {
    loggedIn?: boolean;
    email?: () => string | null;
    /** Stands in for the mount-time restore; omit for one that settles at once. */
    restore?: () => Promise<void>;
    /** Turns every login into one that stops at the factor policy. */
    needsRecovery?: boolean;
    /** Whether this member already holds a recovery phrase. */
    enrolled?: boolean;
    /** Whether the account carries a policy of any factor kind; `enrolled` implies one. */
    factorPolicy?: boolean;
    /** What an enrollment could not confirm after the policy was cut. */
    enrollWarning?: string;
    /** What `identityToken` reports before a login named one; `null` for a restore. */
    identityToken?: string | null;
    /** A browser holding no identity key, as one is left after `forgetDevice`. */
    noDeviceIdentity?: boolean;
  } = {}
) {
  const calls: CoreKitCalls = {
    logins: [],
    exports: 0,
    logouts: 0,
    phrases: [],
    enrollments: 0,
    signed: [],
    mintedFactors: [],
    adopted: [],
    adoptedBytes: [],
  };
  const device = new FakeDeviceIdentity(calls);
  let identityToken =
    options.identityToken === undefined ? FAKE_IDENTITY_TOKEN : options.identityToken;
  let loggedIn = options.loggedIn ?? false;
  // Both read off the redeemed credential, as the real session does: a bare
  // restore knows neither, and a wallet login carries no address.
  let method: IdentityMethod | null = null;
  let email: string | null = null;
  const session: WebCoreKitSession = {
    accountId: () => 'acct01',
    restore: options.restore ?? (() => Promise.resolve()),
    isLoggedIn: () => loggedIn,
    login(credential) {
      calls.logins.push(credential);
      method = credential.method;
      email = credential.email;
      identityToken = credential.token;
      if (options.needsRecovery) return Promise.reject(new RecoveryRequiredError());
      loggedIn = true;
      return Promise.resolve();
    },
    hasRecoveryPhrase: () => options.enrolled ?? false,
    // A phrase is one factor, so an account that carries one carries a policy;
    // `factorPolicy` says so on its own for a device-approval-only member.
    hasFactorPolicy: () => options.factorPolicy ?? options.enrolled ?? false,
    recoverWithPhrase(phrase) {
      calls.phrases.push(phrase);
      if (phrase !== FAKE_PHRASE) {
        return Promise.reject(new Error('that recovery phrase does not open this account'));
      }
      loggedIn = true;
      return Promise.resolve();
    },
    enrollRecoveryPhrase() {
      calls.enrollments += 1;
      return Promise.resolve({ phrase: FAKE_PHRASE, warning: options.enrollWarning ?? null });
    },
    method: () => method,
    email: options.email ?? (() => email),
    logout() {
      calls.logouts += 1;
      loggedIn = false;
      return Promise.resolve();
    },
    forgetDevice: () => Promise.resolve(),
    deviceIdentity: () => (options.noDeviceIdentity === true ? null : device),
    identityToken: () => identityToken,
    mintApprovalFactor() {
      const factor = new Uint8Array(32).fill(0x5a);
      calls.mintedFactors.push(factor);
      return Promise.resolve(factor);
    },
    adoptApprovalFactor(factorKey) {
      calls.adopted.push(factorKey);
      calls.adoptedBytes.push(factorKey.slice());
      loggedIn = true;
      return Promise.resolve();
    },
    _UNSAFE_exportTssKey() {
      calls.exports += 1;
      return Promise.resolve(SECRET_HEX);
    },
  };
  return { session, calls };
}

export interface ExchangeCalls {
  google: string[];
  sentCodes: string[];
  verified: { email: string; code: string }[];
  nonces: number;
  wallet: { message: string; signature: string }[];
}

/** The API's identity surface as the login flow sees it. */
export function fakeIdentityExchange(overrides: Partial<IdentityExchange> = {}): {
  exchange: IdentityExchange;
  calls: ExchangeCalls;
} {
  const calls: ExchangeCalls = {
    google: [],
    sentCodes: [],
    verified: [],
    nonces: 0,
    wallet: [],
  };
  const grant = (method: IdentityMethod, email: string | null): IdentityCredential => ({
    method,
    token: FAKE_IDENTITY_TOKEN,
    verifierId: `subject-for-${method}`,
    email,
  });
  const exchange: IdentityExchange = {
    fromGoogleToken(idToken) {
      calls.google.push(idToken);
      return Promise.resolve(grant('google', 'user@example.test'));
    },
    sendEmailCode(email) {
      calls.sentCodes.push(email);
      return Promise.resolve();
    },
    fromEmailCode(email, code) {
      calls.verified.push({ email, code });
      return Promise.resolve(grant('email', email));
    },
    walletNonce() {
      calls.nonces += 1;
      return Promise.resolve(FAKE_NONCE);
    },
    fromWalletSignature(message, signature) {
      calls.wallet.push({ message, signature });
      return Promise.resolve(grant('wallet', null));
    },
    ...overrides,
  };
  return { exchange, calls };
}

/** Mounts the providers the login flow reads, over the given fakes. */
export function authWrapper(
  client: EngineClient,
  session: WebCoreKitSession,
  exchange: IdentityExchange = fakeIdentityExchange().exchange
) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <EngineProvider createClient={() => client}>
        <CoreKitProvider createSession={() => session}>
          <IdentityProvider exchange={exchange} googleClientId="google-client-id">
            <VaultStorageProvider>{children}</VaultStorageProvider>
          </IdentityProvider>
        </CoreKitProvider>
      </EngineProvider>
    );
  };
}

/** `authWrapper` plus the wallet-side providers the login *page* also mounts. */
export function pageWrapper(
  client: EngineClient,
  session: WebCoreKitSession,
  exchange: IdentityExchange = fakeIdentityExchange().exchange
) {
  const Auth = authWrapper(client, session, exchange);
  // One client per wrapper, not per render: wagmi's cache must survive a
  // re-render or the wallet flow reads as a fresh, disconnected mount.
  const queries = new QueryClient();
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
        <QueryClientProvider client={queries}>
          <Auth>{children}</Auth>
        </QueryClientProvider>
      </WagmiProvider>
    );
  };
}
