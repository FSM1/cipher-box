/**
 * The pure parts of the desktop soak leg: its platform, its time budgets, and
 * the environment the remote-stack mode reads. The grantee ledger and the
 * marker helpers are the web soak's own (`grantee.ts`).
 */

import type { DesktopLeg } from '../../../web-e2e/staging/soak/grantee';
import { PRODUCTION_PROFILE, deadlines, type Deadlines, type SyncTimingProfile } from '../profile';

export const LOGIN_SECRET_ENV = 'SOAK_GRANTEE_LOGIN_SECRET';
const API_URL_ENV = 'VITE_API_URL';
const ROUTING_ENDPOINTS_ENV = 'VITE_ROUTING_ENDPOINTS';

export function legOf(platform: NodeJS.Platform): DesktopLeg {
  if (platform === 'darwin') return 'macos';
  if (platform === 'linux') return 'linux';
  if (platform === 'win32') return 'windows';
  throw new Error(`no desktop soak leg runs on ${platform}`);
}

/** The time each step of a leg gets, so a slow night fails with the reason of its step. */
export interface SoakBudgets {
  /** The API serves a login, the shell writes its control file, and the mount opens. */
  signInMs: number;
  /** The grantee ledger opens through the mount. */
  ledgerMs: number;
  /** The reads of the other legs' markers, before the per-marker share. */
  readBaseMs: number;
  readPerMarkerMs: number;
  /** Today's marker and its ledger line land on the writer's mount. */
  writeMs: number;
  /** A cold mount serves both, after its own sign-in. */
  publishMs: number;
}

/** Multiples of the poll cadence, so the 30-second production cadence paces no step past its budget. */
export function soakBudgets(profile: SyncTimingProfile = PRODUCTION_PROFILE): SoakBudgets {
  const tick = profile.pollCadenceMs;
  return {
    signInMs: 20 * tick,
    ledgerMs: 10 * tick,
    readBaseMs: 10 * tick,
    readPerMarkerMs: Math.round(tick / 10),
    writeMs: 10 * tick,
    publishMs: 20 * tick,
  };
}

export function readBudget(budgets: SoakBudgets, markers: number): number {
  return budgets.readBaseMs + markers * budgets.readPerMarkerMs;
}

/**
 * The instance waits of a leg. The API, the control file and the mount waits
 * together fit inside the sign-in budget, so a start that runs out names the
 * wait that ran out.
 */
export function legDeadlines(
  budgets: SoakBudgets,
  profile: SyncTimingProfile = PRODUCTION_PROFILE
): Deadlines {
  return {
    ...deadlines(profile),
    apiReadyMs: Math.round(budgets.signInMs / 4),
    controlFileMs: Math.round(budgets.signInMs / 4),
    mountMs: Math.round(budgets.signInMs / 2),
  };
}

type Env = Readonly<Record<string, string | undefined>>;

/** `env` without the soak variables, for the environment a host inherits. */
export function withoutSoakVars(env: Env): Record<string, string | undefined> {
  return Object.fromEntries(Object.entries(env).filter(([name]) => !name.startsWith('SOAK_')));
}

/**
 * The grantee login secret as the host reads it: 64 lowercase hex characters.
 * No refusal repeats the value.
 */
export function loginSecret(env: Env): string {
  const raw = env[LOGIN_SECRET_ENV]?.trim();
  if (raw === undefined || raw === '') throw new Error(`${LOGIN_SECRET_ENV} is not set`);
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error(`${LOGIN_SECRET_ENV} is not 32 bytes of hex`);
  }
  return raw.replace(/^0x/, '').toLowerCase();
}

export interface RemoteStack {
  readonly apiUrl: string;
  readonly routingEndpoints: readonly string[];
}

/**
 * The deployment the host was built against, from the variables its build
 * read. An endpoint is https, or http on a loopback host for a local run.
 */
export function remoteStack(env: Env): RemoteStack {
  const apiUrl = endpoint(API_URL_ENV, env[API_URL_ENV]);
  const routingEndpoints = (env[ROUTING_ENDPOINTS_ENV] ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
    .map((entry) => endpoint(ROUTING_ENDPOINTS_ENV, entry));
  if (routingEndpoints.length === 0) {
    throw new Error(`${ROUTING_ENDPOINTS_ENV} must list at least one routing endpoint`);
  }
  return { apiUrl, routingEndpoints };
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

function endpoint(name: string, raw: string | undefined): string {
  const value = raw?.trim();
  if (value === undefined || value === '') throw new Error(`${name} is not set`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} holds a value that is not a URL`);
  }
  if (url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    return value;
  }
  throw new Error(`${name} must be an https URL, or http on a loopback host`);
}
