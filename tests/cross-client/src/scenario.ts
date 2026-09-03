/**
 * What every cross-client scenario gets, and the reads they share.
 */

import { readdir } from 'node:fs/promises';
import type { Instance } from '../../desktop-e2e/src/instance';
import { poll } from '../../desktop-e2e/src/poll';
import type { Deadlines } from '../../desktop-e2e/src/profile';
import type { Stack } from '../../desktop-e2e/src/stack';
import type { WebHost } from './web';

export interface ScenarioContext {
  deadlines: Deadlines;
  /** The API, so a scenario can make a real outage. */
  stack: Stack;
  /** A fresh 32-byte login secret as 64 lowercase hex characters. */
  secret(): string;
  /** A mounted desktop host on `secretHex`. */
  desktop(name: string, secretHex: string): Promise<Instance>;
  /** A web host on `secretHex`, landed on the vault browser. */
  web(name: string, secretHex: string): Promise<WebHost>;
  /** A web host that signs in on the claim route and spends `link`. */
  claimant(name: string, secretHex: string, link: URL): Promise<WebHost>;
  log(message: string): void;
}

export interface Scenario {
  name: string;
  run(context: ScenarioContext): Promise<void>;
}

/** The 32-byte login secret shape the desktop entry and the web tap both take. */
const LOGIN_SECRET = /^[0-9a-f]{64}$/;

export function isLoginSecret(value: string): boolean {
  return LOGIN_SECRET.test(value);
}

/** The mount's own listing of one directory. */
export function mountNames(path: string): Promise<string[]> {
  return readdir(path);
}

/** Waits for the mount to project `name` in `path`. */
export async function projects(
  context: ScenarioContext,
  path: string,
  name: string
): Promise<void> {
  await poll(
    () => mountNames(path),
    (names) => names.includes(name),
    {
      what: `the mount to project ${name}`,
      timeoutMs: context.deadlines.refreshMs,
      intervalMs: context.deadlines.intervalMs,
    }
  );
}
