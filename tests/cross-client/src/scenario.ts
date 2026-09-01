/**
 * What every cross-client scenario gets, and the reads they share.
 */

import { strict as assert } from 'node:assert';
import { readdir } from 'node:fs/promises';
import { expect } from '@playwright/test';
import type { Instance } from '../../desktop-e2e/src/instance';
import type { VaultStatus } from '../../desktop-e2e/src/control';
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
      what: `the mount to project ${name} in ${path}`,
      timeoutMs: context.deadlines.refreshMs,
      intervalMs: context.deadlines.intervalMs,
    }
  );
}

/** The mount held: it dead-lettered nothing, raised no warning, and stayed up. */
export function mountHeld(read: VaultStatus, what: string): void {
  assert.equal(read.deadLetters, 0, `${what} dead-letters nothing at the mount`);
  assert.deepEqual(read.warnings, [], `${what} raises no warning at the mount`);
  assert.equal(read.mount.state, 'mounted', `${what} keeps the mount`);
}

/** Waits for a pass at `host` to list `name` at the vault root. */
export function listsAtRoot(context: ScenarioContext, host: WebHost, name: string): Promise<void> {
  return passUntil(context, `${host.name} to list ${name} at the vault root`, 1, () =>
    vaultRows(host, null, name, null)
  );
}

/** Waits for a pass at `host` to list `name` inside its own folder `folder`. */
export function listsInFolder(
  context: ScenarioContext,
  host: WebHost,
  folder: string,
  name: string
): Promise<void> {
  return passUntil(context, `${host.name} to list ${name} in ${folder}`, 1, () =>
    vaultRows(host, folder, name, null)
  );
}

/**
 * Waits for a pass at `host` to stop listing `name` inside its own `folder`,
 * while it still lists `survivor`.
 */
export function dropsFromFolder(
  context: ScenarioContext,
  host: WebHost,
  folder: string,
  name: string,
  survivor: string
): Promise<void> {
  return passUntil(context, `${host.name} to drop ${name} from ${folder}`, 0, () =>
    vaultRows(host, folder, name, survivor)
  );
}

/** Reads how many rows one fresh pass lists for `name` under `folder`, or at the root. */
async function vaultRows(
  host: WebHost,
  folder: string | null,
  name: string,
  survivor: string | null
): Promise<number> {
  await host.openFiles();
  if (folder !== null) await host.files.open(folder);
  await host.refresh();
  return rowsListed(host, name, survivor);
}

/**
 * The rows a landed listing holds for `name`.
 *
 * A wait for zero rows takes a `survivor` the listing must also hold. A
 * navigation click awaits nothing and `Locator.count` resolves at once, so a
 * count read off a listing that never landed answers zero for a row that is
 * still published.
 */
export async function rowsListed(
  host: WebHost,
  name: string,
  survivor: string | null
): Promise<number> {
  if (survivor !== null) await expect(host.files.row(survivor)).toHaveCount(1);
  return host.files.row(name).count();
}

/**
 * Polls `rows` until one fresh pass counts exactly `want` of them.
 *
 * Each read is a whole pass rather than a retry of one: a record the network
 * has not served yet is discovered, never delivered.
 */
export async function passUntil(
  context: ScenarioContext,
  what: string,
  want: number,
  rows: () => Promise<number>
): Promise<void> {
  await poll(rows, (count) => count === want, {
    what: `a pass at ${what}`,
    timeoutMs: context.deadlines.refreshMs,
    intervalMs: context.deadlines.intervalMs,
  });
}
