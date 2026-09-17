/**
 * What every cross-client scenario gets, and the reads they share.
 */

import { strict as assert } from 'node:assert';
import { readdir, stat } from 'node:fs/promises';
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
  /**
   * A mounted desktop host on `secretHex`. `device` names the local state the
   * instance starts from and defaults to `name`, so a second instance can start
   * on the state the first one left behind.
   */
  desktop(name: string, secretHex: string, device?: string): Promise<Instance>;
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

/** A byte pattern no text transfer survives, so a mangled read cannot pass. */
export function fileBytes(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (index * 7 + 1) % 256);
}

/** The mount's own listing of one directory. */
export function mountNames(path: string): Promise<string[]> {
  return readdir(path);
}

/**
 * Waits for a name this mount itself wrote to reach its own listing. It takes
 * the instance so a wedged read can abandon it.
 *
 * A name another client published needs `converges` instead: that one reads
 * off the network rather than off local state.
 */
export async function projects(
  context: ScenarioContext,
  mount: Instance,
  name: string,
  at: string = mount.mountRoot
): Promise<void> {
  await poll(
    () => mountNames(at),
    (names) => names.includes(name),
    {
      what: `the mount to project ${name} in ${at}`,
      timeoutMs: context.deadlines.refreshMs,
      intervalMs: context.deadlines.intervalMs,
      release: () => mount.abandon(),
    }
  );
}

/**
 * Waits for a name another client published to reach this mount.
 *
 * It needs a record off the network rather than a render of local state, so it
 * runs on the cross-device budget and refreshes on every pass
 * (`Deadlines.convergeMs`).
 */
export function converges(
  context: ScenarioContext,
  mount: Instance,
  name: string,
  at: string = mount.mountRoot
): Promise<void> {
  return afterRefresh(
    context,
    mount,
    `the mount to converge on ${name} in ${at}`,
    () => mountNames(at),
    (names) => names.includes(name)
  );
}

/**
 * Waits for the mount to size `path` at `bytes`. The length rides the child's
 * own record, which the parent's listing does not carry, so it needs a pass of
 * its own once the name has arrived.
 */
export function sizes(
  context: ScenarioContext,
  mount: Instance,
  path: string,
  bytes: number
): Promise<void> {
  return afterRefresh(
    context,
    mount,
    `the mount to size ${path} at ${bytes} bytes`,
    () =>
      stat(path).then(
        (read): number | string => read.size,
        (error: NodeJS.ErrnoException) => error.code ?? String(error)
      ),
    (size) => size === bytes
  );
}

/** One cross-device wait at the mount: a nocache pass, then the read it proves. */
async function afterRefresh<T>(
  context: ScenarioContext,
  mount: Instance,
  what: string,
  read: () => Promise<T>,
  accept: (value: T) => boolean
): Promise<void> {
  await poll(
    async () => {
      await mount.refresh();
      return read();
    },
    accept,
    {
      what,
      timeoutMs: context.deadlines.convergeMs,
      intervalMs: context.deadlines.readIntervalMs,
      release: () => mount.abandon(),
    }
  );
}

export function mountHeld(read: VaultStatus, what: string): void {
  assert.equal(read.deadLetters, 0, `${what} dead-letters nothing at the mount`);
  assert.deepEqual(read.warnings, [], `${what} raises no warning at the mount`);
  assert.equal(read.mount.state, 'mounted', `${what} keeps the mount`);
}

export function listsAtRoot(context: ScenarioContext, host: WebHost, name: string): Promise<void> {
  return passUntil(context, `${host.name} to list ${name} at the vault root`, 1, () =>
    vaultRows(host, null, name, null)
  );
}

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
 * The rows a landed listing holds for `name`, or `-1` when it did not land.
 *
 * A wait for zero rows takes a `survivor` the listing must also hold. A
 * navigation click awaits nothing and `Locator.count` resolves at once, so a
 * count read off a listing that never landed answers zero for a row that is
 * still published. An absent anchor is therefore a pass to read again, not a
 * result, so it reports a count no wait accepts.
 */
export async function rowsListed(
  host: WebHost,
  name: string,
  survivor: string | null
): Promise<number> {
  if (survivor !== null && (await host.files.row(survivor).count()) !== 1) return -1;
  return host.files.row(name).count();
}

/**
 * Polls `rows` until one fresh pass counts exactly `want` of them.
 *
 * Each read is a whole pass rather than a retry of one: a record the network
 * has not served yet is discovered, never delivered. Every caller waits on what
 * another client published, so the budget is the cross-device one
 * (`Deadlines.convergeMs`).
 */
export async function passUntil(
  context: ScenarioContext,
  what: string,
  want: number,
  rows: () => Promise<number>
): Promise<void> {
  await poll(rows, (count) => count === want, {
    what: `a pass at ${what}`,
    timeoutMs: context.deadlines.convergeMs,
    intervalMs: context.deadlines.intervalMs,
  });
}
