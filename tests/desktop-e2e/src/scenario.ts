/**
 * What every scenario gets, and the assertions they share.
 */

import { strict as assert } from 'node:assert';
import { stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { VaultStatus } from './control';
import type { Instance } from './instance';
import { poll } from './poll';
import type { Deadlines } from './profile';
import type { Stack } from './stack';

export interface ScenarioContext {
  deadlines: Deadlines;
  /** The API, so a scenario can make a real outage. */
  stack: Stack;
  /** Starts a named instance on this scenario's own home root. */
  start(name: string): Promise<Instance>;
  log(message: string): void;
}

export interface Scenario {
  name: string;
  run(context: ScenarioContext): Promise<void>;
}

/**
 * Whether `path` is the root of a mounted filesystem.
 *
 * A mount root and the directory that holds it sit on different devices, and an
 * empty directory alone does not tell a live mount from a released one.
 */
export async function isMounted(path: string): Promise<boolean> {
  try {
    const [root, parent] = await Promise.all([stat(path), stat(dirname(path))]);
    return root.dev !== parent.dev;
  } catch {
    return false;
  }
}

/**
 * Runs `body` with the named instances and stops every one of them, so a failed
 * scenario cannot strand a mount for the next one.
 */
export async function withInstances<T>(
  context: ScenarioContext,
  names: string[],
  body: (instances: Instance[]) => Promise<T>
): Promise<T> {
  const started: Instance[] = [];
  try {
    // In order: two cold starts of one secret must not race to mint one vault.
    for (const name of names) started.push(await context.start(name));
    return await withDeadline(body(started), context.deadlines.scenarioMs, started);
  } finally {
    for (const instance of started.reverse()) await instance.stop();
  }
}

/**
 * Fails the scenario when its whole body outlasts the budget, and takes its
 * mounts away when it does.
 *
 * A kernel call on a mount has no timeout of its own. Rejecting the race leaves
 * every blocked call holding one of the few filesystem threads Node has, and
 * the teardown that follows needs those threads — so the mounts go first, which
 * is what returns the calls.
 */
function withDeadline<T>(body: Promise<T>, timeoutMs: number, started: Instance[]): Promise<T> {
  let timer: NodeJS.Timeout;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      void Promise.all(started.map((instance) => instance.abandon()));
      reject(new Error(`the scenario did not finish within ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref();
  });
  return Promise.race([body, expiry]).finally(() => clearTimeout(timer));
}

/**
 * Waits until `instance` renders `items` children at the vault root, and fails
 * if the engine dead-lettered anything on the way.
 *
 * The rendered root carries the pending-op overlay, so this proves the engine
 * accepted the work rather than that it published it. Only a second instance
 * that refreshes and reads proves a publish.
 */
export async function rendersItems(
  context: ScenarioContext,
  instance: Instance,
  items: number,
  what: string
): Promise<VaultStatus> {
  return poll(
    () => instance.status(),
    (status) => status.items === items && status.deadLetters === 0,
    {
      what: `${instance.name}: ${what}`,
      timeoutMs: context.deadlines.refreshMs,
      intervalMs: context.deadlines.intervalMs,
    }
  );
}

/**
 * Asserts that a filesystem call the projection must refuse did refuse, and
 * hands back the error it refused with.
 *
 * An operation the engine did not accept must reach the caller as an error. A
 * call that returns success and reaches no engine is silent loss, which is
 * worse than any refusal.
 */
export async function refuses(
  call: Promise<unknown>,
  what: string
): Promise<NodeJS.ErrnoException> {
  try {
    await call;
  } catch (error) {
    return error as NodeJS.ErrnoException;
  }
  assert.fail(`${what} must be refused, and it succeeded`);
}
