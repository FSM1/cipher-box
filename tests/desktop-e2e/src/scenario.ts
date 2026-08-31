/**
 * What every scenario gets, and the assertions they share.
 */

import { strict as assert } from 'node:assert';
import { readFile, readdir, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
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
    return await withDeadline(body(started), context.deadlines.scenarioMs);
  } finally {
    for (const instance of started.reverse()) await instance.stop();
  }
}

/**
 * Fails the scenario when its whole body outlasts the budget.
 *
 * A kernel call on a mount has no timeout of its own, so a mount that stops
 * answering hangs the process rather than the wait. The teardown that follows
 * unmounts, which is what releases the call.
 */
function withDeadline<T>(body: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`the scenario did not finish within ${timeoutMs}ms`)),
      timeoutMs
    );
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

/**
 * Waits until `path` under a mount reads back `text`.
 *
 * A read that follows a write is not instant. The write journals one op and its
 * content resolves after that, and until it does the projection answers the
 * retryable `EAGAIN` rather than blocking (blueprint/desktop.md "Reads, writes,
 * and the never-block law"). A read that lands ahead of it sees the version
 * before the write, which for a create is an empty file.
 */
export async function readsBack(
  context: ScenarioContext,
  what: string,
  path: string,
  text: string,
  timeoutMs: number
): Promise<void> {
  await poll(
    () => contentOf(path),
    (read) => read === text,
    {
      what: `${what} to read back what was written`,
      timeoutMs,
      intervalMs: context.deadlines.intervalMs,
    }
  );
}

/**
 * Waits until `instance` lists `name` at its mount root and reads `text` back
 * from it, and hands back the whole listing.
 *
 * Each read re-resolves: the manual refresh reads past every cache, and the
 * listing that follows it is the one the mount answers from. A second instance
 * reading through its own mount is the only proof of a publish — the instance
 * that wrote renders its own pending op whether or not it left the device.
 */
export async function readsThrough(
  context: ScenarioContext,
  instance: Instance,
  name: string,
  text: string,
  timeoutMs: number
): Promise<string[]> {
  const seen = await poll(
    async () => {
      await instance.refresh();
      const listed = await readdir(instance.mountRoot);
      const read = listed.includes(name)
        ? await contentOf(join(instance.mountRoot, name))
        : 'not listed';
      return { listed, read };
    },
    (found) => found.read === text,
    {
      what: `${instance.name}: the mount to serve ${name}`,
      timeoutMs,
      intervalMs: context.deadlines.intervalMs,
    }
  );
  return seen.listed;
}

/**
 * The file's content, or the error code a read that the projection refused
 * carried — so a wait that runs out reports the refusal rather than a stack.
 */
async function contentOf(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    return (error as NodeJS.ErrnoException).code ?? 'the read failed';
  }
}
