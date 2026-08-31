/**
 * What every scenario gets, and the assertions they share.
 */

import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Instance } from './instance';
import { poll } from './poll';
import type { Deadlines } from './profile';
import type { Stack } from './stack';

/** Multi-byte and multi-line, so no transfer that mangles either passes. */
export const PAYLOAD = 'ciphertext round trip\n\tédition — 中文\r\nlast line without a newline';

export interface ScenarioContext {
  /** The login secret. One secret is one vault, so two instances share it. */
  devKey: string;
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
    for (const name of names) started.push(await context.start(name));
    return await body(started);
  } finally {
    for (const instance of started.reverse()) await instance.stop();
  }
}

/** Waits until the root holds the expected items and carries no dead letter. */
export async function settled(
  instance: Instance,
  items: number,
  deadlines: Deadlines
): Promise<void> {
  await instance.waitFor(
    `the root to hold ${items} items with no dead letter`,
    (seen) => seen.items === items && seen.deadLetters === 0,
    deadlines.publishMs
  );
}

const ABSENT = 'absent: ';

/** Reads a path off a mount, and waits for it to appear. */
export async function readWhenPresent(
  instance: Instance,
  relativePath: string,
  deadlines: Deadlines
): Promise<string> {
  const path = join(instance.mountRoot, relativePath);
  return poll(
    async () => {
      try {
        return await readFile(path, 'utf8');
      } catch (error) {
        return ABSENT + (error as NodeJS.ErrnoException).code;
      }
    },
    (text) => !text.startsWith(ABSENT),
    {
      what: `${instance.name}: ${relativePath} to appear on the mount`,
      timeoutMs: deadlines.refreshMs,
      intervalMs: deadlines.intervalMs,
    }
  );
}

/** Asserts an operation is refused with the errno the projection promises. */
export async function refusedWith(
  code: string,
  what: string,
  operation: () => Promise<unknown>
): Promise<void> {
  let raised: NodeJS.ErrnoException | null = null;
  try {
    await operation();
  } catch (error) {
    raised = error as NodeJS.ErrnoException;
  }
  assert.ok(raised, `${what} must be refused, and it succeeded`);
  assert.equal(raised.code, code, `${what} must be refused with ${code}`);
}

export { assert };
